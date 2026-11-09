'use strict';
// The list's HTTPS server: Node's own, with every limit in PROTOCOL.md section 5, around list/routes.js. Written 2026-11-08 by Melanikus
// for AVPx Dedicated Server.
//
// THE LIMITS, all from anyone on the internet (AVP Tao 3):
// - headers at most 8 KB (Node refuses more), a body at most 1 KB (refused with 413 as soon as it's over, not after it's all come);
// - 5 s for the TLS handshake, 5 s to send the headers, and 10 s for the whole request, each checked every second: a sender who
//   trickles a byte at a time is cut off;
// - 200 connections at once in all, and 10 from one address;
// - from one address, 5 requests a second (20 at once), and GET /v1/games and GET /v1/relays 1 a second (5 at once).
// TLS is 1.2 or newer. Every answer is JSON, with headers that tell a browser to treat it as nothing but data, and HSTS.
//
// THE CERTIFICATE comes from two PEM files, the certificate (with its chain) and its private key, which a tool such as win-acme or certbot
// makes and renews. The server reads them at start, and every kCertificateLookMilliseconds looks again: if either file has changed, it
// reads them again and uses them for new connections, so a renewed certificate is taken up without a restart. A pair that won't load is
// written in the log and the old pair kept. The key never leaves the machine and is never written anywhere by this.
//
// NO ADDRESS IS WRITTEN ANYWHERE. A connection's address is only used, in memory, to key its limits through a hash (relay/limits.js).
//
// Once a second, the listings' tick takes down the ones not renewed in time, and once a minute gives a line of counts for the log.

const fs = require('fs');
const https = require('https');
const tls = require('tls');
const { PerSender, TokenBucket } = require('../relay/limits');
const { handle } = require('./routes');
const { kMostBodyBytes } = require('./requests');

const LIMITS = {
  mostHeaderBytes: 8 * 1024,
  handshakeMilliseconds: 5000,       // for the TLS handshake (Node's own default is 120 s)
  headersMilliseconds: 5000,
  requestMilliseconds: 10000,
  keepAliveMilliseconds: 5000,
  // How often Node looks for requests past their time. Its default is 30 s, so a sender could hold a connection that long past its 5 s;
  // looking every second keeps each limit within a second of what it says.
  checkMilliseconds: 1000,
  mostConnections: 200,
  mostConnectionsPerAddress: 10,
  requestRate: 5, requestBurst: 20,
  listRate: 1, listBurst: 5,
  everyoneRate: 500, everyoneBurst: 1000,
  mostSenders: 10000,
};
const kCertificateLookMilliseconds = 60 * 60 * 1000;

// After a body too big is refused, how much more of it is thrown away before the connection is cut
const kMostThrownAwayBytes = 64 * 1024;

const kHeaders = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'none'",
  'Referrer-Policy': 'no-referrer',
};

// The certificate and key, read from their files: { cert, key, stamp }, stamp saying which version of the files they are
function readCertificate(certFile, keyFile) {
  const cert = fs.readFileSync(certFile);
  const key = fs.readFileSync(keyFile);
  // Checks the pair can be used, before anything takes it up: this throws if the key doesn't match or either is broken
  tls.createSecureContext({ cert, key });
  const stamp = `${fs.statSync(certFile).mtimeMs}|${fs.statSync(keyFile).mtimeMs}`;
  return { cert, key, stamp };
}

// The server. listings: the Listings (listings.js) it serves. certFile, keyFile: the PEM files. log(line): where its lines go. now(): the
// time in milliseconds. hasher: the relay's AddressHasher, so one secret keys every limit. makeServer: only a test passes this, to run the
// same code over plain HTTP on the loopback address.
function createListServer({ listings, certFile, keyFile, log, now = Date.now, hasher, makeServer = null }) {
  let certificate = makeServer ? null : readCertificate(certFile, keyFile);
  const options = {
    maxHeaderSize: LIMITS.mostHeaderBytes,
    headersTimeout: LIMITS.headersMilliseconds,
    requestTimeout: LIMITS.requestMilliseconds,
    keepAliveTimeout: LIMITS.keepAliveMilliseconds,
    connectionsCheckingInterval: LIMITS.checkMilliseconds,
  };

  const perAddress = new PerSender({ rate: LIMITS.requestRate, burst: LIMITS.requestBurst, most: LIMITS.mostSenders, hasher });
  const lists = new PerSender({ rate: LIMITS.listRate, burst: LIMITS.listBurst, most: LIMITS.mostSenders, hasher });
  const everyone = new TokenBucket(LIMITS.everyoneRate, LIMITS.everyoneBurst);
  const open = new Map();   // hashed address -> how many connections it has open
  const counts = { requests: 0, refusedForLimits: 0, tooBig: 0 };

  const onRequest = (request, response) => {
    const address = request.socket.remoteAddress || '';
    const at = now();
    const send = (status, body) => {
      const text = body === null ? '' : JSON.stringify(body);
      response.writeHead(status, { ...kHeaders, 'Content-Length': Buffer.byteLength(text) });
      response.end(text);
    };

    counts.requests++;
    // The path is what comes before the first ?, and the query is everything after it, a second ? and all, so routes.js sees the whole
    // of what was sent and refuses "version=7?x" (split('?', 2) would quietly have dropped the "?x")
    const url = request.url || '';
    const mark = url.indexOf('?');
    const path = mark < 0 ? url : url.slice(0, mark);
    const query = mark < 0 ? '' : url.slice(mark + 1);
    const isList = request.method === 'GET' && (path === '/v1/games' || path === '/v1/relays');

    if (!perAddress.allows(address, at) || (isList && !lists.allows(address, at)) || !everyone.take(at)) {
      counts.refusedForLimits++;
      send(429, { error: 'too many requests: wait and try again' });
      return;
    }

    // The body, at most kMostBodyBytes: one byte more and the request is refused there and then. The refusal is sent, and the connection
    // closed once it has gone; what the sender is still sending is thrown away as it comes, up to kMostThrownAwayBytes, and past that
    // the connection is cut. (Cutting it at once, before the answer has gone, leaves an honest sender with a broken connection and no
    // answer, which the live test found.)
    const declared = request.headers['content-length'];
    const parts = [];
    let size = 0;
    let refused = false;

    const refuseTooBig = () => {
      refused = true;
      counts.tooBig++;
      response.setHeader('Connection', 'close');
      send(413, { error: 'the body is too big' });
      response.on('finish', () => request.socket.end());
    };

    if (declared !== undefined && !(/^[0-9]{1,4}$/.test(declared) && Number(declared) <= kMostBodyBytes)) {
      refuseTooBig();
    }

    request.on('data', (part) => {
      size += part.length;

      if (refused) {
        if (size > kMostThrownAwayBytes) {
          request.destroy();
        }

        return;
      }

      if (size > kMostBodyBytes) {
        refuseTooBig();
        return;
      }

      parts.push(part);
    });

    request.on('end', () => {
      if (refused) {
        return;
      }

      const result = handle(listings, { method: request.method, path, query, body: Buffer.concat(parts) }, now());
      send(result.status, result.body);
    });

    request.on('error', () => { /* the sender went away: nothing to answer */ });
  };

  const server = makeServer ? makeServer(options, onRequest) : https.createServer({ ...options, cert: certificate.cert, key: certificate.key, minVersion: 'TLSv1.2', handshakeTimeout: LIMITS.handshakeMilliseconds }, onRequest);
  server.maxConnections = LIMITS.mostConnections;

  // At most so many connections from one address
  server.on('connection', (socket) => {
    const key = hasher.keyOf(socket.remoteAddress || '', now());
    const count = (open.get(key) || 0) + 1;

    if (count > LIMITS.mostConnectionsPerAddress) {
      counts.refusedForLimits++;
      socket.destroy();
      return;
    }

    open.set(key, count);
    socket.on('close', () => {
      const left = (open.get(key) || 1) - 1;
      if (left > 0) open.set(key, left); else open.delete(key);
    });
  });

  // A TLS handshake that fails says nothing about who sent it in the log; it's only counted
  server.on('tlsClientError', () => { counts.refusedForLimits++; });
  server.on('clientError', (error, socket) => { socket.destroy(); });

  // A renewed certificate is taken up without a restart
  const look = makeServer ? null : setInterval(() => {
    try {
      const stamp = `${fs.statSync(certFile).mtimeMs}|${fs.statSync(keyFile).mtimeMs}`;

      if (stamp !== certificate.stamp) {
        certificate = readCertificate(certFile, keyFile);
        server.setSecureContext({ cert: certificate.cert, key: certificate.key, minVersion: 'TLSv1.2' });
        log('list: the certificate files changed, and the new ones are in use');
      }
    } catch (e) {
      log('list: the certificate files changed but could not be used, so the old ones are kept');
    }
  }, kCertificateLookMilliseconds);

  if (look) {
    look.unref();
  }

  const ticker = setInterval(() => {
    for (const line of listings.tick(now())) log(line);
  }, 1000);
  ticker.unref();

  return {
    server,
    counts,
    stop: () => { if (look) clearInterval(look); clearInterval(ticker); server.close(); },
  };
}

module.exports = { createListServer, readCertificate, LIMITS, kHeaders };
