'use strict';
// The tests with real sockets: the relay's UDP ports and the list's server, on the loopback address (127.0.0.1) only, so nothing goes to
// any network. They run only when AVPX_LIVE=1 is set (GitHub's Tests check sets it), so a plain `node --test` opens no socket. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// The list's server is tested over plain HTTP here: the same code, with Node's HTTP server put in place of HTTPS by the test (no
// certificate is needed or kept in the repository). TLS itself is Node's.
const test = require('node:test');
const assert = require('node:assert');
const dgram = require('dgram');
const http = require('http');
const P = require('../relay/protocol');
const { RelayCore } = require('../relay/core');
const { startRelay } = require('../relay/sockets');
const { createListServer } = require('../list/https');
const { Listings } = require('../list/listings');

const live = process.env.AVPX_LIVE === '1';
const LOOPBACK = '127.0.0.1';
const CONTROL = 37500;
const PORTS = [37501, 37502];
const REGION = 'virginia';
const KEY = Buffer.alloc(32, 0x5a);
const core = (ports = PORTS) => new RelayCore({ controlPort: CONTROL, ports, region: REGION, passKey: KEY });

function socket() {
  return new Promise((resolve) => {
    const s = dgram.createSocket('udp4');
    s.bind(0, LOOPBACK, () => resolve(s));
  });
}

// Sends a message from s to a port, and waits for the next packet s gets (or none within ms)
function ask(s, port, data, ms = 1000) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => { s.removeListener('message', on); resolve(null); }, ms);
    const on = (msg) => { clearTimeout(timer); s.removeListener('message', on); resolve(msg); };
    s.on('message', on);
    s.send(data, port, LOOPBACK);
  });
}

test('a whole game through the relay\'s real UDP ports', { skip: !live && 'set AVPX_LIVE=1 to open sockets on 127.0.0.1' }, async () => {
  const lines = [];
  const relay = await startRelay({ address: LOOPBACK, core: core(), log: (l) => lines.push(l) });
  const host = await socket();
  const joiner = await socket();

  try {
    const mine = Buffer.from('sixteen bytes!!!', 'latin1');
    const echo = P.encode({ type: P.TYPE.ECHO, secret: mine, number: 1 });
    const echoed = await ask(host, CONTROL, echo);
    assert.strictEqual(echoed.length, echo.length, 'the echo comes back the same size');
    assert.strictEqual(P.decode(echoed).type, P.TYPE.ECHO_BACK);
    assert.ok(P.decode(echoed).secret.equals(mine), 'with the asker\'s own bytes');

    const cookie = P.decode(await ask(host, CONTROL, P.encode({ type: P.TYPE.HOST_OPEN })));
    assert.strictEqual(cookie.type, P.TYPE.COOKIE);
    const opened = P.decode(await ask(host, CONTROL, P.encode({ type: P.TYPE.HOST_OPEN, secret: cookie.secret })));
    assert.strictEqual(opened.type, P.TYPE.HOST_OPENED);
    assert.ok(opened.pass && opened.passTime > 0, 'with a pass for the list');

    const joinCookie = P.decode(await ask(joiner, CONTROL, P.encode({ type: P.TYPE.JOIN, code: opened.code })));
    const newJoiner = new Promise((resolve) => host.once('message', (m) => resolve(P.decode(m))));
    const joined = P.decode(await ask(joiner, CONTROL, P.encode({ type: P.TYPE.JOIN, secret: joinCookie.secret, code: opened.code })));
    assert.strictEqual(joined.type, P.TYPE.JOIN_PORT);
    assert.strictEqual((await newJoiner).port, joined.port);

    host.send(P.encode({ type: P.TYPE.HOST_HELLO, secret: opened.secret, port: joined.port }), joined.port, LOOPBACK);
    const ready = P.decode(await ask(joiner, joined.port, P.encode({ type: P.TYPE.JOINER_HELLO, secret: joined.secret })));
    assert.strictEqual(ready.type, P.TYPE.READY);

    const toHost = new Promise((resolve) => host.once('message', resolve));
    joiner.send(Buffer.from('an ENet packet'), joined.port, LOOPBACK);
    assert.strictEqual((await toHost).toString(), 'an ENet packet');
    const back = await ask(host, joined.port, Buffer.from('and its answer'));
    assert.strictEqual(back, null, 'the host\'s answer goes to the joiner, not back to the host');
  } finally {
    host.close();
    joiner.close();
    relay.stop();
  }
  assert.ok(lines.some((l) => l.startsWith('relay: listening')));
});

test('the relay won\'t start on a port that\'s taken, and closes what it opened', { skip: !live && 'set AVPX_LIVE=1' }, async () => {
  const blocker = dgram.createSocket('udp4');
  await new Promise((resolve) => blocker.bind(PORTS[1], LOOPBACK, resolve));
  try {
    await assert.rejects(startRelay({ address: LOOPBACK, core: core(), log: () => {} }), /could not be opened/);
    const again = await startRelay({ address: LOOPBACK, core: core([PORTS[0]]), log: () => {} });
    again.stop();
  } finally {
    blocker.close();
  }
});

function request(port, method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: LOOPBACK, port, method, path, headers: { ...headers, ...(body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}) } }, (res) => {
      const parts = [];
      res.on('data', (d) => parts.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts).toString() }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function listServer() {
  const relay = core();
  const listings = new Listings({ relays: [{ region: REGION, host: 'virginia.relay.example.net', port: CONTROL, passKey: KEY }], now: Date.now() });
  const list = createListServer({ listings, log: () => {}, hasher: relay.hasher, makeServer: (options, onRequest) => http.createServer(options, onRequest) });
  await new Promise((resolve) => list.server.listen(0, LOOPBACK, resolve));
  return { list, port: list.server.address().port };
}

test('the list\'s server answers with JSON and its safety headers, and refuses a body over 1 KB', { skip: !live && 'set AVPX_LIVE=1' }, async () => {
  const { list, port } = await listServer();
  try {
    const empty = await request(port, 'GET', '/v1/games?version=1');
    assert.strictEqual(empty.status, 200);
    assert.deepStrictEqual(JSON.parse(empty.body), { games: [] });
    assert.match(empty.headers['content-type'], /^application\/json/);
    assert.strictEqual(empty.headers['x-content-type-options'], 'nosniff');
    assert.match(empty.headers['strict-transport-security'], /max-age=/);
    assert.strictEqual((await request(port, 'POST', '/v1/games', 'x'.repeat(1025))).status, 413);
    const relays = await request(port, 'GET', '/v1/relays');
    assert.deepStrictEqual(JSON.parse(relays.body), { relays: [{ region: REGION, host: 'virginia.relay.example.net', port: CONTROL }] });
    assert.strictEqual((await request(port, 'GET', '/nothing')).status, 404);
  } finally {
    list.stop();
  }
});

test('the list\'s server holds one address to its rate', { skip: !live && 'set AVPX_LIVE=1' }, async () => {
  const { list, port } = await listServer();
  try {
    const statuses = [];
    for (let i = 0; i < 8; i++) statuses.push((await request(port, 'GET', '/v1/games?version=1')).status);
    assert.ok(statuses.includes(429), `some of 8 quick list reads are refused: ${statuses}`);
  } finally {
    list.stop();
  }
});
