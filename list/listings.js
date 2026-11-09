'use strict';
// What the list holds: the games hosts have listed, each checked with its relay's pass. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
//
// The list may be on another machine than a game's relay, and never asks the relay anything. A host shows the list the pass its relay
// gave it (relay/pass.js), and the list makes the pass again with that relay's key: if it matches and is less than a minute old, the room
// is real. The host then gets an OWNER key, 16 random bytes that travel only over HTTPS, and only it can change or take down its listing
// with that. The host renews its listing with a fresh pass every 15 s; one not renewed for kListingLifeMilliseconds goes.
//
// A game is known here by its region and code together: two relays could, rarely, make the same code.
//
// Nothing here is an address, and nothing here is written anywhere but the counts in tick's line. PROTOCOL.md sections 3 and 4.

const crypto = require('crypto');
const { Refusal } = require('./requests');
const { makePass, kPassBytes } = require('../relay/pass');

const kMostListings = 2000;
const kListingLifeMilliseconds = 45000;        // a host renews every 15 s
const kPassLifeMilliseconds = 60000;           // a pass is good for a minute after its pass time
const kMostPassAheadMilliseconds = 5000;       // and not at all if its time is ahead of the list's own clock by more than this
const kStatsMilliseconds = 60000;

const kOwnerBytes = 16;

function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);
}

class Listings {
  // relays: [{ region, host, port, passKey (32 bytes) }], already checked (settings.js). random(n): n random bytes.
  constructor({ relays, random = crypto.randomBytes, now = 0 }) {
    this.relays = new Map(relays.map((r) => [r.region, { region: r.region, host: r.host, port: r.port, passKey: Buffer.from(r.passKey) }]));
    this.random = random;
    this.byGame = new Map();   // "region code" -> listing
    this.statsAt = now;
    this.counts = Listings.zeroCounts();
  }

  static zeroCounts() {
    return { listed: 0, renewed: 0, ended: 0, expired: 0, passesRefused: 0, full: 0 };
  }

  // The relays, as GET /v1/relays gives them: never a key
  relayList() {
    return [...this.relays.values()].map((r) => ({ region: r.region, host: r.host, port: r.port }));
  }

  // Whether a pass is good for this region and code, at now: made with that relay's key, and less than a minute old
  passIsGood(region, code, pass, passTime, now) {
    const relay = this.relays.get(region);

    if (!relay) {
      throw new Refusal(400, 'region must be one of the regions in GET /v1/relays');
    }

    const madeAt = passTime * 1000;

    if (now > madeAt + kPassLifeMilliseconds || madeAt > now + kMostPassAheadMilliseconds || pass.length !== kPassBytes) {
      return false;
    }

    return same(pass, makePass(relay.passKey, region, Buffer.from(code, 'latin1'), passTime));
  }

  checkPass(pass, listing, now) {
    if (!this.passIsGood(listing.region, listing.code, pass, listing.passTime, now)) {
      this.counts.passesRefused++;
      throw new Refusal(403, 'that pass is not good: ask the relay for a fresh one');
    }
  }

  // The listing for this game, if it's there and alive
  find(region, code, now) {
    const listing = this.byGame.get(`${region} ${code}`);
    return listing && now - listing.renewedAt < kListingLifeMilliseconds ? listing : null;
  }

  // POST: puts a game on the list. Gives back its owner key, as 32 hex digits.
  add(pass, listing, now) {
    this.checkPass(pass, listing, now);

    if (this.find(listing.region, listing.code, now)) {
      throw new Refusal(409, 'that game is listed already');
    }

    this.expire(now);

    if (this.byGame.size >= kMostListings) {
      this.counts.full++;
      throw new Refusal(503, 'the list is full: try again later');
    }

    const owner = this.random(kOwnerBytes);
    const { passTime, ...shown } = listing;
    this.byGame.set(`${listing.region} ${listing.code}`, { ...shown, owner, listedAt: now, renewedAt: now });
    this.counts.listed++;
    return owner.toString('hex');
  }

  // PUT: renews a listing, and changes what it says, with its owner key and a fresh pass
  renew(owner, pass, listing, now) {
    this.checkPass(pass, listing, now);
    const old = this.find(listing.region, listing.code, now);

    if (!old) {
      throw new Refusal(404, 'that game is not listed');
    }

    if (!same(owner, old.owner)) {
      throw new Refusal(403, 'that is not the owner key of that listing');
    }

    const { passTime, ...shown } = listing;
    this.byGame.set(`${listing.region} ${listing.code}`, { ...shown, owner: old.owner, listedAt: old.listedAt, renewedAt: now });
    this.counts.renewed++;
  }

  // DELETE: takes a listing down, with its owner key. The room itself is the relay's, and stays until its host ends it.
  remove(region, code, owner, now) {
    const old = this.find(region, code, now);

    if (!old) {
      throw new Refusal(404, 'that game is not listed');
    }

    if (!same(owner, old.owner)) {
      throw new Refusal(403, 'that is not the owner key of that listing');
    }

    old.owner.fill(0);
    this.byGame.delete(`${region} ${code}`);
    this.counts.ended++;
  }

  // The live listings of one network version, the newest first, at most `most`
  games(version, now, most) {
    const out = [];

    for (const listing of this.byGame.values()) {
      if (listing.version === version && now - listing.renewedAt < kListingLifeMilliseconds) {
        out.push(listing);
      }
    }

    out.sort((a, b) => b.listedAt - a.listedAt);
    return out.slice(0, most);
  }

  // Takes down every listing not renewed in time
  expire(now) {
    for (const [key, listing] of this.byGame) {
      if (now - listing.renewedAt >= kListingLifeMilliseconds) {
        listing.owner.fill(0);
        this.byGame.delete(key);
        this.counts.expired++;
      }
    }
  }

  // Called about once a second: takes down what has run out, and gives back the line to write, if any (counts only)
  tick(now) {
    this.expire(now);

    if (now - this.statsAt < kStatsMilliseconds) {
      return [];
    }

    const c = this.counts;
    const line = `list: in the last ${Math.round((now - this.statsAt) / 1000)} s: ${c.listed} games listed, ${c.renewed} renewals, ` +
      `${c.ended} taken down, ${c.expired} ended unrenewed; ${c.passesRefused} passes refused, ${c.full} refused as the list was full. ` +
      `Now ${this.byGame.size} listed`;
    this.statsAt = now;
    this.counts = Listings.zeroCounts();
    return [line];
  }
}

module.exports = { Listings, kMostListings, kListingLifeMilliseconds, kPassLifeMilliseconds, kMostPassAheadMilliseconds };
