'use strict';
// How much the relay lets anyone ask for, and how it tells one asker from another without keeping their address. Written 2026-11-08 by
// Melanikus for AVPx Dedicated Server.
//
// The relay is on the internet, so anyone can send it anything, as fast as they like, from an address that isn't even theirs (AVP Tao 3:
// input is hostile). Every kind of asking has a limit, so no one sender, and no crowd of them, can use up the relay for everyone else.
//
// A TOKEN BUCKET is how each limit is kept: it holds up to `burst` tokens and fills at `rate` a second; each thing asked for takes one
// (or, for bytes, as many as the packet has). An empty bucket says no until it fills again. So a sender can go as fast as `rate` for
// ever, and faster for a moment, up to `burst`.
//
// TELLING SENDERS APART WITHOUT KEEPING THEIR ADDRESS (the user's ruling: no IPs). A limit per sender has to know which sender is which,
// so it keys its buckets by a hash of the address with a secret only this run of the relay has, made at random and changed every day.
// The hash can't be turned back into the address, and once the secret is gone nobody can even check a guess against it. Nothing here is
// written anywhere: the buckets live in memory, and are forgotten when the secret changes.

const crypto = require('crypto');

class TokenBucket {
  // rate: tokens a second; burst: the most it holds. It starts full.
  constructor(rate, burst) {
    if (!(rate > 0) || !(burst >= 1)) {
      throw new Error('TokenBucket: a rate above 0 and a burst of at least 1');
    }

    this.rate = rate;
    this.burst = burst;
    this.tokens = burst;
    this.at = null;
  }

  // Takes amount tokens at now (milliseconds) if there are that many, and says whether it did. A clock that goes back is taken as no time.
  take(now, amount = 1) {
    if (this.at !== null && now > this.at) {
      this.tokens = Math.min(this.burst, this.tokens + ((now - this.at) / 1000) * this.rate);
    }

    if (this.at === null || now > this.at) {
      this.at = now;
    }

    if (this.tokens < amount) {
      return false;
    }

    this.tokens -= amount;
    return true;
  }
}

// The secret the addresses are hashed with: random, and new every kKeyLifeMilliseconds. random(n) gives n random bytes (crypto's, or a
// test's own).
const kKeyLifeMilliseconds = 24 * 60 * 60 * 1000;

class AddressHasher {
  constructor(random = crypto.randomBytes) {
    this.random = random;
    this.key = null;
    this.madeAt = null;
    this.generation = 0;
  }

  // A short name for an address, the same for the same address until the secret changes. generation says which secret it was made with,
  // so whatever is keyed by these can forget the old ones.
  keyOf(address, now) {
    if (this.key === null || now - this.madeAt >= kKeyLifeMilliseconds || now < this.madeAt) {
      this.key = this.random(32);
      this.madeAt = now;
      this.generation++;
    }

    return crypto.createHmac('sha256', this.key).update(String(address)).digest('hex').slice(0, 32);
  }
}

// A limit for each sender, at most `most` senders remembered. When it's full, the sender heard from longest ago is forgotten: a crowd of
// made-up senders can push real ones out, but each of those starts again with its own limit, and the relay's limit for everyone (a
// TokenBucket of its own, kept by the caller) still holds.
class PerSender {
  constructor({ rate, burst, most, hasher }) {
    if (!(most >= 1)) {
      throw new Error('PerSender: room for at least one sender');
    }

    this.rate = rate;
    this.burst = burst;
    this.most = most;
    this.hasher = hasher;
    this.buckets = new Map();
    this.generation = null;
  }

  // Whether this sender may have amount more, at now
  allows(address, now, amount = 1) {
    const key = this.hasher.keyOf(address, now);

    // A new secret: every key made with the old one means nothing now
    if (this.generation !== this.hasher.generation) {
      this.buckets.clear();
      this.generation = this.hasher.generation;
    }

    let bucket = this.buckets.get(key);

    if (bucket) {
      // Heard from now: to the end of the line, the last to be forgotten
      this.buckets.delete(key);
    } else {
      bucket = new TokenBucket(this.rate, this.burst);

      if (this.buckets.size >= this.most) {
        this.buckets.delete(this.buckets.keys().next().value);
      }
    }

    this.buckets.set(key, bucket);
    return bucket.take(now, amount);
  }

  get size() {
    return this.buckets.size;
  }
}

module.exports = { TokenBucket, AddressHasher, PerSender, kKeyLifeMilliseconds };
