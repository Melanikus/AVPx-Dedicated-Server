'use strict';
// The tests of relay/limits.js: buckets fill and empty as they say, senders are told apart by a hash that changes daily, and the most
// senders remembered is kept to. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const { TokenBucket, AddressHasher, PerSender, kKeyLifeMilliseconds } = require('../relay/limits');
const { seededRandom } = require('../support/seeded-random');

test('a bucket starts full, empties, and fills at its rate', () => {
  const b = new TokenBucket(2, 3);
  assert.ok(b.take(0) && b.take(0) && b.take(0), 'its burst');
  assert.ok(!b.take(0), 'then nothing');
  assert.ok(!b.take(499), 'not yet one token after 0.499 s at 2 a second');
  assert.ok(b.take(500), 'one after 0.5 s');
  assert.ok(!b.take(500));
  assert.ok(b.take(100000) && b.take(100000) && b.take(100000) && !b.take(100000), 'it never holds more than its burst');
});

test('a bucket takes amounts, and a clock going back gives nothing', () => {
  const b = new TokenBucket(1000, 1000);
  assert.ok(b.take(10, 600));
  assert.ok(!b.take(10, 600), 'not 600 more');
  assert.ok(!b.take(5, 600), 'and going back in time fills nothing');
  assert.ok(b.take(310, 600), '300 ms at 1000 a second is 300 more: 700');
});

test('a bucket refuses a rate or burst it cannot keep', () => {
  assert.throws(() => new TokenBucket(0, 10));
  assert.throws(() => new TokenBucket(1, 0));
  assert.throws(() => new TokenBucket(NaN, 1));
});

test('an address hashes the same until the secret changes, and never shows the address', () => {
  const h = new AddressHasher(seededRandom(7));
  const a = h.keyOf('203.0.113.7', 0);
  assert.strictEqual(a, h.keyOf('203.0.113.7', 1000));
  assert.notStrictEqual(a, h.keyOf('203.0.113.8', 1000));
  assert.ok(!a.includes('203') && /^[0-9a-f]{32}$/.test(a), 'a hash, not the address');
  const generation = h.generation;
  assert.notStrictEqual(a, h.keyOf('203.0.113.7', kKeyLifeMilliseconds), 'a day later the same address has another hash');
  assert.strictEqual(h.generation, generation + 1);
});

test('each sender has its own limit', () => {
  const s = new PerSender({ rate: 1, burst: 2, most: 100, hasher: new AddressHasher(seededRandom(1)) });
  assert.ok(s.allows('198.51.100.1', 0) && s.allows('198.51.100.1', 0));
  assert.ok(!s.allows('198.51.100.1', 0), 'the first sender has used its burst');
  assert.ok(s.allows('198.51.100.2', 0), 'the second has its own');
});

test('the senders remembered stop at the most, forgetting the one heard from longest ago', () => {
  const s = new PerSender({ rate: 1, burst: 1, most: 3, hasher: new AddressHasher(seededRandom(1)) });
  s.allows('a', 0);
  s.allows('b', 0);
  s.allows('c', 0);
  assert.ok(!s.allows('a', 0), 'a has used its one, and is heard from last now');
  s.allows('d', 0);
  assert.strictEqual(s.size, 3, 'still 3');
  assert.ok(s.allows('b', 0), 'b was the one heard from longest ago, so it was forgotten, and starts again');
  assert.ok(!s.allows('a', 0), 'a was kept');
});

test('a new secret forgets every sender', () => {
  const h = new AddressHasher(seededRandom(1));
  const s = new PerSender({ rate: 1, burst: 1, most: 10, hasher: h });
  assert.ok(s.allows('a', 0));
  assert.ok(!s.allows('a', 1));
  assert.ok(s.allows('a', kKeyLifeMilliseconds), 'a day on, the old limits are gone');
  assert.strictEqual(s.size, 1);
});
