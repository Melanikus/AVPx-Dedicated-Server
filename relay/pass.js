'use strict';
// Passes: how the list knows a room is real when the room's relay is another machine. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server.
//
// The list and a relay may be in different countries, and never talk to each other: no connection between them, no port open. So the
// relay hands its room's host a PASS in every HOST_OPENED and HOST_KEPT (protocol.js), and the host shows it to the list. A pass is an
// HMAC-SHA-256, with the relay's own pass key, of:
//
//     the 11 letters AVPX-PASS-1, the relay's region name, one 0 byte, the room's code (8 bytes), the pass time (8 bytes, little-endian)
//
// cut to 16 bytes. The pass time is when the relay made it, in whole seconds since 1970-01-01 UTC. The list holds every relay's pass key,
// makes the pass again from what the host sent, and takes it only if it matches and is less than a minute old (list/listings.js).
//
// Each relay has its own key, so a relay machine broken into can make passes only for its own region; and a pass key makes passes and
// nothing else, so it can't open, end or touch a room. PROTOCOL.md section 3 says all this for any language.

const crypto = require('crypto');

const kPassBytes = 16;
const kPassKeyBytes = 32;
const kPassLabel = Buffer.from('AVPX-PASS-1', 'latin1');

// A region's name: 1 to 16 small letters, digits and -, such as "virginia". It goes into every pass and every listing, so it's held to
// letters nobody could read two ways.
const kRegionPattern = /^[a-z0-9-]{1,16}$/;

function isRegion(value) {
  return typeof value === 'string' && kRegionPattern.test(value);
}

// The pass for a room: key (32 bytes), region (a region name), code (the room's 8 code letters, as bytes), passTime (whole seconds).
// Throws on anything else: only our own code calls this, with what it has already checked.
function makePass(key, region, code, passTime) {
  if (!Buffer.isBuffer(key) || key.length !== kPassKeyBytes || !isRegion(region) || !Buffer.isBuffer(code) || code.length !== 8 ||
      !Number.isSafeInteger(passTime) || passTime < 0) {
    throw new Error('makePass: a 32-byte key, a region name, an 8-byte code and a whole number of seconds');
  }

  const time = Buffer.alloc(8);
  time.writeBigUInt64LE(BigInt(passTime));
  const what = Buffer.concat([kPassLabel, Buffer.from(region, 'latin1'), Buffer.alloc(1), code, time]);
  return crypto.createHmac('sha256', key).update(what).digest().subarray(0, kPassBytes);
}

module.exports = { kPassBytes, kPassKeyBytes, isRegion, makePass };
