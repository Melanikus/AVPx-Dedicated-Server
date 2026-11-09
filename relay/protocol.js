'use strict';
// The relay's own messages: what a host, a joiner and the relay say to each other. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// WHY THE RELAY: a game hosted behind carrier-grade NAT (an ISP sharing one public address between many homes) can't be reached from
// the internet, however the home router is set. So every internet game goes through our own small relay: the host and each joiner talk
// to the relay, which passes the game's packets between them. The plan is AvP-docs/engine/net-online-server-plan.md (not in the
// repository); README.md says how this works.
//
// WHAT A MESSAGE IS: exactly kMessageBytes bytes, every field in its place, little-endian:
//
//     bytes  0-3    'AVPR', so a stray packet is never taken for one
//     byte   4      the version of these messages, kVersion
//     byte   5      the type, one of TYPE below
//     bytes  6-7    0
//     bytes  8-23   a secret, 16 bytes: a host's token, a joiner's ticket, a cookie (core.js says what those are), or an echo's bytes
//     bytes 24-31   a game's code, 8 letters from kCodeLetters
//     bytes 32-33   a port
//     bytes 34-35   a number: why the relay refused, how many joiners a game has, or an echo's count
//     bytes 36-51   a pass, 16 bytes (pass.js says what that is)
//     bytes 52-59   the pass time: when the pass was made, whole seconds since 1970-01-01 UTC
//     bytes 60-63   0
//
// Each type uses only some of the fields (USES, below), and every field it doesn't use is 0.
//
// Every message is the same size, questions and answers alike, so the relay never answers with more bytes than it was sent: nobody can
// use it to flood someone else by asking in their name (an "amplification" attack). Anything that isn't exactly a message, with its
// zeros zero and its type known, isn't one: decode gives back null, and the relay drops it. Nothing in a message is ever a length or an
// index into anything, so a message can't make the relay read past what it was given (AVP Tao 3: input is hostile).
//
// THE GAME'S OWN PACKETS are never one of these, and the relay never reads or changes them: it only passes them on. See core.js.
//
// PROTOCOL.md section 2 says all this for any language, with the same numbers.

const { kPassBytes } = require('./pass');

const kMagic = Buffer.from('AVPR', 'latin1');
const kVersion = 1;
const kMessageBytes = 64;
const kSecretBytes = 16;
const kCodeBytes = 8;

// A game's code is what a joiner types or picks, so it has no letters that look alike (no 0, 1, I, O): 32 letters, 5 bits each, 40 bits.
// Guessing one is slowed by the relay's limits on asking (limits.js).
const kCodeLetters = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

const TYPE = {
  HOST_OPEN: 1,       // a host asks for a game: a cookie, or nothing the first time
  HOST_OPENED: 2,     // the relay's answer: the host's token, the game's code, and a pass for the list
  HOST_KEEP: 3,       // a host says it's still there, every 15 s: its token
  HOST_KEPT: 4,       // the relay's answer: the token, how many joiners the game has, and a fresh pass
  HOST_CLOSE: 5,      // a host ends its game: its token. No answer.
  JOIN: 6,            // a joiner asks to join a game: its code, and a cookie, or nothing the first time
  JOIN_PORT: 7,       // the relay's answer: a ticket, the code, and the relay's port for this joiner
  NEW_JOINER: 8,      // the relay tells the host a joiner is coming, on that port: the host's token, the port
  HOST_HELLO: 9,      // the host, from its game's own socket, to that port: its token, the port
  JOINER_HELLO: 10,   // the joiner, from its game's own socket, to that port: its ticket
  READY: 11,          // the relay, from that port, to the joiner: both ends are there, start the game's connection
  REFUSED: 12,        // the relay's answer when it won't: why, in the number
  COOKIE: 13,         // the relay's answer to a HOST_OPEN or JOIN with no good cookie: the cookie to ask again with, in the secret
  ECHO: 14,           // anyone asks for an answer at once, to time the round trip: 16 bytes of its own, and a count
  ECHO_BACK: 15,      // the relay's answer: the same 16 bytes and count. A different type, so two relays can't be set answering each other.
};

const REFUSED_WHY = {
  NO_SUCH_GAME: 1,    // no game has that code (or it has ended)
  GAME_FULL: 2,       // the game has as many joiners as it can
  BUSY: 3,            // the relay has no room: too many games, or no port free
  TOO_MANY_GAMES: 4,  // this address already has as many games open as one address can
};

// The fields each type uses; every other field of that type is 0. "pass" is the pass and its pass time together.
const USES = {
  [TYPE.HOST_OPEN]: ['secret'],
  [TYPE.HOST_OPENED]: ['secret', 'code', 'pass'],
  [TYPE.HOST_KEEP]: ['secret'],
  [TYPE.HOST_KEPT]: ['secret', 'number', 'pass'],
  [TYPE.HOST_CLOSE]: ['secret'],
  [TYPE.JOIN]: ['secret', 'code'],
  [TYPE.JOIN_PORT]: ['secret', 'code', 'port'],
  [TYPE.NEW_JOINER]: ['secret', 'port'],
  [TYPE.HOST_HELLO]: ['secret', 'port'],
  [TYPE.JOINER_HELLO]: ['secret'],
  [TYPE.READY]: ['secret', 'port'],
  [TYPE.REFUSED]: ['number'],
  [TYPE.COOKIE]: ['secret'],
  [TYPE.ECHO]: ['secret', 'number'],
  [TYPE.ECHO_BACK]: ['secret', 'number'],
};

const kZeroSecret = Buffer.alloc(kSecretBytes);
const kZeroCode = Buffer.alloc(kCodeBytes);
const kZeroPass = Buffer.alloc(kPassBytes);

function isKnownType(type) {
  return Object.prototype.hasOwnProperty.call(USES, type);
}

// Whether 8 bytes are a game's code: every one of them one of kCodeLetters
function isCode(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== kCodeBytes) {
    return false;
  }

  for (const b of bytes) {
    if (kCodeLetters.indexOf(String.fromCharCode(b)) < 0) {
      return false;
    }
  }

  return true;
}

// A message, from its fields. secret, code and pass are Buffers of their sizes, or null for zeros; port and number are whole numbers that
// fit in 16 bits; passTime is a whole number of seconds. A field the type doesn't use must be left out (or zero). Throws on anything else:
// only our own code calls this, so a wrong field is a bug to find at once.
function encode({ type, secret = null, code = null, port = 0, number = 0, pass = null, passTime = 0 }) {
  if (!isKnownType(type)) {
    throw new Error('encode: no such type');
  }

  if (secret !== null && !(Buffer.isBuffer(secret) && secret.length === kSecretBytes)) {
    throw new Error('encode: a secret is 16 bytes');
  }

  if (code !== null && !isCode(code)) {
    throw new Error('encode: a code is 8 of the code letters');
  }

  for (const n of [port, number]) {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) {
      throw new Error('encode: a port or number fits in 16 bits');
    }
  }

  if (pass !== null && !(Buffer.isBuffer(pass) && pass.length === kPassBytes)) {
    throw new Error('encode: a pass is 16 bytes');
  }

  if (!Number.isSafeInteger(passTime) || passTime < 0) {
    throw new Error('encode: a pass time is a whole number of seconds');
  }

  const uses = USES[type];
  const given = { secret: secret !== null, code: code !== null, port: port !== 0, number: number !== 0, pass: pass !== null || passTime !== 0 };

  for (const field of Object.keys(given)) {
    if (given[field] && !uses.includes(field)) {
      throw new Error(`encode: this type has no ${field}`);
    }
  }

  const out = Buffer.alloc(kMessageBytes);
  kMagic.copy(out, 0);
  out[4] = kVersion;
  out[5] = type;
  (secret || kZeroSecret).copy(out, 8);
  (code || kZeroCode).copy(out, 24);
  out.writeUInt16LE(port, 32);
  out.writeUInt16LE(number, 34);
  (pass || kZeroPass).copy(out, 36);
  out.writeBigUInt64LE(BigInt(passTime), 52);
  return out;
}

// A message's fields from its bytes, or null if the bytes aren't exactly a message. The secret, code and pass are copies, so nothing kept
// from a message holds on to the packet it came in.
function decode(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== kMessageBytes) {
    return null;
  }

  if (!bytes.subarray(0, 4).equals(kMagic) || bytes[4] !== kVersion || !isKnownType(bytes[5])) {
    return null;
  }

  // The bytes that are always 0
  if (bytes[6] !== 0 || bytes[7] !== 0) {
    return null;
  }

  for (let i = 60; i < kMessageBytes; i++) {
    if (bytes[i] !== 0) {
      return null;
    }
  }

  const secret = Buffer.from(bytes.subarray(8, 24));
  const codeBytes = Buffer.from(bytes.subarray(24, 32));
  const pass = Buffer.from(bytes.subarray(36, 52));
  const passTime = bytes.readBigUInt64LE(52);
  const codeIsZero = codeBytes.equals(kZeroCode);

  // A code is all code letters, or all zeros; anything in between isn't a message
  if (!codeIsZero && !isCode(codeBytes)) {
    return null;
  }

  // A pass time past the most a JavaScript number holds exactly isn't one any relay made
  if (passTime > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }

  const m = {
    type: bytes[5],
    secret: secret.equals(kZeroSecret) ? null : secret,
    code: codeIsZero ? null : codeBytes,
    port: bytes.readUInt16LE(32),
    number: bytes.readUInt16LE(34),
    pass: pass.equals(kZeroPass) ? null : pass,
    passTime: Number(passTime),
  };

  // A field this type doesn't use must be 0
  const uses = USES[m.type];
  const given = { secret: m.secret !== null, code: m.code !== null, port: m.port !== 0, number: m.number !== 0, pass: m.pass !== null || m.passTime !== 0 };

  for (const field of Object.keys(given)) {
    if (given[field] && !uses.includes(field)) {
      return null;
    }
  }

  return m;
}

module.exports = { kMagic, kVersion, kMessageBytes, kSecretBytes, kCodeBytes, kCodeLetters, TYPE, REFUSED_WHY, USES, isCode, encode, decode };
