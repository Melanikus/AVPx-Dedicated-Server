'use strict';
// Writes test-vectors/relay-v1.json: the relay's messages as exact bytes, the bytes that are not a message (and why), and passes, for
// every implementation to test itself against: this server's own tests, a later port to another language, and the game's. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
//   node tools/make-vectors.js     writes the file again from the code
//
// test/vectors.test.js makes the same text and fails if the file differs, so the file can't drift from the code without a test failing.
// Every value is fixed (no randomness), so the file is the same on every machine.
//
// What each part says:
// - messages: a good message of every type, with every field it uses filled in, as 128 hex digits and as its fields;
// - refused: bytes that are not a message, each with one word for why: size, magic, version, type, zero (a reserved or padding byte),
//   unused (a field its type doesn't use, not 0), code (code bytes that are neither all code letters nor all 0), passtime (a pass time
//   past 2^53 - 1);
// - passes: a pass key, region, code and pass time, and the pass a relay makes from them (PROTOCOL.md section 3).

const fs = require('fs');
const path = require('path');
const P = require('../relay/protocol');
const { makePass } = require('../relay/pass');

const kFile = path.join(__dirname, '..', 'test-vectors', 'relay-v1.json');

const SECRET = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const CODE = Buffer.from('ABCD2345', 'latin1');
const PASS = Buffer.from('fedcba98765432100123456789abcdef', 'hex');
const PASS_TIME = 1794268800;   // 2026-11-11 00:00:00 UTC
const NAMES = Object.fromEntries(Object.entries(P.TYPE).map(([name, n]) => [n, name]));

// Every field a type uses, filled in with the fixed values above
function full(type, change = {}) {
  const uses = P.USES[type];
  return {
    type,
    ...(uses.includes('secret') ? { secret: SECRET } : {}),
    ...(uses.includes('code') ? { code: CODE } : {}),
    ...(uses.includes('port') ? { port: 27501 } : {}),
    ...(uses.includes('number') ? { number: 3 } : {}),
    ...(uses.includes('pass') ? { pass: PASS, passTime: PASS_TIME } : {}),
    ...change,
  };
}

// A message's fields as the file writes them: bytes as small hex digits, a field not there as "" or 0
function written(fields) {
  return {
    type: fields.type,
    secret: fields.secret ? fields.secret.toString('hex') : '',
    code: fields.code ? fields.code.toString('latin1') : '',
    port: fields.port || 0,
    number: fields.number || 0,
    pass: fields.pass ? fields.pass.toString('hex') : '',
    passTime: fields.passTime || 0,
  };
}

function vectors() {
  const messages = [];
  const refused = [];
  const good = (name, fields) => messages.push({ name, hex: P.encode(fields).toString('hex'), fields: written(fields) });
  const bad = (name, bytes, why) => refused.push({ name, hex: bytes.toString('hex'), why });
  const changed = (bytes, at, value) => { const b = Buffer.from(bytes); b[at] = value; return b; };

  for (const type of Object.values(P.TYPE)) {
    good(`${NAMES[type]} with every field it uses`, full(type));
  }

  good('HOST_OPEN the first time, with no cookie', { type: P.TYPE.HOST_OPEN });
  good('JOIN the first time, with no cookie', { type: P.TYPE.JOIN, code: CODE });
  good('ECHO of nothing, which is answered with nothing', { type: P.TYPE.ECHO });
  for (const [why, n] of Object.entries(P.REFUSED_WHY)) good(`REFUSED ${n}, ${why}`, { type: P.TYPE.REFUSED, number: n });
  good('HOST_KEPT with the largest pass time a relay can send', full(P.TYPE.HOST_KEPT, { passTime: Number.MAX_SAFE_INTEGER }));
  good('JOIN_PORT with the highest port and the last code letters', { type: P.TYPE.JOIN_PORT, secret: SECRET, code: Buffer.from('ZZZZZZZZ', 'latin1'), port: 65535 });

  const join = P.encode(full(P.TYPE.JOIN));
  bad('63 bytes', join.subarray(0, 63), 'size');
  bad('65 bytes', Buffer.concat([join, Buffer.alloc(1)]), 'size');
  bad('no bytes', Buffer.alloc(0), 'size');
  bad('another magic', changed(join, 0, 0x42), 'magic');
  bad('a magic in small letters', Buffer.concat([Buffer.from('avpr', 'latin1'), join.subarray(4)]), 'magic');
  bad('version 0', changed(join, 4, 0), 'version');
  bad('version 2', changed(join, 4, 2), 'version');
  bad('type 0', changed(join, 5, 0), 'type');
  bad('type 16, after the last', changed(join, 5, 16), 'type');
  bad('type 255', changed(join, 5, 255), 'type');
  bad('reserved byte 6 not 0', changed(join, 6, 1), 'zero');
  bad('reserved byte 7 not 0', changed(join, 7, 1), 'zero');
  bad('padding byte 60 not 0', changed(join, 60, 1), 'zero');
  bad('padding byte 63 not 0', changed(join, 63, 1), 'zero');
  bad('a code with a 0 in it', changed(join, 24, 0x30), 'code');
  bad('a code with an I in it', changed(join, 25, 0x49), 'code');
  bad('a code in small letters', Buffer.concat([join.subarray(0, 24), Buffer.from('abcd2345', 'latin1'), join.subarray(32)]), 'code');
  bad('a code half letters, half 0', Buffer.concat([join.subarray(0, 28), Buffer.alloc(4), join.subarray(32)]), 'code');

  const kept = P.encode(full(P.TYPE.HOST_KEPT));
  const past = Buffer.from(kept);
  past.writeBigUInt64LE(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 52);
  bad('a pass time of 2^53', past, 'passtime');
  const most = Buffer.from(kept);
  most.writeBigUInt64LE(0xffffffffffffffffn, 52);
  bad('a pass time of 2^64 - 1', most, 'passtime');

  // Every field each type doesn't use, set: one byte of it, or a whole code for the code field
  const at = { secret: 8, code: 24, port: 32, number: 34, pass: 36, passTime: 52 };
  const usedBy = { secret: 'secret', code: 'code', port: 'port', number: 'number', pass: 'pass', passTime: 'pass' };
  for (const type of Object.values(P.TYPE)) {
    const bytes = P.encode(full(type));
    for (const field of Object.keys(at)) {
      if (!P.USES[type].includes(usedBy[field])) {
        const b = Buffer.from(bytes);
        if (field === 'code') b.write('ABCD2345', at.code, 'latin1'); else b[at[field]] = 1;
        bad(`${NAMES[type]} with a ${field}`, b, 'unused');
      }
    }
  }

  const passes = [];
  const pass = (key, region, code, passTime) => passes.push({
    key: key.toString('hex'), region, code, passTime, pass: makePass(key, region, Buffer.from(code, 'latin1'), passTime).toString('hex'),
  });
  pass(Buffer.alloc(32, 0x07), 'virginia', 'ABCD2345', PASS_TIME);
  pass(Buffer.alloc(32, 0x07), 'virginia', 'ABCD2345', PASS_TIME + 15);
  pass(Buffer.alloc(32, 0x07), 'paris', 'ABCD2345', PASS_TIME);
  pass(Buffer.alloc(32, 0x07), 'virginia', 'ABCD2346', PASS_TIME);
  pass(Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex'), 'saopaulo', 'ZZZZZZZZ', 0);
  pass(Buffer.alloc(32, 0xff), 'longest-region-1', '23456789', Number.MAX_SAFE_INTEGER);

  return {
    protocol: 'PROTOCOL.md as at 7014de1',
    about: 'Made by tools/make-vectors.js, and checked against the code by test/vectors.test.js. Hex digits are small letters. A field a type does not use is "" (bytes) or 0 (numbers).',
    messages,
    refused,
    passes,
  };
}

function text() {
  return `${JSON.stringify(vectors(), null, 2)}\n`;
}

if (require.main === module) {
  fs.mkdirSync(path.dirname(kFile), { recursive: true });
  fs.writeFileSync(kFile, text());
  const v = vectors();
  process.stdout.write(`${path.relative(process.cwd(), kFile)}: ${v.messages.length} messages, ${v.refused.length} refused, ${v.passes.length} passes\n`);
}

module.exports = { vectors, text, kFile };
