'use strict';
// The tests of test-vectors/relay-v1.json: the file is exactly what the code makes now, and every vector in it holds, read the way any
// other implementation would read it. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const P = require('../relay/protocol');
const { makePass } = require('../relay/pass');
const { text, kFile } = require('../tools/make-vectors');

const file = fs.readFileSync(kFile, 'latin1');
const v = JSON.parse(file);

test('the vectors file is what the code makes now (run node tools/make-vectors.js after a change, and say why in the commit)', () => {
  assert.strictEqual(file.replace(/\r/g, ''), text());
});

test('every message reads back as its fields', () => {
  const types = new Set();
  for (const m of v.messages) {
    const bytes = Buffer.from(m.hex, 'hex');
    assert.strictEqual(bytes.length, 64, m.name);
    const d = P.decode(bytes);
    assert.ok(d, m.name);
    assert.deepStrictEqual({
      type: d.type, secret: d.secret ? d.secret.toString('hex') : '', code: d.code ? d.code.toString('latin1') : '', port: d.port,
      number: d.number, pass: d.pass ? d.pass.toString('hex') : '', passTime: d.passTime,
    }, m.fields, m.name);
    types.add(d.type);
  }
  assert.strictEqual(types.size, Object.keys(P.TYPE).length, 'every type has a message');
});

test('every refused vector is not a message, and every reason is one of the eight words', () => {
  const whys = new Set(['size', 'magic', 'version', 'type', 'zero', 'unused', 'code', 'passtime']);
  for (const r of v.refused) {
    assert.ok(whys.has(r.why), r.name);
    assert.strictEqual(P.decode(Buffer.from(r.hex, 'hex')), null, r.name);
  }
  assert.ok(v.refused.filter((r) => r.why === 'unused').length > 40, 'every unused field of every type');
});

test('every pass is the one a relay makes', () => {
  for (const p of v.passes) {
    assert.strictEqual(makePass(Buffer.from(p.key, 'hex'), p.region, Buffer.from(p.code, 'latin1'), p.passTime).toString('hex'), p.pass);
  }
});
