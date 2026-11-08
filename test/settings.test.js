'use strict';
// The tests of settings.js and log.js. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseSettings } = require('../settings');
const { makeLog, kMostFileBytes } = require('../log');

const good = { certFile: 'C:\\AVPx\\cert.pem', keyFile: 'C:\\AVPx\\key.pem' };
const parse = (o) => parseSettings(JSON.stringify(o));

test('the defaults, with only the certificate given', () => {
  const s = parse(good);
  assert.strictEqual(s.controlPort, 27500);
  assert.strictEqual(s.relayPorts.length, 64);
  assert.strictEqual(s.relayPorts[0], 27501);
  assert.strictEqual(s.listPort, 443);
  assert.strictEqual(s.relayAddress, '0.0.0.0');
  assert.strictEqual(s.logFile, '');
});

test('every setting is held to its limits', () => {
  const refused = (change, why) => assert.throws(() => parse({ ...good, ...change }), /^Error: settings: /, why);
  refused({ certFile: '' }, 'no certificate');
  refused({ keyFile: undefined, certFile: 'x' }, 'no key');
  refused({ controlPort: 80 }, 'a control port below 1024');
  refused({ controlPort: 70000 }, 'a port over 65535');
  refused({ controlPort: '27500' }, 'a port as text');
  refused({ relayPorts: '27501' }, 'one number');
  refused({ relayPorts: '27564-27501' }, 'going down');
  refused({ relayPorts: '20000-30000' }, 'over 4000 ports');
  refused({ relayPorts: '27400-27600' }, 'the control port among them');
  refused({ relayAddress: 'localhost' }, 'a name, not an address');
  refused({ relayAddress: '::1' }, 'IPv6');
  refused({ listAddress: '300.1.1.1' }, 'not an address');
  refused({ logFile: 'a\nb' }, 'a line break in a path');
  refused({ certFile: 'x'.repeat(261) }, 'a path over 260');
  refused({ relayport: 1 }, 'a name it doesn\'t know');
  assert.throws(() => parseSettings('{'), /must be JSON/);
  assert.throws(() => parseSettings('[]'), /JSON object/);
  assert.throws(() => parseSettings(' '.repeat(16 * 1024 + 1)), /at most 16 KB/);
});

test('the log writes a line with its time, keeps the file to its size, and turns a line break into a space', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avpx-log-'));
  const file = path.join(dir, 'server.log');
  const realWrite = process.stdout.write;
  process.stdout.write = () => true;
  try {
    const log = makeLog(file, () => new Date(0));
    log('first\nsecond');
    assert.strictEqual(fs.readFileSync(file, 'utf8'), '1970-01-01T00:00:00.000Z first second\n');
    const long = 'x'.repeat(1024 * 1024);
    for (let i = 0; i < 12; i++) log(long);
    assert.ok(fs.statSync(file).size <= kMostFileBytes, 'the file stays under its size');
    assert.ok(fs.existsSync(`${file}.1`), 'and the old lines moved to .1');
  } finally {
    process.stdout.write = realWrite;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
