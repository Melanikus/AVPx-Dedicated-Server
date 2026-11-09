'use strict';
// The tests of settings.js and log.js. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parseSettings } = require('../settings');
const { makeLog, kMostFileBytes } = require('../log');

const KEY = '5a'.repeat(32);
const PARIS_KEY = '7b'.repeat(32);
const relayOnly = { region: 'virginia', passKey: KEY };
const withList = {
  ...relayOnly,
  list: {
    certFile: 'C:\\AVPx\\cert.pem',
    keyFile: 'C:\\AVPx\\key.pem',
    relays: [{ region: 'virginia', host: 'virginia.relay.example.net', port: 27500 }, { region: 'paris', host: 'paris.relay.example.net', port: 27500, passKey: PARIS_KEY }],
  },
};
const parse = (o) => parseSettings(JSON.stringify(o));
const listWith = (change) => ({ ...withList, list: { ...withList.list, ...change } });
const relaysWith = (relays) => listWith({ relays });

test('a relay-only machine needs only its region and pass key; the rest are defaults', () => {
  const s = parse(relayOnly);
  assert.strictEqual(s.region, 'virginia');
  assert.ok(s.passKey.equals(Buffer.from(KEY, 'hex')));
  assert.strictEqual(s.controlPort, 27500);
  assert.strictEqual(s.relayPorts.length, 64);
  assert.strictEqual(s.relayPorts[0], 27501);
  assert.strictEqual(s.relayAddress, '0.0.0.0');
  assert.strictEqual(s.logFile, '');
  assert.strictEqual(s.list, null, 'and no list');
});

test('the list machine names every relay, and its own relay\'s key is its own pass key, written once', () => {
  const s = parse(withList);
  assert.strictEqual(s.list.port, 443);
  assert.strictEqual(s.list.address, '0.0.0.0');
  assert.strictEqual(s.list.relays.length, 2);
  assert.ok(s.list.relays[0].passKey.equals(s.passKey), 'its own relay uses the passKey above');
  assert.ok(s.list.relays[1].passKey.equals(Buffer.from(PARIS_KEY, 'hex')));
  assert.deepStrictEqual(s.list.relays.map((r) => [r.region, r.host, r.port]), [['virginia', 'virginia.relay.example.net', 27500], ['paris', 'paris.relay.example.net', 27500]]);
});

test('every setting is held to its limits', () => {
  const refused = (o, why) => assert.throws(() => parse(o), /^Error: settings: /, why);
  refused({ passKey: KEY }, 'no region');
  refused({ ...relayOnly, region: 'Virginia' }, 'a region with a capital');
  refused({ region: 'virginia' }, 'no pass key');
  refused({ ...relayOnly, passKey: '0'.repeat(64) }, 'a pass key of all 0, as one left unset would be');
  refused({ ...relayOnly, passKey: KEY.slice(2) }, 'a pass key of 31 bytes');
  refused({ ...relayOnly, passKey: KEY.toUpperCase() }, 'a pass key in capitals');
  refused({ ...relayOnly, passKey: 'make it with: openssl rand -hex 32' }, 'the example file\'s words, left in');
  refused({ ...relayOnly, controlPort: 80 }, 'a control port below 1024');
  refused({ ...relayOnly, controlPort: 70000 }, 'a port over 65535');
  refused({ ...relayOnly, controlPort: '27500' }, 'a port as text');
  refused({ ...relayOnly, relayPorts: '27501' }, 'one number');
  refused({ ...relayOnly, relayPorts: '27564-27501' }, 'going down');
  refused({ ...relayOnly, relayPorts: '20000-30000' }, 'over 4000 ports');
  refused({ ...relayOnly, relayPorts: '27400-27600' }, 'the control port among them');
  refused({ ...relayOnly, relayAddress: 'localhost' }, 'a name, not an address');
  refused({ ...relayOnly, relayAddress: '::1' }, 'IPv6');
  refused({ ...relayOnly, logFile: 'a\nb' }, 'a line break in a path');
  refused({ ...relayOnly, relayport: 1 }, 'a name it doesn\'t know');
  refused({ ...relayOnly, list: 'yes' }, 'a list that isn\'t an object');

  refused(listWith({ certFile: '' }), 'no certificate');
  refused(listWith({ keyFile: undefined }), 'no key');
  refused(listWith({ certFile: 'x'.repeat(261) }), 'a path over 260');
  refused(listWith({ address: '300.1.1.1' }), 'not an address');
  refused(listWith({ port: 0 }), 'port 0');
  refused(listWith({ listPort: 443 }), 'a name the list doesn\'t know');
  refused(listWith({ relays: undefined }), 'no relays');
  refused(relaysWith([]), 'no relays at all');
  const many = [];
  for (let i = 0; i < 17; i++) many.push({ region: i === 0 ? 'virginia' : `r${i}`, host: `r${i}.example.net`, port: 27500, ...(i === 0 ? {} : { passKey: PARIS_KEY }) });
  refused(relaysWith(many), '17 relays');
  assert.doesNotThrow(() => parse(relaysWith(many.slice(0, 16))), '16 is allowed');

  const [own, paris] = withList.list.relays;
  refused(relaysWith([{ ...own, passKey: KEY }, paris]), 'its own relay with a passKey of its own: the secret would be written twice');
  refused(relaysWith([own, { ...paris, passKey: undefined }]), 'another relay with no passKey');
  refused(relaysWith([paris]), 'a list that doesn\'t name its own region');
  refused(relaysWith([own, paris, { ...paris, host: 'other.example.net' }]), 'one region twice');
  refused(relaysWith([own, { ...paris, host: '203.0.113.5' }]), 'an address for a host, not a name');
  refused(relaysWith([own, { ...paris, host: '0x7f.0.0.1' }]), 'an address some resolvers read from a name with a letter in it');
  refused(relaysWith([own, { ...paris, host: 'fe80::1' }]), 'an IPv6 address');
  refused(relaysWith([own, { ...paris, host: 'paris.example.123' }]), 'a last part that starts with a digit');
  assert.doesNotThrow(() => parse(relaysWith([own, { ...paris, host: '1e100.example.net' }])), 'a name may start with a digit; only its last part may not');
  refused(relaysWith([own, { ...paris, host: 'x'.repeat(64) }]), 'a host of 64');
  refused(relaysWith([own, { ...paris, host: 'paris..example.net' }]), 'an empty part in a name');
  refused(relaysWith([own, { ...paris, host: 'paris example.net' }]), 'a space in a name');
  refused(relaysWith([own, { ...paris, port: 0 }]), 'a relay on port 0');
  refused(relaysWith([own, { ...paris, extra: 1 }]), 'a name a relay doesn\'t know');
  refused(relaysWith([own, 'paris']), 'a relay that isn\'t an object');

  assert.throws(() => parseSettings('{'), /must be JSON/);
  assert.throws(() => parseSettings('[]'), /JSON object/);
  assert.throws(() => parseSettings(' '.repeat(16 * 1024 + 1)), /at most 16 KB/);
});

test('deploy/settings.example.json is refused as it is, until a real pass key is put in', () => {
  const example = fs.readFileSync(path.join(__dirname, '..', 'deploy', 'settings.example.json'), 'utf8');
  assert.throws(() => parseSettings(example), /passKey must be 64 hex digits/);
  const filled = JSON.parse(example);
  filled.passKey = KEY;
  assert.throws(() => parse(filled), /host must be a DNS name/, 'nor until the domain is put in');
  filled.list.relays[0].host = 'virginia.relay.example.net';
  assert.strictEqual(parse(filled).region, 'virginia', 'with one, it is the Virginia machine: its relay and the list');
  assert.strictEqual(parse(filled).list.relays.length, 1);
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
