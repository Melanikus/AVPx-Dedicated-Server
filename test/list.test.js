'use strict';
// The tests of list/requests.js and list/routes.js: every call of PROTOCOL.md section 4, every field's limits, and every refusal, by
// handing it requests. No socket is opened. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const P = require('../relay/protocol');
const { RelayCore } = require('../relay/core');
const { handle, kMostGames } = require('../list/routes');
const { seededRandom } = require('../support/seeded-random');

const CONTROL = 27500;
const relay = () => new RelayCore({ controlPort: CONTROL, ports: [27501, 27502], random: seededRandom(5) });
let nextHost = 1;

// Opens a room the whole way, as a host's game would: gives back its token as hex
function openRoom(r, now = 0) {
  const host = { address: `198.51.100.${nextHost++}`, port: 40000 };
  const cookie = P.decode(r.receive(CONTROL, host.address, host.port, P.encode({ type: P.TYPE.HOST_OPEN }), now)[0].data).secret;
  const opened = P.decode(r.receive(CONTROL, host.address, host.port, P.encode({ type: P.TYPE.HOST_OPEN, secret: cookie }), now)[0].data);
  return { token: opened.secret.toString('hex'), code: opened.code.toString('latin1'), host };
}

const body = (o) => Buffer.from(JSON.stringify(o));
const listing = (token, change = {}) => ({ token, name: 'Ripley\'s game', level: 'Genshd1', mode: 'Coop', players: 1, maxPlayers: 4, version: 7, ...change });
const call = (r, method, o, query = '', now = 0, path = '/v1/games') => handle(r, { method, path, query, body: o === undefined ? Buffer.alloc(0) : (Buffer.isBuffer(o) ? o : body(o)) }, now);

test('a room goes on the list, shows in it, changes, and comes off when it ends', () => {
  const r = relay();
  const room = openRoom(r);
  const posted = call(r, 'POST', listing(room.token), '', 1000);
  assert.deepStrictEqual([posted.status, posted.body], [201, { code: room.code }]);

  const listed = call(r, 'GET', undefined, 'version=7', 4000);
  assert.strictEqual(listed.status, 200);
  assert.deepStrictEqual(listed.body.games, [{ code: room.code, name: 'Ripley\'s game', level: 'Genshd1', mode: 'Coop', players: 1, maxPlayers: 4, version: 7, seconds: 3 }]);
  assert.deepStrictEqual(call(r, 'GET', undefined, 'version=8').body.games, [], 'another version sees nothing');

  assert.strictEqual(call(r, 'PUT', listing(room.token, { players: 3 })).status, 200);
  assert.strictEqual(call(r, 'GET', undefined, 'version=7', 4000).body.games[0].players, 3);
  assert.strictEqual(call(r, 'GET', undefined, 'version=7', 4000).body.games[0].seconds, 3, 'a change doesn\'t make it new');

  assert.strictEqual(call(r, 'DELETE', { token: room.token }).status, 204);
  assert.deepStrictEqual(call(r, 'GET', undefined, 'version=7').body.games, []);
  assert.strictEqual(r.games.size, 0, 'the room ended too');
});

test('a list entry ends when its room is not kept', () => {
  const r = relay();
  const room = openRoom(r);
  call(r, 'POST', listing(room.token));
  r.tick(45000);
  assert.deepStrictEqual(call(r, 'GET', undefined, 'version=7', 45000).body.games, []);
});

test('only a live room\'s token can list it, and only once', () => {
  const r = relay();
  const room = openRoom(r);
  assert.strictEqual(call(r, 'POST', listing('0'.repeat(32))).status, 403);
  assert.strictEqual(call(r, 'PUT', listing(room.token)).status, 404, 'not listed yet');
  assert.strictEqual(call(r, 'POST', listing(room.token)).status, 201);
  assert.strictEqual(call(r, 'POST', listing(room.token)).status, 409);
  assert.strictEqual(call(r, 'DELETE', { token: 'f'.repeat(32) }).status, 403);
});

test('the list gives at most 100 games, the newest first', () => {
  const r = new RelayCore({ controlPort: CONTROL, ports: [27501], random: seededRandom(9), limits: { mostGames: 200 } });
  for (let i = 0; i < 120; i++) {
    const room = openRoom(r, i);
    call(r, 'POST', listing(room.token, { name: `game ${i}` }), '', i);
  }
  const games = call(r, 'GET', undefined, 'version=7', 200).body.games;
  assert.strictEqual(games.length, kMostGames);
  assert.strictEqual(games[0].name, 'game 119');
  assert.strictEqual(games[99].name, 'game 20');
});

test('the list never gives an address or a token', () => {
  const r = relay();
  const room = openRoom(r);
  call(r, 'POST', listing(room.token));
  const text = JSON.stringify(call(r, 'GET', undefined, 'version=7'));
  assert.ok(!text.includes(room.host.address) && !text.includes(room.token));
});

test('every field is held to its limits', () => {
  const r = relay();
  const room = openRoom(r);
  const refused = (change, why) => assert.strictEqual(call(r, 'POST', listing(room.token, change)).status, 400, why);
  refused({ name: '' }, 'an empty name');
  refused({ name: 'x'.repeat(33) }, 'a name of 33');
  refused({ name: 'line\nbreak' }, 'a line break');
  refused({ name: 'café' }, 'a letter outside printable ASCII');
  refused({ name: 'tab\there' }, 'a tab');
  refused({ name: 7 }, 'a number for a name');
  refused({ level: '' }, 'an empty level');
  refused({ mode: 'x'.repeat(33) }, 'a mode of 33');
  refused({ players: 0 }, 'no players');
  refused({ players: 5 }, 'more players than maxPlayers');
  refused({ maxPlayers: 9, players: 1 }, 'maxPlayers over 8');
  refused({ players: 1.5 }, 'a fraction');
  refused({ players: '1' }, 'a number as text');
  refused({ version: 0 }, 'version 0');
  refused({ version: 65536 }, 'version over 65535');
  refused({ token: room.token.toUpperCase() }, 'a token in capitals');
  refused({ token: room.token.slice(1) }, 'a token of 31');
  assert.strictEqual(call(r, 'POST', listing(room.token, { name: 'x'.repeat(32) })).status, 201, '32 is allowed');
});

test('a body is exactly its call\'s fields, as JSON, at most 1 KB', () => {
  const r = relay();
  const room = openRoom(r);
  assert.strictEqual(call(r, 'POST', { ...listing(room.token), extra: 1 }).status, 400, 'a field no call has');
  const missing = listing(room.token);
  delete missing.mode;
  assert.strictEqual(call(r, 'POST', missing).status, 400, 'a field missing');
  assert.strictEqual(call(r, 'POST', Buffer.from('{"token":')).status, 400, 'not JSON');
  assert.strictEqual(call(r, 'POST', Buffer.from('[1,2]')).status, 400, 'not an object');
  assert.strictEqual(call(r, 'POST', Buffer.from('null')).status, 400, 'null');
  assert.strictEqual(call(r, 'POST', Buffer.alloc(0)).status, 400, 'no body');
  assert.strictEqual(call(r, 'POST', Buffer.from([0xff, 0xfe])).status, 400, 'not UTF-8');
  assert.strictEqual(call(r, 'POST', Buffer.alloc(1025, 0x20)).status, 400, 'over 1 KB');
  assert.strictEqual(call(r, 'POST', Buffer.from(`{"__proto__":{"x":1},${JSON.stringify(listing(room.token)).slice(1)}`)).status, 400, 'a __proto__ field is just an extra field');
});

test('a GET\'s query is exactly version=N', () => {
  const r = relay();
  for (const q of ['', 'version=', 'version=0', 'version=65536', 'version=07', 'version=1&x=2', 'x=1', 'version=1e3', 'version=-1', 'version= 1']) {
    assert.strictEqual(call(r, 'GET', undefined, q).status, 400, `query "${q}"`);
  }
  assert.strictEqual(call(r, 'GET', undefined, 'version=65535').status, 200);
  assert.strictEqual(call(r, 'GET', Buffer.from('x'), 'version=1').status, 400, 'a GET with a body');
});

test('only the four calls are there', () => {
  const r = relay();
  assert.strictEqual(call(r, 'GET', undefined, 'version=1', 0, '/v1/games/').status, 404);
  assert.strictEqual(call(r, 'GET', undefined, 'version=1', 0, '/v2/games').status, 404);
  assert.strictEqual(call(r, 'GET', undefined, 'version=1', 0, '/../v1/games').status, 404);
  assert.strictEqual(call(r, 'PATCH', { token: 'a'.repeat(32) }).status, 405);
  assert.strictEqual(call(r, 'HEAD', undefined).status, 405);
  assert.strictEqual(call(r, 'POST', listing('a'.repeat(32)), 'version=1').status, 400, 'a POST with a query');
});

test('what a refusal says never holds what the request sent', () => {
  const r = relay();
  const room = openRoom(r);
  const evil = '<script>alert(1)</script>'.slice(0, 32);
  for (const answer of [call(r, 'POST', listing(room.token, { name: `${evil}\n` })), call(r, 'GET', undefined, `version=${evil}`), call(r, 'POST', { [evil]: 1 })]) {
    assert.ok(!JSON.stringify(answer.body).includes('script'), JSON.stringify(answer.body));
  }
});
