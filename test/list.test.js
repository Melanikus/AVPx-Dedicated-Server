'use strict';
// The tests of list/requests.js, list/listings.js and list/routes.js: every call of PROTOCOL.md section 4, every pass check of section 3,
// every field's limits, and every refusal, by handing it requests. No socket is opened. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const P = require('../relay/protocol');
const { makePass } = require('../relay/pass');
const { Listings, kMostListings } = require('../list/listings');
const { handle, kMostGames, kMostSeconds, kMostListBytes, kMostRelaysBytes } = require('../list/routes');
const { seededRandom } = require('../support/seeded-random');

const KEYS = { virginia: Buffer.alloc(32, 1), paris: Buffer.alloc(32, 2), 'longest-region-1': Buffer.alloc(32, 3) };
const RELAYS = Object.keys(KEYS).map((region) => ({ region, host: `${region}.relay.example.net`, port: 27500, passKey: KEYS[region] }));
const NOW = 1794268800000;   // 2026-11-11, in milliseconds
const at = (ms) => NOW + ms;

const listings = (relays = RELAYS) => new Listings({ relays, random: seededRandom(5), now: NOW });

// The code of game number n: 8 code letters, different for every n
function codeOf(n) {
  let out = '';
  for (let i = 0; i < 8; i++) { out = P.kCodeLetters[n % 32] + out; n = Math.floor(n / 32); }
  return out;
}

// What a host's game would POST at `now`, with a pass its relay made then
function game({ region = 'virginia', code = 'ABCD2345', now = NOW, passKey = KEYS[region], ...change } = {}) {
  const passTime = Math.floor(now / 1000);
  return {
    region, code, pass: makePass(passKey, region, Buffer.from(code, 'latin1'), passTime).toString('hex'), passTime,
    name: 'Ripley\'s game', level: 'Genshd1', mode: 'Coop', gameStyle: 3, levelNumber: 12, coopLobby: 0, players: 1, maxPlayers: 4, version: 7, hostMs: 40,
    ...change,
  };
}

const body = (o) => Buffer.from(JSON.stringify(o));
const call = (L, method, o, query = '', now = NOW, path = '/v1/games') => handle(L, { method, path, query, body: o === undefined ? Buffer.alloc(0) : (Buffer.isBuffer(o) ? o : body(o)) }, now);
const list = (L, now = NOW, version = 7) => call(L, 'GET', undefined, `version=${version}`, now).body.games;

test('a game goes on the list with its relay\'s pass, shows in it, is renewed and changed, and comes off', () => {
  const L = listings();
  const posted = call(L, 'POST', game());
  assert.strictEqual(posted.status, 201);
  assert.match(posted.body.owner, /^[0-9a-f]{32}$/);
  const owner = posted.body.owner;

  assert.deepStrictEqual(list(L, at(5000)), [{
    region: 'virginia', code: 'ABCD2345', name: 'Ripley\'s game', level: 'Genshd1', mode: 'Coop', gameStyle: 3, levelNumber: 12, coopLobby: 0,
    players: 1, maxPlayers: 4, version: 7, hostMs: 40, seconds: 5,
  }]);

  const renewed = call(L, 'PUT', { owner, ...game({ now: at(15000), players: 3 }) }, '', at(15000));
  assert.deepStrictEqual([renewed.status, renewed.body], [204, null]);
  const after = list(L, at(20000));
  assert.strictEqual(after[0].players, 3);
  assert.strictEqual(after[0].seconds, 20, 'how long it has been listed counts from the POST, not the PUT');

  assert.strictEqual(call(L, 'DELETE', { region: 'virginia', code: 'ABCD2345', owner }, '', at(21000)).status, 204);
  assert.deepStrictEqual(list(L, at(21000)), []);
  assert.strictEqual(call(L, 'DELETE', { region: 'virginia', code: 'ABCD2345', owner }, '', at(21000)).status, 404, 'gone already');
});

test('a pass is good only from its own relay\'s key, for its region and code, for a minute', () => {
  const L = listings();
  const refused = (o, now, why) => assert.strictEqual(call(L, 'POST', o, '', now).status, 403, why);
  refused(game({ passKey: KEYS.paris }), NOW, 'made with another relay\'s key');
  refused({ ...game(), pass: game({ code: 'ABCD2346' }).pass }, NOW, 'made for another code');
  refused({ ...game(), region: 'paris' }, NOW, 'made for another region');
  refused({ ...game(), passTime: game().passTime + 1 }, NOW, 'a pass time it wasn\'t made with');
  refused(game({ now: at(-60001) }), NOW, 'made 60.001 s ago');
  refused(game({ now: at(6000) }), NOW, 'made 6 s ahead of the list\'s clock');
  assert.strictEqual(call(L, 'POST', { ...game(), region: 'tokyo' }).status, 400, 'a region the list has no relay for');

  assert.strictEqual(call(L, 'POST', game({ code: 'AAAA2222', now: at(-60000) })).status, 201, 'made exactly 60 s ago is still good');
  assert.strictEqual(call(L, 'POST', game({ code: 'AAAA3333', now: at(5000) })).status, 201, 'and 5 s ahead is allowed for the clocks');
  assert.strictEqual(call(L, 'POST', game({ region: 'paris' })).status, 201, 'a game on another relay, with that relay\'s pass');
});

test('only the owner key, with a fresh pass, changes or takes down a listing', () => {
  const L = listings();
  const { owner } = call(L, 'POST', game()).body;
  const wrong = 'f'.repeat(32);
  assert.strictEqual(call(L, 'POST', game()).status, 409, 'listed already');
  assert.strictEqual(call(L, 'PUT', { owner: wrong, ...game() }).status, 403, 'a PUT with the wrong owner key');
  assert.strictEqual(call(L, 'DELETE', { region: 'virginia', code: 'ABCD2345', owner: wrong }).status, 403, 'a DELETE with the wrong owner key');
  assert.strictEqual(call(L, 'PUT', { owner, ...game({ now: at(-61000) }) }).status, 403, 'the right owner, but a stale pass');
  assert.strictEqual(call(L, 'PUT', { owner, ...game({ code: 'ZZZZ2222' }) }).status, 404, 'a game not listed');
  assert.strictEqual(call(L, 'DELETE', { region: 'paris', code: 'ABCD2345', owner }).status, 404, 'the same code in another region is another game');
  assert.strictEqual(list(L).length, 1, 'and none of that changed it');
});

test('a listing not renewed for 45 s goes, and a renewed one stays', () => {
  const L = listings();
  const { owner } = call(L, 'POST', game()).body;
  assert.strictEqual(list(L, at(44999)).length, 1);
  assert.strictEqual(list(L, at(45000)).length, 0, 'unrenewed for 45 s');
  assert.strictEqual(call(L, 'PUT', { owner, ...game({ now: at(45000) }) }, '', at(45000)).status, 404, 'and can\'t be renewed after');
  L.tick(at(45000));
  assert.strictEqual(L.byGame.size, 0, 'the tick takes it out');
  assert.strictEqual(call(L, 'POST', game({ now: at(46000) }), '', at(46000)).status, 201, 'its code can be listed again');

  const { owner: second } = call(L, 'POST', game({ code: 'BBBB2222', now: at(46000) }), '', at(46000)).body;
  assert.strictEqual(call(L, 'PUT', { owner: second, ...game({ code: 'BBBB2222', now: at(76000) }) }, '', at(76000)).status, 204);
  assert.ok(list(L, at(120999)).some((g) => g.code === 'BBBB2222'), 'renewed at 76 s, alive at 121 s');
  assert.ok(!list(L, at(121000)).some((g) => g.code === 'BBBB2222'), 'and gone at 121 s');
});

test('the list holds at most 2,000 games', () => {
  const L = listings();
  for (let i = 0; i < kMostListings; i++) {
    assert.strictEqual(call(L, 'POST', game({ code: codeOf(i) })).status, 201);
  }
  assert.strictEqual(call(L, 'POST', game({ code: codeOf(kMostListings) })).status, 503);
  assert.strictEqual(kMostListings, 2000);
});

test('the list gives at most 100 games, the newest first, of the version asked for', () => {
  const L = listings();
  for (let i = 0; i < 120; i++) {
    call(L, 'POST', game({ code: codeOf(i), name: `game ${i}`, now: at(i) }), '', at(i));
  }
  call(L, 'POST', game({ code: codeOf(500), version: 8 }));
  const games = list(L, at(200));
  assert.strictEqual(games.length, kMostGames);
  assert.strictEqual(games[0].name, 'game 119');
  assert.strictEqual(games[99].name, 'game 20');
  assert.strictEqual(list(L, at(200), 8).length, 1, 'version 8 has only its own');
});

test('the largest list answer is 41,111 bytes, under 48 KB; it uses only the escapes \\" and \\\\, and says a year at most', () => {
  const L = listings();
  const quote = String.fromCharCode(34), backslash = String.fromCharCode(92);
  for (let i = 0; i < 120; i++) {
    const worst = game({ region: 'longest-region-1', code: codeOf(i), name: quote.repeat(32), level: backslash.repeat(39), mode: quote.repeat(32),
      gameStyle: 255, levelNumber: 100, coopLobby: 255, players: 8, maxPlayers: 8, version: 65535, hostMs: 9999 });
    assert.strictEqual(call(L, 'POST', worst).status, 201);
  }
  // Two years on, with every game still renewed
  const later = NOW + 2 * kMostSeconds * 1000;
  for (const g of L.byGame.values()) g.renewedAt = later;
  const answer = call(L, 'GET', undefined, 'version=65535', later);
  const text = JSON.stringify(answer.body);
  assert.strictEqual(answer.body.games.length, 100);
  assert.strictEqual(text.length, 41111, 'the worst case PROTOCOL.md section 4 gives');
  assert.ok(text.length <= kMostListBytes);
  assert.ok(answer.body.games.every((g) => g.seconds === kMostSeconds), 'seconds stops at a year');

  let printable = '';
  for (let c = 0x20; c <= 0x7e; c++) printable += String.fromCharCode(c);
  const all = JSON.stringify({ name: printable });
  const escapes = new Set();
  for (let i = 0; i < all.length; i++) if (all[i] === backslash) { escapes.add(all.slice(i, i + 2)); i++; }
  assert.deepStrictEqual([...escapes].sort(), [backslash + quote, backslash + backslash].sort(), 'printable ASCII only ever needs these two');
});

test('GET /v1/relays gives each relay\'s region, name and port, never a key, and at most 4 KB', () => {
  const answer = call(listings(), 'GET', undefined, '', NOW, '/v1/relays');
  assert.strictEqual(answer.status, 200);
  assert.deepStrictEqual(answer.body.relays, RELAYS.map((r) => ({ region: r.region, host: r.host, port: r.port })));
  for (const key of Object.values(KEYS)) assert.ok(!JSON.stringify(answer.body).includes(key.toString('hex')));

  // The worst case: 16 relays (settings.js allows no more), every region and host name at its longest
  const most = [];
  for (let i = 0; i < 16; i++) most.push({ region: `region-${String(i).padStart(9, '0')}`, host: 'h'.repeat(60) + String(i).padStart(3, '0'), port: 65535, passKey: KEYS.paris });
  const text = JSON.stringify(call(listings(most), 'GET', undefined, '', NOW, '/v1/relays').body);
  assert.strictEqual(text.length, 1868, 'the worst case PROTOCOL.md section 4 gives');
  assert.ok(text.length <= kMostRelaysBytes);
});

test('the list never gives an address, an owner key or a pass', () => {
  const L = listings();
  const posted = game();
  const { owner } = call(L, 'POST', posted).body;
  const text = JSON.stringify(call(L, 'GET', undefined, 'version=7'));
  assert.ok(!text.includes(owner) && !text.includes(posted.pass));
  assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(text), 'nothing that looks like an address');
});

test('every field is held to its limits', () => {
  const L = listings();
  const refused = (change, why) => assert.strictEqual(call(L, 'POST', { ...game(), ...change }).status, 400, why);
  refused({ name: '' }, 'an empty name');
  refused({ name: 'x'.repeat(33) }, 'a name of 33');
  refused({ name: 'line\nbreak' }, 'a line break');
  refused({ name: `caf${String.fromCharCode(0xe9)}` }, 'a letter outside printable ASCII (an e with an accent), written as a number so this file stays ASCII');
  refused({ name: 'tab\there' }, 'a tab');
  refused({ name: 7 }, 'a number for a name');
  refused({ level: '' }, 'an empty level');
  refused({ level: 'x'.repeat(40) }, 'a level of 40');
  refused({ mode: 'x'.repeat(33) }, 'a mode of 33');
  refused({ players: 0 }, 'no players');
  refused({ players: 5 }, 'more players than maxPlayers');
  refused({ maxPlayers: 9, players: 1 }, 'maxPlayers over 8');
  refused({ players: 1.5 }, 'a fraction');
  refused({ players: '1' }, 'a number as text');
  refused({ version: 0 }, 'version 0');
  refused({ version: 65536 }, 'version over 65535');
  refused({ gameStyle: 256 }, 'gameStyle over 255');
  refused({ gameStyle: -1 }, 'gameStyle below 0');
  refused({ levelNumber: 101 }, 'levelNumber over 100');
  refused({ coopLobby: 256 }, 'coopLobby over 255');
  refused({ hostMs: 10000 }, 'hostMs over 9999');
  refused({ hostMs: -1 }, 'hostMs below 0');
  refused({ region: 'Virginia' }, 'a region with a capital');
  refused({ region: 'x'.repeat(17) }, 'a region of 17');
  refused({ code: 'ABCD234' }, 'a code of 7');
  refused({ code: 'ABCD234I' }, 'a code with an I');
  refused({ code: 'abcd2345' }, 'a code in small letters');
  refused({ pass: game().pass.toUpperCase() }, 'a pass in capitals');
  refused({ pass: game().pass.slice(1) }, 'a pass of 31');
  refused({ passTime: -1 }, 'a pass time below 0');
  refused({ passTime: 1.5 }, 'a fraction of a second');
  refused({ passTime: Number.MAX_SAFE_INTEGER + 1 }, 'a pass time past the most a number holds exactly');
  refused({ passTime: String(game().passTime) }, 'a pass time as text');
  assert.strictEqual(call(L, 'POST', game({ name: 'x'.repeat(32), level: 'y'.repeat(39) })).status, 201, '32 and 39 are allowed');
  assert.strictEqual(call(L, 'POST', game({ code: 'ABCD2346', gameStyle: 0, levelNumber: 0, coopLobby: 0, hostMs: 0 })).status, 201, 'and 0 for each number that may be 0');

  const { owner } = call(L, 'POST', game({ code: 'ABCD2347' })).body;
  assert.strictEqual(call(L, 'PUT', { owner: owner.toUpperCase(), ...game({ code: 'ABCD2347' }) }).status, 400, 'an owner key in capitals');
  assert.strictEqual(call(L, 'DELETE', { region: 'virginia', code: 'ABCD2347', owner: owner.slice(2) }).status, 400, 'an owner key of 30');
});

test('a body is exactly its call\'s fields, as JSON, at most 1 KB', () => {
  const L = listings();
  assert.strictEqual(call(L, 'POST', { ...game(), extra: 1 }).status, 400, 'a field no call has');
  assert.strictEqual(call(L, 'POST', { ...game(), owner: 'a'.repeat(32) }).status, 400, 'a POST with an owner');
  const missing = game();
  delete missing.mode;
  assert.strictEqual(call(L, 'POST', missing).status, 400, 'a field missing');
  assert.strictEqual(call(L, 'PUT', game()).status, 400, 'a PUT with no owner');
  assert.strictEqual(call(L, 'DELETE', { region: 'virginia', code: 'ABCD2345' }).status, 400, 'a DELETE with no owner');
  // A good listing with spaces after it, which JSON allows: 1,024 bytes in all is taken, and 1,025 refused for its size alone
  const padded = (code, size) => { const b = body(game({ code })); return Buffer.concat([b, Buffer.alloc(size - b.length, 0x20)]); };
  assert.strictEqual(call(L, 'POST', padded('ABCD2398', 1024)).status, 201, 'a good listing of 1,024 bytes');
  assert.strictEqual(call(L, 'POST', padded('ABCD2399', 1025)).status, 400, 'a good listing of 1,025 bytes');
  assert.strictEqual(call(L, 'POST', Buffer.from('{"region":')).status, 400, 'not JSON');
  assert.strictEqual(call(L, 'POST', Buffer.from('[1,2]')).status, 400, 'not an object');
  assert.strictEqual(call(L, 'POST', Buffer.from('null')).status, 400, 'null');
  assert.strictEqual(call(L, 'POST', Buffer.alloc(0)).status, 400, 'no body');
  assert.strictEqual(call(L, 'POST', Buffer.from([0xff, 0xfe])).status, 400, 'not UTF-8');
  assert.strictEqual(call(L, 'POST', Buffer.alloc(1025, 0x20)).status, 400, 'over 1 KB');
  assert.strictEqual(call(L, 'POST', Buffer.from(`{"__proto__":{"x":1},${JSON.stringify(game()).slice(1)}`)).status, 400, 'a __proto__ field is just an extra field');
  assert.ok(body({ owner: 'f'.repeat(32), ...game({ name: '"'.repeat(32), level: '"'.repeat(39), mode: '"'.repeat(32) }) }).length < 1024, 'the largest PUT a game sends fits');
});

test('a body is read strictly, as PROTOCOL.md section 4 writes it: what JSON.parse would take is refused', () => {
  const L = listings();
  const text = JSON.stringify(game());
  const refused = (raw, why) => assert.strictEqual(call(L, 'POST', Buffer.from(raw, 'latin1')).status, 400, why);
  refused(`{"name":"first",${text.slice(1)}`, 'a key twice (JSON.parse would keep the second)');
  refused(text.replace('"players":1', '"players":1.0'), 'a whole number written with .0');
  refused(text.replace('"players":1', '"players":1e0'), 'a whole number written with an exponent');
  refused(text.replace('"hostMs":40', '"hostMs":040'), 'a leading 0');
  refused(text.replace('"Coop"', `"C${String.fromCharCode(92)}u006fop"`), 'a \\u escape, even of a plain letter');
  refused(text.replace('{', '{"extra":{"x":1},'), 'an object inside');
  assert.strictEqual(call(L, 'POST', Buffer.from(` \r\n${text.replace(/,/g, ' ,\t')}\n `, 'latin1')).status, 201, 'JSON\'s own whitespace is fine');
});

test('a GET\'s query is exactly version=N, and GET /v1/relays has none', () => {
  const L = listings();
  for (const q of ['', 'version=', 'version=0', 'version=65536', 'version=07', 'version=1&x=2', 'x=1', 'version=1e3', 'version=-1', 'version= 1']) {
    assert.strictEqual(call(L, 'GET', undefined, q).status, 400, `query "${q}"`);
  }
  assert.strictEqual(call(L, 'GET', undefined, 'version=65535').status, 200);
  assert.strictEqual(call(L, 'GET', Buffer.from('x'), 'version=1').status, 400, 'a GET with a body');
  assert.strictEqual(call(L, 'GET', undefined, 'version=1', NOW, '/v1/relays').status, 400, 'GET /v1/relays with a query');
  assert.strictEqual(call(L, 'GET', Buffer.from('x'), '', NOW, '/v1/relays').status, 400, 'GET /v1/relays with a body');
});

test('only the five calls are there', () => {
  const L = listings();
  assert.strictEqual(call(L, 'GET', undefined, 'version=1', NOW, '/v1/games/').status, 404);
  assert.strictEqual(call(L, 'GET', undefined, 'version=1', NOW, '/v2/games').status, 404);
  assert.strictEqual(call(L, 'GET', undefined, 'version=1', NOW, '/../v1/games').status, 404);
  assert.strictEqual(call(L, 'GET', undefined, '', NOW, '/v1/relays/').status, 404);
  assert.strictEqual(call(L, 'PATCH', { owner: 'a'.repeat(32) }).status, 405);
  assert.strictEqual(call(L, 'HEAD', undefined).status, 405);
  assert.strictEqual(call(L, 'POST', game(), '', NOW, '/v1/relays').status, 405, 'nothing but GET on /v1/relays');
  assert.strictEqual(call(L, 'POST', game(), 'version=1').status, 400, 'a POST with a query');
});

test('what a refusal says never holds what the request sent', () => {
  const L = listings();
  const evil = '<script>alert(1)</script>'.slice(0, 32);
  for (const answer of [call(L, 'POST', game({ name: `${evil}\n` })), call(L, 'GET', undefined, `version=${evil}`), call(L, 'POST', { [evil]: 1 }),
    call(L, 'POST', game({ region: 'script', passKey: KEYS.paris })), call(L, 'POST', game({ passKey: KEYS.paris, name: evil }))]) {
    assert.ok(!JSON.stringify(answer.body).includes('script'), JSON.stringify(answer.body));
  }
});

test('the list\'s log line is counts only, once a minute: no code, name, owner key or pass', () => {
  const L = listings();
  const posted = game();
  const { owner } = call(L, 'POST', posted).body;
  call(L, 'POST', game({ passKey: KEYS.paris }));
  assert.deepStrictEqual(L.tick(at(59999)), [], 'not before a minute');
  const lines = L.tick(at(60000));
  assert.strictEqual(lines.length, 1);
  assert.match(lines[0], /1 games listed/);
  assert.match(lines[0], /1 passes refused/);
  for (const secret of ['ABCD2345', 'Ripley', owner, posted.pass]) assert.ok(!lines[0].includes(secret), `the line has no ${secret}`);
  assert.deepStrictEqual(L.tick(at(60001)), [], 'and the next only a minute later');
});
