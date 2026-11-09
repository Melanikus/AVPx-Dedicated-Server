'use strict';
// Writes tools/takeouts.json, the rows tools/takeouts.js runs, from the rows below. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server; moved into the repository 2026-11-09 (it had lived outside it, so nobody else could make the file again).
//
//   node tools/make-takeouts.js     checks each row's "from" is in its file exactly once, then writes tools/takeouts.json
//
// Change a row here, never in tools/takeouts.json: test/takeouts-file.test.js fails if the two differ.
//
// A row is T(name, file, from, to) for one the tests must notice, S(...) for one the coding standard must notice, or NEW(name, file,
// text) for a new file the coding standard must notice. "from" is read with \n line ends, as tools/takeouts.js reads it.
//
// Some rows put words into a copy that the coding standard refuses (code made from text, a package from outside). Those words are
// written here in pieces, as check-standard.js writes its own list, so this file keeps the standard itself. tools/takeouts.json holds
// them whole, which is why check-standard.js leaves that one file out of its rules 3 to 6.
const fs = require('fs');
const path = require('path');
const repo = path.join(__dirname, '..');
const kFile = path.join(__dirname, 'takeouts.json');

const T = (name, file, from, to) => ({ name, check: 'tests', file, from, to });
const S = (name, file, from, to) => ({ name, check: 'standard', file, from, to });
const NEW = (name, file, to) => ({ name, check: 'standard', file, from: '', to });
const BQ = String.fromCharCode(96);
const D = String.fromCharCode(36);

const rows = [
  // relay/core.js
  T('cookies are never checked', 'relay/core.js', 'return secret !== null && (sameSecret(', 'return true || (sameSecret('),
  T('no size cap on a packet', 'relay/core.js', 'if (!Buffer.isBuffer(data) || data.length > this.L.mostDatagramBytes) {', 'if (!Buffer.isBuffer(data)) {'),
  T('strangers are passed on', 'relay/core.js', "if (slot.state !== 'active' || !(fromHost || fromJoiner)) {", "if (slot.state !== 'active') {"),
  T('no cap on games for one address', 'relay/core.js', '>= this.L.mostGamesPerSender', '>= 1000'),
  T('no cap on games in all', 'relay/core.js', 'if (this.games.size >= this.L.mostGames) {', 'if (false) {'),
  T('no cap on joiners in a game', 'relay/core.js', 'if (game.joiners.size >= this.L.mostJoinersPerGame) {', 'if (false) {'),
  T('a host hello with any token', 'relay/core.js', 'm.type === P.TYPE.HOST_HELLO && sameSecret(m.secret, slot.game.token) && m.port === slot.port', 'm.type === P.TYPE.HOST_HELLO && m.port === slot.port'),
  T('a joiner hello with any ticket', 'relay/core.js', 'm.type === P.TYPE.JOINER_HELLO && sameSecret(m.secret, slot.ticket)', 'm.type === P.TYPE.JOINER_HELLO'),
  T('no rate limit on a joiner\'s port', 'relay/core.js', 'if (!way.packets.take(now) || !way.bytes.take(now, data.length)) {', 'if (false) {'),
  T('no per-address limit on control messages', 'relay/core.js', 'if (!this.perSender.allows(address, now) || !this.everyone.take(now)) {', 'if (!this.everyone.take(now)) {'),
  T('no limit on control messages from everyone', 'relay/core.js', 'if (!this.perSender.allows(address, now) || !this.everyone.take(now)) {', 'if (!this.perSender.allows(address, now)) {'),
  T('refusals not limited', 'relay/core.js', 'if (!this.refusals.allows(address, now)) {', 'if (false) {'),
  T('games never expire', 'relay/core.js', 'if (now - game.keptAt >= this.L.gameLifeMilliseconds) {', 'if (false) {'),
  T('ports never expire', 'relay/core.js', "if ((slot.state === 'pending' && now - slot.madeAt >= this.L.pendingMilliseconds) || (slot.state === 'active' && now - slot.trafficAt >= this.L.idleMilliseconds)) {", 'if (false) {'),
  T('a keep keeps nothing', 'relay/core.js', 'game.keptAt = now;', ''),
  T('a freed port is lost', 'relay/core.js', 'this.free.push(slot.port);', ''),
  T('the log line on every tick', 'relay/core.js', '    if (now - this.statsAt < this.L.statsMilliseconds) {', '    if (false) {'),
  T('an address in the log', 'relay/core.js', `${BQ}${D}{c.joins} joins, `, `${BQ}${D}{c.joins} joins from ${D}{[...this.slots.values()].filter((s) => s.joinerEnd).map((s) => s.joinerEnd.address).join(',')}, `),
  T('a HOST_KEPT with no fresh pass', 'relay/core.js', 'number: game.joiners.size, ...this.passFor(game, now) })', 'number: game.joiners.size })'),
  T('a pass made for another region', 'relay/core.js', 'makePass(this.passKey, this.region, game.code, passTime)', "makePass(this.passKey, 'paris', game.code, passTime)"),
  T('a pass time in milliseconds, not seconds', 'relay/core.js', 'const passTime = Math.floor(now / 1000);', 'const passTime = now;'),
  T('an echo answered with another count', 'relay/core.js', 'type: P.TYPE.ECHO_BACK, secret: m.secret, number: m.number', 'type: P.TYPE.ECHO_BACK, secret: m.secret, number: 0'),
  T('an echo answered with an echo, so two relays could answer each other', 'relay/core.js', 'type: P.TYPE.ECHO_BACK, secret: m.secret, number: m.number', 'type: P.TYPE.ECHO, secret: m.secret, number: m.number'),
  T('an ECHO_BACK answered', 'relay/core.js', '      case P.TYPE.ECHO:\n', '      case P.TYPE.ECHO:\n      case P.TYPE.ECHO_BACK:\n'),
  T('echoes answered before the limits', 'relay/core.js', "    // The sender's own limit first, so one sender going too fast doesn't use up everyone's\n",
    "    const early = P.decode(data);\n    if (early && early.type === P.TYPE.ECHO) return [{ from: this.controlPort, address, port, data: P.encode({ type: P.TYPE.ECHO_BACK, secret: early.secret, number: early.number }) }];\n"),
  T('a relay with no region or pass key', 'relay/core.js', 'if (!isRegion(region) || !Buffer.isBuffer(passKey) || passKey.length !== kPassKeyBytes) {', 'if (false) {'),

  // relay/protocol.js
  T('the padding not checked', 'relay/protocol.js', '  for (let i = 60; i < kMessageBytes; i++) {', '  for (let i = 64; i < kMessageBytes; i++) {'),
  T('any code bytes taken', 'relay/protocol.js', 'if (!codeIsZero && !isCode(codeBytes)) {', 'if (false) {'),
  T('fields a type does not use not checked', 'relay/protocol.js', 'if (given[field] && !uses.includes(field)) {\n      return null;', 'if (false) {\n      return null;'),
  T('the relay may write fields a type does not use', 'relay/protocol.js', 'if (given[field] && !uses.includes(field)) {\n      throw', 'if (false) {\n      throw'),
  T('a pass time past the most a number holds taken', 'relay/protocol.js', 'if (passTime > BigInt(Number.MAX_SAFE_INTEGER)) {', 'if (false) {'),
  T('the magic not checked', 'relay/protocol.js', "if (!bytes.subarray(0, 4).equals(kMagic) || bytes[4] !== kVersion", 'if (bytes[4] !== kVersion'),
  T('a message longer than 64 bytes taken', 'relay/protocol.js', 'if (!Buffer.isBuffer(bytes) || bytes.length !== kMessageBytes) {', 'if (!Buffer.isBuffer(bytes) || bytes.length < kMessageBytes) {'),

  // relay/pass.js
  T('the region left out of a pass', 'relay/pass.js', "Buffer.from(region, 'latin1'), Buffer.alloc(1), ", 'Buffer.alloc(1), '),
  T('the time left out of a pass', 'relay/pass.js', ', code, time]);', ', code]);'),
  T('another label in a pass', 'relay/pass.js', "Buffer.from('AVPX-PASS-1', 'latin1')", "Buffer.from('AVPX-PASS-2', 'latin1')"),

  // relay/limits.js
  T('a bucket over its burst', 'relay/limits.js', 'this.tokens = Math.min(this.burst, this.tokens', 'this.tokens = (this.tokens'),
  T('senders remembered without end', 'relay/limits.js', '        this.buckets.delete(this.buckets.keys().next().value);', ''),
  T('the address secret kept for ever', 'relay/limits.js', 'now - this.madeAt >= kKeyLifeMilliseconds || ', ''),

  // list/requests.js
  T('a body over 1 KB taken', 'list/requests.js', 'bytes.length > kMostBodyBytes', 'bytes.length > 1000000'),
  T('a level of any length', 'list/requests.js', 'isPlainText(v.level, kMostLevelLength)', 'isPlainText(v.level, 1000)'),
  T('fields no call has taken', 'list/requests.js', 'keys.length !== fields.length || ', ''),
  T('hostMs of any size', 'list/requests.js', 'isWhole(v.hostMs, 0, kMostHostMilliseconds)', 'isWhole(v.hostMs, 0, 100000)'),
  T('a code of any capitals and digits', 'list/requests.js', 'kCodeLetters.includes(c)', '/[A-Z0-9]/.test(c)'),
  T('more players than maxPlayers', 'list/requests.js', 'isWhole(v.players, 1, v.maxPlayers)', 'isWhole(v.players, 1, kMostPlayers)'),
  T('a level number past 100', 'list/requests.js', 'isWhole(v.levelNumber, 0, kMostLevelNumber)', 'isWhole(v.levelNumber, 0, 255)'),
  T('any query taken', 'list/requests.js', '/^version=([1-9][0-9]{0,4})$/', '/version=([0-9]+)/'),
  T('a pass time of any kind', 'list/requests.js', 'if (!isWhole(v.passTime, 0, Number.MAX_SAFE_INTEGER)) {', 'if (false) {'),

  // list/listings.js
  T('a pass never checked', 'list/listings.js', 'return same(pass, makePass(', 'return true || same(pass, makePass('),
  T('a pass of any age', 'list/listings.js', 'now > madeAt + kPassLifeMilliseconds || ', ''),
  T('a pass from the future', 'list/listings.js', 'madeAt > now + kMostPassAheadMilliseconds || ', ''),
  T('anyone may renew a listing', 'list/listings.js', "    if (!same(owner, old.owner)) {\n      throw new Refusal(403, 'that is not the owner key of that listing');\n    }\n\n    const { passTime",
    "    if (false) {\n      throw new Refusal(403, 'that is not the owner key of that listing');\n    }\n\n    const { passTime"),
  T('anyone may take a listing down', 'list/listings.js', "    if (!same(owner, old.owner)) {\n      throw new Refusal(403, 'that is not the owner key of that listing');\n    }\n\n    old.owner.fill(0);",
    "    if (false) {\n      throw new Refusal(403, 'that is not the owner key of that listing');\n    }\n\n    old.owner.fill(0);"),
  T('an unrenewed listing can still be renewed', 'list/listings.js', 'return listing && now - listing.renewedAt < kListingLifeMilliseconds ? listing : null;', 'return listing || null;'),
  T('an unrenewed listing is still shown', 'list/listings.js', 'if (listing.version === version && now - listing.renewedAt < kListingLifeMilliseconds) {', 'if (listing.version === version) {'),
  T('no cap on listings', 'list/listings.js', 'if (this.byGame.size >= kMostListings) {', 'if (false) {'),
  T('a game listed twice', 'list/listings.js', 'if (this.find(listing.region, listing.code, now)) {', 'if (false) {'),
  T('the relays\' keys in GET /v1/relays', 'list/listings.js', '.map((r) => ({ region: r.region, host: r.host, port: r.port }))', ".map((r) => ({ region: r.region, host: r.host, port: r.port, passKey: r.passKey.toString('hex') }))"),
  T('a renewal starts the listing\'s time again', 'list/listings.js', 'listedAt: old.listedAt, renewedAt: now', 'listedAt: now, renewedAt: now'),

  // list/routes.js
  T('the owner key in GET /v1/games', 'list/routes.js', '          hostMs: g.hostMs,\n', "          hostMs: g.hostMs,\n          owner: g.owner.toString('hex'),\n"),
  T('seconds past a year', 'list/routes.js', 'Math.min(kMostSeconds, ', 'Math.min(Infinity, '),
  T('more than 100 games in an answer', 'list/routes.js', 'listings.games(version, now, kMostGames)', 'listings.games(version, now, 1000)'),
  T('a GET /v1/games with a body', 'list/routes.js', '      checkNoBody(body);\n      const { version }', '      const { version }'),

  // list/strict-json.js
  T('a key twice taken', 'list/strict-json.js', 'if (key === null || seen.has(key)) return null;', 'if (key === null) return null;'),
  T('any escape taken', 'list/strict-json.js', 'if (next !== 0x22 && next !== 0x5c) return null;', 'if (next < 0) return null;'),
  T('a number with a leading 0 taken', 'list/strict-json.js', ' || (digits > 1 && bytes[start] === 0x30)', ''),
  T('a number past 2^53 - 1 taken', 'list/strict-json.js', 'return Number.isSafeInteger(value) ? value : null;', 'return value;'),
  T('control bytes and bytes past ASCII in a string', 'list/strict-json.js', '} else if (b >= 0x20 && b <= 0x7e) {', '} else if (b !== 0x22) {'),
  T('something after the object taken', 'list/strict-json.js', 'return at === end ? out : null;', 'return out;'),
  T('a body read with JSON.parse, which keeps the last of two keys', 'list/requests.js', '  const value = readObject(bytes);', '  let value = null; try { value = JSON.parse(bytes.toString()); } catch (e) { value = null; }'),

  // settings.js
  T('a pass key of all 0 taken', 'settings.js', ' || /^0+$/.test(value)', ''),
  T('an address for a relay\'s host', 'settings.js', ' ||\n      !/(^|\\.)[A-Za-z][A-Za-z0-9-]*$/.test(value)) {', ') {'),
  T('a list that does not name its own region', 'settings.js', 'if (!relays.some((r) => r.region === ownRegion)) {', 'if (false) {'),
  T('the own pass key written twice', 'settings.js', 'if (own && r.passKey !== undefined) {', 'if (false) {'),
  T('any number of relays', 'settings.js', 's.relays.length > kMostRelays', 's.relays.length > 1000'),
  T('a setting nobody knows taken', 'settings.js', "  onlyKnown(given, DEFAULTS, '');\n", ''),

  // log.js
  T('a line break kept in a log line', 'log.js', ".replace(/[\\r\\n]/g, ' ')", ''),

  // tools/takeouts.json itself
  T('a row added to tools/takeouts.json by hand', 'tools/takeouts.json', '"rows": [', '"rows": [\n    { "name": "by hand", "check": "tests", "file": "x", "from": "a", "to": "b" },'),

  // The coding standard (tools/check-standard.js), on files and changes no one should make
  NEW('console. in the relay', 'relay/takeout-console.js', "'use strict';\nconsole.log('x');\n"),
  NEW('code made from text', 'list/takeout-eval.js', `'use strict';\nmodule.exports = ${'ev' + 'al'}('1');\n`),
  NEW('a package from outside', 'relay/takeout-require.js', `'use strict';\n${'requ' + 'ire'}('left-pad');\n`),
  NEW('a byte that is not ASCII', 'relay/takeout-ascii.js', `'use strict';\n// caf${String.fromCharCode(0xe9)}\n`),
  NEW('an action not pinned to a commit', '.github/workflows/takeout.yml', 'on: push\njobs:\n  x:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@v4\n'),
  NEW('another program started by the server', 'relay/takeout-program.js', "'use strict';\nrequire('child_process');\n"),
  NEW('a comment that silences a scanner', 'relay/takeout-silence.js', "'use strict';\n// " + 'eslint' + '-disable\n'),
  NEW('a file that silences a scanner', '.snyk', 'version: v1\n'),
  NEW('node_modules in the tree', 'node_modules/x/index.js', "'use strict';\n"),
  S('a package in package.json', 'package.json', '  "engines": {', '  "dependencies": { "left-pad": "1.3.0" },\n  "engines": {'),
];

const out = {
  about: [
    'The take-out rows tools/takeouts.js runs: each breaks one thing in a copy, and the check it names must fail. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.',
    'Made by tools/make-takeouts.js: change the rows there and run it. test/takeouts-file.test.js fails if this file and that one differ.',
    'A row is { name, check: "tests" or "standard", file, from, to }. "from" is in its file exactly once; a "from" of "" makes a new file whose text is "to".',
    'list/https.js and relay/sockets.js have no rows: their limits are tested only by test/live.test.js, which opens sockets, and take-outs run the tests without AVPX_LIVE. That is owed: rows run with the live tests, in the Tests check on GitHub.',
    'The HTTP rules in list/https.js (one request a connection, Transfer-Encoding refused, 431) are checked by test/live.test.js only, so they have no rows yet either.',
  ],
  rows,
};

// The file's text. Every character outside ASCII is written as \u and its number, so tools/takeouts.json keeps the coding standard's
// rule 1
function text() {
  return `${JSON.stringify(out, null, 2)}\n`.replace(/[\u0080-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

// Run as a command: every "from" must be in its file exactly once (a row that can't find its text would only fail later, in
// tools/takeouts.js), and then the file is written
if (require.main === module) {
  let bad = 0;
  for (const row of rows) {
    if (row.from === '') continue;
    const found = fs.readFileSync(path.join(repo, row.file), 'latin1').replace(/\r/g, '').split(row.from).length - 1;
    if (found !== 1) { process.stdout.write(`${row.name}: its text is in ${row.file} ${found} times\n`); bad++; }
  }
  if (bad) process.exit(1);
  fs.writeFileSync(kFile, text());
  process.stdout.write(`${rows.length} rows written to tools/takeouts.json\n`);
}

module.exports = { text, rows, kFile };
