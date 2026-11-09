'use strict';
// The tests of relay/core.js: a game's whole life through the relay, and every refusal and limit in PROTOCOL.md, by handing it packets.
// No socket is opened. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const P = require('../relay/protocol');
const { RelayCore, makeCode } = require('../relay/core');
const { makePass } = require('../relay/pass');
const { seededRandom } = require('../support/seeded-random');

const CONTROL = 27500;
const PORTS = [27501, 27502, 27503];
const HOST = { address: '198.51.100.10', port: 40000 };
const JOINER = { address: '203.0.113.20', port: 50000 };
const STRANGER = { address: '192.0.2.30', port: 60000 };
const REGION = 'virginia';
const KEY = Buffer.alloc(32, 0x5a);

const relay = (limits = {}) => new RelayCore({ controlPort: CONTROL, ports: PORTS, region: REGION, passKey: KEY, random: seededRandom(3), limits });
const send = (r, to, from, msg, now = 0) => r.receive(to, from.address, from.port, Buffer.isBuffer(msg) ? msg : P.encode(msg), now);
const only = (out) => { assert.strictEqual(out.length, 1, `one packet out, not ${out.length}`); return { ...out[0], m: P.decode(out[0].data) }; };

// Opens a game the whole way, cookie and all: gives back its token and code
function openGame(r, from = HOST, now = 0) {
  const cookie = only(send(r, CONTROL, from, { type: P.TYPE.HOST_OPEN }, now));
  assert.strictEqual(cookie.m.type, P.TYPE.COOKIE);
  const opened = only(send(r, CONTROL, from, { type: P.TYPE.HOST_OPEN, secret: cookie.m.secret }, now));
  assert.strictEqual(opened.m.type, P.TYPE.HOST_OPENED);
  return { token: opened.m.secret, code: opened.m.code, pass: opened.m.pass, passTime: opened.m.passTime };
}

// A joiner asks to join, cookie and all: gives back what the relay sent (the answer to the joiner, and the note to the host)
function join(r, code, from = JOINER, now = 0) {
  const cookie = only(send(r, CONTROL, from, { type: P.TYPE.JOIN, code }, now));
  assert.strictEqual(cookie.m.type, P.TYPE.COOKIE);
  return send(r, CONTROL, from, { type: P.TYPE.JOIN, secret: cookie.m.secret, code }, now).map((o) => ({ ...o, m: P.decode(o.data) }));
}

// A game with one joiner connected, both hellos said: gives back the game, the joiner's port and its ticket
function connected(r, now = 0) {
  const game = openGame(r, HOST, now);
  const [toJoiner] = join(r, game.code, JOINER, now);
  const port = toJoiner.m.port;
  send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port }, now);
  const ready = only(send(r, port, JOINER, { type: P.TYPE.JOINER_HELLO, secret: toJoiner.m.secret }, now));
  assert.strictEqual(ready.m.type, P.TYPE.READY);
  return { game, port, ticket: toJoiner.m.secret };
}

test('a game\'s whole life: open, join, both hellos, READY, packets both ways', () => {
  const r = relay();
  const game = openGame(r);
  assert.ok(P.isCode(game.code) && game.token.length === 16);

  const out = join(r, game.code);
  assert.strictEqual(out.length, 2);
  const [toJoiner, toHost] = out;
  assert.strictEqual(toJoiner.m.type, P.TYPE.JOIN_PORT);
  assert.ok(PORTS.includes(toJoiner.m.port), 'one of the relay\'s ports');
  assert.ok(toJoiner.m.code.equals(game.code));
  assert.deepStrictEqual([toJoiner.address, toJoiner.port], [JOINER.address, JOINER.port]);
  assert.strictEqual(toHost.m.type, P.TYPE.NEW_JOINER);
  assert.deepStrictEqual([toHost.address, toHost.port], [HOST.address, HOST.port]);
  assert.strictEqual(toHost.m.port, toJoiner.m.port);
  assert.ok(toHost.m.secret.equals(game.token), 'the note to the host carries its token, so the host knows it came from the relay');

  const port = toJoiner.m.port;
  assert.deepStrictEqual(send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port }), [], 'the host\'s hello alone: nothing yet');
  const ready = only(send(r, port, JOINER, { type: P.TYPE.JOINER_HELLO, secret: toJoiner.m.secret }));
  assert.strictEqual(ready.m.type, P.TYPE.READY);
  assert.strictEqual(ready.from, port, 'READY comes from the joiner\'s own port');

  const up = Buffer.from('a game packet from the joiner');
  const forwardedUp = only(send(r, port, JOINER, up));
  assert.deepStrictEqual([forwardedUp.from, forwardedUp.address, forwardedUp.port], [port, HOST.address, HOST.port]);
  assert.ok(forwardedUp.data.equals(up), 'passed on unchanged');
  const down = Buffer.from('and one from the host');
  const forwardedDown = only(send(r, port, HOST, down));
  assert.deepStrictEqual([forwardedDown.from, forwardedDown.address, forwardedDown.port], [port, JOINER.address, JOINER.port]);
  assert.ok(forwardedDown.data.equals(down));
});

test('the host\'s hello can come second, and READY still goes to the joiner', () => {
  const r = relay();
  const game = openGame(r);
  const [toJoiner] = join(r, game.code);
  const port = toJoiner.m.port;
  assert.deepStrictEqual(send(r, port, JOINER, { type: P.TYPE.JOINER_HELLO, secret: toJoiner.m.secret }), []);
  const ready = only(send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port }));
  assert.strictEqual(ready.m.type, P.TYPE.READY);
  assert.deepStrictEqual([ready.address, ready.port], [JOINER.address, JOINER.port]);
});

test('a lost READY is sent again when the joiner says hello again', () => {
  const r = relay();
  const { port, ticket } = connected(r);
  const again = only(send(r, port, JOINER, { type: P.TYPE.JOINER_HELLO, secret: ticket }));
  assert.strictEqual(again.m.type, P.TYPE.READY);
});

test('opening and joining need a cookie, and only the asker\'s own address gets it', () => {
  const r = relay();
  const first = only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN }));
  assert.strictEqual(first.m.type, P.TYPE.COOKIE);
  assert.deepStrictEqual([first.address, first.port], [HOST.address, HOST.port]);
  assert.strictEqual(r.games.size, 0, 'nothing is kept for a first ask');

  const someoneElses = only(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN, secret: first.m.secret }));
  assert.strictEqual(someoneElses.m.type, P.TYPE.COOKIE, 'one address\'s cookie is no good from another');
  assert.strictEqual(r.games.size, 0);

  const wrongPort = only(send(r, CONTROL, { address: HOST.address, port: HOST.port + 1 }, { type: P.TYPE.HOST_OPEN, secret: first.m.secret }));
  assert.strictEqual(wrongPort.m.type, P.TYPE.COOKIE, 'nor from another port of the same address');
});

test('a cookie is good for 10 to 20 s', () => {
  const r = relay();
  const cookie = only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN }, 5000)).m.secret;
  assert.strictEqual(only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN, secret: cookie }, 19999)).m.type, P.TYPE.HOST_OPENED, 'made at 5 s, good at 19.999 s');
  const later = only(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN }, 5000)).m.secret;
  assert.strictEqual(only(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN, secret: later }, 20000)).m.type, P.TYPE.COOKIE, 'and no good at 20 s');
});

test('every answer to an address not yet proven is no bigger than its question', () => {
  const r = relay();
  for (const msg of [{ type: P.TYPE.HOST_OPEN }, { type: P.TYPE.JOIN, code: Buffer.from('ABCD2345', 'latin1') }, { type: P.TYPE.HOST_KEEP, secret: Buffer.alloc(16, 7) }, { type: P.TYPE.ECHO, secret: Buffer.alloc(16, 3), number: 1 }]) {
    const question = P.encode(msg);
    for (const answer of r.receive(CONTROL, STRANGER.address, STRANGER.port, question, 0)) {
      assert.ok(answer.data.length <= question.length, `answer to type ${msg.type}`);
    }
  }
});

test('a host can open 2 games, not 3; and the relay holds at most its most', () => {
  const r = relay();
  openGame(r);
  openGame(r);
  const cookie = only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN })).m.secret;
  const third = only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN, secret: cookie }));
  assert.deepStrictEqual([third.m.type, third.m.number], [P.TYPE.REFUSED, P.REFUSED_WHY.TOO_MANY_GAMES]);

  const small = relay({ mostGames: 1 });
  openGame(small);
  const cookie2 = only(send(small, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN })).m.secret;
  const busy = only(send(small, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN, secret: cookie2 }));
  assert.deepStrictEqual([busy.m.type, busy.m.number], [P.TYPE.REFUSED, P.REFUSED_WHY.BUSY]);
});

test('joining a code that is no game is refused', () => {
  const r = relay();
  const out = join(r, Buffer.from('ZZZZZZZZ', 'latin1'));
  assert.strictEqual(out.length, 1);
  assert.deepStrictEqual([out[0].m.type, out[0].m.number], [P.TYPE.REFUSED, P.REFUSED_WHY.NO_SUCH_GAME]);
});

test('a game takes at most its most joiners, and the relay at most its ports', () => {
  const r = relay({ mostJoinersPerGame: 2 });
  const game = openGame(r);
  assert.strictEqual(join(r, game.code, { address: '203.0.113.1', port: 1 })[0].m.type, P.TYPE.JOIN_PORT);
  assert.strictEqual(join(r, game.code, { address: '203.0.113.2', port: 1 })[0].m.type, P.TYPE.JOIN_PORT);
  const full = join(r, game.code, { address: '203.0.113.3', port: 1 })[0];
  assert.deepStrictEqual([full.m.type, full.m.number], [P.TYPE.REFUSED, P.REFUSED_WHY.GAME_FULL]);

  const r2 = relay();
  const g2 = openGame(r2);
  for (let i = 0; i < PORTS.length; i++) {
    assert.strictEqual(join(r2, g2.code, { address: `203.0.113.${10 + i}`, port: 1 })[0].m.type, P.TYPE.JOIN_PORT);
  }
  const noPort = join(r2, g2.code, { address: '203.0.113.99', port: 1 })[0];
  assert.deepStrictEqual([noPort.m.type, noPort.m.number], [P.TYPE.REFUSED, P.REFUSED_WHY.BUSY], 'every port is taken');
});

test('a hello with the wrong secret binds nothing', () => {
  const r = relay();
  const game = openGame(r);
  const [toJoiner] = join(r, game.code);
  const port = toJoiner.m.port;
  assert.deepStrictEqual(send(r, port, STRANGER, { type: P.TYPE.HOST_HELLO, secret: Buffer.alloc(16, 1), port }), []);
  assert.deepStrictEqual(send(r, port, STRANGER, { type: P.TYPE.JOINER_HELLO, secret: Buffer.alloc(16, 1) }), []);
  assert.deepStrictEqual(send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port: port === 27501 ? 27502 : 27501 }), [], 'a host hello naming another port');
  assert.strictEqual(r.slots.get(port).hostEnd, null);
  assert.strictEqual(r.slots.get(port).joinerEnd, null);
});

test('on a joiner\'s port, only its two ends are heard', () => {
  const r = relay();
  const { port } = connected(r);
  assert.deepStrictEqual(send(r, port, STRANGER, Buffer.from('anything')), [], 'a stranger');
  assert.deepStrictEqual(send(r, port, { address: JOINER.address, port: JOINER.port + 1 }, Buffer.from('x')), [], 'the joiner\'s address, from another port');
  assert.deepStrictEqual(send(r, PORTS.find((p) => p !== port), JOINER, Buffer.from('x')), [], 'the joiner, on a port that isn\'t its');
});

test('a host or joiner whose NAT moved it is heard again after a hello with its secret', () => {
  const r = relay();
  const { game, port, ticket } = connected(r);
  const moved = { address: JOINER.address, port: JOINER.port + 7 };
  assert.strictEqual(only(send(r, port, moved, { type: P.TYPE.JOINER_HELLO, secret: ticket })).m.type, P.TYPE.READY);
  const out = only(send(r, port, HOST, Buffer.from('to the joiner, where it is now')));
  assert.deepStrictEqual([out.address, out.port], [moved.address, moved.port]);

  const hostMoved = { address: HOST.address, port: HOST.port + 9 };
  send(r, port, hostMoved, { type: P.TYPE.HOST_HELLO, secret: game.token, port });
  const up = only(send(r, port, moved, Buffer.from('to the host, where it is now')));
  assert.deepStrictEqual([up.address, up.port], [hostMoved.address, hostMoved.port]);
});

test('nothing on a joiner\'s port is passed on before both hellos', () => {
  const r = relay();
  const game = openGame(r);
  const [toJoiner] = join(r, game.code);
  const port = toJoiner.m.port;
  send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port });
  assert.deepStrictEqual(send(r, port, HOST, Buffer.from('too early')), []);
});

test('a packet over 1,500 bytes is dropped, and 1,500 is passed on', () => {
  const r = relay();
  const { port } = connected(r);
  assert.deepStrictEqual(send(r, port, JOINER, Buffer.alloc(1501)), []);
  assert.strictEqual(send(r, port, JOINER, Buffer.alloc(1500)).length, 1);
  assert.deepStrictEqual(send(r, CONTROL, JOINER, Buffer.alloc(1501)), [], 'on the control port too');
});

test('a port passes on at most its packets and bytes a second, each way', () => {
  const r = relay({ portPacketRate: 2, portPacketBurst: 3, portByteRate: 1000000, portByteBurst: 1000000 });
  const { port } = connected(r);
  for (let i = 0; i < 3; i++) assert.strictEqual(send(r, port, JOINER, Buffer.from('x'), 1).length, 1);
  assert.deepStrictEqual(send(r, port, JOINER, Buffer.from('x'), 1), [], 'the 4th at once is over the limit');
  assert.strictEqual(send(r, port, HOST, Buffer.from('x'), 1).length, 1, 'the other way has its own');
  assert.strictEqual(send(r, port, JOINER, Buffer.from('x'), 501).length, 1, 'half a second later, one more');

  const bytes = relay({ portByteRate: 100, portByteBurst: 1000 });
  const b = connected(bytes);
  assert.strictEqual(send(bytes, b.port, JOINER, Buffer.alloc(1000), 1).length, 1);
  assert.deepStrictEqual(send(bytes, b.port, JOINER, Buffer.alloc(1), 1), [], 'its bytes are used up');
});

test('one address asking too fast is held back, and others are not', () => {
  const r = relay({ controlRate: 1, controlBurst: 2 });
  assert.strictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN }).length, 1);
  assert.strictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN }).length, 1);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPEN }), [], 'the 3rd at once');
  assert.strictEqual(send(r, CONTROL, HOST, { type: P.TYPE.HOST_OPEN }).length, 1, 'another address is not held back');
});

test('refusals to one address are kept to their own limit', () => {
  const r = relay({ refusalRate: 1, refusalBurst: 1 });
  const keep = { type: P.TYPE.HOST_KEEP, secret: Buffer.alloc(16, 9) };
  assert.strictEqual(only(send(r, CONTROL, STRANGER, keep)).m.type, P.TYPE.REFUSED);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, keep), [], 'the second refusal at once isn\'t sent');
});

test('anything on the control port that isn\'t a message is dropped, as are messages that belong elsewhere', () => {
  const r = relay();
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, Buffer.from('hello')), []);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_OPENED, secret: Buffer.alloc(16, 1), code: Buffer.from('ABCD2345', 'latin1') }), []);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.JOINER_HELLO, secret: Buffer.alloc(16, 1) }), []);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.ECHO_BACK, secret: Buffer.alloc(16, 1), number: 1 }), [], 'an ECHO_BACK, so two relays can\'t answer each other');
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.COOKIE, secret: Buffer.alloc(16, 1) }), []);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, { type: P.TYPE.REFUSED, number: 1 }), []);
  assert.deepStrictEqual(send(r, 1234, STRANGER, Buffer.from('a port the relay doesn\'t have')), []);
});

test('an echo comes straight back to its sender, the same size, with its own bytes and count, and nothing is kept', () => {
  const r = relay();
  const mine = Buffer.from('sixteen bytes!!!', 'latin1');
  const question = P.encode({ type: P.TYPE.ECHO, secret: mine, number: 3 });
  const back = only(r.receive(CONTROL, STRANGER.address, STRANGER.port, question, 0));
  assert.strictEqual(back.m.type, P.TYPE.ECHO_BACK);
  assert.ok(back.m.secret.equals(mine), 'the asker\'s own 16 bytes');
  assert.strictEqual(back.m.number, 3, 'and its count');
  assert.deepStrictEqual([back.from, back.address, back.port], [CONTROL, STRANGER.address, STRANGER.port], 'from the control port, to the sender only');
  assert.strictEqual(back.data.length, question.length, 'no bigger than the question');
  assert.deepStrictEqual([r.games.size, r.free.length], [0, PORTS.length], 'nothing kept');

  const empty = only(send(r, CONTROL, STRANGER, { type: P.TYPE.ECHO }));
  assert.deepStrictEqual([empty.m.type, empty.m.secret, empty.m.number], [P.TYPE.ECHO_BACK, null, 0], 'an echo of nothing is answered with nothing');
  assert.deepStrictEqual(send(r, PORTS[0], STRANGER, { type: P.TYPE.ECHO, secret: mine }), [], 'only the control port answers echoes');
});

test('echoes are held to the control limits, and one over gets no answer at all', () => {
  const r = relay({ controlRate: 1, controlBurst: 3 });
  const echo = { type: P.TYPE.ECHO, secret: Buffer.alloc(16, 4), number: 1 };
  for (let i = 0; i < 3; i++) assert.strictEqual(only(send(r, CONTROL, STRANGER, echo)).m.type, P.TYPE.ECHO_BACK);
  assert.deepStrictEqual(send(r, CONTROL, STRANGER, echo), [], 'the 4th at once: nothing, not a REFUSED');
  assert.strictEqual(only(send(r, CONTROL, HOST, echo)).m.type, P.TYPE.ECHO_BACK, 'another address has its own');

  const all = relay({ everyoneRate: 1, everyoneBurst: 2 });
  assert.strictEqual(send(all, CONTROL, STRANGER, echo).length, 1);
  assert.strictEqual(send(all, CONTROL, HOST, echo).length, 1);
  assert.deepStrictEqual(send(all, CONTROL, JOINER, echo), [], 'and everyone\'s together');
});

test('HOST_OPENED and every HOST_KEPT carry a fresh pass the list can check with this relay\'s key', () => {
  const r = relay();
  const now = 1794268800123;
  const game = openGame(r, HOST, now);
  assert.strictEqual(game.passTime, 1794268800, 'the pass time is now, in whole seconds');
  assert.ok(game.pass.equals(makePass(KEY, REGION, game.code, game.passTime)), 'made from this relay\'s key, region and the game\'s code');

  const kept = only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token }, now + 15000));
  assert.strictEqual(kept.m.passTime, 1794268815, 'a HOST_KEPT has a fresh one');
  assert.ok(kept.m.pass.equals(makePass(KEY, REGION, game.code, 1794268815)));
  assert.ok(!kept.m.pass.equals(game.pass));

  const other = new RelayCore({ controlPort: CONTROL, ports: PORTS, region: 'paris', passKey: KEY, random: seededRandom(3) });
  assert.ok(!openGame(other, HOST, now).pass.equals(game.pass), 'the same key in another region makes another pass');
});

test('a kept game lives; an unkept one ends, with its ports and its code', () => {
  const r = relay();
  const { game, port } = connected(r);
  assert.strictEqual(only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token }, 30000)).m.type, P.TYPE.HOST_KEPT);
  send(r, port, JOINER, Buffer.from('x'), 30000);
  r.tick(70000);
  assert.strictEqual(r.games.size, 1, 'kept at 30 s, so alive at 70 s');
  r.tick(75000);
  assert.strictEqual(r.games.size, 0, 'not kept for 45 s: it ends');
  assert.strictEqual(r.slots.get(port).state, 'free');
  assert.deepStrictEqual(join(r, game.code, JOINER, 75000)[0].m.number, P.REFUSED_WHY.NO_SUCH_GAME);
});

test('HOST_KEPT says how many joiners the game has', () => {
  const r = relay();
  const { game } = connected(r);
  assert.strictEqual(only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token })).m.number, 1);
});

test('a host that closes its game ends it at once; a wrong token closes nothing', () => {
  const r = relay();
  const { game, port } = connected(r);
  send(r, CONTROL, STRANGER, { type: P.TYPE.HOST_CLOSE, secret: Buffer.alloc(16, 5) });
  assert.strictEqual(r.games.size, 1);
  assert.deepStrictEqual(send(r, CONTROL, HOST, { type: P.TYPE.HOST_CLOSE, secret: game.token }), []);
  assert.strictEqual(r.games.size, 0);
  assert.strictEqual(r.slots.get(port).state, 'free');
  assert.strictEqual(only(send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token })).m.number, P.REFUSED_WHY.NO_SUCH_GAME, 'its token is no good now');
});

test('a port waiting for its hellos is freed after 15 s, and an idle one after 30 s', () => {
  const r = relay();
  const game = openGame(r);
  const [toJoiner] = join(r, game.code);
  r.tick(14999);
  assert.strictEqual(r.slots.get(toJoiner.m.port).state, 'pending');
  r.tick(15000);
  assert.strictEqual(r.slots.get(toJoiner.m.port).state, 'free');

  const r2 = relay();
  const c = connected(r2);
  send(r2, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: c.game.token }, 20000);
  r2.tick(29999);
  assert.strictEqual(r2.slots.get(c.port).state, 'active');
  r2.tick(30000);
  assert.strictEqual(r2.slots.get(c.port).state, 'free');
  assert.strictEqual(r2.games.size, 1, 'the game lives on without that joiner');
});

test('a freed port goes back to be used again', () => {
  const r = relay();
  const game = openGame(r);
  const ports = [];
  for (let i = 0; i < PORTS.length; i++) ports.push(join(r, game.code, { address: `203.0.113.${i}`, port: 1 })[0].m.port);
  r.tick(15000);
  send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token }, 15000);
  assert.ok(PORTS.includes(join(r, game.code, JOINER, 15000)[0].m.port));
});

test('the log lines are counts and times only: no address, code, token or ticket', () => {
  const r = relay();
  const { game, port, ticket } = connected(r, 0);
  send(r, port, JOINER, Buffer.from('x'), 1);
  send(r, port, HOST, Buffer.from('y'), 1);
  send(r, port, HOST, Buffer.from('z'), 1);
  send(r, port, STRANGER, Buffer.from('x'), 1);
  // The game and its joiner are still alive when the line is made, so anything of theirs could get into it
  send(r, CONTROL, HOST, { type: P.TYPE.HOST_KEEP, secret: game.token }, 50000);
  send(r, port, HOST, { type: P.TYPE.HOST_HELLO, secret: game.token, port }, 50000);
  send(r, port, JOINER, { type: P.TYPE.JOINER_HELLO, secret: ticket }, 50000);
  const lines = r.tick(60000);
  assert.strictEqual(r.games.size, 1, 'the game is alive as the line is made');
  assert.strictEqual(r.slots.get(port).state, 'active', 'and so is its joiner');
  assert.strictEqual(lines.length, 1);
  const line = lines[0];
  assert.ok(/forwarded 3 packets \(1 joiners to hosts, 2 hosts to joiners\)/.test(line), line);
  assert.ok(/1 joins, 1 joiners ready,/.test(line), 'one joiner, ready once, though its READY went twice');
  for (const secret of [HOST.address, JOINER.address, STRANGER.address, game.code.toString('latin1'), game.token.toString('hex'), ticket.toString('hex')]) {
    assert.ok(!line.includes(secret), `the line has no ${secret}`);
  }
  assert.ok(!/\d+\.\d+\.\d+\.\d+/.test(line), 'nothing that looks like an address');
  assert.deepStrictEqual(r.tick(60001), [], 'and the next line only a minute later');
});

test('a game\'s code is 8 code letters made from 40 random bits', () => {
  const seen = new Set();
  const random = seededRandom(11);
  for (let i = 0; i < 500; i++) {
    const code = makeCode(random);
    assert.ok(P.isCode(code), code.toString('latin1'));
    seen.add(code.toString('latin1'));
  }
  assert.ok(seen.size > 490, 'they differ');
  assert.strictEqual(makeCode(() => Buffer.alloc(5, 0)).toString('latin1'), '22222222', 'all 0 bits is the first letter each time');
  assert.strictEqual(makeCode(() => Buffer.alloc(5, 0xff)).toString('latin1'), 'ZZZZZZZZ', 'all 1 bits is the last');
});

test('nothing a packet holds can throw out of the relay', () => {
  const r = relay();
  const { port } = connected(r);
  const random = seededRandom(99);
  for (let i = 0; i < 2000; i++) {
    const size = random(1)[0] % 80;
    const junk = random(size);
    if (size >= 6) { junk.write('AVPR', 0, 'latin1'); junk[4] = 1; }
    for (const at of [CONTROL, port]) {
      assert.ok(Array.isArray(r.receive(at, STRANGER.address, STRANGER.port, junk, i)));
    }
  }
  assert.ok(Array.isArray(r.receive(CONTROL, STRANGER.address, STRANGER.port, 'not bytes', 0)));
  assert.ok(Array.isArray(r.receive(CONTROL, STRANGER.address, STRANGER.port, null, 0)));
});

test('the relay refuses ports it could not keep apart, and needs its region and pass key', () => {
  const made = (o) => () => new RelayCore({ controlPort: 27500, ports: [27501], region: REGION, passKey: KEY, random: seededRandom(1), ...o });
  assert.doesNotThrow(made({}));
  assert.throws(made({ ports: [27500] }), /each relay port/, 'the control port as a relay port');
  assert.throws(made({ ports: [27501, 27501] }), /each relay port/, 'one port twice');
  assert.throws(made({ ports: [0] }), /each relay port/, 'port 0');
  assert.throws(made({ region: undefined }), /region/, 'no region');
  assert.throws(made({ region: 'Virginia' }), /region/, 'a region with a capital');
  assert.throws(made({ passKey: undefined }), /pass key/, 'no pass key');
  assert.throws(made({ passKey: Buffer.alloc(16, 1) }), /pass key/, 'a pass key of 16 bytes');
});
