'use strict';
// What the relay does with each packet it's sent, with no network of its own: a packet in, the packets to send out. Written 2026-11-08 by
// Melanikus for AVPx Dedicated Server.
//
// Keeping the sockets out of here (main.js has them) means every rule below can be tested by handing it packets, with no socket opened
// (test/core.test.js).
//
// HOW A GAME GOES THROUGH THE RELAY (protocol.js has the messages):
//
//   1. The host asks the relay's CONTROL port for a game (HOST_OPEN). The relay first answers with a COOKIE, a stamp only that sender's
//      address can have seen, and opens the game only when the host asks again with it (see "cookies" below). Its answer, HOST_OPENED,
//      has the host's TOKEN (16 random bytes: proof it's the host, from then on) and the game's CODE (8 letters, for joiners).
//   2. The host says HOST_KEEP with its token every 15 s. A game not kept for gameLifeMilliseconds ends.
//   3. A joiner asks the control port to JOIN a game by its code, with a cookie too. The relay gives it one of its other ports, its own
//      for this joiner (JOIN_PORT, with a TICKET: proof it's that joiner), and tells the host (NEW_JOINER, with that port).
//   4. Both send a hello to that port, from their game's own socket: the host with its token, the joiner with its ticket. That fixes the
//      address and port each one's packets come from, as the relay sees them, through whatever NAT is between.
//   5. Once both are there, the relay tells the joiner READY, and from then on passes every packet from one to the other, from that
//      port, unread and unchanged. The host sees each joiner as a peer of its own, because each comes from a port of its own.
//
// WHAT IT REFUSES, AND THE LIMITS (AVP Tao 3: input is hostile): a packet bigger than mostDatagramBytes; anything on the control port
// that isn't exactly a message, or comes too fast from its sender or from everyone; a hello with the wrong secret; a packet on a joiner's
// port from anyone but its two ends; more than a port's share of packets and bytes a second. The most games, games for one sender,
// joiners for one game and ports there are are all fixed. A port waiting for its two ends is freed after pendingMilliseconds, and one with
// no traffic after idleMilliseconds.
//
// COOKIES: a sender can put any address on its packets. Without cookies, someone could ask for a thousand games or ports in other
// people's names, and fill the relay. So the two asks that make the relay keep something (HOST_OPEN, JOIN) need a cookie: 16 bytes the
// relay makes from the sender's address and port, the time, and a secret of its own, and sends to that address. Only someone who gets
// packets at that address can know it, and the relay keeps nothing to check it: it makes it again. A cookie is good for 10 to 20 s.
//
// NO ADDRESSES ARE WRITTEN ANYWHERE (the user's ruling: no IPs). Addresses live in memory only while a game or a port needs them, and are
// forgotten when it ends; the per-sender limits key by a hash (limits.js). The relay's lines (tick) are counts and times only. Codes,
// tokens and tickets are never written either: a code would let anyone join.

const crypto = require('crypto');
const P = require('./protocol');
const { TokenBucket, AddressHasher, PerSender } = require('./limits');

const DEFAULTS = {
  mostGames: 500,
  mostGamesPerSender: 2,
  mostJoinersPerGame: 8,                 // the game's own most players is 8, the host among them
  gameLifeMilliseconds: 45000,           // a host keeps its game every 15 s
  pendingMilliseconds: 15000,            // for both ends of a joiner's port to say hello
  idleMilliseconds: 30000,               // a connected game's ENet sends something every second or so
  mostDatagramBytes: 1500,               // ENet's packets are at most 1400 bytes as the game sets it up; nothing bigger is a game's
  cookieSlotMilliseconds: 10000,
  controlRate: 10, controlBurst: 20,     // control messages a second from one sender
  everyoneRate: 2000, everyoneBurst: 4000, // and from everyone
  refusalRate: 1, refusalBurst: 2,       // REFUSED answers a second to one sender: a refusal is an answer anyone can ask for
  joinRate: 4, joinBurst: 8,             // joins a second for one game
  helloRate: 20, helloBurst: 40,         // hellos a second on one joiner's port
  portPacketRate: 400, portPacketBurst: 800,               // each way, on one joiner's port
  portByteRate: 256 * 1024, portByteBurst: 512 * 1024,     // each way, on one joiner's port
  mostSenders: 10000,                    // senders the per-sender limits remember
  statsMilliseconds: 60000,
};

// A game's code: 5 random bytes (40 bits) as 8 code letters, 5 bits each. Only the bits not yet used are kept between bytes, so the number
// never grows past 12 bits (JavaScript's << works on 32).
function makeCode(random) {
  const bytes = random(5);
  let bits = 0;
  let value = 0;
  let out = '';

  for (const b of bytes) {
    value = ((value << 8) | b) & 0xfff;
    bits += 8;

    while (bits >= 5) {
      out += P.kCodeLetters[(value >>> (bits - 5)) & 31];
      bits -= 5;
      value &= (1 << bits) - 1;
    }
  }

  return Buffer.from(out, 'latin1');
}

function sameSecret(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sameEnd(end, address, port) {
  return end !== null && end.address === address && end.port === port;
}

class RelayCore {
  // controlPort: the port hosts and joiners ask on. ports: the relay's other ports, one for each joiner while it's connected, all already
  // open (main.js opens them). random(n): n random bytes. limits: anything in DEFAULTS to change.
  constructor({ controlPort, ports, random = crypto.randomBytes, limits = {}, now = 0 }) {
    const L = { ...DEFAULTS, ...limits };
    this.L = L;
    this.controlPort = controlPort;
    this.random = random;
    this.hasher = new AddressHasher(random);
    this.cookieKey = random(32);
    this.cookieKeyMadeAt = now;

    this.games = new Map();          // code (text) -> game
    this.gamesByToken = new Map();   // token (hex) -> game
    this.gamesPerSender = new Map(); // hashed address -> how many games it has open
    this.slots = new Map();          // relay port -> what it's for
    this.free = [];

    for (const port of ports) {
      if (!Number.isInteger(port) || port < 1 || port > 65535 || port === controlPort || this.slots.has(port)) {
        throw new Error('RelayCore: each relay port is a different port from 1 to 65535, and not the control port');
      }

      this.slots.set(port, { port, state: 'free' });
      this.free.push(port);
    }

    this.everyone = new TokenBucket(L.everyoneRate, L.everyoneBurst);
    this.perSender = new PerSender({ rate: L.controlRate, burst: L.controlBurst, most: L.mostSenders, hasher: this.hasher });
    this.refusals = new PerSender({ rate: L.refusalRate, burst: L.refusalBurst, most: L.mostSenders, hasher: this.hasher });
    this.statsAt = now;
    this.counts = RelayCore.zeroCounts();
  }

  static zeroCounts() {
    return { opened: 0, closed: 0, expired: 0, joins: 0, refused: 0, forwardedPackets: 0, forwardedBytes: 0, tooBig: 0, overLimit: 0, notAMessage: 0, strangers: 0, portsExpired: 0 };
  }

  // ----- A packet in

  // A packet came to localPort from address:port at now (milliseconds). Gives back what to send: [{ from, address, port, data }], each
  // from one of the relay's own ports.
  receive(localPort, address, port, data, now) {
    try {
      if (!Buffer.isBuffer(data) || data.length > this.L.mostDatagramBytes) {
        this.counts.tooBig++;
        return [];
      }

      if (localPort === this.controlPort) {
        return this.onControl(address, port, data, now);
      }

      const slot = this.slots.get(localPort);
      return slot ? this.onRelayPort(slot, address, port, data, now) : [];
    } catch (e) {
      // Nothing a packet holds should get here; if something does, the packet is dropped and the relay goes on
      this.counts.notAMessage++;
      return [];
    }
  }

  onControl(address, port, data, now) {
    // The sender's own limit first, so one sender going too fast doesn't use up everyone's
    if (!this.perSender.allows(address, now) || !this.everyone.take(now)) {
      this.counts.overLimit++;
      return [];
    }

    const m = P.decode(data);

    if (m === null) {
      this.counts.notAMessage++;
      return [];
    }

    const to = (msg) => ({ from: this.controlPort, address, port, data: P.encode(msg) });

    switch (m.type) {
      case P.TYPE.HOST_OPEN: {
        if (!this.cookieIsGood(m.secret, address, port, now)) {
          return [to({ type: P.TYPE.COOKIE, secret: this.cookieFor(address, port, now) })];
        }

        const sender = this.hasher.keyOf(address, now);

        if ((this.gamesPerSender.get(sender) || 0) >= this.L.mostGamesPerSender) {
          return this.refuse(address, port, now, P.REFUSED_WHY.TOO_MANY_GAMES);
        }

        if (this.games.size >= this.L.mostGames) {
          return this.refuse(address, port, now, P.REFUSED_WHY.BUSY);
        }

        let code = null;

        for (let tries = 0; tries < 8 && code === null; tries++) {
          const made = makeCode(this.random);
          code = this.games.has(made.toString('latin1')) ? null : made;
        }

        if (code === null) {
          return this.refuse(address, port, now, P.REFUSED_WHY.BUSY);
        }

        const game = {
          code,
          token: this.random(P.kSecretBytes),
          host: { address, port },
          sender,
          keptAt: now,
          joiners: new Set(),
          joinLimit: new TokenBucket(this.L.joinRate, this.L.joinBurst),
        };

        this.games.set(code.toString('latin1'), game);
        this.gamesByToken.set(game.token.toString('hex'), game);
        this.gamesPerSender.set(sender, (this.gamesPerSender.get(sender) || 0) + 1);
        this.counts.opened++;
        return [to({ type: P.TYPE.HOST_OPENED, secret: game.token, code })];
      }

      case P.TYPE.HOST_KEEP: {
        const game = m.secret ? this.gamesByToken.get(m.secret.toString('hex')) : undefined;

        if (!game || !sameSecret(game.token, m.secret)) {
          return this.refuse(address, port, now, P.REFUSED_WHY.NO_SUCH_GAME);
        }

        // The host's NAT may have given it a new port: the token says it's the host, so this is where it is now
        game.host = { address, port };
        game.keptAt = now;
        return [to({ type: P.TYPE.HOST_KEPT, secret: game.token, number: game.joiners.size })];
      }

      case P.TYPE.HOST_CLOSE: {
        const game = m.secret ? this.gamesByToken.get(m.secret.toString('hex')) : undefined;

        if (game && sameSecret(game.token, m.secret)) {
          this.closeGame(game);
          this.counts.closed++;
        }

        return [];
      }

      case P.TYPE.JOIN: {
        if (!this.cookieIsGood(m.secret, address, port, now)) {
          return [to({ type: P.TYPE.COOKIE, secret: this.cookieFor(address, port, now) })];
        }

        const game = m.code ? this.games.get(m.code.toString('latin1')) : undefined;

        if (!game) {
          return this.refuse(address, port, now, P.REFUSED_WHY.NO_SUCH_GAME);
        }

        if (game.joiners.size >= this.L.mostJoinersPerGame) {
          return this.refuse(address, port, now, P.REFUSED_WHY.GAME_FULL);
        }

        if (!game.joinLimit.take(now) || this.free.length === 0) {
          return this.refuse(address, port, now, P.REFUSED_WHY.BUSY);
        }

        const relayPort = this.free.shift();
        const slot = this.slots.get(relayPort);
        Object.assign(slot, {
          state: 'pending',
          game,
          ticket: this.random(P.kSecretBytes),
          hostEnd: null,
          joinerEnd: null,
          madeAt: now,
          trafficAt: now,
          hellos: new TokenBucket(this.L.helloRate, this.L.helloBurst),
          up: { packets: new TokenBucket(this.L.portPacketRate, this.L.portPacketBurst), bytes: new TokenBucket(this.L.portByteRate, this.L.portByteBurst) },
          down: { packets: new TokenBucket(this.L.portPacketRate, this.L.portPacketBurst), bytes: new TokenBucket(this.L.portByteRate, this.L.portByteBurst) },
        });
        game.joiners.add(relayPort);
        this.counts.joins++;

        return [
          to({ type: P.TYPE.JOIN_PORT, secret: slot.ticket, code: game.code, port: relayPort }),
          { from: this.controlPort, address: game.host.address, port: game.host.port, data: P.encode({ type: P.TYPE.NEW_JOINER, secret: game.token, port: relayPort }) },
        ];
      }

      default:
        // A message the relay sends, or a hello, which belongs on a joiner's port
        this.counts.notAMessage++;
        return [];
    }
  }

  onRelayPort(slot, address, port, data, now) {
    if (slot.state === 'free') {
      this.counts.strangers++;
      return [];
    }

    const fromHost = sameEnd(slot.hostEnd, address, port);
    const fromJoiner = sameEnd(slot.joinerEnd, address, port);

    // A hello: only ever exactly a message, so a game's packet is never taken for one unless it is one, secret and all
    if (data.length === P.kMessageBytes) {
      const m = P.decode(data);

      if (m !== null && (m.type === P.TYPE.HOST_HELLO || m.type === P.TYPE.JOINER_HELLO)) {
        return this.onHello(slot, m, address, port, now);
      }
    }

    if (slot.state !== 'active' || !(fromHost || fromJoiner)) {
      this.counts.strangers++;
      return [];
    }

    const way = fromJoiner ? slot.up : slot.down;

    if (!way.packets.take(now) || !way.bytes.take(now, data.length)) {
      this.counts.overLimit++;
      return [];
    }

    slot.trafficAt = now;
    this.counts.forwardedPackets++;
    this.counts.forwardedBytes += data.length;
    const to = fromJoiner ? slot.hostEnd : slot.joinerEnd;
    return [{ from: slot.port, address: to.address, port: to.port, data }];
  }

  onHello(slot, m, address, port, now) {
    if (!slot.hellos.take(now)) {
      this.counts.overLimit++;
      return [];
    }

    if (m.type === P.TYPE.HOST_HELLO && sameSecret(m.secret, slot.game.token) && m.port === slot.port) {
      slot.hostEnd = { address, port };
    } else if (m.type === P.TYPE.JOINER_HELLO && sameSecret(m.secret, slot.ticket)) {
      slot.joinerEnd = { address, port };
    } else {
      this.counts.strangers++;
      return [];
    }

    if (slot.hostEnd === null || slot.joinerEnd === null) {
      return [];
    }

    slot.state = 'active';
    slot.trafficAt = now;

    // The joiner hears READY each time it says hello once both ends are there, so a READY that was lost is sent again when it asks again
    if (m.type === P.TYPE.JOINER_HELLO) {
      return [{ from: slot.port, address, port, data: P.encode({ type: P.TYPE.READY, secret: slot.ticket, port: slot.port }) }];
    }

    return [{ from: slot.port, address: slot.joinerEnd.address, port: slot.joinerEnd.port, data: P.encode({ type: P.TYPE.READY, secret: slot.ticket, port: slot.port }) }];
  }

  refuse(address, port, now, why) {
    this.counts.refused++;

    if (!this.refusals.allows(address, now)) {
      return [];
    }

    return [{ from: this.controlPort, address, port, data: P.encode({ type: P.TYPE.REFUSED, number: why }) }];
  }

  // ----- Cookies

  cookieFor(address, port, now, slotsBack = 0) {
    if (now - this.cookieKeyMadeAt >= 24 * 60 * 60 * 1000 || now < this.cookieKeyMadeAt) {
      this.cookieKey = this.random(32);
      this.cookieKeyMadeAt = now;
    }

    const slot = Math.floor(now / this.L.cookieSlotMilliseconds) - slotsBack;
    return crypto.createHmac('sha256', this.cookieKey).update(`${address}|${port}|${slot}`).digest().subarray(0, P.kSecretBytes);
  }

  cookieIsGood(secret, address, port, now) {
    return secret !== null && (sameSecret(secret, this.cookieFor(address, port, now, 0)) || sameSecret(secret, this.cookieFor(address, port, now, 1)));
  }

  // ----- Endings

  freeSlot(slot) {
    if (slot.state === 'free') {
      return;
    }

    slot.game.joiners.delete(slot.port);
    slot.ticket.fill(0);
    Object.keys(slot).forEach((k) => { if (k !== 'port') delete slot[k]; });
    slot.state = 'free';
    this.free.push(slot.port);
  }

  closeGame(game) {
    for (const port of [...game.joiners]) {
      this.freeSlot(this.slots.get(port));
    }

    this.games.delete(game.code.toString('latin1'));
    this.gamesByToken.delete(game.token.toString('hex'));
    const left = (this.gamesPerSender.get(game.sender) || 1) - 1;

    if (left > 0) {
      this.gamesPerSender.set(game.sender, left);
    } else {
      this.gamesPerSender.delete(game.sender);
    }

    game.token.fill(0);
  }

  // Called about once a second: ends what has run out, and gives back the lines to write, if any (counts only, never an address or code)
  tick(now) {
    for (const game of [...this.games.values()]) {
      if (now - game.keptAt >= this.L.gameLifeMilliseconds) {
        this.closeGame(game);
        this.counts.expired++;
      }
    }

    for (const slot of this.slots.values()) {
      if ((slot.state === 'pending' && now - slot.madeAt >= this.L.pendingMilliseconds) || (slot.state === 'active' && now - slot.trafficAt >= this.L.idleMilliseconds)) {
        this.freeSlot(slot);
        this.counts.portsExpired++;
      }
    }

    if (now - this.statsAt < this.L.statsMilliseconds) {
      return [];
    }

    const c = this.counts;
    let pending = 0;

    for (const slot of this.slots.values()) {
      if (slot.state === 'pending') pending++;
    }

    const line = `relay: in the last ${Math.round((now - this.statsAt) / 1000)} s: ${c.opened} games opened, ${c.closed} closed, ${c.expired} ended unkept; ` +
      `${c.joins} joins, ${c.refused} refusals; forwarded ${c.forwardedPackets} packets, ${c.forwardedBytes} bytes; ` +
      `dropped ${c.tooBig} too big, ${c.overLimit} over a limit, ${c.notAMessage} not a message, ${c.strangers} from strangers; ${c.portsExpired} ports timed out. ` +
      `Now ${this.games.size} games, ${this.slots.size - this.free.length} of ${this.slots.size} ports in use (${pending} waiting for both ends)`;
    this.statsAt = now;
    this.counts = RelayCore.zeroCounts();
    return [line];
  }
}

module.exports = { RelayCore, DEFAULTS, makeCode };
