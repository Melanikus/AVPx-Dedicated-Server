'use strict';
// The relay's UDP sockets, around relay/core.js: one for the control port and one for each joiner's port, all opened at start. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// This is all the relay does on the network: a packet that comes to one of its ports goes to the core, and whatever the core says to send
// is sent, from the port it names. Every decision is the core's, so it can be tested without sockets. The sockets are IPv4 only (udp4),
// as the game's ENet is.
//
// A socket's error is written in the log, with no address, and the relay goes on. Once a second, the core's tick ends what has run out and
// may give a line for the log.

const dgram = require('dgram');

// Opens every port and starts. address: the machine's address to listen on ('0.0.0.0' for all). core: a RelayCore made with these
// ports. log(line). now(): the time in milliseconds. Gives back a promise of { stop }, and fails if any port can't be opened, closing the
// ones that could.
function startRelay({ address, core, log, now = Date.now }) {
  const ports = [core.controlPort, ...core.slots.keys()];
  const sockets = new Map();
  let errors = 0;

  const sendAll = (out) => {
    for (const o of out) {
      const socket = sockets.get(o.from);

      if (socket) {
        socket.send(o.data, o.port, o.address, (error) => { if (error) errors++; });
      }
    }
  };

  const openOne = (port) => new Promise((resolve, reject) => {
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: false });
    socket.once('error', reject);
    socket.on('message', (data, from) => sendAll(core.receive(port, from.address, from.port, data, now())));
    socket.bind(port, address, () => {
      socket.removeListener('error', reject);
      socket.on('error', () => { errors++; });
      sockets.set(port, socket);
      resolve();
    });
  });

  const closeAll = () => { for (const s of sockets.values()) s.close(); sockets.clear(); };

  return ports.reduce((chain, port) => chain.then(() => openOne(port)), Promise.resolve())
    .then(() => {
      const ticker = setInterval(() => {
        for (const line of core.tick(now())) log(line);

        if (errors > 0) {
          log(`relay: ${errors} socket errors in the last moments, and the relay goes on`);
          errors = 0;
        }
      }, 1000);

      log(`relay: listening on UDP ${core.controlPort} for control, and ${core.slots.size} ports for joiners`);
      return { stop: () => { clearInterval(ticker); closeAll(); } };
    })
    .catch((error) => {
      closeAll();
      throw new Error(`relay: a UDP port could not be opened (${error.code || 'unknown'}), so the relay did not start`);
    });
}

module.exports = { startRelay };
