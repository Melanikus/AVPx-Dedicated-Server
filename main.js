'use strict';
// AVPx Dedicated Server: a relay, and the list if the settings say so, started together. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
//
//   node main.js <settings file>
//
// settings.js says what the file holds. Every machine runs the same code: a relay for its region, and, on the one machine whose settings
// have a "list", the list too. The list never asks the relay anything, even on the same machine: it checks each room's pass with the
// relay's key (relay/pass.js), just as it would for a relay in another country. The relay and the list share one address hasher, so every
// per-address limit is keyed by the same daily secret. The server stops on Ctrl+C, or when the machine asks it to stop.

const { readSettings } = require('./settings');
const { makeLog } = require('./log');
const { RelayCore } = require('./relay/core');
const { startRelay } = require('./relay/sockets');
const { createListServer } = require('./list/https');
const { Listings } = require('./list/listings');

function main(argv) {
  if (argv.length !== 1) {
    process.stdout.write('use: node main.js <settings file>\n');
    return Promise.resolve(2);
  }

  let settings;
  try {
    settings = readSettings(argv[0]);
  } catch (e) {
    process.stdout.write(`${e.message}\n`);
    return Promise.resolve(2);
  }

  const log = makeLog(settings.logFile);
  const core = new RelayCore({ controlPort: settings.controlPort, ports: settings.relayPorts, region: settings.region, passKey: settings.passKey, now: Date.now() });
  log(`server: starting the ${settings.region} relay, version 1 of the relay's messages, ${settings.relayPorts.length} relay ports` +
    `${settings.list ? `, and the list for ${settings.list.relays.length} relays` : ', and no list'}`);

  let list = null;

  if (settings.list) {
    try {
      const listings = new Listings({ relays: settings.list.relays, now: Date.now() });
      list = createListServer({ listings, certFile: settings.list.certFile, keyFile: settings.list.keyFile, log, hasher: core.hasher });
    } catch (e) {
      log(`list: the certificate files could not be used (${e.code || 'unreadable or not a matching pair'}), so the server did not start`);
      return Promise.resolve(1);
    }
  }

  const stopList = () => { if (list) list.stop(); };

  return startRelay({ address: settings.relayAddress, core, log })
    .then((relay) => new Promise((resolve) => {
      if (list) {
        list.server.listen(settings.list.port, settings.list.address, () => log(`list: listening on HTTPS ${settings.list.port}`));
        list.server.on('error', (e) => { log(`list: the HTTPS port could not be used (${e.code || 'unknown'})`); relay.stop(); stopList(); resolve(1); });
      }

      const stop = () => { log('server: stopping'); relay.stop(); stopList(); resolve(0); };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      process.once('SIGBREAK', stop);
    }))
    .catch((e) => { log(e.message); stopList(); return 1; });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}

module.exports = { main };
