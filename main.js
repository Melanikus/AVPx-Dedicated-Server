'use strict';
// AVPx Dedicated Server: the list and the relay, started together. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
//   node main.js <settings file>
//
// settings.js says what the file holds. The relay and the list share one RelayCore (the list shows its rooms) and one address hasher (so
// every per-address limit is keyed by the same daily secret). The server stops on Ctrl+C, or when the machine asks it to stop.

const { readSettings } = require('./settings');
const { makeLog } = require('./log');
const { RelayCore } = require('./relay/core');
const { startRelay } = require('./relay/sockets');
const { createListServer } = require('./list/https');

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
  const core = new RelayCore({ controlPort: settings.controlPort, ports: settings.relayPorts, now: Date.now() });
  log(`server: starting, version 1 of the relay's messages, ${settings.relayPorts.length} relay ports`);

  let list;
  try {
    list = createListServer({ relay: core, certFile: settings.certFile, keyFile: settings.keyFile, log, hasher: core.hasher });
  } catch (e) {
    log(`list: the certificate files could not be used (${e.code || 'unreadable or not a matching pair'}), so the server did not start`);
    return Promise.resolve(1);
  }

  return startRelay({ address: settings.relayAddress, core, log })
    .then((relay) => new Promise((resolve) => {
      list.server.listen(settings.listPort, settings.listAddress, () => log(`list: listening on HTTPS ${settings.listPort}`));
      list.server.on('error', (e) => { log(`list: the HTTPS port could not be used (${e.code || 'unknown'})`); relay.stop(); list.stop(); resolve(1); });

      const stop = () => { log('server: stopping'); relay.stop(); list.stop(); resolve(0); };
      process.once('SIGINT', stop);
      process.once('SIGTERM', stop);
      process.once('SIGBREAK', stop);
    }))
    .catch((e) => { log(e.message); list.stop(); return 1; });
}

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}

module.exports = { main };
