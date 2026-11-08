'use strict';
// The server's settings, from a JSON file, each one checked against its limits before anything starts. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server.
//
// The file is the machine owner's, not the internet's, but a wrong setting must still stop the server with a plain reason, never start
// it half-right. Every setting is named here with what it may be; a setting the file doesn't name takes its default, and a name this
// doesn't know is refused (it's most likely a typing mistake).
//
//   relayAddress   the address the relay listens on                  an IPv4 address, default "0.0.0.0" (all of the machine's)
//   controlPort    the relay's control port                          1024 to 65535, default 27500
//   relayPorts     the relay's ports for joiners, "first-last"       1024 to 65535, 1 to 4000 of them, default "27501-27564"
//   listAddress    the address the HTTPS list listens on             an IPv4 address, default "0.0.0.0"
//   listPort       the HTTPS list's port                             1 to 65535, default 443
//   certFile       the certificate, with its chain, PEM              a path; required
//   keyFile        its private key, PEM                              a path; required
//   logFile        where the log goes as well as the screen          a path, or "" for the screen only; default ""

const fs = require('fs');
const net = require('net');

const DEFAULTS = {
  relayAddress: '0.0.0.0',
  controlPort: 27500,
  relayPorts: '27501-27564',
  listAddress: '0.0.0.0',
  listPort: 443,
  certFile: null,
  keyFile: null,
  logFile: '',
};
const kMostRelayPorts = 4000;
const kMostSettingsBytes = 16 * 1024;

function refuse(words) {
  throw new Error(`settings: ${words}`);
}

function port(value, name, least) {
  if (!Number.isInteger(value) || value < least || value > 65535) {
    refuse(`${name} must be a whole number from ${least} to 65535`);
  }

  return value;
}

function path(value, name, required) {
  if (value === null || value === undefined || value === '') {
    if (required) refuse(`${name} is required`);
    return '';
  }

  if (typeof value !== 'string' || value.length > 260 || /[\x00-\x1f]/.test(value)) {
    refuse(`${name} must be a path, at most 260 characters`);
  }

  return value;
}

// The settings from a file's text: an object with every setting checked, or it throws with the reason
function parseSettings(text) {
  if (typeof text !== 'string' || text.length > kMostSettingsBytes) {
    refuse('the file must be text, at most 16 KB');
  }

  let given;
  try {
    given = JSON.parse(text);
  } catch (e) {
    refuse('the file must be JSON');
  }

  if (given === null || typeof given !== 'object' || Array.isArray(given)) {
    refuse('the file must be a JSON object');
  }

  for (const name of Object.keys(given)) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULTS, name)) {
      refuse(`there's no setting called ${JSON.stringify(name).slice(0, 40)}`);
    }
  }

  const s = { ...DEFAULTS, ...given };

  for (const name of ['relayAddress', 'listAddress']) {
    if (typeof s[name] !== 'string' || !net.isIPv4(s[name])) {
      refuse(`${name} must be an IPv4 address`);
    }
  }

  const controlPort = port(s.controlPort, 'controlPort', 1024);
  const listPort = port(s.listPort, 'listPort', 1);
  const range = typeof s.relayPorts === 'string' ? /^([0-9]{4,5})-([0-9]{4,5})$/.exec(s.relayPorts) : null;

  if (!range) {
    refuse('relayPorts must be "first-last", such as "27501-27564"');
  }

  const first = port(Number(range[1]), 'relayPorts\' first', 1024);
  const last = port(Number(range[2]), 'relayPorts\' last', 1024);

  if (last < first || last - first + 1 > kMostRelayPorts) {
    refuse(`relayPorts must go up, and be at most ${kMostRelayPorts} ports`);
  }

  if (controlPort >= first && controlPort <= last) {
    refuse('controlPort must not be one of relayPorts');
  }

  const relayPorts = [];
  for (let p = first; p <= last; p++) relayPorts.push(p);

  return {
    relayAddress: s.relayAddress,
    controlPort,
    relayPorts,
    listAddress: s.listAddress,
    listPort,
    certFile: path(s.certFile, 'certFile', true),
    keyFile: path(s.keyFile, 'keyFile', true),
    logFile: path(s.logFile, 'logFile', false),
  };
}

function readSettings(file) {
  return parseSettings(fs.readFileSync(file, 'utf8'));
}

module.exports = { parseSettings, readSettings, DEFAULTS };
