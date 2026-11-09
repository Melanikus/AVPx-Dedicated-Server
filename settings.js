'use strict';
// The server's settings, from a JSON file, each one checked against its limits before anything starts. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server.
//
// The file is the machine owner's, not the internet's, but a wrong setting must still stop the server with a plain reason, never start
// it half-right. Every setting is named here with what it may be; a setting the file doesn't name takes its default, and a name this
// doesn't know is refused (it's most likely a typing mistake).
//
// Every machine runs the same code, and every machine runs a relay. The settings say which region its relay is, and whether this machine
// runs the list too ("list" there) or not (no "list"). PROTOCOL.md says what a region and a pass key are.
//
//   region         this relay's region name                          1 to 16 small letters, digits and -, such as "virginia"; required
//   passKey        this relay's pass key, as 64 hex digits           32 random bytes (openssl rand -hex 32); required, never all 0
//   relayAddress   the address the relay listens on                  an IPv4 address, default "0.0.0.0" (all of the machine's)
//   controlPort    the relay's control port                          1024 to 65535, default 27500
//   relayPorts     the relay's ports for joiners, "first-last"       1024 to 65535, 1 to 4000 of them, default "27501-27564"
//   logFile        where the log goes as well as the screen          a path, or "" for the screen only; default ""
//   list           the list, if this machine runs it                 an object, below; leave it out on a machine that doesn't
//
// The list:
//   address        the address the HTTPS list listens on             an IPv4 address, default "0.0.0.0"
//   port           the HTTPS list's port                             1 to 65535, default 443
//   certFile       the certificate, with its chain, PEM              a path; required
//   keyFile        its private key, PEM                              a path; required
//   relays         every relay the list knows, 1 to 16 of them:      required, and must name this machine's own region
//                  { region, host (its DNS name, never an address), port (its control port), passKey (that relay's pass key) }.
//                  This machine's own relay leaves passKey out: it's the passKey above, so the one secret is written once.
//
// The file holds pass keys, so it's readable only by root and the server's own user (deploy/README.md).

const fs = require('fs');
const net = require('net');
const { isRegion, kPassKeyBytes } = require('./relay/pass');

const DEFAULTS = {
  region: null,
  passKey: null,
  relayAddress: '0.0.0.0',
  controlPort: 27500,
  relayPorts: '27501-27564',
  logFile: '',
  list: null,
};
const LIST_DEFAULTS = {
  address: '0.0.0.0',
  port: 443,
  certFile: null,
  keyFile: null,
  relays: null,
};
const kMostRelayPorts = 4000;
const kMostRelays = 16;
const kMostHostLength = 63;
const kMostSettingsBytes = 16 * 1024;

function refuse(words) {
  throw new Error(`settings: ${words}`);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Refuses any name in `given` that `known` doesn't have
function onlyKnown(given, known, where) {
  for (const name of Object.keys(given)) {
    if (!Object.prototype.hasOwnProperty.call(known, name)) {
      refuse(`there's no setting called ${JSON.stringify(name).slice(0, 40)}${where}`);
    }
  }
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

function region(value, name) {
  if (!isRegion(value)) {
    refuse(`${name} must be 1 to 16 small letters, digits and -`);
  }

  return value;
}

// A pass key from its 64 hex digits, as 32 bytes. All zeros is refused: it's what a key left unset would look like.
function passKey(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) || /^0+$/.test(value)) {
    refuse(`${name} must be 64 hex digits, small letters, made at random (openssl rand -hex 32)`);
  }

  const key = Buffer.from(value, 'hex');
  return key.length === kPassKeyBytes ? key : refuse(`${name} must be 32 bytes`);
}

// A relay's DNS name, never an address, so a relay can move to another machine without a game update: letters, digits and -, in parts
// joined by dots, and the last part starts with a letter. No real top-level domain starts with a digit, while every way of writing an
// IPv4 address ends in a number (1.2.3.4, and forms some resolvers also take as addresses, such as 0x7f.0.0.1), so this refuses them
// all, and IPv6 has colons, which no name has.
function host(value, name) {
  if (typeof value !== 'string' || value.length > kMostHostLength || !/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/.test(value) ||
      !/(^|\.)[A-Za-z][A-Za-z0-9-]*$/.test(value)) {
    refuse(`${name} must be a DNS name, 1 to ${kMostHostLength} characters, not an address`);
  }

  return value;
}

function parseList(given, ownRegion, ownKey) {
  if (!isObject(given)) {
    refuse('list must be an object, or left out');
  }

  onlyKnown(given, LIST_DEFAULTS, ' in list');
  const s = { ...LIST_DEFAULTS, ...given };

  if (typeof s.address !== 'string' || !net.isIPv4(s.address)) {
    refuse('list.address must be an IPv4 address');
  }

  if (!Array.isArray(s.relays) || s.relays.length < 1 || s.relays.length > kMostRelays) {
    refuse(`list.relays must be a list of 1 to ${kMostRelays} relays`);
  }

  const relays = s.relays.map((r, k) => {
    const where = `list.relays[${k}]`;

    if (!isObject(r)) {
      refuse(`${where} must be an object`);
    }

    onlyKnown(r, { region: 0, host: 0, port: 0, passKey: 0 }, ` in ${where}`);
    const itsRegion = region(r.region, `${where}.region`);
    const own = itsRegion === ownRegion;

    if (own && r.passKey !== undefined) {
      refuse(`${where} is this machine's own relay, so it leaves passKey out (it's the passKey above)`);
    }

    return {
      region: itsRegion,
      host: host(r.host, `${where}.host`),
      port: port(r.port, `${where}.port`, 1),
      passKey: own ? ownKey : passKey(r.passKey, `${where}.passKey`),
    };
  });

  if (new Set(relays.map((r) => r.region)).size !== relays.length) {
    refuse('list.relays must name each region once');
  }

  if (!relays.some((r) => r.region === ownRegion)) {
    refuse('list.relays must name this machine\'s own region, or its own games could not be listed');
  }

  return {
    address: s.address,
    port: port(s.port, 'list.port', 1),
    certFile: path(s.certFile, 'list.certFile', true),
    keyFile: path(s.keyFile, 'list.keyFile', true),
    relays,
  };
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

  if (!isObject(given)) {
    refuse('the file must be a JSON object');
  }

  onlyKnown(given, DEFAULTS, '');
  const s = { ...DEFAULTS, ...given };
  const ownRegion = region(s.region, 'region');
  const ownKey = passKey(s.passKey, 'passKey');

  if (typeof s.relayAddress !== 'string' || !net.isIPv4(s.relayAddress)) {
    refuse('relayAddress must be an IPv4 address');
  }

  const controlPort = port(s.controlPort, 'controlPort', 1024);
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
    region: ownRegion,
    passKey: ownKey,
    relayAddress: s.relayAddress,
    controlPort,
    relayPorts,
    logFile: path(s.logFile, 'logFile', false),
    list: s.list === null ? null : parseList(s.list, ownRegion, ownKey),
  };
}

function readSettings(file) {
  return parseSettings(fs.readFileSync(file, 'utf8'));
}

module.exports = { parseSettings, readSettings, DEFAULTS, LIST_DEFAULTS, kMostRelays };
