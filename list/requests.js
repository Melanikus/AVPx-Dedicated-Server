'use strict';
// What the list accepts from a request, field by field, as PROTOCOL.md section 4 writes it. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
//
// Everything here comes from anyone on the internet (AVP Tao 3: input is hostile). So each function takes what came, checks every byte of
// it against a written limit, and gives back either exactly what it allows or the reason it doesn't, never anything half-checked:
// - a body is at most kMostBodyBytes, and must be a JSON object with only the fields its call names, each of its own type and range;
// - a name or mode is 1 to 32 printable ASCII characters (0x20 to 0x7E), and a level's name 1 to 39, so nothing in it can be a line break,
//   a control character or anything a screen or a log could take for something else;
// - a number is a whole number in its range, never a string, a fraction or something huge;
// - a pass and an owner key are exactly 32 hex digits, a code exactly 8 code letters, a region a region name (relay/pass.js).
// Nothing here writes anything anywhere.

const { kCodeLetters } = require('../relay/protocol');
const { isRegion } = require('../relay/pass');
const { readObject } = require('./strict-json');

const kMostBodyBytes = 1024;
const kMostTextLength = 32;
const kMostLevelLength = 39;          // the game's own level names go to kLevelNameSize - 1 (networking.h)
const kMostPlayers = 8;
const kMostVersion = 65535;
const kMostGameStyle = 255;           // the game's NGT_ numbers
const kMostLevelNumber = 100;         // 0 to 99 a stock level, 100 a custom one
const kMostCoopLobby = 255;           // coop_lobby.h's states
const kMostHostMilliseconds = 9999;   // 0 means the host didn't measure it

// A reason a request is refused, with the HTTP status it gets. The words go back to the asker, so they never hold anything it sent.
class Refusal extends Error {
  constructor(status, words) {
    super(words);
    this.status = status;
  }
}

// Every string a body holds is already printable ASCII (0x20 to 0x7E): strict-json.js takes no other byte, so that rule lives there,
// once, and this checks only the length
function isPlainText(value, most = kMostTextLength) {
  return typeof value === 'string' && value.length >= 1 && value.length <= most;
}

function isWhole(value, least, most) {
  return Number.isInteger(value) && value >= least && value <= most;
}

// The body of a POST, PUT or DELETE, from its bytes: a JSON object with exactly the fields named in `fields`, all of them there.
function parseBody(bytes, fields) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > kMostBodyBytes) {
    throw new Refusal(400, 'the body must be JSON, 1 to 1024 bytes');
  }

  // Read with strict-json.js, not JSON.parse: one flat object of strings and whole numbers, printable ASCII, no key twice (PROTOCOL.md
  // section 4, "How a body is read"). It gives back an object with no prototype, so a key "__proto__" is only a key.
  const value = readObject(bytes);

  if (value === null) {
    throw new Refusal(400, 'the body must be one JSON object of strings and whole numbers, as PROTOCOL.md section 4 writes it');
  }

  const keys = Object.keys(value);

  if (keys.length !== fields.length || !fields.every((f) => Object.prototype.hasOwnProperty.call(value, f))) {
    throw new Refusal(400, `the body must have exactly these fields: ${fields.join(', ')}`);
  }

  return value;
}

// 16 bytes written as 32 hex digits, small letters (a pass, or an owner key), as bytes
function parseHex16(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) {
    throw new Refusal(400, `${name} must be 32 hex digits, small letters`);
  }

  return Buffer.from(value, 'hex');
}

function checkRegion(value) {
  if (!isRegion(value)) {
    throw new Refusal(400, 'region must be 1 to 16 small letters, digits and -');
  }

  return value;
}

function checkCode(value) {
  if (typeof value !== 'string' || value.length !== 8 || ![...value].every((c) => kCodeLetters.includes(c))) {
    throw new Refusal(400, 'code must be 8 code letters');
  }

  return value;
}

const kListingFields = ['region', 'code', 'pass', 'passTime', 'name', 'level', 'mode', 'gameStyle', 'levelNumber', 'coopLobby', 'players', 'maxPlayers', 'version', 'hostMs'];

// What a POST (or, with withOwner, a PUT) may put on the list: { owner (PUT only), pass, listing: { region, code, passTime, name, level,
// mode, gameStyle, levelNumber, coopLobby, players, maxPlayers, version, hostMs } }. Only the pass's shape is checked here: whether it's
// good is listings.js's to say, which has the relays' keys.
function parseListing(bytes, withOwner = false) {
  const v = parseBody(bytes, withOwner ? ['owner', ...kListingFields] : kListingFields);
  const owner = withOwner ? parseHex16(v.owner, 'owner') : null;
  const region = checkRegion(v.region);
  const code = checkCode(v.code);
  const pass = parseHex16(v.pass, 'pass');

  if (!isWhole(v.passTime, 0, Number.MAX_SAFE_INTEGER)) {
    throw new Refusal(400, 'passTime must be a whole number of seconds');
  }

  if (!isPlainText(v.level, kMostLevelLength)) {
    throw new Refusal(400, `level must be 1 to ${kMostLevelLength} printable ASCII characters`);
  }

  for (const field of ['name', 'mode']) {
    if (!isPlainText(v[field])) {
      throw new Refusal(400, `${field} must be 1 to 32 printable ASCII characters`);
    }
  }

  if (!isWhole(v.maxPlayers, 1, kMostPlayers) || !isWhole(v.players, 1, v.maxPlayers)) {
    throw new Refusal(400, 'players and maxPlayers must be whole numbers, 1 to 8, players no more than maxPlayers');
  }

  if (!isWhole(v.gameStyle, 0, kMostGameStyle) || !isWhole(v.levelNumber, 0, kMostLevelNumber) || !isWhole(v.coopLobby, 0, kMostCoopLobby)) {
    throw new Refusal(400, 'gameStyle must be 0 to 255, levelNumber 0 to 100 and coopLobby 0 to 255, whole numbers');
  }

  if (!isWhole(v.version, 1, kMostVersion)) {
    throw new Refusal(400, 'version must be a whole number, 1 to 65535');
  }

  if (!isWhole(v.hostMs, 0, kMostHostMilliseconds)) {
    throw new Refusal(400, 'hostMs must be a whole number, 0 to 9999');
  }

  return {
    owner,
    pass,
    listing: {
      region, code, passTime: v.passTime, name: v.name, level: v.level, mode: v.mode, gameStyle: v.gameStyle, levelNumber: v.levelNumber,
      coopLobby: v.coopLobby, players: v.players, maxPlayers: v.maxPlayers, version: v.version, hostMs: v.hostMs,
    },
  };
}

// What a DELETE may take down: { region, code, owner }
function parseEnding(bytes) {
  const v = parseBody(bytes, ['region', 'code', 'owner']);
  return { region: checkRegion(v.region), code: checkCode(v.code), owner: parseHex16(v.owner, 'owner') };
}

// A GET has no body
function checkNoBody(body) {
  if (body && body.length) {
    throw new Refusal(400, 'a GET has no body');
  }
}

// The one thing a GET's query may say: version=N, the game's network version, 1 to 65535. Anything else in it is refused.
function parseListQuery(query) {
  const match = /^version=([1-9][0-9]{0,4})$/.exec(typeof query === 'string' ? query : '');

  if (!match || !isWhole(Number(match[1]), 1, kMostVersion)) {
    throw new Refusal(400, 'the query must be version=N, N from 1 to 65535');
  }

  return { version: Number(match[1]) };
}

module.exports = { Refusal, parseListing, parseEnding, parseListQuery, checkNoBody, kMostBodyBytes, kMostTextLength, kMostLevelLength };
