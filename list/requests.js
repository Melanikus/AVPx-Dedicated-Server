'use strict';
// What the list accepts from a request, field by field, as PROTOCOL.md section 4 writes it. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
//
// Everything here comes from anyone on the internet (AVP Tao 3: input is hostile). So each function takes what came, checks every byte of
// it against a written limit, and gives back either exactly what it allows or the reason it doesn't, never anything half-checked:
// - a body is at most kMostBodyBytes, and must be a JSON object with only the fields its call names, each of its own type and range;
// - a name, level or mode is 1 to 32 printable ASCII characters (0x20 to 0x7E), so nothing in it can be a line break, a control character
//   or anything a screen or a log could take for something else;
// - a number is a whole number in its range, never a string, a fraction or something huge;
// - a token is exactly 32 hex digits.
// Nothing here writes anything anywhere.

const kMostBodyBytes = 1024;
const kMostTextLength = 32;
const kMostPlayers = 8;
const kMostVersion = 65535;

// A reason a request is refused, with the HTTP status it gets. The words go back to the asker, so they never hold anything it sent.
class Refusal extends Error {
  constructor(status, words) {
    super(words);
    this.status = status;
  }
}

function isPlainText(value) {
  return typeof value === 'string' && value.length >= 1 && value.length <= kMostTextLength && /^[\x20-\x7e]+$/.test(value);
}

function isWhole(value, least, most) {
  return Number.isInteger(value) && value >= least && value <= most;
}

// The body of a POST, PUT or DELETE, from its bytes: a JSON object with exactly the fields named in `fields`, all of them there.
function parseBody(bytes, fields) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > kMostBodyBytes) {
    throw new Refusal(400, 'the body must be JSON, 1 to 1024 bytes');
  }

  // A body must be UTF-8 that decodes cleanly; anything else is refused, not mended
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (e) {
    throw new Refusal(400, 'the body must be UTF-8');
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new Refusal(400, 'the body must be JSON');
  }

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Refusal(400, 'the body must be a JSON object');
  }

  const keys = Object.keys(value);

  if (keys.length !== fields.length || !fields.every((f) => Object.prototype.hasOwnProperty.call(value, f))) {
    throw new Refusal(400, `the body must have exactly these fields: ${fields.join(', ')}`);
  }

  return value;
}

// A room's token, from 32 hex digits, as 16 bytes
function parseToken(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{32}$/.test(value)) {
    throw new Refusal(400, 'token must be 32 hex digits, small letters');
  }

  return Buffer.from(value, 'hex');
}

const kListingFields = ['token', 'name', 'level', 'mode', 'players', 'maxPlayers', 'version'];

// What a POST or PUT may put on the list: { token, listing: { name, level, mode, players, maxPlayers, version } }
function parseListing(bytes) {
  const v = parseBody(bytes, kListingFields);
  const token = parseToken(v.token);

  for (const field of ['name', 'level', 'mode']) {
    if (!isPlainText(v[field])) {
      throw new Refusal(400, `${field} must be 1 to 32 printable ASCII characters`);
    }
  }

  if (!isWhole(v.maxPlayers, 1, kMostPlayers) || !isWhole(v.players, 1, v.maxPlayers)) {
    throw new Refusal(400, 'players and maxPlayers must be whole numbers, 1 to 8, players no more than maxPlayers');
  }

  if (!isWhole(v.version, 1, kMostVersion)) {
    throw new Refusal(400, 'version must be a whole number, 1 to 65535');
  }

  return { token, listing: { name: v.name, level: v.level, mode: v.mode, players: v.players, maxPlayers: v.maxPlayers, version: v.version } };
}

// What a DELETE may end: { token }
function parseEnding(bytes) {
  return { token: parseToken(parseBody(bytes, ['token']).token) };
}

// The one thing a GET's query may say: version=N, the game's network version, 1 to 65535. Anything else in it is refused.
function parseListQuery(query) {
  const match = /^version=([1-9][0-9]{0,4})$/.exec(typeof query === 'string' ? query : '');

  if (!match || !isWhole(Number(match[1]), 1, kMostVersion)) {
    throw new Refusal(400, 'the query must be version=N, N from 1 to 65535');
  }

  return { version: Number(match[1]) };
}

module.exports = { Refusal, parseListing, parseEnding, parseListQuery, kMostBodyBytes, kMostTextLength };
