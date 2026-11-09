'use strict';
// A JSON reader for the list's request bodies that takes less than JSON allows, on purpose. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server.
//
// WHY NOT JSON.parse: it takes things no honest game sends, and takes some of them in a way another reader wouldn't. A body with the
// same key twice is the worst of these: JSON.parse keeps the last, other readers keep the first, and two programs that read one body
// two ways can be made to disagree about what it said. So the list reads bodies with this, and so must every other server that speaks
// PROTOCOL.md, so they all refuse exactly the same bodies (section 4, "How a body is read").
//
// WHAT IT TAKES, and nothing else:
// - one object, { ... }, with whitespace (space, tab, CR, LF) allowed between its parts and around it;
// - keys and values that are strings or whole numbers: no objects or lists inside it, no true, false or null;
// - a string: printable ASCII (0x20 to 0x7E), with \" and \\ as its only escapes;
// - a whole number: 0, or 1 to 16 digits not starting with 0, at most 9,007,199,254,740,991 (the most a JavaScript number holds
//   exactly); no sign, no fraction, no exponent;
// - no key twice.
// Every byte is looked at once, from the start; nothing is ever an index from the body, so a body can't make this read past its end.
//
// readObject(bytes) gives back an object with no prototype (so a key "__proto__" is just a key), or null for anything not taken.

const kMostDigits = 16;

function isSpace(b) {
  return b === 0x20 || b === 0x09 || b === 0x0d || b === 0x0a;
}

function readObject(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    return null;
  }

  let at = 0;
  const end = bytes.length;
  const skip = () => { while (at < end && isSpace(bytes[at])) at++; };

  // A string, from its opening " to its closing one; null if it breaks a rule
  const string = () => {
    if (bytes[at] !== 0x22) return null;
    at++;
    let out = '';

    while (at < end) {
      const b = bytes[at++];

      if (b === 0x22) {
        return out;
      }

      if (b === 0x5c) {
        const next = at < end ? bytes[at++] : -1;
        if (next !== 0x22 && next !== 0x5c) return null;
        out += String.fromCharCode(next);
      } else if (b >= 0x20 && b <= 0x7e) {
        out += String.fromCharCode(b);
      } else {
        return null;
      }
    }

    return null;
  };

  // A whole number; null if it breaks a rule
  const number = () => {
    const start = at;
    while (at < end && bytes[at] >= 0x30 && bytes[at] <= 0x39) at++;
    const digits = at - start;

    if (digits === 0 || digits > kMostDigits || (digits > 1 && bytes[start] === 0x30)) {
      return null;
    }

    const value = Number(bytes.toString('latin1', start, at));
    return Number.isSafeInteger(value) ? value : null;
  };

  skip();
  if (bytes[at] !== 0x7b) return null;
  at++;
  skip();

  const out = Object.create(null);
  const seen = new Set();

  if (bytes[at] === 0x7d) {
    at++;
  } else {
    for (;;) {
      skip();
      const key = string();
      if (key === null || seen.has(key)) return null;
      seen.add(key);
      skip();
      if (bytes[at] !== 0x3a) return null;
      at++;
      skip();

      const value = bytes[at] === 0x22 ? string() : number();
      if (value === null) return null;
      out[key] = value;
      skip();

      if (bytes[at] === 0x2c) {
        at++;
        continue;
      }

      if (bytes[at] === 0x7d) {
        at++;
        break;
      }

      return null;
    }
  }

  skip();
  return at === end ? out : null;
}

module.exports = { readObject };
