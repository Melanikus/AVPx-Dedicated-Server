'use strict';
// Random bytes the tests can repeat. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.

// Random bytes that are the same on every run, so a test can say exactly what it expects: a simple generator started from a seed. Not
// for the relay itself, which uses crypto.randomBytes.
function seededRandom(seed = 1) {
  let s = seed >>> 0;

  return (n) => {
    const out = Buffer.alloc(n);

    for (let i = 0; i < n; i++) {
      s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
      out[i] = s >>> 24;
    }

    return out;
  };
}

module.exports = { seededRandom };
