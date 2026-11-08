'use strict';
// The server's log: each line on the screen, with the time, and in a file if one is set, which is kept to a size. Written 2026-11-08 by
// Melanikus for AVPx Dedicated Server.
//
// What goes in it is decided where each line is made, and none of those lines ever holds an address, a code, a token or a name (the
// user's ruling: no IPs). This only adds the time, and keeps the file from growing without end: past kMostFileBytes it's moved to
// <file>.1 (and .1 to .2, up to kOldFiles), and a new one started.

const fs = require('fs');

const kMostFileBytes = 10 * 1024 * 1024;
const kOldFiles = 3;

function makeLog(file = '', now = () => new Date()) {
  let size = 0;

  if (file) {
    try {
      size = fs.statSync(file).size;
    } catch (e) {
      size = 0;
    }
  }

  const turnOver = () => {
    for (let i = kOldFiles - 1; i >= 1; i--) {
      try { fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`); } catch (e) { /* not there yet */ }
    }

    try { fs.renameSync(file, `${file}.1`); } catch (e) { /* not there yet */ }
    size = 0;
  };

  return (line) => {
    const text = `${now().toISOString()} ${String(line).replace(/[\r\n]/g, ' ')}\n`;
    process.stdout.write(text);

    if (!file) {
      return;
    }

    try {
      if (size + text.length > kMostFileBytes) {
        turnOver();
      }

      fs.appendFileSync(file, text);
      size += text.length;
    } catch (e) {
      process.stdout.write(`${now().toISOString()} log: the log file could not be written (${e.code || 'unknown'}); lines go to the screen only\n`);
    }
  };
}

module.exports = { makeLog, kMostFileBytes };
