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
  // The file is opened once, for adding to its end, and its size read through that same handle, so the size is the size of the very file
  // being written (looking it up by name could give another file's, if it were swapped between)
  let fd = null;
  let size = 0;

  const open = () => {
    fd = fs.openSync(file, 'a');
    size = fs.fstatSync(fd).size;
  };

  const turnOver = () => {
    fs.closeSync(fd);
    fd = null;

    for (let i = kOldFiles - 1; i >= 1; i--) {
      try { fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`); } catch (e) { /* not there yet */ }
    }

    try { fs.renameSync(file, `${file}.1`); } catch (e) { /* not there yet */ }
    open();
  };

  return (line) => {
    const text = `${now().toISOString()} ${String(line).replace(/[\r\n]/g, ' ')}\n`;
    process.stdout.write(text);

    if (!file) {
      return;
    }

    try {
      if (fd === null) {
        open();
      }

      if (size + text.length > kMostFileBytes) {
        turnOver();
      }

      fs.writeSync(fd, text);
      size += text.length;
    } catch (e) {
      process.stdout.write(`${now().toISOString()} log: the log file could not be written (${e.code || 'unknown'}); lines go to the screen only\n`);
    }
  };
}

module.exports = { makeLog, kMostFileBytes };
