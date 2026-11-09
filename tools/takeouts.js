'use strict';
// Proves the checks can fail: breaks the code one thing at a time, in a copy, and runs the check each row names. Every row must make its
// check fail. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// A test that passes only shows the code does what the test looks for. This shows the tests would notice the code going wrong: each row
// of tools/takeouts.json takes out one thing (a limit, a check, a refusal), and the tests, or the coding-standard check, must fail on it.
//
// Before any row, the unbroken copy must pass, or every row would "fail" for the wrong reason (that happened once while this was being
// written: the copy left out a folder the tests needed).
//
//   node tools/takeouts.js      exits 1 if any row isn't noticed, can't find its text, or the unbroken copy fails
//
// A row is { name, check: "tests" or "standard", file, from, to }. "from" must be in its file exactly once.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
// What the copy holds: the code, its tests, and what the tests read (deploy/ has the example settings test/settings.test.js checks)
const COPY = ['relay', 'list', 'test', 'support', 'tools', 'deploy', '.github', 'main.js', 'settings.js', 'log.js', 'package.json', 'package-lock.json', 'CODING-STANDARD.md'];
const rows = JSON.parse(fs.readFileSync(path.join(__dirname, 'takeouts.json'), 'utf8')).rows;

// No file is checked for and then used: between the two, it could change (CodeQL calls that a file-system race). Each is used once, and
// what happens if it isn't there is caught instead.
function makeCopy() {
  const where = fs.mkdtempSync(path.join(os.tmpdir(), 'avpx-takeouts-'));
  for (const item of COPY) {
    try {
      fs.cpSync(path.join(root, item), path.join(where, item), { recursive: true });
    } catch (e) {
      // An item the repository doesn't have yet (.github, before its workflows) is left out; anything else is a real failure
      if (e.code !== 'ENOENT') throw e;
    }
  }
  return where;
}

// Changes a file through one handle: opened once, read, and written back over itself, so nothing can swap the file between the read
// and the write. change(text) gives the new text, or null to leave it. Gives back 'changed', 'left', or 'no file'.
function editOnce(file, change) {
  let fd;
  try {
    fd = fs.openSync(file, 'r+');
  } catch (e) {
    if (e.code === 'ENOENT') return 'no file';
    throw e;
  }

  try {
    const out = change(fs.readFileSync(fd, 'latin1'));
    if (out === null) return 'left';
    const bytes = Buffer.from(out, 'latin1');
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, bytes, 0, bytes.length, 0);
    return 'changed';
  } finally {
    fs.closeSync(fd);
  }
}

function run(where, check) {
  const args = check === 'standard' ? [path.join(where, 'tools', 'check-standard.js'), '--walk'] : ['--test'];
  return spawnSync(process.execPath, args, { cwd: where, encoding: 'utf8', env: { ...process.env, AVPX_LIVE: '' } }).status === 0;
}

let bad = 0;
const base = makeCopy();
const baseTests = run(base, 'tests');
const baseStandard = run(base, 'standard');
fs.rmSync(base, { recursive: true, force: true });

if (!baseTests || !baseStandard) {
  process.stdout.write(`THE UNBROKEN COPY FAILS (tests ${baseTests ? 'pass' : 'fail'}, standard ${baseStandard ? 'passes' : 'fails'}): nothing below would mean anything\n`);
  process.exit(1);
}

process.stdout.write('the unbroken copy passes its tests and the standard\n');

rows.forEach((row, k) => {
  const where = makeCopy();
  try {
    const file = path.join(where, row.file);

    if (row.from === '') {
      // A row that makes a new file: "to" is all of it. 'wx' makes it only if it isn't there, so a row never writes over a real file.
      fs.mkdirSync(path.dirname(file), { recursive: true });
      try {
        fs.writeFileSync(file, row.to, { encoding: 'latin1', flag: 'wx' });
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        process.stdout.write(`row ${k} CAN'T RUN, its new file is there already: ${row.name}\n`);
        bad++;
        return;
      }
    } else {
      const done = editOnce(file, (text) => {
        const normal = text.replace(/\r/g, '');
        return normal.split(row.from).length === 2 ? normal.replace(row.from, row.to) : null;
      });

      if (done !== 'changed') {
        process.stdout.write(`row ${k} CAN'T RUN, ${done === 'no file' ? 'no such file' : 'its text is not there exactly once'}: ${row.name}\n`);
        bad++;
        return;
      }
    }

    const passed = run(where, row.check);
    if (passed) bad++;
    process.stdout.write(`row ${k} ${passed ? 'NOT NOTICED' : 'noticed'} (${row.check}): ${row.name}\n`);
  } finally {
    fs.rmSync(where, { recursive: true, force: true });
  }
});

process.stdout.write(`${rows.length} rows, ${bad} not noticed or not run\n`);
process.exitCode = bad ? 1 : 0;
