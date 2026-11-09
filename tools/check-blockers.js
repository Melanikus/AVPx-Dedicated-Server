'use strict';
// Refuses a deploy while SERVER-BLOCKERS.md lists anything. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   node tools/check-blockers.js          exits 0 only if the list says "Nothing.", and 1 otherwise, saying why
//   node tools/check-blockers.js --list   says what's listed, and exits 0 (for the gate's report; a deploy never uses this)
//
// Every deploy workflow runs the first form as its first step. What it refuses:
// - a file that isn't there;
// - a file with no "## Blocking a deploy" heading, or with it twice;
// - a file cut short: its last line must be "End of the list.";
// - a list that is empty, or holds anything but the one line "Nothing.".
// Blank lines don't count. test/blockers.test.js checks each of these.

const fs = require('fs');
const path = require('path');

const kFile = path.join(__dirname, '..', 'SERVER-BLOCKERS.md');
const kHeading = '## Blocking a deploy';
const kEnd = 'End of the list.';
const kClear = 'Nothing.';

// What the file's text says: { clear, why, items }. clear is true only when a deploy may go on.
function readBlockers(text) {
  if (typeof text !== 'string') {
    return { clear: false, why: 'there is no SERVER-BLOCKERS.md', items: [] };
  }

  const lines = text.replace(/\r/g, '').split('\n').map((l) => l.trimEnd());
  const headings = lines.filter((l) => l === kHeading).length;

  if (headings !== 1) {
    return { clear: false, why: `the heading "${kHeading}" must be there exactly once (it's there ${headings} times)`, items: [] };
  }

  const filled = lines.filter((l) => l !== '');

  if (filled[filled.length - 1] !== kEnd) {
    return { clear: false, why: `the file is cut short: its last line must be "${kEnd}"`, items: [] };
  }

  const start = lines.indexOf(kHeading) + 1;
  const stop = lines.lastIndexOf(kEnd);
  const items = lines.slice(start, stop).filter((l) => l !== '');

  if (items.length === 0) {
    return { clear: false, why: 'the list is empty: it must say "Nothing." or name what blocks', items };
  }

  if (items.length === 1 && items[0] === kClear) {
    return { clear: true, why: 'nothing blocks a deploy', items: [] };
  }

  return { clear: false, why: `${items.length} lines block a deploy`, items };
}

if (require.main === module) {
  let text;
  try {
    text = fs.readFileSync(kFile, 'utf8');
  } catch (e) {
    text = null;
  }

  const result = readBlockers(text);
  process.stdout.write(`SERVER-BLOCKERS.md: ${result.why}\n`);
  for (const item of result.items) process.stdout.write(`  ${item}\n`);
  process.exitCode = result.clear || process.argv.includes('--list') ? 0 : 1;
}

module.exports = { readBlockers, kFile };
