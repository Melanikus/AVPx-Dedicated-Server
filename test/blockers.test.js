'use strict';
// The tests of tools/check-blockers.js: a deploy may go on only when SERVER-BLOCKERS.md says "Nothing.", and every other shape of the
// file refuses. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { readBlockers, kFile } = require('../tools/check-blockers');

const file = (list, end = 'End of the list.') => `# What blocks\n\nSome words.\n\n## Blocking a deploy\n\n${list}\n\n${end}\n`;

test('the file as it is today refuses a deploy, and names what blocks', () => {
  const r = readBlockers(fs.readFileSync(kFile, 'utf8'));
  assert.strictEqual(r.clear, false);
  assert.ok(r.items.length >= 5, `${r.items.length} lines listed`);
});

test('only "Nothing." under the heading lets a deploy go on', () => {
  assert.strictEqual(readBlockers(file('Nothing.')).clear, true);
  assert.strictEqual(readBlockers(file('Nothing.').replace(/\n/g, '\r\n')).clear, true, 'Windows line ends too');
});

test('every other shape refuses', () => {
  const refused = (text, why) => assert.strictEqual(readBlockers(text).clear, false, why);
  refused(null, 'no file');
  refused('', 'an empty file');
  refused(file(''), 'an empty list');
  refused(file('1. Something to do.'), 'something listed');
  refused(file('Nothing.\n1. Something to do.'), '"Nothing." with something else');
  refused(file('nothing.'), '"nothing." in small letters');
  refused(file('Nothing'), '"Nothing" with no full stop');
  refused(file('Nothing. Really.'), '"Nothing." with more on its line');
  refused(file('Nothing.', ''), 'cut short: no last line');
  refused(file('Nothing.', 'End of the'), 'cut short in the last line');
  refused(file('Nothing.').replace('## Blocking a deploy', '## Blocking'), 'no heading');
  // The heading twice would be refused anyway (the second lands inside the list), so what's checked is that the reason says so plainly
  const twice = readBlockers(file('Nothing.').replace('Some words.', '## Blocking a deploy\n\nNothing.'));
  assert.strictEqual(twice.clear, false, 'the heading twice');
  assert.match(twice.why, /exactly once/, 'and the reason names it');
  refused(`# What blocks\n\nNothing.\n\nEnd of the list.\n`, '"Nothing." but not under the heading');
});
