'use strict';
// The test that tools/takeouts.json is what tools/make-takeouts.js makes, so a row is never changed in one and not the other. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// It reads no file a take-out row breaks (the rows are fixed text in make-takeouts.js), so it never fails in a take-out copy for the wrong
// reason and can't hide a row that the other tests don't notice. Whether each row's text is in its file is checked by
// make-takeouts.js when it's run, and again by tools/takeouts.js.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const { text, rows, kFile } = require('../tools/make-takeouts');

test('tools/takeouts.json is what tools/make-takeouts.js makes (run node tools/make-takeouts.js after changing a row)', () => {
  assert.strictEqual(fs.readFileSync(kFile, 'latin1').replace(/\r/g, ''), text());
});

test('every row is whole: a name, a check that exists, a file, and text to put in', () => {
  const names = new Set();
  for (const row of rows) {
    assert.ok(typeof row.name === 'string' && row.name.length > 0 && !names.has(row.name), `a name, once: ${row.name}`);
    names.add(row.name);
    assert.ok(row.check === 'tests' || row.check === 'standard' || row.check === 'live', row.name);
    assert.ok(typeof row.file === 'string' && row.file.length > 0 && !row.file.startsWith('/') && !row.file.includes('..'), `a file inside the copy: ${row.name}`);
    assert.ok(typeof row.from === 'string' && typeof row.to === 'string' && row.from !== row.to, `a change: ${row.name}`);
  }
});
