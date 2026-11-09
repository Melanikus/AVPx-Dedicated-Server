'use strict';
// Checks CODING-STANDARD.md's rules on every file git tracks, and says each one it breaks, by file and line. Written 2026-11-08 by
// Melanikus for AVPx Dedicated Server.
//
//   node tools/check-standard.js        exits 1 if any rule is broken, 0 if none
//
// This file is the one place the words that silence a scanner are listed (rule 6), so it leaves its own text out of rules 3 to 6. So
// does tools/takeouts.json, whose rows put those words into a copy on purpose, to prove this check notices them.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { builtinModules } = require('module');

const root = path.join(__dirname, '..');
const SELF = 'tools/check-standard.js';
const SERVER = /^(relay\/|list\/|main\.js$|settings\.js$|log\.js$)/;

// Rule 6: the words that tell a scanner to look away (written in pieces so this file doesn't trip the code scanners itself)
const SILENCERS = ['eslint' + '-disable', 'code' + 'ql[', 'lg' + 'tm[', 'snyk' + ':ignore', 'deep' + 'code ignore', 'no' + 'semgrep', 'istanbul ' + 'ignore'];
const SILENCER_FILES = /(^|\/)\.(snyk|dcignore|eslintignore)$/;

const problems = [];
const say = (file, line, words) => problems.push(`${file}${line ? `:${line}` : ''}: ${words}`);

// The files git tracks; or, with --walk (tools/takeouts.js runs this on a copy that isn't a git repository), every file in the folder
// but .git's
function trackedFiles() {
  if (!process.argv.includes('--walk')) {
    return execFileSync('git', ['ls-files', '-z'], { cwd: root }).toString('latin1').split('\0').filter(Boolean);
  }

  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
      const rel = dir ? `${dir}/${entry.name}` : entry.name;
      if (entry.name === '.git') continue;
      if (entry.isDirectory()) walk(rel); else out.push(rel);
    }
  };
  walk('');
  return out.sort();
}

function checkFile(file) {
  const bytes = fs.readFileSync(path.join(root, file));

  // Rule 1: every byte ASCII
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] > 0x7e || (bytes[i] < 0x20 && bytes[i] !== 0x0a && bytes[i] !== 0x0d && bytes[i] !== 0x09)) {
      const line = bytes.subarray(0, i).toString('latin1').split('\n').length;
      say(file, line, `rule 1: a byte that isn't printable ASCII (0x${bytes[i].toString(16)})`);
      break;
    }
  }

  if (SILENCER_FILES.test(file)) {
    say(file, 0, 'rule 6: a file that tells a scanner to look away');
  }

  if (file === SELF || file === 'tools/takeouts.json') {
    return;
  }

  const text = bytes.toString('latin1');
  const lines = text.split('\n');

  lines.forEach((line, k) => {
    const n = k + 1;

    for (const word of SILENCERS) {
      if (line.includes(word)) say(file, n, `rule 6: "${word}" tells a scanner to look away`);
    }

    if (!file.endsWith('.js')) {
      return;
    }

    // Rule 3: no code made from text
    if (/(^|[^A-Za-z0-9_.$])eval\s*\(/.test(line) || /new\s+Function\s*\(/.test(line) || /(^|[^A-Za-z0-9_.$])Function\s*\(/.test(line)) {
      say(file, n, 'rule 3: code made from text (eval or Function)');
    }

    // Rule 4: no other programs but from the tools
    if (line.includes('child_process') && !file.startsWith('tools/')) {
      say(file, n, 'rule 4: child_process outside tools/');
    }

    // Rule 5: the server writes only through its log
    if (SERVER.test(file) && /(^|[^A-Za-z0-9_$])console\./.test(line)) {
      say(file, n, 'rule 5: console. in the server\'s own code (use log())');
    }

    // Rule 2: every require is one of Node's own modules, or a file of ours
    for (const m of line.matchAll(/require\(\s*(['"`])([^'"`]*)\1\s*\)/g)) {
      const name = m[2];
      const bare = name.replace(/^node:/, '');
      // Node lists a module that only has a node: name (such as node:test) with its node:, and the rest without
      if (!(name.startsWith('./') || name.startsWith('../') || builtinModules.includes(bare) || builtinModules.includes(name))) {
        say(file, n, `rule 2: require of "${name}", which isn't one of Node's own modules or a file of ours`);
      }
    }
  });

  // Rule 7: every action pinned to a commit
  if (file.startsWith('.github/workflows/')) {
    lines.forEach((line, k) => {
      const m = /^\s*-?\s*uses:\s*([^\s#]+)/.exec(line);
      if (m && !m[1].startsWith('./') && !/@[0-9a-f]{40}$/.test(m[1])) {
        say(file, k + 1, `rule 7: "${m[1]}" isn't pinned to a full commit hash`);
      }
    });
  }
}

function checkPackages(files) {
  if (files.some((f) => f === 'node_modules' || f.startsWith('node_modules/') || f.includes('/node_modules/'))) {
    say('node_modules', 0, 'rule 2: node_modules is tracked');
  }

  if (files.includes('package.json')) {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    for (const kind of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies']) {
      if (pkg[kind] && Object.keys(pkg[kind]).length) say('package.json', 0, `rule 2: it has ${kind}`);
    }
  }

  if (files.includes('package-lock.json')) {
    const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
    const listed = Object.keys(lock.packages || {}).filter((k) => k !== '');
    if (listed.length || (lock.dependencies && Object.keys(lock.dependencies).length)) say('package-lock.json', 0, 'rule 2: it lists packages');
  }
}

const files = trackedFiles();
for (const file of files) checkFile(file);
checkPackages(files);

if (files.length === 0) {
  problems.push('no files were found to check, which would mean nothing was checked');
}

for (const p of problems) process.stdout.write(`${p}\n`);
process.stdout.write(`Checked ${files.length} files against CODING-STANDARD.md: ${problems.length} problems\n`);
process.exitCode = problems.length ? 1 : 0;
