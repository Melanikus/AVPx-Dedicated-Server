'use strict';
// Makes test-vectors/crypto-kat/: the published known-answer tests for protocol version 2's primitives (CRYPTO.md section 2), taken
// from their sources as they are, kept to the cases v2 uses, and written in one plain JSON shape every reader here can read. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// WHY: a primitive that computes the wrong answer can still look fine in every test we write ourselves, because our tests and our code
// can share the same mistake. A known answer from the people who wrote the standard can't. So the Java server, the Node server and the
// game all check their primitives against these.
//
// WHERE THE CASES COME FROM: two independent sources for each, where both exist, so a bad copy of one shows up against the other:
//   - NIST: CAVP's response files (AES-GCM, ECC CDH, ECDSA) and the ACVP server's JSON (ML-KEM, ML-DSA, HKDF);
//   - Wycheproof (C2SP), which adds cases that must be refused: invalid points, bad signatures, wrong lengths.
// Each folder's PROVENANCE.md says where each file came from, its SHA-256, the commit, the date, the licence and exactly which cases
// were taken. This program never goes online: it reads files someone has already fetched and checked against those SHA-256s.
//
// THE SHAPE, the same in every file, which the servers' strict JSON readers take as it is:
//   { "primitive", "source", "about", "count", "cases": [ { "id", ..., "result" } ] }
//   - every byte string is hex in small letters, "" for none;
//   - every number is a whole number;
//   - "result" is "valid" (the answer must come out exactly so), "invalid" (it must be refused), or, for Wycheproof's ECDH only,
//     "acceptable" (either is allowed);
//   - no true, false or null, and every string is printable ASCII with no escapes but \" and \\.
// Nothing in a case is changed, only written out: the bytes of every key, message and answer are the source's own.
//
// Usage: node tools/make-crypto-kat.js <fetched folder> <folder with the CAVP files unzipped> <out folder>
//   <fetched folder> holds acvp/, wycheproof/ and rfc/; the unzipped folder holds nist-gcm/, nist-ecdh/ and nist-ecdsa/.

const fs = require('fs');
const path = require('path');

const [fetched, unzipped, out] = process.argv.slice(2);

if (!fetched || !unzipped || !out) {
  throw new Error('usage: node tools/make-crypto-kat.js <fetched folder> <unzipped CAVP folder> <out folder>');
}

// ----- Small helpers

// Hex in small letters, checked to be hex: a source with anything else in a byte field is a source to look at, not to guess about
function hex(text, what) {
  const h = String(text === undefined ? '' : text).trim().toLowerCase();

  if (!/^([0-9a-f]{2})*$/.test(h)) {
    throw new Error(`${what}: not whole bytes of hex: ${h.slice(0, 40)}`);
  }

  return h;
}

// A whole number, as the readers want
function whole(n, what) {
  if (!Number.isInteger(n)) {
    throw new Error(`${what}: not a whole number`);
  }

  return n;
}

// Free text from a source (a comment, a reason), kept to printable ASCII so every reader takes it: anything else becomes "?"
function words(text) {
  return String(text || '').replace(/[^\x20-\x7e]/g, '?').replace(/["\\]/g, "'");
}

// A big-endian number in hex, padded on the left to a fixed number of bytes (CAVP sometimes leaves off leading zeros)
function padded(text, bytes, what) {
  const h = hex(text.length % 2 ? '0' + text : text, what);

  if (h.length > bytes * 2) {
    throw new Error(`${what}: longer than ${bytes} bytes`);
  }

  return h.padStart(bytes * 2, '0');
}

function readJson(...parts) {
  return JSON.parse(fs.readFileSync(path.join(...parts), 'utf8'));
}

function write(folder, name, primitive, source, about, cases) {
  const dir = path.join(out, folder);
  fs.mkdirSync(dir, { recursive: true });
  const body = { primitive, source, about, count: cases.length, cases };
  const text = JSON.stringify(body, null, 2) + '\n';

  if (/[^\x0a\x20-\x7e]/.test(text) || /\\u|\\[bfnrt/]/.test(text)) {
    throw new Error(`${folder}/${name}: something isn't printable ASCII, or is escaped other than \\" and \\\\`);
  }

  fs.writeFileSync(path.join(dir, name), text);
  console.log(`${folder}/${name}: ${cases.length} cases`);
}

// CAVP's .rsp and .txt files: "[section]" lines, then blocks of "Name = value" lines. Gives back each block with the sections over it.
function readCavp(file) {
  const blocks = [];
  let sections = {};
  let block = null;

  for (const raw of fs.readFileSync(file, 'latin1').split(/\r?\n/)) {
    const line = raw.trim();

    if (line === '' || line.startsWith('#')) {
      if (block) {
        blocks.push(block);
        block = null;
      }
      continue;
    }

    const section = line.match(/^\[(.+)\]$/);

    if (section) {
      if (block) {
        blocks.push(block);
        block = null;
      }

      const named = section[1].match(/^(\w+)\s*=\s*(.*)$/);

      if (named) {
        sections[named[1]] = named[2];
      } else {
        sections = { name: section[1] };
      }
      continue;
    }

    block = block || { sections: { ...sections }, fields: {} };
    const field = line.match(/^(\w+)\s*=\s*(.*)$/);

    if (field) {
      block.fields[field[1]] = field[2];
    } else {
      block.fields[line] = '';   // a word on its own, as gcmDecrypt's FAIL
    }
  }

  if (block) {
    blocks.push(block);
  }

  return blocks;
}

// ACVP's prompt and expectedResults side by side: each test with its group's settings, and its answer
function readAcvp(folder) {
  const prompt = readJson(fetched, 'acvp', folder, 'prompt.json');
  const expected = readJson(fetched, 'acvp', folder, 'expectedResults.json');
  const answers = new Map();

  for (const g of expected.testGroups) {
    for (const t of g.tests) {
      answers.set(`${g.tgId}/${t.tcId}`, t);
    }
  }

  const tests = [];

  for (const g of prompt.testGroups) {
    for (const t of g.tests) {
      const answer = answers.get(`${g.tgId}/${t.tcId}`);

      if (!answer) {
        throw new Error(`${folder}: no expected result for group ${g.tgId}, test ${t.tcId}`);
      }

      tests.push({ group: g, test: t, answer });
    }
  }

  return tests;
}

const passed = (b, what) => {
  if (b !== true && b !== false) {
    throw new Error(`${what}: testPassed isn't true or false`);
  }
  return b ? 'valid' : 'invalid';
};

// Wycheproof: every test, with its group, and its flags as one string ("Normal,EmptySalt")
function readWycheproof(file) {
  const j = readJson(fetched, 'wycheproof', file);
  const tests = [];

  for (const g of j.testGroups) {
    for (const t of g.tests) {
      if (!['valid', 'invalid', 'acceptable'].includes(t.result)) {
        throw new Error(`${file}: test ${t.tcId} has the result ${t.result}`);
      }

      tests.push({ group: g, test: t, flags: (t.flags || []).map(words).join(',') });
    }
  }

  return tests;
}

// ----- AES-256-GCM: 12-byte IVs and 16-byte tags, as v2 seals with them (CRYPTO.md section 5)

const kGcmIvBits = 96;
const kGcmTagBits = 128;
const ofV2 = (s) => s.Keylen === '256' && s.IVlen === String(kGcmIvBits) && s.Taglen === String(kGcmTagBits);

write('aes-256-gcm', 'nist-cavp-encrypt.json', 'AES-256-GCM', 'NIST CAVP gcmEncryptExtIV256.rsp (SP 800-38D)',
  'Keylen 256, IVlen 96 and Taglen 128 only. Encrypting pt with key, iv and aad gives exactly ct and tag.',
  readCavp(path.join(unzipped, 'nist-gcm', 'gcmEncryptExtIV256.rsp')).filter((b) => ofV2(b.sections)).map((b) => ({
    id: `PTlen ${b.sections.PTlen}, AADlen ${b.sections.AADlen}, Count ${b.fields.Count}`,
    key: hex(b.fields.Key, 'Key'), iv: hex(b.fields.IV, 'IV'), aad: hex(b.fields.AAD, 'AAD'),
    pt: hex(b.fields.PT, 'PT'), ct: hex(b.fields.CT, 'CT'), tag: hex(b.fields.Tag, 'Tag'), result: 'valid',
  })));

write('aes-256-gcm', 'nist-cavp-decrypt.json', 'AES-256-GCM', 'NIST CAVP gcmDecrypt256.rsp (SP 800-38D)',
  'Keylen 256, IVlen 96 and Taglen 128 only. "valid": opening ct with key, iv, aad and tag gives exactly pt. "invalid": the source says FAIL, so opening it must be refused, and no plaintext given out (pt is "").',
  readCavp(path.join(unzipped, 'nist-gcm', 'gcmDecrypt256.rsp')).filter((b) => ofV2(b.sections)).map((b) => {
    const fails = Object.prototype.hasOwnProperty.call(b.fields, 'FAIL');
    return {
      id: `PTlen ${b.sections.PTlen}, AADlen ${b.sections.AADlen}, Count ${b.fields.Count}`,
      key: hex(b.fields.Key, 'Key'), iv: hex(b.fields.IV, 'IV'), aad: hex(b.fields.AAD, 'AAD'),
      ct: hex(b.fields.CT, 'CT'), tag: hex(b.fields.Tag, 'Tag'), pt: fails ? '' : hex(b.fields.PT, 'PT'),
      result: fails ? 'invalid' : 'valid',
    };
  }));

write('aes-256-gcm', 'wycheproof.json', 'AES-256-GCM', 'Wycheproof testvectors_v1/aes_gcm_test.json',
  'keySize 256, ivSize 96 and tagSize 128 only. "valid": sealing msg gives exactly ct and tag, and opening them gives msg. "invalid": opening must be refused.',
  readWycheproof('aes_gcm_test.json').filter(({ group }) => group.keySize === 256 && group.ivSize === kGcmIvBits && group.tagSize === kGcmTagBits)
    .map(({ test, flags }) => ({
      id: `tcId ${test.tcId}`, comment: words(test.comment), flags,
      key: hex(test.key, 'key'), iv: hex(test.iv, 'iv'), aad: hex(test.aad, 'aad'), msg: hex(test.msg, 'msg'),
      ct: hex(test.ct, 'ct'), tag: hex(test.tag, 'tag'), result: test.result,
    })));

// ----- HKDF-SHA-384 (and RFC 5869's own cases, which are SHA-256 and SHA-1, to prove an HKDF written by hand)

write('hkdf-sha384', 'wycheproof.json', 'HKDF-SHA-384', 'Wycheproof testvectors_v1/hkdf_sha384_test.json',
  'Every case. "valid": HKDF-SHA-384(salt, ikm, info) to size bytes gives exactly okm. "invalid": that size must be refused (SizeTooLarge: more than 255 x 48 bytes).',
  readWycheproof('hkdf_sha384_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags,
    ikm: hex(test.ikm, 'ikm'), salt: hex(test.salt, 'salt'), info: hex(test.info, 'info'), size: whole(test.size, 'size'),
    okm: hex(test.okm, 'okm'), result: test.result,
  })));

// ACVP's KDA with HKDF (SP 800-56C rev 2), the SHA2-384 groups. They're written as a key-establishment's derivation, so they're
// turned into plain HKDF's three inputs here, by SP 800-56C's own rules as ACVP's groups state them:
//   - ikm is the shared secret Z, then the auxiliary secret T, since every SHA2-384 group here is "usesHybridSharedSecret" (Z' = Z || T);
//   - salt is the test's salt as given (all zeros when the group's saltMethod is "default");
//   - info is the group's fixedInfoPattern "uPartyInfo||vPartyInfo||l", "concatenation": each party's partyId, then its ephemeralData if
//     it has one, then L in bits as 4 bytes, big-endian.
// Any group of another shape would need its own rule, so it's refused here rather than guessed at.
{
  const cases = [];

  for (const { group, test, answer } of readAcvp('KDA-HKDF-Sp800-56Cr2')) {
    const c = group.kdfConfiguration || {};

    if (c.hmacAlg !== 'SHA2-384') {
      continue;
    }

    if (c.kdfType !== 'hkdf' || c.fixedInfoPattern !== 'uPartyInfo||vPartyInfo||l' || c.fixedInfoEncoding !== 'concatenation' ||
      group.usesHybridSharedSecret !== true || group.multiExpansion !== false) {
      throw new Error(`KDA-HKDF group ${group.tgId}: a shape this doesn't turn into plain HKDF`);
    }

    const p = test.kdfParameter;
    const party = (x) => hex(x.partyId, 'partyId') + (x.ephemeralData ? hex(x.ephemeralData, 'ephemeralData') : '');
    const lBits = whole(p.l, 'l');
    const lBytes = Buffer.alloc(4);
    lBytes.writeUInt32BE(lBits);

    if (lBits % 8) {
      throw new Error(`KDA-HKDF test ${test.tcId}: L isn't whole bytes`);
    }

    const valid = group.testType === 'VAL' ? passed(answer.testPassed, `KDA-HKDF test ${test.tcId}`) : 'valid';
    cases.push({
      id: `tgId ${group.tgId}, tcId ${test.tcId}, ${group.testType}`,
      ikm: hex(p.z, 'z') + hex(p.t, 't'), salt: hex(p.salt, 'salt'),
      info: party(test.fixedInfoPartyU) + party(test.fixedInfoPartyV) + lBytes.toString('hex'),
      size: lBits / 8, okm: hex(group.testType === 'VAL' ? test.dkm : answer.dkm, 'dkm'), result: valid,
    });
  }

  write('hkdf-sha384', 'nist-acvp-kda.json', 'HKDF-SHA-384', 'NIST ACVP KDA-HKDF-Sp800-56Cr2 (SP 800-56C rev 2)',
    'The SHA2-384 groups, written as plain HKDF: ikm = Z || T, salt as given, info = U partyId || U ephemeralData || V partyId || V ephemeralData || L in bits (4 bytes, big-endian). AFT cases are all "valid": HKDF-SHA-384(salt, ikm, info) to size bytes gives exactly okm. VAL cases say whether the okm given is the right one.',
    cases);
}

// RFC 5869's appendix A: its test cases are SHA-256 and SHA-1 (it has none for SHA-384). They prove an HKDF written by hand over HMAC.
{
  // The page breaks go first (a footer, a form feed, the next page's header), so a value split over two pages reads as one
  const text = fs.readFileSync(path.join(fetched, 'rfc', 'rfc5869.txt'), 'latin1').replace(/\r/g, '')
    .replace(/\n+Krawczyk & Eronen[^\n]*\[Page \d+\]\n\f\nRFC 5869[^\n]*\n+/g, '\n');
  // Each test case's heading, then its lines up to the next heading. The table of contents has the same headings, with no "Hash ="
  // after them, so only those with one count.
  const parts = [...text.matchAll(/A\.(\d)\.\s+Test Case (\d+)\n([\s\S]*?)(?=\nA\.\d\.\s+Test Case|\n\S|$)/g)]
    .filter((m) => /Hash\s*=/.test(m[3]));
  const cases = [];

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i][3];
    const take = (name) => {
      // A value can carry on over the next lines, which are only hex, indented
      // (the last of them ends in "(42 octets)", which is taken off below with the rest of the brackets, and can be the last line of the
      // case, with no line end after it)
      const m = part.match(new RegExp(`${name}\\s*=\\s*([^\\n]*(?:\\n\\s+[0-9a-fA-F]+(?:\\s*\\(\\d+ octets\\))?\\s*(?=\\n|$))*)`));
      if (!m) {
        return null;
      }
      return m[1].replace(/\(.*?\)/g, '').replace(/\s+/g, '').replace(/^0x/, '');
    };
    const hash = (part.match(/Hash\s*=\s*(SHA-\d+)/) || [])[1];
    const L = Number((part.match(/L\s*=\s*(\d+)/) || [])[1]);

    if (!hash || !Number.isInteger(L)) {
      throw new Error(`RFC 5869 test case ${i + 1}: no Hash or L`);
    }

    // Case 7's salt is "not provided (defaults to HashLen zero octets)". HMAC pads a short key with zeros, so no salt and HashLen zero
    // bytes give the same PRK: it's written as "", no salt.
    const saltText = /salt\s*=\s*not provided/.test(part) ? '' : take('salt');
    const ikm = take('IKM'), salt = saltText, info = take('info'), prk = take('PRK'), okm = take('OKM');
    cases.push({
      id: `RFC 5869 A.${parts[i][2]}`, hash, ikm: hex(ikm, 'IKM'), salt: hex(salt || '', 'salt'), info: hex(info || '', 'info'),
      size: L, prk: hex(prk, 'PRK'), okm: hex(okm, 'OKM'), result: 'valid',
    });
  }

  write('hkdf-sha384', 'rfc5869.json', 'HKDF (SHA-256 and SHA-1)', 'RFC 5869, appendix A',
    'All seven test cases, each with its hash. Not SHA-384: RFC 5869 has none. HKDF-Extract(salt, ikm) gives exactly prk, and HKDF-Expand(prk, info) to size bytes gives exactly okm.',
    cases);
}

// ----- HMAC-SHA-384

write('hmac-sha384', 'wycheproof.json', 'HMAC-SHA-384', 'Wycheproof testvectors_v1/hmac_sha384_test.json',
  'Every case. tagSize is in bits, and a tag shorter than 384 bits is the full tag cut short. "valid": HMAC-SHA-384(key, msg) gives exactly tag. "invalid": a check of tag must fail.',
  readWycheproof('hmac_sha384_test.json').map(({ group, test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, keySize: whole(group.keySize, 'keySize'), tagSize: whole(group.tagSize, 'tagSize'),
    key: hex(test.key, 'key'), msg: hex(test.msg, 'msg'), tag: hex(test.tag, 'tag'), result: test.result,
  })));

// ----- ECDH on P-384

const kP384Bytes = 48;
const point = (x, y, what) => '04' + padded(x, kP384Bytes, what + ' x') + padded(y, kP384Bytes, what + ' y');

write('ecdh-p384', 'nist-cavp.json', 'ECDH P-384', 'NIST CAVP KAS_ECC_CDH_PrimitiveTest.txt (SP 800-56A), [P-384]',
  'The P-384 section. public is the other side\'s point, uncompressed (04, X, Y, 97 bytes); private is ours, 48 bytes; ourPublic is the point it makes. ECDH(private, public) gives exactly shared, 48 bytes.',
  readCavp(path.join(unzipped, 'nist-ecdh', 'KAS_ECC_CDH_PrimitiveTest.txt')).filter((b) => b.sections.name === 'P-384').map((b) => ({
    id: `COUNT ${b.fields.COUNT}`,
    public: point(b.fields.QCAVSx, b.fields.QCAVSy, 'QCAVS'), private: padded(b.fields.dIUT, kP384Bytes, 'dIUT'),
    ourPublic: point(b.fields.QIUTx, b.fields.QIUTy, 'QIUT'), shared: padded(b.fields.ZIUT, kP384Bytes, 'ZIUT'), result: 'valid',
  })));

// Some of its cases have a coordinate too big for 48 bytes ("out of range"). x and y are kept as the source has them (padded to 48 bytes
// when shorter), and the 97-byte point only where both fit: a point that can't be written in 97 bytes is refused by its length alone.
const atLeast = (text, bytes, what) => {
  const h = hex(text.length % 2 ? '0' + text : text, what);
  return h.length >= bytes * 2 ? h : h.padStart(bytes * 2, '0');
};

write('ecdh-p384', 'nist-cavp-pkv.json', 'P-384 public key check', 'NIST CAVP 186-4 PKV.rsp, [P-384]',
  'The P-384 section. x and y are as the source gives them, at least 48 bytes each; public is (04, X, Y) where both fit in 48 bytes, and "" where one is longer, which can only be refused. "valid": the point is on the curve and may be used. "invalid": it must be refused. reason is the source\'s own words.',
  readCavp(path.join(unzipped, 'nist-ecdsa', 'PKV.rsp')).filter((b) => b.sections.name === 'P-384').map((b, i) => {
    const r = (b.fields.Result || '').trim();
    const x = atLeast(b.fields.Qx, kP384Bytes, 'Qx'), y = atLeast(b.fields.Qy, kP384Bytes, 'Qy');
    const fits = x.length === kP384Bytes * 2 && y.length === kP384Bytes * 2;
    return {
      id: `case ${i + 1}`, x, y, public: fits ? '04' + x + y : '',
      reason: words(r.replace(/^[PF]\s*/, '').replace(/^\(|\)$/g, '').trim()), result: r.startsWith('P') ? 'valid' : 'invalid',
    };
  }));

write('ecdh-p384', 'wycheproof-ecpoint.json', 'ECDH P-384', 'Wycheproof testvectors_v1/ecdh_secp384r1_ecpoint_test.json',
  'Every case. public is the other side\'s point as X9.62 bytes (04 X Y uncompressed, or 02/03 X compressed), as sent; private is ours. "valid": ECDH gives exactly shared. "invalid": the point must be refused (off the curve, the wrong length, a bad encoding). "acceptable": either is allowed (a compressed point, which v2 never sends, so v2 refuses it).',
  readWycheproof('ecdh_secp384r1_ecpoint_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags,
    public: hex(test.public, 'public'), private: hex(test.private, 'private'), shared: hex(test.shared, 'shared'), result: test.result,
  })));

write('ecdh-p384', 'wycheproof-der.json', 'ECDH P-384', 'Wycheproof testvectors_v1/ecdh_secp384r1_test.json',
  'Every case, with the other side\'s key as a DER SubjectPublicKeyInfo, as Java\'s X509EncodedKeySpec reads it. Results as in wycheproof-ecpoint.json.',
  readWycheproof('ecdh_secp384r1_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags,
    publicDer: hex(test.public, 'public'), private: hex(test.private, 'private'), shared: hex(test.shared, 'shared'), result: test.result,
  })));

// ----- ECDSA on P-384 with SHA-384, signatures as r then s (IEEE P1363, 96 bytes), as v2 sends them (CRYPTO.md section 12)

const p1363 = (r, s, what) => padded(r, kP384Bytes, what + ' R') + padded(s, kP384Bytes, what + ' S');
const isP384Sha384 = (b) => b.sections.name === 'P-384,SHA-384';

write('ecdsa-p384-sha384', 'nist-cavp-sigver.json', 'ECDSA P-384 SHA-384', 'NIST CAVP 186-4 SigVer.rsp, [P-384,SHA-384]',
  'The [P-384,SHA-384] section. public is (04, X, Y); sig is r then s, 48 bytes each. "valid": the signature on msg checks. "invalid": it must not. reason is the source\'s own words.',
  readCavp(path.join(unzipped, 'nist-ecdsa', 'SigVer.rsp')).filter(isP384Sha384).map((b, i) => {
    const r = (b.fields.Result || '').trim();
    return {
      id: `case ${i + 1}`, public: point(b.fields.Qx, b.fields.Qy, 'Q'), msg: hex(b.fields.Msg, 'Msg'), sig: p1363(b.fields.R, b.fields.S, 'sig'),
      reason: words(r.replace(/^[PF]\s*/, '').replace(/^\(|\)$/g, '').trim()), result: r.startsWith('P') ? 'valid' : 'invalid',
    };
  }));

write('ecdsa-p384-sha384', 'nist-cavp-siggen.json', 'ECDSA P-384 SHA-384', 'NIST CAVP 186-4 SigGen.txt, [P-384,SHA-384]',
  'The [P-384,SHA-384] section, with the per-signature secret k the source used. Signing msg with private and that k gives exactly sig (r then s); public is the private key\'s point. A signer that picks its own k makes another signature, which must still check.',
  readCavp(path.join(unzipped, 'nist-ecdsa', 'SigGen.txt')).filter(isP384Sha384).map((b, i) => ({
    id: `case ${i + 1}`, private: padded(b.fields.d, kP384Bytes, 'd'), public: point(b.fields.Qx, b.fields.Qy, 'Q'),
    msg: hex(b.fields.Msg, 'Msg'), k: padded(b.fields.k, kP384Bytes, 'k'), sig: p1363(b.fields.R, b.fields.S, 'sig'), result: 'valid',
  })));

write('ecdsa-p384-sha384', 'wycheproof-p1363.json', 'ECDSA P-384 SHA-384', 'Wycheproof testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json',
  'Every case. public is the group\'s key, uncompressed (04, X, Y); sig is r then s as given, which may be the wrong length on purpose. "valid": the signature on msg checks. "invalid": it must not.',
  readWycheproof('ecdsa_secp384r1_sha384_p1363_test.json').map(({ group, test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags,
    public: hex(group.publicKey.uncompressed, 'publicKey'), msg: hex(test.msg, 'msg'), sig: hex(test.sig, 'sig'), result: test.result,
  })));

// ----- ML-KEM-1024 (FIPS 203)

const is1024 = (g) => g.parameterSet === 'ML-KEM-1024';

write('ml-kem-1024', 'nist-acvp-keygen.json', 'ML-KEM-1024', 'NIST ACVP ML-KEM-keyGen-FIPS203',
  'The ML-KEM-1024 group. ML-KEM.KeyGen_internal(d, z) gives exactly ek (1,568 bytes) and dk (3,168 bytes).',
  readAcvp('ML-KEM-keyGen-FIPS203').filter(({ group }) => is1024(group)).map(({ group, test, answer }) => ({
    id: `tgId ${group.tgId}, tcId ${test.tcId}`, d: hex(test.d, 'd'), z: hex(test.z, 'z'), ek: hex(answer.ek, 'ek'), dk: hex(answer.dk, 'dk'), result: 'valid',
  })));

{
  const cases = [];

  for (const { group, test, answer } of readAcvp('ML-KEM-encapDecap-FIPS203').filter(({ group: g }) => is1024(g))) {
    const id = `tgId ${group.tgId}, tcId ${test.tcId}`;

    switch (group.function) {
      case 'encapsulation':
        cases.push({ id, function: 'encapsulation', ek: hex(test.ek, 'ek'), m: hex(test.m, 'm'), c: hex(answer.c, 'c'), k: hex(answer.k, 'k'), result: 'valid' });
        break;
      case 'decapsulation':
        cases.push({ id, function: 'decapsulation', dk: hex(test.dk || group.dk, 'dk'), c: hex(test.c, 'c'), k: hex(answer.k, 'k'), result: 'valid' });
        break;
      case 'encapsulationKeyCheck':
        cases.push({ id, function: 'encapsulationKeyCheck', ek: hex(test.ek, 'ek'), result: passed(answer.testPassed, id) });
        break;
      case 'decapsulationKeyCheck':
        cases.push({ id, function: 'decapsulationKeyCheck', dk: hex(test.dk, 'dk'), result: passed(answer.testPassed, id) });
        break;
      default:
        throw new Error(`ML-KEM-encapDecap: a function this doesn't know: ${group.function}`);
    }
  }

  write('ml-kem-1024', 'nist-acvp-encapdecap.json', 'ML-KEM-1024', 'NIST ACVP ML-KEM-encapDecap-FIPS203',
    'The ML-KEM-1024 groups. "encapsulation": ML-KEM.Encaps_internal(ek, m) gives exactly c and k. "decapsulation": ML-KEM.Decaps(dk, c) gives exactly k (where c was changed, k is the implicit rejection\'s, and is still exactly that). "encapsulationKeyCheck" and "decapsulationKeyCheck": FIPS 203 section 7.2 and 7.3\'s checks; "valid" passes, "invalid" must be refused.',
    cases);
}

write('ml-kem-1024', 'wycheproof-keygen-seed.json', 'ML-KEM-1024', 'Wycheproof testvectors_v1/mlkem_1024_keygen_seed_test.json',
  'Every case. seed is d then z, 32 bytes each; KeyGen from it gives exactly ek and dk.',
  readWycheproof('mlkem_1024_keygen_seed_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, seed: hex(test.seed, 'seed'), ek: hex(test.ek, 'ek'), dk: hex(test.dk, 'dk'), result: test.result,
  })));

write('ml-kem-1024', 'wycheproof-encaps.json', 'ML-KEM-1024', 'Wycheproof testvectors_v1/mlkem_1024_encaps_test.json',
  'Every case. "valid": encapsulating to ek with the randomness m gives exactly c and K. "invalid": ek must be refused (ModulusOverflow: a coefficient past q, FIPS 203 section 7.2), and c and K are "".',
  readWycheproof('mlkem_1024_encaps_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, ek: hex(test.ek, 'ek'), m: hex(test.m, 'm'), c: hex(test.c, 'c'), K: hex(test.K, 'K'), result: test.result,
  })));

write('ml-kem-1024', 'wycheproof-decaps.json', 'ML-KEM-1024', 'Wycheproof testvectors_v1/mlkem_1024_test.json',
  'Every case. KeyGen from seed (d then z) gives ek; decapsulating c with that key gives exactly K, including where c was changed (implicit rejection). "invalid": the case must be refused.',
  readWycheproof('mlkem_1024_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, seed: hex(test.seed, 'seed'), ek: hex(test.ek, 'ek'), c: hex(test.c, 'c'), K: hex(test.K, 'K'), result: test.result,
  })));

write('ml-kem-1024', 'wycheproof-decaps-checked.json', 'ML-KEM-1024', 'Wycheproof testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json',
  'Every case. "valid": decapsulating c with dk gives exactly K. "invalid": dk or c must be refused (the wrong length, or a dk that fails FIPS 203 section 7.3\'s check).',
  readWycheproof('mlkem_1024_semi_expanded_decaps_test.json').map(({ test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, dk: hex(test.dk, 'dk'), c: hex(test.c, 'c'), ek: hex(test.ek, 'ek'), K: hex(test.K, 'K'), result: test.result,
  })));

// ----- ML-DSA-87 (FIPS 204): pure ML-DSA through the external interface, with a context, as v2 signs and checks (CRYPTO.md section 12)

const is87 = (g) => g.parameterSet === 'ML-DSA-87';
// ACVP leaves externalMu out of the external groups, rather than writing false, so "not true" is the test
const pureExternal = (g) => g.signatureInterface === 'external' && g.preHash === 'pure' && g.externalMu !== true;

write('ml-dsa-87', 'nist-acvp-keygen.json', 'ML-DSA-87', 'NIST ACVP ML-DSA-keyGen-FIPS204',
  'The ML-DSA-87 group. ML-DSA.KeyGen_internal(seed) gives exactly pk (2,592 bytes) and sk (4,896 bytes).',
  readAcvp('ML-DSA-keyGen-FIPS204').filter(({ group }) => is87(group)).map(({ group, test, answer }) => ({
    id: `tgId ${group.tgId}, tcId ${test.tcId}`, seed: hex(test.seed, 'seed'), pk: hex(answer.pk, 'pk'), sk: hex(answer.sk, 'sk'), result: 'valid',
  })));

write('ml-dsa-87', 'nist-acvp-sigver.json', 'ML-DSA-87', 'NIST ACVP ML-DSA-sigVer-FIPS204',
  'The ML-DSA-87 groups that are pure ML-DSA through the external interface (ML-DSA.Verify(pk, message, signature, context)). "valid": the signature checks. "invalid": it must not. context may be "" (an empty context).',
  readAcvp('ML-DSA-sigVer-FIPS204').filter(({ group }) => is87(group) && pureExternal(group)).map(({ group, test, answer }) => ({
    id: `tgId ${group.tgId}, tcId ${test.tcId}`, pk: hex(test.pk || group.pk, 'pk'), message: hex(test.message, 'message'),
    context: hex(test.context, 'context'), signature: hex(test.signature, 'signature'), result: passed(answer.testPassed, `sigVer ${test.tcId}`),
  })));

write('ml-dsa-87', 'nist-acvp-siggen.json', 'ML-DSA-87', 'NIST ACVP ML-DSA-sigGen-FIPS204',
  'The ML-DSA-87 groups that are pure ML-DSA through the external interface. ML-DSA.Sign(sk, message, context) gives exactly signature: "deterministic" uses no randomness, and "hedged" uses rnd as given.',
  readAcvp('ML-DSA-sigGen-FIPS204').filter(({ group }) => is87(group) && pureExternal(group)).map(({ group, test, answer }) => ({
    id: `tgId ${group.tgId}, tcId ${test.tcId}`, mode: group.deterministic === true ? 'deterministic' : 'hedged',
    sk: hex(test.sk || group.sk, 'sk'), message: hex(test.message, 'message'), context: hex(test.context, 'context'),
    rnd: group.deterministic === true ? '' : hex(test.rnd, 'rnd'), signature: hex(answer.signature, 'signature'), result: 'valid',
  })));

write('ml-dsa-87', 'wycheproof-verify.json', 'ML-DSA-87', 'Wycheproof testvectors_v1/mldsa_87_verify_test.json',
  'Every case. pk is the group\'s public key (it can be the wrong length on purpose); context is "" where the source gives none. "valid": the signature on msg checks. "invalid": it, or pk, must be refused.',
  readWycheproof('mldsa_87_verify_test.json').map(({ group, test, flags }) => ({
    id: `tcId ${test.tcId}`, comment: words(test.comment), flags, pk: hex(group.publicKey, 'publicKey'), msg: hex(test.msg, 'msg'),
    context: hex(test.ctx || '', 'ctx'), sig: hex(test.sig, 'sig'), result: test.result,
  })));
