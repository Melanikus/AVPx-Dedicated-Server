# Where the AES-256-GCM cases come from

**The standard:** NIST SP 800-38D (GCM and GMAC).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. tools/make-crypto-kat.js does it, and run on the same sources it makes these files again, byte for byte.

## nist-cavp-encrypt.json (375 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip, the file gcmEncryptExtIV256.rsp inside it.
- **The zip:** SHA-256 f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023, 9154174 bytes.
- **gcmEncryptExtIV256.rsp:** SHA-256 4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8, 3182939 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The sections with Keylen 256, IVlen 96 and Taglen 128 (CRYPTO.md section 5: a 12-byte IV and a 16-byte tag).

## nist-cavp-decrypt.json (375 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip, the file gcmDecrypt256.rsp inside it.
- **The zip:** SHA-256 f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023, 9154174 bytes.
- **gcmDecrypt256.rsp:** SHA-256 ed318735a517d5a85c82d2846c23dcf56e57a352fb0f0a163d9e7617a7bd12ad, 3001776 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The same sections. A block with FAIL is "invalid".

## wycheproof.json (66 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/aes_gcm_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/aes_gcm_test.json, SHA-256 985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7, 213177 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** The groups with keySize 256, ivSize 96 and tagSize 128.
