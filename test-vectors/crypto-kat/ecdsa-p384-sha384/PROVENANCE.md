# Where the ECDSA on P-384 with SHA-384 cases come from

**The standard:** FIPS 186-4 (ECDSA); IEEE P1363 (the r || s form CRYPTO.md section 12 sends).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. tools/make-crypto-kat.js does it, and run on the same sources it makes these files again, byte for byte.

## nist-cavp-sigver.json (15 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip, the file 186-4ecdsatestvectors/SigVer.rsp inside it.
- **The zip:** SHA-256 fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752, 1144603 bytes.
- **SigVer.rsp:** SHA-256 e9841c3d12e323042751460d0b8ef4bc59c2640105ec7da4852775f80ab10191, 730106 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The [P-384,SHA-384] section, with R and S written as r || s, 48 bytes each. (PO found no FIPS 186-5 set at that place; this is the 186-4 one.)

## nist-cavp-siggen.json (15 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip, the file 186-4ecdsatestvectors/SigGen.txt inside it.
- **The zip:** SHA-256 fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752, 1144603 bytes.
- **SigGen.txt:** SHA-256 95d0a19c03f6d2dc16e9e18fd5c3318e1952e0bc88a45127c996c35b4a15f4e2, 616267 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The [P-384,SHA-384] section of the .txt file, which gives each signature's k.

## wycheproof-p1363.json (280 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json, SHA-256 e27344bf6daae75fa19663620883809f91c79fc4b4420eff9eae8036b34476be, 283550 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case, with each group's public key written uncompressed.
