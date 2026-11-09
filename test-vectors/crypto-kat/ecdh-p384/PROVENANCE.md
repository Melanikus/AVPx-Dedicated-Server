# Where the ECDH on P-384 cases come from

**The standard:** NIST SP 800-56A rev 3 (the ECC CDH primitive); FIPS 186-4 (the public key check).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. java/tools/MakeCryptoKat.java makes the files, from the sources put in crypto-kat-sources/ beside the repository's top folder, after checking each one's SHA-256 against the ones below. Run again on them, it makes these files byte for byte.

**Checked when first made (2026-11-09):** 826 classical cases, each redone with OpenSSL (through Node's crypto), 0 wrong (the one "acceptable" case wasn't checked, as either answer is right); every invalid point is refused. That check was a one-off script and isn't in the repository; the readers' own tests are the check from now on.

## nist-cavp.json (25 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/ecccdhtestvectors.zip, the file KAS_ECC_CDH_PrimitiveTest.txt inside it.
- **The zip:** SHA-256 5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39, 113523 bytes.
- **KAS_ECC_CDH_PrimitiveTest.txt:** SHA-256 456068d3f8aad8ac62a03d19ed3173f00ad51f42b51aeab4753c20f30c01cf23, 216962 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The [P-384] section. The points are written uncompressed (04, X, Y), each coordinate 48 bytes.

## nist-cavp-pkv.json (12 cases)

- **Source:** NIST CAVP, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip, the file 186-4ecdsatestvectors/PKV.rsp inside it.
- **The zip:** SHA-256 fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752, 1144603 bytes.
- **PKV.rsp:** SHA-256 1d33551c1a199b1fc2b0e4075cdfd52d4830503ef37e6b16f04ce617d524f3f1, 38511 bytes.
- **NIST's page for it:** https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105).
- **Taken:** The [P-384] section: points to accept or refuse.

## wycheproof-ecpoint.json (790 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/ecdh_secp384r1_ecpoint_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdh_secp384r1_ecpoint_test.json, SHA-256 ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3, 549253 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case: the other side's point as X9.62 bytes, invalid and off-curve ones included.

## wycheproof-der.json (1047 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/ecdh_secp384r1_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/ecdh_secp384r1_test.json, SHA-256 25a9c41573dbea97c5b4be2dd00369fa68dc37ac8f41807d8e16226d188ec6a7, 817540 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case: the other side's key as DER SubjectPublicKeyInfo.
