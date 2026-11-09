# Where the ML-KEM-1024 cases come from

**The standard:** FIPS 203 (ML-KEM).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. tools/make-crypto-kat.js does it, and run on the same sources it makes these files again, byte for byte.

## nist-acvp-keygen.json (25 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/ML-KEM-keyGen-FIPS203/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json, SHA-256 3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523, 16066 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json, SHA-256 a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4, 544032 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The ML-KEM-1024 group.

## nist-acvp-encapdecap.json (55 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/ML-KEM-encapDecap-FIPS203/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json, SHA-256 998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91, 624189 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json, SHA-256 9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf, 190940 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The ML-KEM-1024 groups: encapsulation, decapsulation, and the two key checks.

## wycheproof-keygen-seed.json (100 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/mlkem_1024_keygen_seed_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mlkem_1024_keygen_seed_test.json, SHA-256 cd9241bf5d65a78e005866ea2c660615c17f50caa9afc2b96fd1573cc65617b5, 980689 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.

## wycheproof-encaps.json (269 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/mlkem_1024_encaps_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mlkem_1024_encaps_test.json, SHA-256 da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e, 1323251 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.

## wycheproof-decaps.json (202 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/mlkem_1024_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mlkem_1024_test.json, SHA-256 17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a, 1269556 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.

## wycheproof-decaps-checked.json (9 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json, SHA-256 a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c, 117386 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.
