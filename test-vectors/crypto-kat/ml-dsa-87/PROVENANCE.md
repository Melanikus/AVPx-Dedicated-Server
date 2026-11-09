# Where the ML-DSA-87 cases come from

**The standard:** FIPS 204 (ML-DSA).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. tools/make-crypto-kat.js does it, and run on the same sources it makes these files again, byte for byte.

## nist-acvp-keygen.json (25 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/ML-DSA-keyGen-FIPS204/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json, SHA-256 43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef, 10062 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json, SHA-256 361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df, 873632 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The ML-DSA-87 group.

## nist-acvp-sigver.json (15 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/ML-DSA-sigVer-FIPS204/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json, SHA-256 e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e, 3125947 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json, SHA-256 e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6, 13956 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The ML-DSA-87 groups with signatureInterface "external" and preHash "pure" (CRYPTO.md section 12: pure ML-DSA, with a context).

## nist-acvp-siggen.json (30 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/ML-DSA-sigGen-FIPS204/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json, SHA-256 447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d, 5044293 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json, SHA-256 228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb, 2511972 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The same groups, deterministic and hedged.

## wycheproof-verify.json (241 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/mldsa_87_verify_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mldsa_87_verify_test.json, SHA-256 54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14, 2590324 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.
