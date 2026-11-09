# Where the HKDF-SHA-384 cases come from

**The standard:** RFC 5869 (HKDF); NIST SP 800-56C rev 2 (its two-step key derivation, of which HKDF is one).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. java/tools/MakeCryptoKat.java makes the files, from the sources put in crypto-kat-sources/ beside the repository's top folder, after checking each one's SHA-256 against the ones below. Run again on them, it makes these files byte for byte.

**Checked when first made (2026-11-09):** 190 classical cases, each redone with OpenSSL (through Node's crypto), 0 wrong: every case gives its okm (prk too, for RFC 5869's), all 100 of ACVP's included, and every invalid size is refused. That check was a one-off script and isn't in the repository; the readers' own tests are the check from now on.

## wycheproof.json (83 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/hkdf_sha384_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hkdf_sha384_test.json, SHA-256 69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678, 116155 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case.

## nist-acvp-kda.json (100 cases)

- **Source:** NIST's ACVP server, github.com/usnistgov/ACVP-Server, release v1.1.0.43, commit 975de31eb83d87039ec88934fdc47d8c312b892d, the folder gen-val/json-files/KDA-HKDF-Sp800-56Cr2/.
- **prompt.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/KDA-HKDF-Sp800-56Cr2/prompt.json, SHA-256 2d27b1b69549f383b7583700f7e0622b33debb254db37bf83eb524102a1e3d9c, 21522978 bytes.
- **expectedResults.json:** https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/KDA-HKDF-Sp800-56Cr2/expectedResults.json, SHA-256 de35a4b7b3bc795b9c1b7bba4a28407bcfe2941568d097eadf9de57ff2e76395, 704731 bytes.
- **Licence:** NIST's work, not subject to copyright protection in the United States (17 U.S.C. 105). The repository has no LICENSE file; its README.md says "The software developed by NIST employees is not subject to copyright protection within the United States".
- **Taken:** The groups whose hmacAlg is SHA2-384, written as plain HKDF's inputs (see the file's "about": ikm = Z || T, info = the parties' info and L). Each of the 100 cases was checked here against an HKDF over Node's HMAC, before it went in.

## rfc5869.json (7 cases)

- **Source:** RFC 5869, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", H. Krawczyk and P. Eronen, May 2010, appendix A.
- **The file:** https://www.rfc-editor.org/rfc/rfc5869.txt, SHA-256 7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c, 25854 bytes.
- **Licence:** the RFC is Copyright (c) 2010 IETF Trust and the persons identified as the document authors. Its test cases are code components under the IETF Trust's Legal Provisions, so they're used under the Simplified BSD License, with this reference.
- **Taken:** All seven of appendix A's test cases (SHA-256 and SHA-1: the RFC has none for SHA-384), to prove an HKDF written by hand. Case 7's salt "not provided" is written as "", which gives the same PRK as HashLen zero bytes.
