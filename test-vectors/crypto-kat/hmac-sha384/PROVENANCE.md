# Where the HMAC-SHA-384 cases come from

**The standard:** RFC 2104 and FIPS 198-1 (HMAC), FIPS 180-4 (SHA-384).

Fetched by PO, 2026-11-09 at about 03:00 UTC, each into a folder of its own, and checked here against PO's list of SHA-256s (all 36 matched).
Nothing in a case was changed: each was only written out in this folder's JSON shape (../README.md), with hex in small letters. java/tools/MakeCryptoKat.java makes the files, from the sources put in crypto-kat-sources/ beside the repository's top folder, after checking each one's SHA-256 against the ones below. Run again on them, it makes these files byte for byte.

**Checked when first made (2026-11-09):** 174 classical cases, each redone with OpenSSL (through Node's crypto), 0 wrong. That check was a one-off script and isn't in the repository; the readers' own tests are the check from now on.

## wycheproof.json (174 cases)

- **Source:** Wycheproof, github.com/C2SP/wycheproof, commit d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9, testvectors_v1/hmac_sha384_test.json.
- **The file:** https://raw.githubusercontent.com/C2SP/wycheproof/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/hmac_sha384_test.json, SHA-256 28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0, 78567 bytes.
- **Licence:** Apache-2.0. Its LICENSE is ../LICENSE-wycheproof.txt, copied unchanged.
- **Taken:** Every case, with each group's keySize and tagSize.
