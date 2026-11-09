# Known answers for protocol version 2's primitives

**What this is:** the published test cases for every primitive CRYPTO.md section 2 names, from the people who wrote each standard.
- **AES-256-GCM**, with a 12-byte IV and a 16-byte tag;
- **HKDF-SHA-384**, with **HMAC-SHA-384** under it;
- **ECDH on P-384**;
- **ECDSA on P-384** with SHA-384, the signature as r then s;
- **ML-KEM-1024**;
- **ML-DSA-87**, pure, with a context.

**Why:** our own tests and our own code can share a mistake, and then every test passes on a primitive that's wrong. A known answer
from NIST, or from Wycheproof's set of edge cases, can't share it. The Java server, the Node server and the game all check their
primitives against these files.

**Where they're from:** each folder's PROVENANCE.md names, for every file, the source and its URL, the commit or release, the
SHA-256 and size of the file it came from, its licence, and exactly which cases were taken. In short:

| Folder | NIST | Wycheproof |
|---|---|---|
| aes-256-gcm | CAVP gcmEncryptExtIV256, gcmDecrypt256 | aes_gcm_test |
| hkdf-sha384 | ACVP KDA-HKDF (SP 800-56C rev 2), and RFC 5869's own cases | hkdf_sha384_test |
| hmac-sha384 | | hmac_sha384_test |
| ecdh-p384 | CAVP KAS ECC CDH, and 186-4 PKV | ecdh_secp384r1_ecpoint_test, ecdh_secp384r1_test |
| ecdsa-p384-sha384 | CAVP 186-4 SigVer and SigGen | ecdsa_secp384r1_sha384_p1363_test |
| ml-kem-1024 | ACVP keyGen and encapDecap (FIPS 203) | mlkem_1024 (four files) |
| ml-dsa-87 | ACVP keyGen, sigVer and sigGen (FIPS 204) | mldsa_87_verify_test |

Wycheproof's licence, Apache-2.0, is LICENSE-wycheproof.txt. NIST's work isn't subject to copyright in the United States.

## The shape of every file

```
{ "primitive": "...", "source": "...", "about": "what each case means, and what was taken", "count": N,
  "cases": [ { "id": "...", <the case's inputs and answers>, "result": "valid" } ] }
```

- **Bytes** are hex in small letters, and `""` when there are none.
- **Numbers** are whole numbers.
- **`result`:**
  - `"valid"` means the answer must come out exactly as given;
  - `"invalid"` means it must be refused;
  - `"acceptable"`, in Wycheproof's ECDH only, means either is allowed. Those cases are compressed points, which v2 never sends, so
    v2 refuses them.
- **No `true`, `false` or `null`.** Every string is printable ASCII, with no escape but `\"` and `\\`. So the servers' strict JSON
  reader takes these as they are.
- **Wycheproof's flags** are one string, split by commas (`"Normal,EmptySalt"`), and its comments are kept to printable ASCII.
- **Each file's `about`** says what its fields are and what each `result` means.

## How they were made, and what was checked

- **`tools/make-crypto-kat.js` makes them,** from the fetched files (not in the repository; see PROVENANCE.md). Run on the same
  sources, it makes these files again byte for byte. It writes each case's bytes out as the source has them, and changes nothing but
  how they're written. Anything that isn't as it expects stops it, rather than being guessed at.
- **Every classical case was checked against Node's own crypto (OpenSSL) before it went in,** 2,316 in all, with 0 wrong. The one
  exception is a single "acceptable" ECDH case, where either answer is right:
  - every AES-256-GCM case seals to its ct and tag, and every "invalid" one fails to open;
  - every HKDF case gives its okm, all 100 of ACVP's included (so the rule that turns them into plain HKDF is right), and every
    "invalid" size is refused;
  - every HMAC tag is right, or wrong as marked;
  - every ECDH case gives its shared secret, and every "invalid" point is refused;
  - every ECDSA signature checks or fails as marked.
- **ML-KEM and ML-DSA were checked for their sizes only** (FIPS 203 and 204's). Whether they compute right is what each reader's own
  tests prove against them, with two independent sources for each.

## What a reader does with them

- The **Java server** (Primary) and the **game** (Fifth) each read the folders they need.
- A reader runs every case, and fails if:
  - a "valid" one doesn't give exactly its answer;
  - an "invalid" one isn't refused.
- A case a primitive can't take, such as a key form an API won't import, is counted and named in the test's output, never left out
  silently.
