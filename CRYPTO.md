# How AVPx keeps games secret, sealed and fair (protocol version 2, a design)

Written 2026-11-08 by Melanikus. **This is a design, not code.** Nothing here is built yet. The game (Fifth), the Node server (Third), the Java server (Primary) and the list page (Fourth) build from it, after a fresh reviewer has read it. PROTOCOL.md stays the plain version 1 that the first test runs use. Version 2 is a new deployment: there's no mixing of the two and no negotiation.

**How to read the marks:** **[CHECK]** means a fact from memory, not yet checked against the document named beside it. Every [CHECK] is confirmed, and the mark taken out, before any code is written on it. **[DECIDE]** marks a choice that belongs to the user (section 19).

## 1. What this protects, and what nothing can

**Who we defend against:**
- anyone on the path: the ISP, the Wi-Fi, the carrier-grade NAT;
- a fake relay or list, through a hijacked DNS name or certificate;
- **our own relay**, which must not be able to read or change a game between players. So the game traffic is sealed end to end, from host to joiner, and the relay only ever forwards ciphertext;
- players who change their game's files.

**What this gives:**
- secrecy and integrity of every message, between game and relay and from host to joiner;
- the host is the host the joiner meant, and the joiner the one who did the handshake;
- forward secrecy;
- no downgrade, and no replay;
- no amplification;
- a fair shared coin;
- proof that both sides hold the same files;
- signed releases and a signed relays directory.

**What nothing here can do:**
- **Stop a determined cheater.** A player owns their machine. They can keep an unchanged copy of the files to answer the file proof from (section 11) while playing with changed ones, or change the game in memory. The checks stop wrong versions, damaged files and casual edits. Only a game where the server decides everything can stop a determined cheater, and AvP's host-led netcode isn't that.
- **Hide who plays with whom from the relay.** The relay sees addresses and sizes, the way any relay does. It writes no address down (PROTOCOL.md), but it sees them while a game runs.
- **Make a two-player coin flip perfectly fair.** One side can always quit after seeing the result (section 11.2, with the rule that handles it).

## 2. One suite, no choices

Every key, signature and seal uses one fixed suite: **NSA's CNSA 2.0, as a hybrid of the classical and post-quantum parts.** There's no field that names a suite, and nothing to negotiate. A message from another version is refused (section 16).

| Job | Classical | Post-quantum | Both? |
|---|---|---|---|
| Key exchange | ECDH on P-384 | ML-KEM-1024 (FIPS 203) | both secrets go into the key schedule; a session holds unless both are broken |
| Signatures | ECDSA P-384 with SHA-384 | ML-DSA-87 (FIPS 204) | both are made, and both must check |
| Sealing | AES-256-GCM | (the same: 256-bit keys hold against quantum search) | |
| Hash, MAC, key derivation | SHA-384, HMAC-SHA-384, HKDF-SHA-384 | (the same) | |

**Sizes, in bytes, as they go on the wire:**

| Thing | Size |
|---|---|
| P-384 public key, uncompressed (0x04, X, Y) | 97 |
| ECDSA P-384 signature, r then s, 48 each | 96 |
| ML-KEM-1024 encapsulation key | 1,568 |
| ML-KEM-1024 ciphertext | 1,568 |
| ML-KEM-1024 shared secret | 32 |
| ML-DSA-87 public key | 2,592 |
| ML-DSA-87 signature | 4,627 |
| AES-256-GCM tag | 16 |
| SHA-384 output | 48 |

**Why not X25519, Ed25519 and ChaCha20-Poly1305?** They're as good, and smaller. But Windows' own crypto, CNG, has no Ed25519, so the game would need a library built from source for the signatures. P-384, ECDSA and AES-GCM are in all three platforms already. The post-quantum half (section 3) is the only part that may need a library.

## 3. Where each part comes from

No third-party crypto on the servers (AVP Tao 1). Each platform's own:

| Platform | P-384, ECDSA, AES-GCM, SHA-384, HKDF | ML-KEM-1024, ML-DSA-87 |
|---|---|---|
| Java 25 (LTS) | `KeyAgreement "ECDH"`, `Signature "SHA384withECDSA"`, `Cipher "AES/GCM/NoPadding"`; HKDF through the KDF API, JEP 510, final in JDK 25. **[CHECK: the JEP's example is HKDF-SHA256. Confirm HKDF-SHA384 is among JDK 25's KDF algorithm names; if not, write HKDF by hand over HMAC-SHA384, `javax.crypto.Mac`, in java.base]** | ML-KEM, JEP 496, and ML-DSA, JEP 497, both in JDK 24, through `javax.crypto.KEM` (JEP 452) and `Signature` |
| Node.js 24 (LTS) | `node:crypto`: `diffieHellman` on P-384 keys, `sign`/`verify`, `createCipheriv('aes-256-gcm')`, `hkdfSync('sha384')` | ML-DSA keys from v24.6.0, ML-KEM from v24.7.0, both on OpenSSL 3.5 (the KeyObject history in nodejs.org/api/crypto.html). **[CHECK: `crypto.encapsulate`'s own "Added in" line, once.]** Version 2's code sets `engines` to `>=24.7.0` |
| The game, Windows CNG (bcrypt.dll) | `BCRYPT_ECDH_P384_ALGORITHM`, `BCRYPT_ECDSA_P384_ALGORITHM`, `BCRYPT_AES_ALGORITHM` with `BCRYPT_CHAIN_MODE_GCM`, `BCRYPT_SHA384_ALGORITHM` with the HMAC flag. These have been in Windows since Windows 7 | ML-KEM and ML-DSA have been **generally available since the November 2025 update, on Windows 11 24H2 and 25H2** (at least the 2025-10 update KB5067036, per Microsoft's AD CS document), **and Windows Server 2025. Not on Windows 10.** Handles: `BCRYPT_MLKEM_ALG_HANDLE` (0x481) and `BCRYPT_MLDSA_ALG_HANDLE` (0x471), with the parameter set chosen through `BCryptSetProperty(BCRYPT_PARAMETER_SET_NAME, BCRYPT_MLKEM_PARAMETER_SET_1024 ...)`. Sources: Microsoft's Tech Community post "Post-Quantum Cryptography APIs Now Generally Available on Microsoft Platforms", and the AD CS document for the update number. Microsoft's sample page still says "prerelease"; that's out of date |

The platform facts in this table were read in the official documents by PO on 2026-11-08. The two marks left are each to be confirmed once, in code, before the code relies on them.

**What the game does where Windows lacks ML-KEM or ML-DSA (decided below).** Neither choice falls back to classical-only. A fallback is an attack path, so there isn't one.
- **(a) CNG only.** Online play needs a Windows that has them. Others get a plain refusal: "Online play needs Windows 11 24H2 or later, with the October 2025 update or newer." This adds no code, but players on Windows 10, or on Windows 11 before 24H2, can't play online.
- **(b) The post-quantum half built from source into the game,** from the PQ Code Package's `mlkem-native` and `mldsa-native` (C; Apache-2.0, ISC or MIT; parts machine-proved). It's scanned and take-out tested like ENet; CNG still does the classical half and AES-GCM. One code path on every Windows, and no dependence on the OS version for decades (AVP Tao 2). It adds about 10,000 to 20,000 lines of C to review.
- **I recommend (b)**: it keeps every player and one code path, and the extra code is reviewable C under a permissive licence. Both are secure, but their risks differ, so the choice was the user's.

**Decided 2026-11-08 by the user: (b). Windows 10 plays, with the post-quantum half built from source.**

### 3.1 The post-quantum library: what comes in, and how

- **Upstream:** the PQ Code Package (PQCA, a Linux Foundation project), github.com/pq-code-package:
  - `mlkem-native`, for ML-KEM-1024;
  - `mldsa-native`, for ML-DSA-87.
- **Licence:** each repository's own LICENSE file. **[CHECK]** I believe both offer Apache-2.0, ISC or MIT, at the user's choice. Whichever we take is written into the game's licence notices, beside ENet's.
- **The exact version:** the release tag, its full commit hash, and the SHA-256 of the source archive, for each of the two. **[CHECK, and nothing is fetched until it's done]:**
  - Each must be taken from upstream's own release page.
  - Each must be at least two weeks old.
  - Each must be written here before any code. Until then, the pins in the build are empty and the build refuses to fetch.
  - **If `mldsa-native` has no stable release (a 1.x), say so here,** and the user decides whether a pre-release commit may be pinned, or whether to wait.
- **How it comes in:** as source only, never a built library (AVP Tao 1), the same way ENet does:
  - **a vcpkg overlay port, or the source kept in the repository;** the game's maintainers choose, as they did for ENet;
  - **pinned** by the commit hash and the archive's SHA-256;
  - **read first:** a person reads the whole of it before it's built or run, and records that in the AvP docs. Nothing in it runs before that;
  - **built** with the game's own flags;
  - **checked like our own code:** CodeQL C/C++, Snyk Code, the sanitizer run (AddressSanitizer and UndefinedBehaviorSanitizer), and take-out rows on the parts we call. Upstream's own test vectors, and the NIST ACVP vectors for ML-KEM-1024 and ML-DSA-87, run in the game's tests.
  - **Only the C is built,** with no assembly. The assembly paths are where upstream has some of its proofs, but the plain C is the same on every machine, and the game's x86 build is 32-bit.
- **What upstream has proved by machine, and what it hasn't.** **[CHECK] against each project's README and its proofs folder, from memory:**
  - **mlkem-native:**
    - CBMC proofs that its C code is free of memory-safety and type-safety faults (no reads or writes out of bounds, no overflow);
    - HOL Light proofs of functional correctness for its AArch64, and some x86_64, assembly.
    - **Not proved:** that the C as a whole computes ML-KEM exactly as FIPS 203 says. That rests on tests and vectors.
  - **mldsa-native:** I believe CBMC proofs are in progress, and less complete than mlkem-native's.
  - **In neither:** nothing is proved about the whole program the game builds, or about side channels beyond upstream's own constant-time testing.
  - So the game's own tests (the vectors above) and checks (the sanitizers, CodeQL, the take-outs) stand on their own, with no "already proved" credit.

### 3.2 One code path: the game never uses CNG for ML-KEM or ML-DSA, even where Windows has them

- **Two paths mean twice the bugs.** Each path would need its own tests, its own reading, and its own failure modes in the field. A fault in the path most players don't use would hide the longest.
- **Two paths make a choice, and a choice can be steered.** Whatever picks the path ("does this Windows have ML-KEM?") is something an attacker on the machine, or a broken Windows update, can change. One path has nothing to choose.
- **One path behaves the same for every player,** so a bug report from one is a bug report for all, and the test vectors prove every player's build at once.
- **The cost:** on Windows 11 24H2 and later, the OS's own ML-KEM goes unused. That gives up nothing in security: both implement the same standard, and both are checked against the same vectors.
- **CNG still does the classical half** (P-384, ECDSA, AES-GCM, SHA-384, HKDF over HMAC) on every Windows, because it has done that on every Windows since Windows 7. That's one path too.

## 4. The keys: who holds what

| Key | Kind | Where it lives | What it does |
|---|---|---|---|
| **Root** | ECDSA P-384 plus ML-DSA-87 | offline, on the user's own machine, encrypted; never on a server or in CI | signs the keys below, each with an end date |
| **Release key** | ECDSA plus ML-DSA | offline, on the user's own machine: **the user signs each release by hand** (decided 2026-11-08) | signs each release's manifest (section 12) |
| **Directory key** | ECDSA plus ML-DSA | offline, beside the root | signs the relays directory (section 12) |
| **List key** | ECDSA plus ML-DSA | on the list's machine | signs each answer of `GET /v1/games` |
| **A relay's static key** | ECDH P-384 plus ML-KEM-1024 | on that relay's machine | proves the relay, in handshake A |
| **A player's identity key** | ECDH P-384 plus ML-KEM-1024 | made on first run, in the player's save folder | proves a host or joiner, in handshake B |
| **Session keys** | AES-256 per direction | memory only, wiped at the end (section 9) | seal the messages |

**Pinned in the game:** the root's public keys. There are two roots: the one in use, and the next one, made at the same time and kept offline apart. So a root can be replaced without the game being left with none.

**Rotation:**
- The release and directory keys get one-year certificates from the root. The list key gets a 90-day certificate from the directory key.
- A relay's static key is in the signed directory, and changes with a new directory.
- A player's identity key changes only if they ask, and their friends then see a new fingerprint.

**Revocation:**
- The signed directory carries a list of revoked key fingerprints. The game refuses anything signed by one of them.
- A root is revoked only by a game update that pins the next root alone.

**Decided 2026-11-08: the user signs each release by hand,** on their own machine, with the release key offline. A CI secret was the first brief: any code that runs in that job can read it. The release workflow builds the files and the unsigned `manifest.txt`. The user checks it, signs it, and attaches `manifest.sig`, and only then is the release published.

## 5. Building blocks every handshake uses

These follow the Noise framework, revision 34 (noiseprotocol.org). The post-quantum part follows PQNoise (Angel, Dowling, Huelsing, Schwabe and Weber, ACM CCS 2022), where a KEM takes the place of a Diffie-Hellman for authentication. Rosenpass (a post-quantum handshake in front of WireGuard) is the precedent for using a KEM this way.

**The state:** `h`, the hash of everything said so far (the transcript, 48 bytes); `ck`, the chaining key (48 bytes); `k`, the current sealing key, if any; and `n`, a counter.

**The operations:**
- **MixHash(data):** `h = SHA-384(h || data)`.
- **MixKey(secret):** `ck, k = HKDF-SHA-384(salt = ck, input = secret)`, giving 48 then 32 bytes; `n = 0`.
- **EncryptAndHash(text):** `c = AES-256-GCM(k, nonce(n), aad = h, text)`; then `MixHash(c)`; `n += 1`. With no `k` yet, `c = text`.
- **DecryptAndHash** is the same backwards. A tag that fails ends the handshake.
- **Split():** two 32-byte keys and two 12-byte IVs, one of each per direction, from `HKDF-SHA-384(salt = ck, input = empty, info = "AVPX split v2")`.
- **nonce(n):** the 12-byte IV XOR (4 zero bytes, then `n` as 8 bytes little-endian).

**Tokens.** A Noise pattern is a list of these, done in order:
- `e`: send an ephemeral P-384 key, and MixHash it. The initiator also sends an ephemeral ML-KEM encapsulation key, and MixHashes that; a responder sends none, because what it needs is to encapsulate to the initiator's (`ekem`);
- `ee`, `es`, `se`: MixKey(ECDH of those two keys);
- `ekem`: encapsulate to the other's ephemeral ML-KEM key, send the ciphertext, MixHash it, and MixKey the shared secret;
- `skem`: the same, to the other's static ML-KEM key;
- `s`: send our static keys with EncryptAndHash.

The ECDH results and the ML-KEM secrets go into the same chain one after another, so every key after them depends on both: that's the hybrid.

**The start:**
- `h = SHA-384(the protocol name)` and `ck = h`.
- The names are `AVPX_pqNK_P384+MLKEM1024_AESGCM_SHA384_v2` (handshake A) and `AVPX_pqXX_P384+MLKEM1024_AESGCM_SHA384_v2` (handshake B).
- Then MixHash(the prologue): the region and the relay's static keys for A, and the relay port and the host's fingerprint for B.

**Big messages over UDP.** Handshake messages are 1.6 to 3.4 KB, more than a datagram should carry. Each is cut into fragments, and **every handshake datagram, either way, is exactly 1,200 bytes**: the smallest size the internet carries whole, as QUIC also uses.

| Bytes | Field |
|---|---|
| 0-3 | `AVPR` (to the relay) or `AVPE` (host to joiner) |
| 4 | version, 2 |
| 5 | kind (section 6 and section 8) |
| 6 | this fragment's number, from 0 |
| 7 | how many fragments, 1 to 4 |
| 8-15 | the handshake's id: 8 random bytes the initiator chose |
| 16-31 | the cookie (to the relay), or 0 |
| 32-33 | the whole message's length |
| 34-35 | where this fragment starts in it |
| 36-1199 | up to 1,164 bytes of the message, then 0 |

## 6. Handshake A: a game and its relay (pattern pqNK, hybrid)

The game knows the relay's static keys from the signed directory (section 12) before it says anything. The relay is proved to the game. The game stays anonymous to the relay: its tokens and tickets, sent inside the channel, are what prove a host or joiner, as in PROTOCOL.md.

| Step | From, to | Kind | Holds | Size |
|---|---|---|---|---|
| A0 | game to relay | 1 COOKIE_ASK | the handshake id; the rest of the 1,200 bytes 0 | 1 datagram |
| A0' | relay to game | 2 COOKIE | a 64-byte answer: `AVPR`, 2, kind 2, 0, the id (8), the cookie (16), 0 | 64 bytes |
| A1 | game to relay | 3 | tokens `e, es, skem`, then an empty EncryptAndHash: e (97 + 1,568), the ML-KEM ciphertext to the relay's static key (1,568), the tag (16) | 3,249 bytes: 3 datagrams |
| A2 | relay to game | 4 | tokens `e, ee, ekem`, then EncryptAndHash(the relay's 8-byte session id): e (97), the ML-KEM ciphertext to the game's ephemeral key (1,568), 8 + 16 | 1,689 bytes: 2 datagrams |
| A3 | game to relay | 5 | an empty EncryptAndHash: the game's key confirmation | 16 bytes: 1 datagram |

**The keys:**
- `es` and `skem` together prove the relay: only the holder of its static ECDH and ML-KEM keys can make the A2 that comes back.
- `ee` and `ekem` give forward secrecy.
- A2's tag is the relay's key confirmation, and A3's tag is the game's. Nothing else may be sent before both.

**No amplification:**
- **A0':** 64 bytes, answering a 1,200-byte ask.
- **The cookie:** HMAC-SHA-384 of the address, the port, a 10-second slot and the handshake id, cut to 16 bytes, as PROTOCOL.md section 3 describes. Every A1 datagram carries it, and **the relay checks it, with no memory, before it keeps a single byte**.
- **What the relay keeps:** one handshake being put together per address, at most 4 KB, for at most 2 s; at most 1,000 at once in all.
- **When the expensive work starts:** ML-KEM and ECDH work happens only when the whole of A1 is in.
- **The datagram rule:** for any handshake, the relay never sends more datagrams than it was sent, and all of them are the same size: 3 in, 2 out.

**Losses** (every timer is in section 17):
- The game sends A1 again if no A2 comes in 0.5 s, then waits 1 s, 2 s and 4 s, and then gives up with the reason "the relay doesn't answer".
- The relay keeps its A2 bytes for 10 s, keyed by the handshake id and the hash of A1. An A1 that comes again gets **the same A2, byte for byte**: never a fresh one, which would make a second set of keys.
- If A3 is lost, the game's first sealed message (section 7) counts as its confirmation.

## 7. The sealed control channel (game and relay)

Every control message of PROTOCOL.md (the 64-byte HOST_OPEN, JOIN, hellos and the rest, types 1 to 15) now travels sealed:

| Bytes | Field |
|---|---|
| 0-3 | `AVPR` |
| 4 | 2 |
| 5 | kind 32, SEALED |
| 6-7 | 0 |
| 8-15 | the relay's session id, from A2 |
| 16-23 | the counter, 8 bytes little-endian |
| 24-87 | the 64-byte message of PROTOCOL.md, sealed |
| 88-103 | the tag |

**104 bytes every time, questions and answers alike,** so no answer is bigger than its question. Bytes 0-23 are the AAD. The nonce comes from the counter (section 5).

- **Tokens, tickets, passes and codes are never seen on the path again.** That closes PROTOCOL.md's first two known limits.
- **The hellos on a joiner's port are sealed too,** under the sender's session. A sealed hello from a new address that passes its tag moves that end there, which is how NAT rebinding keeps working.
- **The relay still never answers anything that fails its tag,** and counts it.

## 8. Handshake B: a joiner and its host, end to end (pattern pqXX, hybrid)

This runs on the joiner's relay port after READY, from game to game. The relay forwards these datagrams as it forwards any game packet: it can't read them, and it never answers them. Each player has an identity key (section 4). A **fingerprint** is the first 16 bytes of `SHA-384("AVPX-ID-2" || its P-384 key || its ML-KEM key)`, 32 hex digits, and the host's goes in its listing (version 2 of the list).

| Step | From, to | Kind | Tokens | Size |
|---|---|---|---|---|
| B1 | joiner to host | 16 | `e` | 1,665 bytes: 2 datagrams |
| B2 | host to joiner | 17 | `e, ee, ekem, s, es`, then EncryptAndHash(empty) | 97 + 1,568 + (1,665 + 16) + 16 = 3,362 bytes: 3 datagrams |
| B3 | joiner to host | 18 | `skem, s, se`, then EncryptAndHash(empty) | 1,568 + (1,665 + 16) + 16 = 3,265 bytes: 3 datagrams |
| B4 | host to joiner | 19 | `skem`, then EncryptAndHash(empty) | 1,568 + 16 = 1,584 bytes: 2 datagrams |
| B5 | joiner to host | 20 | EncryptAndHash(empty) | 16 bytes: 1 datagram |

**Who is proved to whom:**
- **The host to the joiner:** by `es` (classical) and the joiner's `skem` to the host's static ML-KEM key (post-quantum). The joiner also checks that the fingerprint of the static keys in B2 matches the listing's. If it doesn't, nothing more is sent, and the reason is "this isn't the host the list named".
- **The joiner to the host:** by `se` and the host's `skem` to the joiner's static key. The host may remember joiners' fingerprints, to welcome back or to ban.
- **Key confirmation:**
  - B4's tag is the host's: the joiner sends no game byte before B4 checks.
  - B5's tag is the joiner's, made after the host's `skem` to the joiner's static ML-KEM key. Before B5, the host had proof only of the joiner's classical key (from `se`, in B3's tag). So the host sends no game byte before B5 checks.
  - That's **mutual authentication, classical and post-quantum, before any game byte**.

**The check code:**
- Both screens show **6 digits from `HKDF(h, "AVPX check code v2")`**, the same on both only if no one is in the middle. **It's always shown on the join screen** (decided 2026-11-08).
- Two players who read them to each other (voice, chat) catch even a list that lied about the fingerprint.
- It's 20 bits, so one try in a million fools them, and a failed try is seen.

**Losses:** the same rule as handshake A. The joiner resends B1 and B3 on the same schedule. The host keeps its B2 and B4 for 10 s and sends them again byte for byte. If B5 is lost, the joiner's first sealed datagram (section 9) counts as its confirmation, just as A3's loss is handled.

## 9. Sealed game traffic (every ENet datagram)

After the handshake (B4 checked on the joiner's side, B5 on the host's), every datagram the game's ENet sends goes as:

| Bytes | Field |
|---|---|
| 0-3 | `AVPG` |
| 4-11 | the counter, 8 bytes little-endian |
| 12 to end - 16 | the ENet datagram, sealed |
| last 16 | the tag |

- **The overhead is 28 bytes,** so ENet's 1,400-byte packets become 1,428 bytes, under the relay's 1,500. Bytes 0-11 are the AAD, and the nonce comes from the counter.
- **Keys:** one per direction, from Split(), then changed by counter:
  - **an epoch is 2^20 datagrams**, and an epoch's key is `HKDF-Expand(that direction's secret, "AVPX epoch v2" || the epoch, 4 bytes, 32 bytes)`;
  - both sides change at the same counter with no message, and each key seals at most 2^20 datagrams, far below the limits RFC 8446 section 5.5 sets for AES-GCM;
  - **a session ends after 2^32 datagrams either way, or 24 hours,** and a new handshake starts. At 60 packets a second, the counter limit is about 2 years away, so in practice it's the 24 hours.
- **The replay window: 1,024 datagrams,** as a bitmap behind the highest counter seen. Anything older, anything seen already, and any tag that fails is dropped, counted, and never answered. After 65,536 failed tags in one session, the session ends ("too many bad packets").
- **No plaintext, ever.** Before the handshake has finished, and after a failure, no game byte is sent. There's no switch to turn sealing off.
- **Padding game packets to fixed sizes: no, for now.** Packet sizes would show roughly what's going on (a firefight, a chat line's length). That's worth little to anyone, and padding to buckets would nearly double the relay's traffic. The handshake already uses only one size. This can be revisited.
- **Wiping keys at the end:**
  - the game: `BCryptDestroyKey`, then `SecureZeroMemory` on every buffer that held a key or a secret;
  - Node: `fill(0)` on every Buffer of ours;
  - Java: `Arrays.fill` on every array of ours, and `destroy()` where a key class has it.
  - **A known limit:** Node's garbage collector and some Java key classes may leave copies we can't reach, so a memory dump of a running server can still hold keys. That's true of every managed-language server.

## 10. Proving the host: a PAKE, or a signed identity

| | (a) A PAKE (CPace, or SPAKE2 of RFC 9382) keyed on a secret both know | (b) A host identity, its fingerprint in the listing, and the check code (section 8) |
|---|---|---|
| What it proves | that both know the game's password, with nothing the relay or list can use to guess it | that the host holds the identity whose fingerprint the joiner was given |
| What it needs | **a secret the players share beforehand.** A listed public game has none: its code is public, and a PAKE keyed on a public value proves nothing | nothing beforehand |
| Post-quantum | no standard post-quantum PAKE exists yet (still research) | yes: ML-KEM inside the handshake |
| Code | CNG has no raw curve arithmetic, so the game needs a library built from source (such as Monocypher, one C file) | CNG only (plus section 3's choice) |
| Weak spot | none, if the password is good | a lying list can swap the fingerprint. The signed list answers (section 12) and the check code catch that |

**I recommend (b) for every game, now.** Later, for private games with a password, add (a) as well: CPace run *inside* the finished pqXX channel, so the password is protected by the post-quantum keys and adds a second factor. A post-quantum PAKE waits until one is standardised.

## 11. Proofs after the handshake (inside the sealed channel)

### 11.1 Key confirmation
This is already in the handshakes: A2 and A3, and B3, B4 and B5. Each is a **challenge-response proof of possession**: a tag only the holder of the keys can make, over a transcript that's fresh for this session. It reveals nothing about the keys, and it can't be replayed, because the transcript differs every time.

### 11.2 "Guess my bit": a fair coin, by commit and reveal
1. Each side picks 32 random bytes `r`, and sends `C = SHA-384("AVPX coin v2" || h || its role || r)`. `h` is the handshake's transcript hash, so a commitment can't be carried into another session.
2. Once each side has the other's `C`, each sends its `r`. Each checks the other's `r` against its `C`; a mismatch ends the game, with the reason "the coin was cheated".
3. The coin is `SHA-384("AVPX coin out v2" || h || r of the host || r of the joiner)`. It seeds what both must share, such as who starts.

**The known limit, and the rule for it:** whoever reveals second can see the result and quit instead. No two-party coin flip can stop that (Cleve, 1986). So **a side that doesn't reveal within 5 s loses the flip**, and the game goes on as if the other side won.

### 11.3 "Battleship": both have the same files, with no file sent
1. Each side sends the other a fresh 32-byte challenge `n`.
2. The answer covers three groups: the game's program files, the shared data, and this level's files. For each group, the answer is `HMAC-SHA-384(key = HKDF(h, n, "AVPX files v2"), the file names and **their bytes**, in sorted order)`.
3. The asker works out the same over its own files and compares. A mismatch refuses the join, with the exact reason ("the game files differ", "the data differs", "this level's files differ").

**What it proves, and doesn't:**
- **Why the bytes, and not the manifest's hashes:** the manifest's hashes are public, so an answer made from them proves nothing. Made from the bytes, the answer needs the files in hand, now.
- **It reveals nothing but the match:** the key is new each time, so an answer says nothing about the files and can't be kept for later or worked out in advance.
- **Why not a zero-knowledge proof system (a zk-SNARK, or "ZK Battleship")?** Those prove things about data the checker doesn't have. Here both sides have the files, and the only question is whether they match, which a keyed hash answers exactly. A SNARK would bring a large third-party library to answer a question we don't have.
- **The limit, again (section 1):** a cheater with an unchanged copy can answer from it. This catches mismatches, not a determined cheater.

## 12. Signed files: the release manifest, the relays directory, the list's answers

**The rule for every signature:** an ECDSA P-384 signature and an ML-DSA-87 signature, both over `SHA-384("AVPX <what> v2" || the bytes)`. ML-DSA uses its context string, also "AVPX <what> v2". **Both must check.**

**The release manifest:**
- The release workflow writes `manifest.txt`, sorted ASCII lines of `sha384 size path`, one for every file shipped: the exe, the DLLs and every data file. It signs it with the release key, giving `manifest.sig`, together with the release key's certificate from the root.
- The game, at start: checks the certificate against the pinned root, checks the signature, then checks every file against the manifest.
- **In multiplayer, a changed or missing file refuses online play,** naming the first such file. **In single player, it warns** and lets the player go on.

**The relays directory:** a signed file, served by the list as `GET /v2/relays`. For each relay, it holds:
- the region, its DNS name and port;
- its static ECDH and ML-KEM keys;
- the directory's **serial number** and **end date** (30 days);
- the list key's certificate;
- the revoked fingerprints.

The game refuses:
- a directory with a serial number lower than the highest it has seen, so an old directory can't be replayed;
- one past its end date;
- any directory whose signature doesn't check.

So a hijacked DNS name or certificate can't feed the game false relays.

**The list's answers:** `GET /v2/games` answers are signed by the list key, with the time. The game refuses an answer more than 60 s old, or one with a bad signature. That protects the host fingerprints the joiner trusts (section 8). The list's own machine could still lie, so the check code (section 8) remains the last line.

## 13. The properties the user asked for, how each is met, and what tries to break it

| # | Property | How it's met | What tries to break it |
|---|---|---|---|
| 1 | A published, analysed pattern | Noise NK and XX (rev 34), made post-quantum as PQNoise does; Rosenpass as the precedent | the formal model (section 14) |
| 2 | Mutual authentication before any game byte | B2 to B5 (section 8); neither side sends a game byte before the other's last confirmation checks | tests: a wrong host static key, a wrong fingerprint, a broken B3 tag. All refused, nothing sent. Model: injective agreement both ways |
| 3 | Forward secrecy | fresh ephemeral ECDH and ML-KEM keys every session (`ee`, `ekem`) | test: record a session, then give the test both sides' static keys; the recording still can't be opened. Model: secrecy after the statics leak |
| 4 | Hybrid post-quantum | every MixKey of ECDH and of ML-KEM is in one chain | test: change either secret alone, and every key after it changes. Model: secrecy if only ECDH holds, and if only ML-KEM holds |
| 5 | Transcript binding | every byte goes through MixHash; tags use `h` as AAD | test: flip each bit of each handshake message, one at a time; every flip fails |
| 6 | No downgrade | one suite, version 2 in every header, the protocol name in `h` | test: version 1, 3 or 0, and a version-1 message sent to a version-2 relay. All refused, with the reason |
| 7 | Replay-proof | handshake ids and cookies; repeats get the same answer; counters and a window of 1,024 | tests: replay each handshake message, each sealed message, and counters below the window |
| 8 | DoS- and amplification-proof | the cookie before any ECDH or ML-KEM; 1,200-byte datagrams, never more out than in; 64-byte A0'; per-address limits | tests: for every kind, the answer's bytes are at most the question's; a stand-in crypto layer counts the calls made before a good cookie (must be 0); reassembly caps |
| 9 | Loss-tolerant | the retry schedule; answers kept and sent again byte for byte; every timer in section 17 | test: drop each message in turn; the handshake still completes, and a repeated A1 gets an identical A2 |
| 10 | A formal model | ProVerif, in the repository (section 14) | it runs, and every query says true |

## 14. The formal model

- **Tool:** ProVerif (INRIA). It's downloaded, so untrusted until reviewed (AVP Tao 1): built from source with its own hash checked, and run offline.
- **What it models:**
  - handshakes A and B;
  - ECDH as Diffie-Hellman equations, and ML-KEM as an ideal KEM (decapsulate of encapsulate gives the secret);
  - the hybrid as two separate secrets, each with an oracle that can break it, to show either one alone is enough.
- **What it queries:**
  - secrecy of the session keys;
  - injective agreement on the transcript, both ways for B and relay-to-game for A;
  - secrecy after the static keys leak (forward secrecy);
  - no agreement across protocol names (no downgrade).
- **Where it lives:** `model/handshakes.pv`, with `model/README.md` giving the command and the `RESULT ... is true.` lines it must print. A check runs it on every change.
- **Who:** I (Third) write it; Primary reads it against the Java code, and the fresh reviewer reads it against this file.
- **The limit:** ProVerif proves the pattern, not our code. The code is held to the pattern by the test vectors (section 15) and the tests in section 13.

## 15. Test vectors: `test-vectors/crypto-v2.json`

These come from tools/make-vectors.js, with fixed keys, and are read by the Node, Java and game tests:
- HKDF chains from fixed inputs;
- AES-GCM seals;
- each handshake's every `h` and `ck`, from fixed ephemeral and static keys;
- ML-KEM decapsulations (a given decapsulation key and ciphertext give a given secret).

ML-KEM's encapsulation is random inside every platform's own API, so vectors fix the decapsulation side only, and each implementation's tests check that its own encapsulations decapsulate.

They also include:
- signatures from fixed keys. ML-DSA as each platform does it may be randomised, so vectors check verification, not the signature bytes;
- every refusal of section 16, as bytes.

## 16. Every refusal (version 2)

Each refusal is dropped and counted. The relay answers none of them. The game shows the player only the reasons marked (P).

1. The wrong size (a handshake datagram that isn't 1,200 bytes; a sealed control message that isn't 104).
2. Another magic.
3. Another version (P: "this server speaks another version").
4. An unknown kind.
5. A bad cookie.
6. Fragments that don't fit together: overlapping, too many, or a length past the most.
7. A handshake not finished in time (P: "the relay doesn't answer").
8. A tag that fails.
9. A counter seen already, or below the window.
10. The wrong host: the fingerprint doesn't match (P: "this isn't the host the list named").
11. A bad signature on the manifest, directory or list answer (P: "the game's files can't be checked" / "the list can't be trusted").
12. A directory too old, or past its end date (P).
13. Changed files in multiplayer (P: names the first).
14. The file proof doesn't match (P: names the group).
15. The coin cheated (P).
16. Too many bad packets (P: "the connection was attacked, and closed").
17. No post-quantum support, under section 3's choice (a) (P: names the Windows version needed).

## 17. Every timer and limit

| What | Limit |
|---|---|
| A handshake datagram | exactly 1,200 bytes; at most 4 fragments a message |
| COOKIE answer | 64 bytes |
| Cookie life | 10 to 20 s (as now) |
| A handshake being put together | 4 KB, 2 s, one per address, 1,000 in all |
| Handshakes started, one address | 2 a second, 4 at once |
| Handshakes started, everyone | 200 a second, 400 at once |
| Retries | after 0.5, 1, 2 and 4 s, then give up |
| A finished answer kept, to send again | 10 s |
| A sealed control message | exactly 104 bytes |
| Sealed game overhead | 28 bytes a datagram |
| An epoch (one key) | 2^20 datagrams each way |
| A session | 2^32 datagrams each way, or 24 hours |
| Replay window | 1,024 datagrams |
| Failed tags before a session ends | 65,536 |
| Coin reveal | 5 s |
| A list answer's age | 60 s |
| A directory's life | 30 days |
| Certificates | root to release and directory keys: 1 year; directory to list key: 90 days |

## 18. Left out, and why

- **A post-quantum PAKE:** none is standardised; section 10 says what to do instead.
- **Hiding packet sizes during play:** section 9.
- **Hiding who plays with whom from the relay:** that needs onion routing through several relays, far past a game's needs.
- **Stopping determined cheaters:** section 1. That needs a server that decides the game.
- **Hardware keys for ML-DSA:** no consumer token holds ML-DSA keys yet. The root's ECDSA half could live on a hardware token.
- **Hole punching (a direct path):** later, and it changes nothing here: handshake B and the sealing run the same over a direct path.

## 19. For the user to decide

1. **The game's post-quantum half: built from source,** so Windows 10 plays. Decided by the user on 2026-11-08 (section 3, 3.1 and 3.2): one code path everywhere, with CNG never used for ML-KEM or ML-DSA.

All three are decided. What's left before code is the [CHECK] marks, and section 3.1's pins.
2. **The release key: signed by hand.** Decided 2026-11-08 (PO, under Tao 1: the secure choice is taken, and the user told).
3. **The check code: always shown on the join screen.** Decided 2026-11-08, the same way.
