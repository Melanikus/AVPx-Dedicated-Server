# Taking over: running this server when we're gone

Written 2026-11-09 by Melanikus, at the owner's word: "20 years from now, we won't be there to enforce tao 1, our keys and tokens will have expired, be mindful of that".

**Who this is for:** you, years from now, with this repository and none of our accounts, keys or tokens. Nobody can give you permission, and you don't need it. This page is how you become the one who decides who plays: **the trust root**.

**What "the trust root" means here:** whoever holds a server's keys and approves its players decides who can play on it, and nobody else does. The game trusts a server only through what it carries in its own files: the server's address, the key of its list's certificate, and its relay's id (servers.cfg, below). None of it depends on us being there. When you make your own keys and your own servers.cfg line, your server is as trusted as ours ever was, by the copies of the game that carry your line.

**Marked [BETA.2]:** parts being built for beta.2 (AvP-docs's BETA2-PLAN.md, "Built to outlive us") that may not be in your copy. If one is missing, the design is still what's written here, and the code to look in is named.

---

## 1. What you need

- **A Linux machine you control,** reachable from the internet, with Ubuntu 24.04 or a later long-term release. deploy/README.md was written for that, and every command in it is Ubuntu's.
- **This repository,** cloned whole: `git clone` and `git log` work with no account at all.
- **The JDK this server is built with,** named and pinned in `java/tools/get-jdk.sh` (version, address, sha256, and the fingerprint of Adoptium's signing key). It's the one thing from outside. If its address no longer answers, see section 6, "The JDK".
- **Nothing of ours.** No GitHub account of ours, no cloud account, no token. Where a gate of ours used one, section 6 says what it proved and what can replace it.

## 2. Build it, and test it, from source

- `sh java/build.sh` builds the jars and runs every test: javac with every warning an error, the tests, the coding standard, and the same jars made twice to show the build gives the same bytes. It needs only the JDK.
- `AVPX_LIVE=1 sh java/build.sh` also runs the tests that open real sockets, on 127.0.0.1 only.
- `java/tools/Takeouts.java` breaks the code on purpose, one row of `java/tools/takeouts.txt` at a time, and each row's named test must notice. That's how you know the tests test something: run it after any change you make.
- **Offline [BETA.2]:** the JDK archived with its sha256, so a machine with no network builds and tests the same. Until it's there, the JDK's archive is the only download, and its sha256 in get-jdk.sh tells you whether a copy you found anywhere is the right one.

## 3. Your own server

**This is also how anyone runs a server for their friends, today as much as in 20 years:** the same steps, the same keys of your own, and your own servers.cfg line to give them. You approve your friends yourself (section 4), and nobody else is asked.

Follow deploy/README.md for the machine: the users (`avpx` runs the server, `avpx-build` builds it, neither can log in), the folders, the firewall, the service. Then make everything that is yours. **Never use a key from this repository, from a backup of ours, or from anyone else: make your own on your own machine.**

1. **The list's certificate key.** The list is reached over HTTPS, and the game trusts it by the key of its certificate (its SPKI), not by any company that signs certificates. [BETA.2: deploy/README.md's certificate step.]
   - Make the key once, on the machine, and keep it: root's and avpx's to read, never copied off the machine.
   - Make a certificate from it. Make each new certificate from the same key, so the games that carry your pin still trust it.
   - If the key is ever stolen or lost, make a new one. Your servers.cfg line changes, and the players need it again (section 7).
   - **The game trusts the pin alone** (the owner's ruling, 2026-11-09). With a pin, it ignores the certificate's dates, its name and its issuer, and checks only that the key is the pinned one. **Why:** a date can only end a server, never save one. In 20 years nobody may be there to make a new certificate, and a date would stop every copy of the game reaching the server on that day, for good, with the key still safe. A key that's stolen or changed is answered by a new key and a new servers.cfg line (section 7), and for a server a release ships, by a new release. So the certificate's dates don't matter to the game: make it last as long as your tools allow.
2. **The relay's static keys:** `java -cp avpx-smoke.jar avpx.tools.MakeRelayKeys`, on the machine itself, so the secret is never anywhere else.
   - It prints three parts: the SECRET `staticKeys` block, which goes in `/etc/avpx/settings.json` and nowhere else; the PUBLIC keys; and the relay's **ID**, 96 hex digits.
   - The ID is public, and it's what the game checks the relay's keys against.
3. **The settings:** `/etc/avpx/settings.json`, as `deploy/settings.example.json` shows, with `"protocol": 2`, your `staticKeys`, your region's name, and `"accessFolder": "/var/lib/avpx"`. The pass key is a secret too: `openssl rand -hex 32`, made on the machine.
4. **Check it:** `java -jar avpx-smoke.jar --installed`. It's healthy when no line says FAIL, the last line is `<n> passed, 0 failed`, and its exit code is 0. It prints the relay's ID as the list gives it: that must be step 2's.
5. **Your servers.cfg line [BETA.2, the game's issue #175]:** the game ships a list of servers, one line each, with every field required: the server's address, the list's SPKI pin (step 1), and the relay's ID (step 2). Players add your line to their servers.cfg, or a release of the game carries it. The game repository's TAKING-OVER.md has the line's exact form. **A public server's address may go in a shipped file. A person's home address never does.**

**Deploys [BETA.2]:** the machine fetches its own deploys (a timer, so no key to it is kept anywhere else), and the first thing it runs is `deploy/check-blockers.sh`. Until that's built, deploy by hand, as deploy/README.md's "A test machine anywhere" says.

**Before it's open to the world, read SERVER-BLOCKERS.md.** It's the list of what must be done before a server is "in the wild", and `deploy/check-blockers.sh` refuses every deploy while it lists anything. If you take over and the list isn't empty, the items are yours to finish, and the rule stays: an item comes off only when it's done.

## 4. Approving players

Every player is approved by a person, always (the owner's ruling, 2026-11-09). There's no open mode, and the relay takes approved players only (CRYPTO.md section 6).

**How a player asks:** their game makes them an identity, and sends a request to your list (`POST /v1/access-requests`, PROTOCOL.md). The game then shows them an **access code**, 16 letters, the first 80 bits of their fingerprint. They give you that code by a way you know is them. **That code is what proves the request is theirs: approve no other.**

**How you answer:** the server keeps the requests in `/var/lib/avpx/requests.json`, and only the server writes that file. **Never edit it.** You answer by dropping a file of decisions in the same folder, which the server takes about a second later. The format is exact, and `java/src/avpx/access/AccessStore.java`'s header says all of it:
- each line is a fingerprint, a space, and `approved`, `refused`, `revoked` or `forgotten`; then a last line, `end <how many>`;
- it's written under another name first, then given the name `decisions.<digits>` without replacing anything;
- it's owned by the server's user, `avpx`, with no rights for anyone else;
- the moves the store allows: waiting to approved, refused or forgotten; refused to forgotten; approved to revoked. Nothing else, and a file with one bad line is refused whole.

**Our own tool for this is in this repository from the beta.2 release** (the owner's ruling, 2026-11-09), reviewed like everything else here. [BETA.2: its folder is named here when it lands; until then it's kept private.] Use it, or write your own from this description and AccessStore.java's header:
- It reads `requests.json` as hostile input: plain ASCII, the exact shape AccessStore.java writes, or it refuses it whole.
- It works inside `/var/lib/avpx` only as `avpx` (for instance with `setpriv`), never as root, since that folder is avpx's.
- It shows each request by its access code (code, state, when, name), and refuses a code that two requests share: a swapped key could look like that.
- It writes one decision file per answer, as above, then reads the store again and says whether each one took.

## 5. Signing what you release

This server isn't released to players as a program: it runs on your machine. What players run is the game, and the game repository's TAKING-OVER.md covers signing it with your own certificate. What this repository proves about itself is its gates (section 6), and its history: every commit's hash names its whole tree.

## 6. The gates: what each proves, and what can replace it

GATES.md lists the checks every change must pass, with branch protection holding them for everyone. A gate's tool may be gone by the time you read this. **The rule for that, which you keep:** a gate whose tool can't be reached **fails**, and says so, with "<tool> is unreachable: replace it with an equivalent, see TAKING-OVER.md". It never passes silently. [BETA.2: the server's gates say that; until then, a gate whose tool is gone simply fails.]

| Gate | What it proves | If its tool is gone |
|---|---|---|
| **Java tests** (java.yml) | the code does what its tests say, built with every warning an error, to the coding standard, the same bytes twice | Needs only the JDK. Runs on any machine: `sh java/build.sh` |
| **Java take-outs** | the tests notice every check in `takeouts.txt` being taken out | Ours, in this repository. Needs only the JDK |
| **Smoke test** | a running server answers every call as PROTOCOL.md says, from outside its process | Ours: `java/tools/Smoke.java`. Needs only the JDK |
| **The JDK is the newest Temurin 25** | the pinned JDK has no newer security release | Adoptium's API. If Adoptium is gone, pin another JDK by its sha256 and its maker's signing key, from a maker you trust, and keep this check's rule: a JDK with a newer security release fails |
| **CodeQL (Java)** | GitHub's static analysis finds nothing, and reads every .java file | Any open-source static analysis for Java that fails on a finding and on a file it can't read: SpotBugs with Find Security Bugs, or Semgrep's open rules |
| **Snyk** | Snyk Code finds nothing in the repository | Needs a Snyk token, which will have expired. Replace it with a second open-source static analysis, as for CodeQL. Two different tools see different things |
| **Server blockers** | `check-blockers.sh` refuses every deploy while SERVER-BLOCKERS.md lists anything | Ours. Plain sh and awk |
| **Deploy scripts** | the deploy scripts do what they say, tested with stand-ins | Ours. Plain sh |
| **Proofs (ProVerif)** | the handshakes' patterns keep their secrets and authenticate, by a formal proof (CRYPTO.md section 14, `proofs/`) | ProVerif, fetched from INRIA and checked by its sha256 (proofs.yml). If the address is gone, any copy of the same file, with that same sha256, is the same program. Archive it [BETA.2] |
| **Secret scanning** (GitHub's) | no key or token is pushed | gitleaks or TruffleHog, run before every push and as a check |
| **Branch protection** (GitHub's) | nothing reaches main without every gate, for everyone, admins too | On any other host: a protected main branch, with every gate required. On none at all: a rule you keep, that main moves only to a commit whose gates you ran and saw pass |

**Why there's no dependency scan:** the server has no package manager file and fetches no package, by design. CheckStandard's rule 2 proves it. The JDK is the only thing from outside, held by its pins.

## 7. When a key is lost or stolen

- **The relay's static keys:** make new ones (section 3, step 2), put them in the settings, restart. The relay's ID changes, so every servers.cfg line naming it changes. Until players have the new line, their games refuse your relay. That's the point: a stolen key stops working the day you change it.
- **The list's certificate key:** the same. A new key means a new SPKI pin in your servers.cfg line.
- **The pass key:** make a new one and restart.
- **A player's identity:** revoke them (section 4). A revoke ends their sessions at the relay's next turn. They make a new identity and ask again.

## 8. How the crypto gets upgraded

Version 2 is one suite, with nothing to choose and nothing to negotiate (CRYPTO.md section 2): ECDH P-384 with ML-KEM-1024, AES-256-GCM, SHA-384 and HKDF-SHA-384, with ECDSA P-384 and ML-DSA-87 for signatures. That's on purpose: there's no older, weaker choice for an attacker to push a game onto. So upgrading isn't a setting. It's a new version, done whole:

1. **A new design,** as CRYPTO.md is for version 2: the new suite, every byte of every message, every refusal, written before any code.
2. **A new version number.** Every message's header carries the protocol's magic and its version, so version 3 has a 3 there. Every label carries its version (`"AVPX split v2"`, `"AVPX epoch v2"`, `"AVPX relay keys v2"`, `"AVPX-ID-2"`), and version 3's say v3. So nothing made under one version can ever be taken for the other's.
3. **New vectors,** `test-vectors/crypto-v3.json`, made by a tool from fixed seeds, read by both the server's tests and the game's. That's how two programs in two languages are held to the same bytes.
4. **New proofs:** the formal models in `proofs/`, for the new handshakes, passing, with each half of the hybrid broken in turn (CRYPTO.md section 14).
5. **A machine runs one version at a time** (`"protocol"` in the settings). So while players move over, run a version 3 server beside the version 2 one, each with its own servers.cfg line. Retire version 2 by taking its line out of the game's shipped servers.cfg, then shutting it down.
6. **What a version never does:** accept another version's messages, or fall back to an older one. A game and a server of different versions refuse each other and say so (CRYPTO.md section 16).

**When to upgrade:** when one of the suite's parts is broken or weakened, by a standards body's word (NIST, or NSA's CNSA guidance this suite follows), not by rumour. The hybrid is there so that one half breaking alone doesn't break a session. That gives you time, not forever.

## 9. What you inherit, and what you replace

| Ours | Yours |
|---|---|
| our servers' keys and certificates | your own, made on your machine (section 3) |
| our approvals | your store starts empty: every player asks you |
| our GitHub settings, tokens and environments | your own host's, or the rules in section 6 |
| our names in the docs and the comments | leave them: they say who wrote what, and when |

Whatever you change, keep the rules this was built on: **security first**, and when it's in the way of anything else, security wins. **Input is hostile:** everything that comes from outside the code is checked before it's trusted. And **anyone after you must be able to do what this page let you do.**
