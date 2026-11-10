# Taking over: running this server when we're gone

Written 2026-11-09 by Melanikus, at the owner's word: "20 years from now, we won't be there to enforce tao 1, our keys and tokens will have expired, be mindful of that".

**Who this is for:** you, years from now, with this repository and none of our accounts, keys or tokens. Nobody can give you permission, and you don't need it. This page is how you become the one who decides who plays: **the trust root**.

**What "the trust root" means here:** whoever holds a server's keys and approves its players decides who can play on it, and nobody else does. The game trusts a server only through what it carries in its own files: one line in servers.cfg with the server's address and a fingerprint of its two keys, the list's certificate key and the relay's keys (section 3, step 5). None of it depends on us being there. When you make your own keys and your own servers.cfg line, your server is as trusted as ours ever was, by the copies of the game that carry your line.

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

1. **The list's certificate key.** The list is reached over HTTPS, and the game trusts it by the key of its certificate (its SPKI), not by any company that signs certificates. deploy/README.md says how, in "The list's key".
   - Make the key once, on the machine, and keep it: root's and avpx's to read, never copied off the machine.
   - Make a certificate from it. Make each new certificate from the same key, so the games that carry your line still trust it.
   - If the key is ever stolen or lost, make a new one. Your servers.cfg line changes, and the players need it again (section 7).
   - **The game trusts the key alone** (the owner's ruling, 2026-11-09). It ignores the certificate's dates, its name and its issuer, and checks only that the key is the one in your line's fingerprint. **Why:** a date can only end a server, never save one. In 20 years nobody may be there to make a new certificate, and a date would stop every copy of the game reaching the server on that day, for good, with the key still safe. A key that's stolen or changed is answered by a new key and a new servers.cfg line (section 7), and for a server a release ships, by a new release. So the certificate's dates don't matter to the game: make it last as long as your tools allow.
2. **The relay's static keys:** `java -cp avpx-smoke.jar avpx.tools.MakeRelayKeys`, on the machine itself, so the secret is never anywhere else.
   - It prints three parts: the SECRET `staticKeys` block, which goes in `/etc/avpx/settings.json` and nowhere else; the PUBLIC keys; and the relay's **ID**, 96 hex digits.
   - The ID is public, and it's what the game checks the relay's keys against.
3. **The settings:** `/etc/avpx/settings.json`, as `deploy/settings.example.json` shows, with `"protocol": 2`, your `staticKeys`, your region's name, and `"accessFolder": "/var/lib/avpx"`. The pass key is a secret too: `openssl rand -hex 32`, made on the machine.
4. **Check it:** `java -jar avpx-smoke.jar --installed`. It's healthy when no line says FAIL, the last line is `<n> passed, 0 failed`, and its exit code is 0. It prints the relay's ID as the list gives it: that must be step 2's.
5. **Your servers.cfg line** (the game's issue #175, the owner's rulings of 2026-11-10): the game's whole list of servers is one file, `servers.cfg`, beside its `bin` folder, with one short line a server:

       address  fingerprint  name

   - **address:** the server's public IPv4 address. The list is at port 443 and the relay's control port at 27500, unless the line says `address:listport:relayport`.
   - **fingerprint:** 64 lowercase hex digits: the SHA-256 of the text `AVPx servers.cfg line 1`, one zero byte, your list certificate's public key (its SubjectPublicKeyInfo, as DER, from step 1) and your relay's 48-byte ID (step 2; CRYPTO.md section 12.1). One number covers both keys (java/src/avpx/list/ServersLine.java makes it; CRYPTO.md section 12.2 has its known answer). The game checks it against what your list serves before it sends your server anything else.
   - **name:** what players see, 1 to 31 plain characters.

   `java -jar avpx-smoke.jar --installed --servers-line <a name for it> <its public IPv4 address>` prints your line. It takes the key from the certificate the list serves and the ID from your settings' keys, and it refuses, printing nothing, if they disagree. [BETA.2: the game's side, which reads the line.]

   **How players switch to your server:** there's no server discovery, so you tell them: "open servers.cfg in the game folder with Notepad, replace the line (or add yours under it), save". Then each asks you for access (section 4). A new release of the game replaces servers.cfg when it's unzipped, so anyone who edited it keeps a copy first. **A public server's address may go in a shipped file. A person's home address never does.**

**Deploys:** the machine fetches its own (deploy/README.md, "The machine fetches its own deploys"), so no key to it is kept anywhere else. A timer runs `deploy/pull-deploy.sh` every 5 minutes. It takes a deploy only if:
- GitHub recorded it, from a Deploy run started by hand from `main` that succeeded;
- you approved that run's `production` environment, by your login and your number;
- the commit is on `main`;
- `main`'s SERVER-BLOCKERS.md lists nothing, checked before anything is built or installed.

Then remote-deploy.sh builds it with no rights and no network, takes the jars only if they're GitHub's, switches, health-checks, and rolls back on any failure. **A deploy never changes the two scripts that decide what runs as root:** only what you installed by hand does. **Without the timer** (`systemctl disable --now avpx-pull.timer`), the server runs exactly as before, and you deploy by hand, as "A test machine anywhere" says. When you take over, pull-deploy.sh names the owner by GitHub login and number: it's yours to change, and install again by hand.

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

GATES.md lists the checks every change must pass, with branch protection holding them for everyone. A gate's tool may be gone by the time you read this. **The rule for that, which you keep:** a gate whose tool can't be reached **fails**, and says so, with "<tool> is unreachable: replace it with an equivalent, see TAKING-OVER.md". It never passes silently. The server's gates do say it, and a step in each proves they would: get-jdk.sh with every download sent nowhere, Snyk out of reach, CodeQL with no results file, and ProVerif missing, stopping, silent, or saying yes to everything (java.yml, snyk.yml, proofs.yml).

| Gate | What it proves, and what it doesn't | If its tool is gone |
|---|---|---|
| **Java tests** (java.yml) | javac with every warning an error; every unit test, and every live test on 127.0.0.1; CheckStandard's rules over the whole repository (ASCII only, no compiled code, no build file that fetches packages, actions pinned by hash, every test registered); and the jars built twice, on two file systems, byte for byte the same. **Proves** the code does what its tests say, and that a build is reproducible, which is what lets a machine check the jars it's sent against its own. **Doesn't prove** the tests would notice a fault: that's the take-outs | Needs only the JDK. Runs on any machine: `sh java/build.sh` |
| **Java take-outs** | each row of `takeouts.txt` breaks one thing (a check, a limit, a refusal) in a copy, and the check it names must fail; one "not noticed" fails the gate. **Proves** the tests aren't decoration: every guarded rule has a test that notices it gone. A row on a check that only Linux has (owners, modes, links) proves itself only on a Linux machine | Ours, in this repository. Needs only the JDK |
| **Smoke test** | the real server, started from its jar, talked to from outside its process: version 1's whole game, and version 2's relay and list, with access asked and approved through the real store and a decisions file. **Proves** the jar runs as deployed: the whole sealed game, a player nobody approved refused, and the relay's keys as the list gives them equal to its settings' | Ours: `java/tools/Smoke.java`. Needs only the JDK |
| **The JDK is the newest Temurin 25** | the newest release of the JDK's maker, against get-jdk.sh's pin. **Proves** nobody is left on a JDK with a known hole. It fails every quarter, by design, until the pin moves | Adoptium's API. If Adoptium is gone, pin another JDK by its sha256 and its maker's signing key, from a maker you trust, and keep this check's rule: a JDK with a newer security release fails |
| **CodeQL (Java)** | GitHub's static analysis, its security-and-quality queries, failing on any result, and on any .java file it didn't read. **Proves** no known pattern of bug is in the code | Any open-source static analysis for Java that fails on a finding and on a file it can't read: SpotBugs with Find Security Bugs, or Semgrep's open rules |
| **Snyk** | Snyk Code over the whole repository, at any severity. **Proves** a second analyser agrees. It's the one gate that needs a paid account: without its token, it fails, never passes | Needs a Snyk token, which will have expired. Replace it with a second open-source static analysis, as for CodeQL. Two different tools see different things |
| **Server blockers** | `test-check-blockers.sh`. **Proves** the refusal works; a deploy itself refuses while SERVER-BLOCKERS.md lists anything | Ours. Plain sh and awk |
| **Deploy scripts** | the machine's side of a deploy (remote-deploy.sh, and the pull route, pull-deploy.sh, against hostile answers from GitHub), the firewall scripts and deploy.yml's shape, each tested with stand-ins: no machine, no network, no GitHub. **Proves** they refuse what they should | Ours. Plain sh |
| **Proofs (ProVerif)** | every model in `proofs/`, as written and with each half of the hybrid broken in turn, against an attacker who owns the network (CRYPTO.md section 14). **Proves** the handshakes' patterns keep their secrets and authenticate their parties with either half broken; with both broken they must fail, so the model isn't true for nothing. **Doesn't prove** our code: the test vectors and tests hold it to the pattern. **Hasn't passed yet:** pqik's queries 2 and 3 and pqxx's don't end on the standard runner (GATES.md). A bigger runner wouldn't help: GitHub stops every job at 6 hours, and the measures show time, not memory, is what they lack. The fix is in the models | ProVerif, fetched from INRIA and checked by its sha256 (proofs.yml). If the address is gone, any copy of the same file, with that same sha256, is the same program. Archive it [BETA.2] |
| **Secret scanning** (GitHub's) | no key or token is pushed | gitleaks or TruffleHog, run before every push and as a check |
| **Branch protection** (GitHub's) | nothing reaches main without every gate, for everyone, admins too | On any other host: a protected main branch, with every gate required. On none at all: a rule you keep, that main moves only to a commit whose gates you ran and saw pass |

**Why there's no dependency scan:** the server has no package manager file and fetches no package, by design. CheckStandard's rule 2 proves it. The JDK is the only thing from outside, held by its pins.

**Where the trust sits, for you to replace** (Primary, 2026-11-09):
- **GitHub:** the hosting, Actions, the deployment records, and the owner's approval of each deploy.
- **Adoptium's signing key,** pinned by its fingerprint in get-jdk.sh.
- **Snyk's account:** a gate only, never anything the running server needs.
- **The owner's GitHub account,** named by its login and by its numeric id, in the pull route's script, `deploy/pull-deploy.sh`.

**The running server depends on none of these.** With the pull route's timer off, it runs, and it's deployed by hand (deploy/README.md, "A test machine anywhere"). So losing all four stops new deploys being checked by them, never the server itself.

## 7. When a key is lost or stolen

- **The relay's static keys:** make new ones (section 3, step 2), put them in the settings, restart. The relay's ID changes, so every servers.cfg line naming it changes. Until players have the new line, their games refuse your relay. That's the point: a stolen key stops working the day you change it.
- **The list's certificate key:** the same. A new key means a new fingerprint in your servers.cfg line.
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
