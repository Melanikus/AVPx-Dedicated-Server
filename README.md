# AVPx Dedicated Server

A small server for playing **AVPx** (the Aliens versus Predator port) over the internet: a **list** of games, and a **relay** that carries each game's packets between its players. With it, a player whose internet provider shares one public address between many homes (carrier-grade NAT), whom nobody can reach from outside, can still host.

> **Outline.** The parts below marked *to come* are written once the code is in.

## How it works

- `PROTOCOL.md` is the whole of what the server says and hears: every message, field and size, the list's HTTPS calls, a game's life from start to end, and the abuse limits.
- **The list (HTTPS):** a host puts its game on it, and players read it.
- **The relay (UDP):** the host and each joiner talk only to the relay, which passes the game's packets between them, unread and unchanged. Each joiner gets a relay port of its own.

## Two versions: Node and Java

The server is written twice, to one spec. Both speak PROTOCOL.md, byte for byte, and both read `test-vectors/relay-v1.json` in their own
tests, so any difference between them fails a check.
- **Node** (`relay/`, `list/`, `main.js`): the first version, and the reference. `node --test` runs its tests.
- **Java** (`java/`): the version the owner chose to keep, "for maintainability". It uses Java SE only: no library, and no build tool
  that fetches packages. `java/src/module-info.java` names no other module, so the compiler itself refuses anything but Java's own core.
  PORTING.md says how it was ported.
  - **What it needs:** the one JDK `java/tools/get-jdk.sh` fetches and checks (Temurin 25, by its signature, its sha256 and its
    version), and nothing else.
  - **Building it and running its tests:** `JAVA_HOME=<that JDK> sh java/build.sh`. That's plain javac and jar, with every warning an
    error. Add `AVPX_LIVE=1` for the tests that open real sockets, on 127.0.0.1 only. It makes `java/build/avpx-server.jar`, the same
    bytes every time for the same code.
  - **Running it:** `java -jar avpx-server.jar`. It reads `/etc/avpx/settings.json` (the same file and settings as the Node version),
    and nothing given on its command line. `deploy/README.md`, "The Java version", has the rest.
  - **Its code:** `java/src/avpx/relay/` (the relay: messages, passes, limits, the core, the UDP sockets), `java/src/avpx/list/` (the
    list: the strict JSON reader, requests, listings, the HTTPS server), `java/src/avpx/` (settings, the log, the start). The tests are in
    `java/test/`, each ported from the Node test of the same name. The checks are in GATES.md, "Java".

## The rules this is built to

- **Security first (AVP Tao 1).** Nothing third-party: no packages from npm or anywhere else. The scans gate every change (`GATES.md`, *to come*).
- **Everything that arrives is hostile (Tao 3).** Every field has a written limit, and anything else is dropped.
- **No IP addresses are written anywhere.** The logs are counts and times.
- **Built to be picked up decades from now (Tao 2).** The comments are in plain language, and there are tests from the first commit.

## Running it *(to come)*

- What it needs: the language's own runtime, from the operating system's signed packages, and nothing else.
- Running it on one machine, to try it: the list and the relay on the loopback address.
- The settings and their limits.
- Its tests, and what each one checks.

## Putting it on a server *(to come, nothing is deployed yet)*

- What to buy: a small VPS near the players (Sao Paulo), a domain, and a Let's Encrypt certificate. The owner buys these; nobody else ever handles payment details.
- The machine:
  - an unprivileged service user, and a systemd unit;
  - a firewall that opens 443/tcp, 80/tcp (Let's Encrypt only) and the relay's UDP ports, nothing more;
  - automatic security updates.
- Renewing the certificate.
- Reading its log, which holds no addresses.

## The game's side

The game's half (its "Find games" page, the list call, and the relay mode in its networking code) lives in the game's own repository, github.com/Melanikus/AvP.

## Reporting a security problem

Use GitHub's private vulnerability reporting on this repository, not a public issue.

## Licence *(to come: the owner's choice)*
