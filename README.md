# AVPx Dedicated Server

A small server for playing **AVPx** (the Aliens versus Predator port) over the internet: a **list** of games, and a **relay** that carries each game's packets between its players. With it, a player whose internet provider shares one public address between many homes (carrier-grade NAT), whom nobody can reach from outside, can still host.

**It isn't running anywhere public yet.** SERVER-BLOCKERS.md says what must be done first, and no deploy runs while it lists anything.

## How it works

- **PROTOCOL.md** is the whole of what the server says and hears: every message, field and size, the list's HTTPS calls, a game's life from start to end, and the abuse limits. **CRYPTO.md** is the next version, sealed end to end and post-quantum, being built.
- **The list (HTTPS):** a host puts its game on it, and players read it.
- **The relay (UDP):** the host and each joiner talk only to the relay, which passes the game's packets between them, unread and unchanged. Each joiner gets a relay port of its own.
- **The server is Java** (`java/`), with Java SE only: no library, and no build tool that fetches packages.
  - `java/src/avpx/relay/` holds the relay: messages, passes, limits, the core and the UDP sockets.
  - `java/src/avpx/list/` holds the list: the strict JSON reader, requests, listings and the HTTPS server.
  - `java/src/avpx/` holds the settings, the log and the start.
  - The tests are in `java/test/`, and the tools (the coding standard, the take-outs, the smoke test, get-jdk.sh) in `java/tools/`.

## Quick start: run it on your own Linux machine

Everything here stays on your machine: the server listens on 127.0.0.1 only, and the certificate is a throwaway one for `localhost`.

1. **The JDK.** The server is built and run with one JDK only, which this fetches and checks (its signature by Adoptium's key, its sha256 and its version) before anything runs it. It needs `curl`, `gpg`, `sha256sum` and `tar`.
   ```
   sh java/tools/get-jdk.sh "$HOME/avpx-jdk"
   export JAVA_HOME="$HOME/avpx-jdk"
   ```
2. **Build it, and run every test.** It's plain javac and jar, with every warning an error:
   ```
   sh java/build.sh
   ```
   Add `AVPX_LIVE=1` in front to include the tests that open real sockets, on 127.0.0.1 only. It makes `java/build/avpx-server.jar` and `java/build/avpx-smoke.jar`, the same bytes every time for the same code.
3. **A throwaway certificate,** in a folder of its own, never committed:
   ```
   mkdir -p "$HOME/avpx-try" && cd "$HOME/avpx-try"
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout list-test-key.pem -out list-test.pem -days 1 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth"
   ```
4. **The settings.** The server reads `/etc/avpx/settings.json`, and nothing given on its command line, so nothing can point it at another file. So this step needs root. Make a pass key with `openssl rand -hex 32`, and write the file with that key, and your folder in place of `/home/you/avpx-try`:
   ```
   {
     "region": "virginia",
     "passKey": "PASS_KEY",
     "relayAddress": "127.0.0.1",
     "controlPort": 27500,
     "relayPorts": "27501-27564",
     "logFile": "/home/you/avpx-try/server.log",
     "list": {
       "address": "127.0.0.1",
       "port": 8443,
       "certFile": "/home/you/avpx-try/list-test.pem",
       "keyFile": "/home/you/avpx-try/list-test-key.pem",
       "relays": [{ "region": "virginia", "host": "localhost", "port": 27500 }]
     }
   }
   ```
   `deploy/settings.example.json` has every setting.
5. **Run it:** `"$JAVA_HOME/bin/java" -jar java/build/avpx-server.jar`. It says what it listens on. Ctrl+C stops it.
6. **Check it works,** from another terminal, in the certificate's folder (the smoke test finds `list-test.pem` and `server.log` there):
   ```
   cd "$HOME/avpx-try" && "$JAVA_HOME/bin/java" -jar /path/to/repo/java/build/avpx-smoke.jar
   ```
   It plays a whole game through the server from outside it: the list, a room, a joiner, 100 packets each way, hostile packets refused, and the log holding no address. Then it prints its 38 checks, each `PASS` or `FAIL`, and exits 0 only if all pass. The settings above are the ones it expects.

## The rules this is built to

- **Security first (AVP Tao 1).** Nothing third-party, and nothing precompiled. Every change passes every gate (GATES.md): the tests, the coding standard, the take-outs, the smoke test, CodeQL and Snyk.
- **Everything that arrives is hostile (Tao 3).** Every field has a written limit, and anything else is refused.
- **No IP addresses are written anywhere.** The logs are counts and times.
- **Built to be picked up decades from now (Tao 2).** The comments are in plain words (CODING-STANDARD.md), and every limit has a test that would notice it going.

## Putting it on a machine

`deploy/README.md`: a test machine by hand, step by step, and later the public machine, deployed by GitHub through AWS Systems Manager with no key stored anywhere, after the owner approves each deploy.

## The game's side

The game's half (its "Find games" page, the list call, and the relay mode in its networking code) lives in the game's own repository, github.com/Melanikus/AvP.

## Writing it in another language

PORTING.md: the spec in the order to read it, the tests to port first, and the traps.

## Reporting a security problem

Use GitHub's private vulnerability reporting on this repository (Security, "Report a vulnerability"), never a public issue.

## Licence *(to come: the owner's choice)*
