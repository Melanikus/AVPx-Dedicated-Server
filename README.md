# AVPx Dedicated Server

A small server for playing **AVPx** (the Aliens versus Predator port) over the internet: a **list** of games, and a **relay** that carries each game's packets between its players. With it, a player whose internet provider shares one public address between many homes (carrier-grade NAT), whom nobody can reach from outside, can still host.

> **Outline.** The parts below marked *to come* are written once the code is in.

## How it works

- `PROTOCOL.md` is the whole of what the server says and hears: every message, field and size, the list's HTTPS calls, a game's life from start to end, and the abuse limits.
- **The list (HTTPS):** a host puts its game on it, and players read it.
- **The relay (UDP):** the host and each joiner talk only to the relay, which passes the game's packets between them, unread and unchanged. Each joiner gets a relay port of its own.

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
