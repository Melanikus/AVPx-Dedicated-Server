# How AVPx Dedicated Server talks

Written 2026-11-08 by Melanikus. This is the whole of what the server says and hears, in any language it's written in. Change it only together with the code and its tests, and say why here.

The server has two parts on one machine:

- **the list,** over HTTPS: hosts put their games on it, and players read it to pick a game;
- **the relay,** over UDP: it carries each game's packets between the host and every joiner. It's needed because many players can't be reached from the internet at all (carrier-grade NAT), and the game's network library, ENet, speaks only UDP.

Everything that arrives is treated as hostile (AVP Tao 3). Every field has a written size, and anything not exactly as written here is dropped. No IP address is ever written to a log or a file (the user's ruling: "no IPs").

## 1. A game's life, start to end

1. **The host asks for a room.** From its game's own UDP socket, it sends `HOST_OPEN` to the relay's control port.
   - The relay answers with a `COOKIE` (section 3, Cookies).
   - The host asks again with the cookie. The relay answers `HOST_OPENED`, with the host's **token** (16 random bytes, the host's proof from then on) and the game's **code** (8 letters).
2. **The host puts the game on the list.** It sends `POST /v1/games` over HTTPS, with its token, the game's name, level and mode. Only a host with a live room can.
3. **The host keeps the room.** It sends `HOST_KEEP` with its token every 15 s, from the same socket. That keeps its NAT's door to the relay open, and keeps the room and its list entry alive.
4. **A player picks the game** from `GET /v1/games`, or types its code.
5. **The joiner asks to join.** It sends `JOIN` with the code to the control port, and gets a cookie first, as the host did.
   - The relay answers `JOIN_PORT`: a **ticket** (16 random bytes, the joiner's proof) and a relay port of its own for this joiner.
   - The relay tells the host `NEW_JOINER`, with that port.
6. **Both say hello on that port,** from their game's own socket: the host `HOST_HELLO` with its token, the joiner `JOINER_HELLO` with its ticket. That fixes, for the relay, where each one's packets come from through its NAT.
7. **When both have said hello,** the relay sends `READY` to the joiner. The joiner's game starts its ENet connection to that relay port. The relay then passes every packet between the two, unread and unchanged.
8. **The end.** A joiner's port is freed after 30 s with no packets, or 15 s after `JOIN_PORT` if both haven't said hello. The room ends:
   - on `HOST_CLOSE` with its token;
   - on `DELETE /v1/games`;
   - or after 45 s with no `HOST_KEEP`.

   When the room ends, its list entry and all its joiners' ports go with it.

**The game's own packets have no header added.** The relay port they come in on says which room and which joiner they're for. So the game's ENet packets are never changed, and the host's ENet sees each joiner as a peer of its own, because each comes from a relay port of its own.

## 2. The relay's messages (UDP)

Every message is exactly **64 bytes**, questions and answers alike, so the relay never answers with more than it was sent (no amplification). All numbers are little-endian.

| Bytes | Field | What it holds |
|---|---|---|
| 0-3 | magic | `AVPR` (0x41 0x56 0x50 0x52) |
| 4 | version | 1 |
| 5 | type | one of the table below |
| 6-7 | reserved | 0 |
| 8-23 | secret | a token, a ticket or a cookie (16 bytes), or all 0 |
| 24-31 | code | 8 code letters, or all 0 |
| 32-33 | port | a relay port, or 0 |
| 34-35 | number | a reason or a count, or 0 |
| 36-63 | padding | 0 |

**Code letters:** `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`. That's 32 of them, with no 0, 1, I or O, so a code can be read aloud. A code is 8 of them, 40 bits.

**Not a message, and dropped:** not exactly 64 bytes; another magic or version; an unknown type; a reserved or padding byte not 0; a code that's neither all code letters nor all 0.

| Type | Name | From, to | Secret | Code | Port | Number |
|---|---|---|---|---|---|---|
| 1 | HOST_OPEN | host to control | cookie, or 0 the first time | | | |
| 2 | HOST_OPENED | relay to host | token | the game's | | |
| 3 | HOST_KEEP | host to control | token | | | |
| 4 | HOST_KEPT | relay to host | token | | | joiners now |
| 5 | HOST_CLOSE | host to control | token | | | |
| 6 | JOIN | joiner to control | cookie, or 0 the first time | the game's | | |
| 7 | JOIN_PORT | relay to joiner | ticket | the game's | the joiner's relay port | |
| 8 | NEW_JOINER | relay to host | token | | the joiner's relay port | |
| 9 | HOST_HELLO | host to the joiner's port | token | | that port | |
| 10 | JOINER_HELLO | joiner to its port | ticket | | | |
| 11 | READY | relay, from the port, to the joiner | ticket | | that port | |
| 12 | REFUSED | relay to the asker | | | | why: 1 no such game, 2 game full, 3 relay busy, 4 too many games from this address |
| 13 | COOKIE | relay to the asker | the cookie | | | |

**What happens to other packets:**
- On a joiner's port, any packet from its bound host or joiner that isn't a hello is game traffic, and is passed on.
- On a joiner's port, a hello from a new address with the right secret moves that end there: its NAT gave it a new port.
- Anything from anyone else is dropped.
- A game packet is at most 1,500 bytes; a bigger one is dropped.

## 3. Cookies

A UDP sender can put anyone's address on its packets. So the two asks that make the relay keep something, `HOST_OPEN` and `JOIN`, must carry a cookie.
- **What a cookie is:** an HMAC-SHA-256 of the asker's address and port and a 10-second time slot, with a key only this run of the relay has, cut to 16 bytes.
- **How it's handed out:** the relay sends it to that address. Only someone who gets packets there can know it.
- **How long it's good for:** the slot it was made in and the next one, so 10 to 20 s.
- **What the relay keeps to check one:** nothing. It makes the cookie again. Its key changes every 24 hours.

## 4. The list (HTTPS)

Every call is HTTPS with TLS 1.2 or newer. On port 80 there's only Let's Encrypt's check and a redirect to HTTPS, and the server sends HSTS. JSON in and out, UTF-8, and only the fields named here; any other field, or one out of range, gets `400`.

| Call | Body | Answer |
|---|---|---|
| `POST /v1/games` | `{"token", "name", "level", "mode", "players", "maxPlayers", "version"}` | `201 {"code"}`; `403` for no room with that token; `409` if it's listed already |
| `PUT /v1/games` | the same | `200`; `403` for no room with that token |
| `DELETE /v1/games` | `{"token"}` | `204`; the room ends too |
| `GET /v1/games?version=N` | none | `200 {"games": [{"code", "name", "level", "mode", "players", "maxPlayers", "version", "seconds"}]}`, at most 100 games, newest first |

**Fields:**
- **token:** 32 hex digits, the room's token from `HOST_OPENED`.
- **name:** 1 to 32 characters, printable ASCII (0x20 to 0x7E).
- **level and mode:** 1 to 32 characters each, the same letters.
- **players and maxPlayers:** whole numbers, 1 to 8, with players no more than maxPlayers.
- **version:** a whole number, 1 to 65535, the game's network version.
- **seconds:** how long the game has been listed.

**Heartbeat and expiry:** a game's list entry lives exactly as long as its room. The room's `HOST_KEEP` is the heartbeat. A room unkept for 45 s ends, and so does its entry.

**The list never holds an address.** A joiner gets only the code, and joins through the relay.

## 5. The abuse limits

Every number is a starting point, written in one place in the code, and changed only with a reason here.

| What | Limit |
|---|---|
| A UDP packet to the relay | 1,500 bytes at most; a control message exactly 64 |
| Control messages from one address | 10 a second, 20 at once |
| Control messages from everyone | 2,000 a second, 4,000 at once |
| `REFUSED` answers to one address | 1 a second, 2 at once |
| Rooms | 500 in all; 2 for one address |
| Joiners in one room | 8 |
| Joins to one room | 4 a second, 8 at once |
| Hellos on one joiner's port | 20 a second, 40 at once |
| Game traffic on one joiner's port, each way | 400 packets a second (800 at once), and 256 KB a second (512 KB at once) |
| A joiner's port waiting for both hellos | 15 s |
| A joiner's port with no traffic | 30 s |
| A room with no `HOST_KEEP` | 45 s |
| Addresses the per-address limits remember | 10,000; the one heard from longest ago is forgotten first |
| An HTTPS request | headers 8 KB, body 1 KB; 5 s to send the headers and 5 s for the body |
| HTTPS connections | 200 at once in all, 10 from one address |
| HTTPS requests from one address | 5 a second, 20 at once; `GET /v1/games` 1 a second, 5 at once |

**How addresses are told apart without keeping them:** a per-address limit keys by an HMAC-SHA-256 of the address, with a random key that changes every 24 hours and is never written anywhere. The address itself lives in memory only while a room or a port needs it.

**The log:** once a minute, counts and times only:
- rooms opened, closed and expired;
- joins and refusals;
- packets and bytes passed on;
- drops by reason;
- rooms and ports in use.

Never an address, a code, a token, a ticket or a name.

## 6. Known limits of this version

- **Neither the relay's UDP messages nor the game's own packets are encrypted.** Someone on the path between a player and the relay can read and change them, as with playing by typed IP today. A later version could sign the hellos with a key handed over the list's HTTPS.
- **Every game goes through the relay.** Hole punching, a direct path when both players' NATs allow it, comes later, with the relay as the fallback.
- **IPv4 only, as the game's ENet is.**
