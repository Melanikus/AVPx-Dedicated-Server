# How AVPx Dedicated Server talks

Written 2026-11-08 by Melanikus. This is the whole of what the server says and hears, in any language it's written in. Change it only together with the code and its tests, and say why here.

**Changed 2026-11-08:** one list and a relay in each region, so the game plays well from Brazil, Europe and the Middle East. New: the round-trip message (`ECHO`), the pass that lets the list check a room on another machine, the relays' directory (`GET /v1/relays`), and the listing's region, level number, game style, co-op state and host's round trip. The protocol is as it was written at 7014de1; the code matches it from the commit after.

AVPx Dedicated Server is one program, and every machine runs the same code. Its settings say which parts a machine runs:

- **a relay,** over UDP, one in each region: it carries each game's packets between the host and every joiner. It's needed because many players can't be reached from the internet at all (carrier-grade NAT), and the game's network library, ENet, speaks only UDP.
- **the list,** over HTTPS, one for everyone: hosts put their games on it, and players read it to pick a game. The list runs on one of the relay machines.

The first relays are on AWS Lightsail: **`saopaulo`** (sa-east-1), **`virginia`** (us-east-1) and **`paris`** (eu-west-3). The list is on the `virginia` machine. A relay can be added (Tel Aviv, say) by starting one more machine and adding it to the list's settings; no game needs changing.

Everything that arrives is treated as hostile (AVP Tao 3). Every field has a written size, and anything not exactly as written here is dropped. No IP address is ever written to a log or a file (the user's ruling: "no IPs"). Everything the list shows is open for anyone to read, and it holds no personal data: no address, no player's name, nothing but what a host typed as its game's name.

## 1. A game's life, start to end

1. **The host picks a relay.** Its game reads the relays from `GET /v1/relays`, and measures its round trip to each with `ECHO` (section 2, Round trips). It takes the relay with the lowest time.
2. **The host asks that relay for a room.** From its game's own UDP socket, it sends `HOST_OPEN` to the relay's control port.
   - The relay answers with a `COOKIE` (section 3, Cookies).
   - The host asks again with the cookie. The relay answers `HOST_OPENED`, with the host's **token** (16 random bytes, the host's proof to the relay from then on), the game's **code** (8 letters), and a **pass** (section 3, Passes: the host's proof to the list that the room is real).
3. **The host puts the game on the list.** It sends `POST /v1/games` over HTTPS, with the relay's region, the code, the pass, and what the game is. The list answers with an **owner** key (16 random bytes, the host's proof to the list from then on).
4. **The host keeps the room, and the listing.** Every 15 s, from the same socket, it sends `HOST_KEEP` with its token. That keeps its NAT's door to the relay open and the room alive, and the relay's `HOST_KEPT` answer carries a fresh pass. Every 15 s too, the host sends `PUT /v1/games` with its owner key and the newest pass. That keeps its listing alive. The list and the relay may be on different machines, so each has its own keepalive.
5. **A player picks the game** from `GET /v1/games`, which says each game's relay region. Its game looks that region up in `GET /v1/relays`. A player who types a code instead: its game asks every relay, and only the one with that room answers `JOIN_PORT` (the rest answer `REFUSED`, reason 1).
6. **The joiner asks that relay to join.** It sends `JOIN` with the code to the control port, and gets a cookie first, as the host did.
   - The relay answers `JOIN_PORT`: a **ticket** (16 random bytes, the joiner's proof) and a relay port of its own for this joiner.
   - The relay tells the host `NEW_JOINER`, with that port.
7. **Both say hello on that port,** from their game's own socket: the host `HOST_HELLO` with its token, the joiner `JOINER_HELLO` with its ticket. That fixes, for the relay, where each one's packets come from through its NAT.
8. **When both have said hello,** the relay sends `READY` to the joiner. The joiner's game starts its ENet connection to that relay port. The relay then passes every packet between the two, unread and unchanged.
9. **The end.** A joiner's port is freed after 30 s with no packets, or 15 s after `JOIN_PORT` if both haven't said hello. The room ends on `HOST_CLOSE` with its token, or after 45 s with no `HOST_KEEP`; all its joiners' ports go with it. The listing ends on `DELETE /v1/games` with its owner key, or after 45 s with no good `PUT`. A host that closes its game does both.

**The game's own packets have no header added.** The relay port they come in on says which room and which joiner they're for. So the game's ENet packets are never changed, and the host's ENet sees each joiner as a peer of its own, because each comes from a relay port of its own.

## 2. The relay's messages (UDP)

Every message is exactly **64 bytes**, questions and answers alike, so the relay never answers with more than it was sent (no amplification). All numbers are little-endian.

| Bytes | Field | What it holds |
|---|---|---|
| 0-3 | magic | `AVPR` (0x41 0x56 0x50 0x52) |
| 4 | version | 1 |
| 5 | type | one of the table below |
| 6-7 | reserved | 0 |
| 8-23 | secret | a token, a ticket, a cookie, or an echo's 16 bytes |
| 24-31 | code | 8 code letters |
| 32-33 | port | a relay port |
| 34-35 | number | a reason or a count |
| 36-51 | pass | a pass (section 3, Passes) |
| 52-59 | pass time | when the pass was made: whole seconds since 1970-01-01 UTC |
| 60-63 | padding | 0 |

**Every field a type doesn't use (a blank in the table below) is 0.**

**Code letters:** `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`. That's 32 of them, with no 0, 1, I or O, so a code can be read aloud. A code is 8 of them, 40 bits.

**Not a message, and dropped:** not exactly 64 bytes; another magic or version; an unknown type; a reserved or padding byte not 0; a field its type doesn't use not 0; a code that's neither all code letters nor all 0; a pass time past 9,007,199,254,740,991 (2^53 - 1, the most a JSON number holds exactly; added 2026-11-08 as a fix, since the code and test-vectors/relay-v1.json already refused it).

| Type | Name | From, to | Secret | Code | Port | Number | Pass and pass time |
|---|---|---|---|---|---|---|---|
| 1 | HOST_OPEN | host to control | cookie, or 0 the first time | | | | |
| 2 | HOST_OPENED | relay to host | token | the game's | | | a fresh pass |
| 3 | HOST_KEEP | host to control | token | | | | |
| 4 | HOST_KEPT | relay to host | token | | | joiners now | a fresh pass |
| 5 | HOST_CLOSE | host to control | token | | | | |
| 6 | JOIN | joiner to control | cookie, or 0 the first time | the game's | | | |
| 7 | JOIN_PORT | relay to joiner | ticket | the game's | the joiner's relay port | | |
| 8 | NEW_JOINER | relay to host | token | | the joiner's relay port | | |
| 9 | HOST_HELLO | host to the joiner's port | token | | that port | | |
| 10 | JOINER_HELLO | joiner to its port | ticket | | | | |
| 11 | READY | relay, from the port, to the joiner | ticket | | that port | | |
| 12 | REFUSED | relay to the asker | | | | why: 1 no such game, 2 game full, 3 relay busy, 4 too many games from this address | |
| 13 | COOKIE | relay to the asker | the cookie | | | | |
| 14 | ECHO | anyone to control | 16 bytes the asker chose | | | the asker's count | |
| 15 | ECHO_BACK | relay to the asker | the same 16 bytes | | | the same count | |

**What happens to other packets:**
- The relay answers only the types a game sends it (1, 3, 5, 6, 9, 10 and 14). Any other type sent to it is dropped.
- On a joiner's port, any packet from its bound host or joiner that isn't a hello is game traffic, and is passed on.
- On a joiner's port, a hello from a new address with the right secret moves that end there: its NAT gave it a new port.
- Anything from anyone else is dropped.
- A game packet is at most 1,500 bytes; a bigger one is dropped.

### Round trips: choosing a relay

`ECHO` asks a relay to answer at once, so the asker can time the round trip.
- **The answer:** `ECHO_BACK`, with the asker's 16 bytes and count unchanged, sent from the control port to the address and port the `ECHO` came from, and nowhere else.
- **Its size:** 64 bytes in, 64 out, never bigger.
- **No cookie:** the relay keeps nothing for an echo, so nobody can make it hold anything with one.
- **Its limits:** an echo is a control message, so it counts in the same per-address and everyone limits as the rest (section 5). An echo over a limit gets no answer at all, not a `REFUSED`.
- **Two types, not one:** the answer is a different type from the question, and a relay drops any `ECHO_BACK` sent to it. So nobody can set two relays answering each other for ever, by sending one an echo with the other's address on it.

**How the game uses it:**
- **The host,** before it opens a room: it sends 3 echoes to every relay in `GET /v1/relays`, 100 ms apart, each with 16 fresh random bytes. It drops any answer whose bytes aren't ones it sent. It takes each relay's lowest time, leaves out a relay that hasn't answered within a second, and opens its room on the relay with the lowest time. It lists that time as `hostMs`.
- **A joiner,** for the games it shows: it measures its own time to each relay the same way, once a relay, not once a game. A game's **estimated ping** is the joiner's time to that game's relay plus the game's `hostMs`, because every packet goes from the host to the relay to the joiner. A game with `hostMs` 0 (not measured) shows only the joiner's own time.
- **This version picks the relay nearest the host.** The relay best for the whole group comes later (section 6).

## 3. Cookies and passes

### Cookies

A UDP sender can put anyone's address on its packets. So the two asks that make the relay keep something, `HOST_OPEN` and `JOIN`, must carry a cookie.
- **What a cookie is:** an HMAC-SHA-256 of the asker's address and port and a 10-second time slot, with a key only this run of the relay has, cut to 16 bytes.
- **How it's handed out:** the relay sends it to that address. Only someone who gets packets there can know it.
- **How long it's good for:** the slot it was made in and the next one, so 10 to 20 s.
- **What the relay keeps to check one:** nothing. It makes the cookie again. Its key changes every 24 hours.

### Passes

The list and a room's relay may be on different machines, in different countries. A pass is how the list knows a room is real without ever talking to the relay: no connection between the machines, and no port open between them.
- **What a pass is:** an HMAC-SHA-256, with the relay's **pass key**, of these bytes one after another: the 11 ASCII letters `AVPX-PASS-1`, the relay's region name in ASCII, one 0 byte, the room's code (8 bytes), and the pass time (8 bytes, little-endian). Cut to its first 16 bytes.
- **Who has the key:** each relay has its own, 32 random bytes, in its settings. The list's settings hold every relay's key. No key is in the repository.
- **How it's handed out:** the relay puts a fresh pass in every `HOST_OPENED` and `HOST_KEPT`, to the room's host only. A host that keeps its room every 15 s always has a pass less than 15 s old.
- **How the list checks one:** it makes the pass again from the region, code and pass time sent with it, and the key of the relay with that region. It's good for 60 s after its pass time. One whose pass time is more than 5 s ahead of the list's own clock is refused. The machines' clocks are kept to network time (NTP).
- **What a pass can't do:** it lets a host list one room, for a minute. It can't end a room, or open one, or reach a relay. A relay's pass key makes passes and nothing else, so a relay machine broken into could make passes only for its own region, and nothing at all on another relay.

## 4. The list (HTTPS)

Every call is HTTPS with TLS 1.2 or newer, and the server sends HSTS. The server listens on HTTPS only: getting the certificate (Let's Encrypt, through certbot) is that tool's own job, on the machine. JSON in and out, UTF-8, and only the fields named here; any other field, or one out of range, gets `400`.

| Call | Body | Answer |
|---|---|---|
| `GET /v1/relays` | none | `200 {"relays": [{"region", "host", "port"}]}`, at most 16 relays |
| `POST /v1/games` | `{"region", "code", "pass", "passTime", "name", "level", "mode", "gameStyle", "levelNumber", "coopLobby", "players", "maxPlayers", "version", "hostMs"}` | `201 {"owner"}`; `403` for a pass that isn't good; `409` if that game is listed already; `503` if the list is full |
| `PUT /v1/games` | `{"owner"}` and all of POST's fields | `204`, no body; `403` for a pass that isn't good, or the wrong owner; `404` if that game isn't listed |
| `DELETE /v1/games` | `{"region", "code", "owner"}` | `204`, no body; `403` for the wrong owner; `404` if that game isn't listed. The room itself stays until its host closes it, or stops keeping it. |
| `GET /v1/games?version=N` | none | `200 {"games": [{"region", "code", "name", "level", "mode", "gameStyle", "levelNumber", "coopLobby", "players", "maxPlayers", "version", "hostMs", "seconds"}]}`, at most 100 games, newest first |

A game is known to the list by its region and code together: two relays could, rarely, make the same code.

Any other status, and every `{"error"}` answer, means the call didn't work. The error's words are for the server's own tests and are never shown to a player: they come from the network.

**Fields:**
- **region:** 1 to 16 characters, small letters, digits and `-`, one of the regions in `GET /v1/relays`.
- **host:** a relay's DNS name, 1 to 63 characters, letters, digits, `-` and `.`. A name, never an address, so a relay can move to another machine without a game update.
- **port:** a relay's control port, 1 to 65535.
- **code:** 8 code letters (section 2).
- **pass:** 32 hex digits, small letters, from the newest `HOST_OPENED` or `HOST_KEPT` (section 3, Passes).
- **passTime:** a whole number, 0 to 9,007,199,254,740,991 (the most a JSON number holds exactly), from that same message.
- **owner:** 32 hex digits, small letters, from the `POST`'s answer. It travels only over HTTPS, between the list and the host.
- **name:** 1 to 32 characters, printable ASCII (0x20 to 0x7E). The only text a player types that the list shows.
- **level:** the level's name, 1 to 39 characters, the same letters. 39 is the longest the game's own level names go (`kLevelNameSize` - 1, networking.h).
- **mode:** the game style's name, for people to read, 1 to 32 characters, the same letters.
- **gameStyle:** the game's style number (the game's `NGT_` numbers), 0 to 255.
- **levelNumber:** 0 to 99 for a stock level, 100 for a custom one, which the game then finds by `level`.
- **coopLobby:** the game's co-op lobby state (coop_lobby.h), 0 to 255. With `gameStyle`, `levelNumber` and `level`, it's how a joiner's game picks the level it will load, which on a LAN comes from the session search.
- **players and maxPlayers:** whole numbers, 1 to 8, with players no more than maxPlayers.
- **version:** a whole number, 1 to 65535, the game's network version.
- **hostMs:** the host's round trip to its relay, in milliseconds, 1 to 9999; 0 if it wasn't measured (section 2, Round trips).
- **seconds:** how long the game has been listed, 0 to 31,536,000 (a year); a game listed longer still says a year.

**What a reader can hold the answer to:**
- **Its size:** an answer to `GET /v1/games` is at most 48 KB. The worst case, 100 games with every text at its longest and made of the characters JSON writes as two, and every number at its longest, is 41,111 bytes. An answer to `GET /v1/relays` is at most 4 KB (worst case, 16 relays: 1,868 bytes). A reader can refuse anything bigger.
- **Its escapes:** every text is printable ASCII, and for those JSON writes only two escapes, `\"` and `\\`. A reader can refuse any other escape (`\u`, `\n`, `\/` and the rest). The server's tests check both of these.

**Heartbeat and expiry:** a listing lives 45 s after its last good `POST` or `PUT`. A host `PUT`s every 15 s with its newest pass. A pass is good for 60 s, so a listing outlives its room by at most 105 s, and a joiner who tries it meanwhile gets `REFUSED` (reason 1).

**The list never holds an address.** A joiner gets only the region and the code, and joins through that region's relay.

**How a request is read** (added 2026-11-08 as a fix, so that every server that speaks this, in any language, refuses exactly the same requests; nothing an honest game sends is refused):
- **One request a connection.** Every answer says `Connection: close`, and the connection closes after it.
- **A body comes with one `Content-Length`.** A request with `Transfer-Encoding` gets `400`, and so does one with two `Content-Length`s. Headers over 8 KB get `431`.
- **A body is JSON, held to less than JSON allows:**
  - one object, with JSON's whitespace (space, tab, CR, LF) between its parts;
  - its values are strings or whole numbers, with no object or list inside it, and no `true`, `false` or `null`;
  - every byte of a string is printable ASCII, and its only escapes are `\"` and `\\`;
  - a number is `0`, or 1 to 16 digits with no leading `0`, at most 9,007,199,254,740,991, with no sign, fraction or exponent (`1.0`, `1e0`, `-1` and `01` are all refused);
  - no key appears twice. Readers differ on which of two keys counts, and two programs that read one body two ways can be made to disagree about what it said;
  - no key is `__proto__`, `constructor` or `prototype`. Those name parts of every JavaScript object, and a reader that wrote them into one could change how every other object behaves. No field here has those names, so every server refuses them, in any language (added 2026-11-09 as a fix, from a CodeQL finding). The Java server's words for it are "a field named __proto__, constructor or prototype, which name a part of every JavaScript object"; as with every refusal, the words are for the server's own tests, and never shown to a player.

  Anything else gets `400`.

## 5. The abuse limits

Every number is a starting point, written in one place in the code, and changed only with a reason here.

| What | Limit |
|---|---|
| A UDP packet to the relay | 1,500 bytes at most; a control message exactly 64 |
| Control messages from one address, echoes among them | 10 a second, 20 at once |
| Control messages from everyone, echoes among them | 2,000 a second, 4,000 at once |
| `REFUSED` answers to one address | 1 a second, 2 at once |
| Rooms on one relay | 500 in all; 2 for one address |
| Joiners in one room | 8 |
| Joins to one room | 4 a second, 8 at once |
| Hellos on one joiner's port | 20 a second, 40 at once |
| Game traffic on one joiner's port, each way | 400 packets a second (800 at once), and 256 KB a second (512 KB at once) |
| A joiner's port waiting for both hellos | 15 s |
| A joiner's port with no traffic | 30 s |
| A room with no `HOST_KEEP` | 45 s |
| A pass | good 60 s after its pass time; refused if its pass time is more than 5 s ahead |
| Listings | 2,000 in all |
| A listing with no good `POST` or `PUT` | 45 s |
| Relays the list names | 16 |
| Addresses the per-address limits remember | 10,000; the one heard from longest ago is forgotten first |
| An HTTPS request | headers 8 KB, body 1 KB; 5 s to send the headers and 5 s for the body |
| HTTPS connections | 200 at once in all, 10 from one address |
| HTTPS requests from one address | 5 a second, 20 at once; `GET /v1/games` and `GET /v1/relays` 1 a second, 5 at once |
| HTTPS requests from everyone | 500 a second, 1,000 at once (in the code from the start; added to this table 2026-11-08 as a fix) |
| An HTTPS connection's TLS handshake | 5 s |

**How addresses are told apart without keeping them:** a per-address limit keys by an HMAC-SHA-256 of the address, with a random key that changes every 24 hours and is never written anywhere. The address itself lives in memory only while a room or a port needs it.

**The log:** once a minute, counts and times only:
- rooms opened, closed and expired;
- joins and refusals;
- echoes answered;
- listings made, ended and expired, and passes refused;
- packets and bytes passed on;
- drops by reason;
- rooms and ports in use.

Never an address, a code, a token, a ticket, a pass, an owner key or a name.

## 6. Known limits of this version

- **Neither the relay's UDP messages nor the game's own packets are encrypted.** Someone on the path between a player and the relay can read and change them, as with playing by typed IP today. A later version could sign the hellos with a key handed over the list's HTTPS.
- **A pass seen on the path can be used by whoever saw it,** for its minute, to list that room before its host does. It can't change or take down a listing already there: that needs the owner key, which travels only over HTTPS. This goes when the relay's messages are encrypted.
- **The host picks the relay nearest itself,** not the one best for the whole group. Picking for the group comes later.
- **A typed code is asked of every relay,** because the code alone doesn't say which relay has the room.
- **What a listing says is the host's word.** Its name, players, level and round trip are shown to players and used to pick a level, never trusted for anything else.
- **Every game goes through a relay.** Hole punching, a direct path when both players' NATs allow it, comes later, with the relay as the fallback.
- **IPv4 only, as the game's ENet is.**
