# Porting the server to another language

Written 2026-11-08 by Melanikus, for the Java version (Primary) and for anyone after. The Node code here is the reference. A port is right when it passes the same tests, reads the same test vectors, and refuses the same things for the same reasons.

## 1. The spec, in the order to port it

1. **PROTOCOL.md** (version 1, as at 7014de1 plus the section 4 and 5 fixes of 9f8dd70). **CRYPTO.md** is version 2, a design not yet built.
2. **test-vectors/relay-v1.json:** read it in the port's own tests. Every message must read back as its fields, every refused entry must be refused, and every pass must come out the same.
3. **The tests, file by file.** Port these first, line for line, and only then the code:

| Test file | What it holds the code to |
|---|---|
| test/protocol.test.js | the 64-byte layout, the USES table row for row, every unused field refused, the pass HMAC byte for byte, region names |
| test/vectors.test.js | the vectors file (a port reads it; it doesn't write it) |
| test/core.test.js | a game's whole life, cookies, every cap and limit, hellos, NAT moves, echo, passes in HOST_OPENED/HOST_KEPT, expiry, the log line, a fuzz of 2,000 junk packets |
| test/limits.test.js | token buckets, the address hasher, the per-sender memory |
| test/strict-json.test.js | the body reader: every rule both ways, agreement with a plain JSON reader on bodies it takes, 5,000 junk bodies |
| test/list.test.js | every list call, the pass checks, the owner key, expiry, the caps, the exact worst-case sizes (41,111 and 1,868 bytes), every field limit |
| test/settings.test.js | every setting and its refusal, the example file refused until filled in |
| test/live.test.js | real sockets on 127.0.0.1 only, run only with AVPX_LIVE=1 |

4. **tools/takeouts.json:** the take-out idea, not its rows. The rows are Node text, so a port writes its own, one for each Node row: each breaks one thing, and a test must notice.

## 2. Where every limit lives (Node)

| File | Names |
|---|---|
| relay/core.js `DEFAULTS` | mostGames 500, mostGamesPerSender 2, mostJoinersPerGame 8, gameLifeMilliseconds 45000, pendingMilliseconds 15000, idleMilliseconds 30000, mostDatagramBytes 1500, cookieSlotMilliseconds 10000, controlRate/Burst 10/20, everyoneRate/Burst 2000/4000, refusalRate/Burst 1/2, joinRate/Burst 4/8, helloRate/Burst 20/40, portPacketRate/Burst 400/800, portByteRate/Burst 256 KB/512 KB, mostSenders 10000, statsMilliseconds 60000 |
| relay/limits.js | kKeyLifeMilliseconds (24 h) |
| relay/protocol.js | kMessageBytes 64, kSecretBytes 16, kCodeBytes 8, kCodeLetters, TYPE, REFUSED_WHY, USES |
| relay/pass.js | kPassBytes 16, kPassKeyBytes 32, the label AVPX-PASS-1, kRegionPattern |
| list/requests.js | kMostBodyBytes 1024, kMostTextLength 32, kMostLevelLength 39, kMostPlayers 8, kMostVersion 65535, kMostGameStyle 255, kMostLevelNumber 100, kMostCoopLobby 255, kMostHostMilliseconds 9999 |
| list/strict-json.js | kMostDigits 16 |
| list/listings.js | kMostListings 2000, kListingLifeMilliseconds 45000, kPassLifeMilliseconds 60000, kMostPassAheadMilliseconds 5000, kOwnerBytes 16, kStatsMilliseconds 60000 |
| list/routes.js | kMostGames 100, kMostSeconds 31536000, kMostListBytes 48 KB, kMostRelaysBytes 4 KB |
| list/https.js `LIMITS` | mostHeaderBytes 8 KB, handshakeMilliseconds 5000, headersMilliseconds 5000, requestMilliseconds 10000, checkMilliseconds 1000, mostConnections 200, mostConnectionsPerAddress 10, requestRate/Burst 5/20, listRate/Burst 1/5, everyoneRate/Burst 500/1000, mostSenders 10000; kCertificateLookMilliseconds 1 h; kMostThrownAwayBytes 64 KB |
| settings.js | kMostRelayPorts 4000, kMostRelays 16, kMostHostLength 63, kMostSettingsBytes 16 KB |
| log.js | kMostFileBytes 10 MB, kOldFiles 3 |

## 3. Traps I know of

**Edges: which side of each limit is in.** The tests check every one of these.

| Limit | In | Out |
|---|---|---|
| A game | `now - keptAt < 45000` | it ends when `>= 45000` |
| A listing | `now - renewedAt < 45000` | ends at `>= 45000` |
| A pass, in age | `now <= passTime*1000 + 60000` (exactly 60 s old is good) | older |
| A pass, ahead of the clock | `passTime*1000 <= now + 5000` | further ahead |
| A cookie | the slot it was made in, or the one before | |
| A pending port | up to 15000 | freed at `>= 15000` |
| An idle port | up to 30000 | freed at `>= 30000` |

**Numbers:**
- **A pass time is a uint64 on the wire, but anything over 2^53 - 1 is refused,** in the relay's decode and the list alike. A Java `long` holds more, so the port must refuse past 2^53 - 1 by hand, or Java and Node will take different bytes.
- **makeCode:** take 5 random bytes, read most-significant bit first, and turn each 5 bits, in order, into one of kCodeLetters. All 0 bits give `22222222` and all 1 bits `ZZZZZZZZ` (a test checks both).
- **Token buckets:**
  - each starts full;
  - the refill is `elapsed ms / 1000 * rate`, capped at burst, as floating point;
  - a clock that goes back gives nothing, and doesn't move the bucket's time back;
  - taking more tokens than there are takes none.

**The relay's order:**
- **In onControl,** the per-sender limit comes first, then the everyone limit, then decode. A sender going too fast is cut off before it can use up everyone's share.
- **The per-sender memory:** at most `mostSenders`; the address heard from longest ago is forgotten first, and hearing from one moves it to the back. A new hasher key (every 24 h) empties it.
- **On a joiner's port,** a packet is a hello only if it's exactly 64 bytes, decodes, and is HOST_HELLO or JOINER_HELLO. Anything else from a bound end is game traffic and passed on unread. A HOST_HELLO also needs its port field to be that port.
- **The "joiners ready" count** goes up once, when a port first becomes active; a READY sent again is not counted again.
- **An ECHO with an all-zero secret** is answered with an all-zero secret.
- **The relay never answers** ECHO_BACK, COOKIE, REFUSED, HOST_OPENED, HOST_KEPT, JOIN_PORT, NEW_JOINER or READY: they're counted "not a message".

**The list:**
- **The query is everything after the first `?`.** `version=7?x` is refused. Node's `split('?', 2)` would have dropped the `?x`.
- **Bodies:** use strict-json.js's rules exactly (PROTOCOL.md section 4). The object it gives back has no prototype, so a key `__proto__` is just a key. In Java there's no such trap, but a key twice must still be refused. Field checks check lengths only: the reader has already refused every byte that isn't printable ASCII.
- **A body over 1 KB:**
  - refused with 413 as soon as the declared Content-Length is over, or as soon as the bytes are;
  - the answer goes out with Connection: close;
  - up to 64 KB more is read and thrown away, and past that the connection is cut.
  - Cutting at once gives an honest client a reset and no answer: the live test found that.
- **The answers' JSON:** keys in the order routes.js writes them (the worst-case byte counts in the tests assume it). Text is all printable ASCII, so the only escapes ever written are `\"` and `\\`. A writer that escapes `/` or writes `\u` gives different bytes.
- **A listing is keyed by region and code together.**
- **The owner key and the pass are compared in constant time.** In Java that's `MessageDigest.isEqual`.
- **The list never asks the relay anything,** even on the same machine: the pass is the only link between them.

**Files (CodeQL js/file-system-race):** never look a file up by name and then open it. Open it once, and read its size, its date and its bytes through that handle. There are three places this matters: the certificate files, the log file, and tools/takeouts.js.

**Settings:**
- an unknown key is refused, at the top and in `list`;
- this machine's own relay in `list.relays` leaves its passKey out;
- a pass key of all 0 is refused;
- a relay's host must have a last part that starts with a letter, which refuses every IPv4 form (`0x7f.0.0.1` too) and IPv6.

**The log:**
- one line a minute for the relay and one for the list, counts only;
- the tests look for parts of the lines (such as `forwarded 3 packets (1 joiners to hosts, 2 hosts to joiners)`), so keep the words;
- never an address, code, token, ticket, pass, owner key or name.

## 4. What isn't the spec

- **How Node does TLS, timeouts and sockets:** Java does them its own way, to the same limits. The design agreed with Primary is SSLServerSocket with a virtual thread per connection, counted and refused at accept().
- **The proof-run scripts in the scratchpad:** they aren't in the repository.
