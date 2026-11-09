# Writing the server in another language

Written 2026-11-08 by Melanikus; the Java server is the reference from 2026-11-09. The server was first written in Node.js and ported to Java (`java/`), and the Node version is gone. This is for anyone who writes it again, in any language: a port is right when it refuses the same things for the same reasons, reads the same test vectors, and passes the same smoke test.

## 1. The spec, in the order to read it

1. **PROTOCOL.md:** version 1, every message, field and limit. **CRYPTO.md** is version 2, being built; its section 5.1 has the byte-exact choices.
2. **test-vectors/relay-v1.json:** read it in your own tests. Every message must read back as its fields, every refused entry must be refused for the reason given, and every pass must come out the same. The game and the Java server read the same file.
3. **The Java tests, `java/test/avpx/`:** port these first, and only then the code:

| Test | What it holds the code to |
|---|---|
| relay/ProtocolTest | the 64-byte layout, which fields each type uses, every unused field refused, the pass HMAC byte for byte, region names |
| relay/VectorsTest | the vectors file (a port reads it; it doesn't write it) |
| relay/CoreTest | a game's whole life, cookies, every cap and limit, hellos, NAT moves, echo, passes, expiry, the log line, junk packets |
| relay/LimitsTest | token buckets, the address hasher, the per-sender memory |
| list/StrictJsonTest, list/JsonTest | the body reader: every rule both ways |
| list/ListTest, list/HttpTest | every list call, the pass checks, the owner key, expiry, the caps, the worst-case sizes, every field limit, the HTTP rules |
| SettingsTest | every setting and its refusal |
| LiveTest | real sockets on 127.0.0.1 only, run only with AVPX_LIVE=1 |

4. **`java/tools/takeouts.txt`:** the take-out idea. Each row breaks one thing in a copy, and a test must notice. Write your own rows, one for each.
5. **`java/tools/Smoke.java`:** the smoke test from outside the process. Run it against your server: it must pass all its checks.

## 2. Traps

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
- **A pass time is a uint64 on the wire, but anything over 2^53 - 1 is refused,** in the relay's reading and the list's alike. A 64-bit integer holds more, so refuse past 2^53 - 1 by hand.
- **A game's code:** take 5 random bytes, read them most-significant bit first, and turn each 5 bits, in order, into one of the code letters. All 0 bits give `22222222`, and all 1 bits `ZZZZZZZZ`.
- **Token buckets:**
  - each starts full;
  - the refill is elapsed milliseconds / 1000 x the rate, capped at the burst, in floating point;
  - a clock that goes back gives nothing, and doesn't move the bucket's time back;
  - taking more tokens than there are takes none.

**The relay's order:**
- **On the control port:** the per-sender limit first, then the everyone limit, then reading the message. A sender going too fast is cut off before it can use up everyone's share.
- **On a joiner's port:** a packet is a hello only if it's exactly 64 bytes, reads as a message, and is HOST_HELLO or JOINER_HELLO. Anything else from a bound end is game traffic, passed on unread.
- **The relay never answers** ECHO_BACK, COOKIE, REFUSED, HOST_OPENED, HOST_KEPT, JOIN_PORT, NEW_JOINER or READY.

**The list:**
- **The query** is everything after the first `?`, so `version=7?x` is refused.
- **Bodies** follow PROTOCOL.md section 4's rules exactly: one flat object, no key twice, no `__proto__`, `constructor` or `prototype`, only two escapes, whole numbers with no sign, fraction or exponent.
- **The answers' JSON:** keys in the order the Java server writes them (the worst-case byte counts assume it). The text is all printable ASCII, so the only escapes ever written are `\"` and `\\`.
- **A listing is keyed by region and code together.** Owner keys and passes are compared in constant time.
- **The list never asks the relay anything,** even on the same machine: the pass is the only link between them.

**Files:** never look a file up by name and then open it. Open it once, and read its size, its date and its bytes through that handle.

**The log:** counts and times only, never an address, a code, a token, a ticket, a pass, an owner key or a name.
