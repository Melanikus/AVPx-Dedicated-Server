package avpx.v2;

import avpx.crypto.Hkdf;
import avpx.relay.AddressHasher;
import avpx.relay.PerSender;
import avpx.relay.RandomBytes;
import avpx.relay.Relay;
import avpx.relay.RelayCore;
import avpx.relay.RelayCore.Out;
import avpx.relay.TokenBucket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

// A version 2 relay (CRYPTO.md sections 5 to 7, 16 and 17): handshake A, then every control message sealed, in front of the same
// RelayCore that keeps the games. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// WHAT COMES TO IT, AND WHAT IT DOES. A refusal is counted, by its number in CRYPTO.md section 16, and never answered.
//
//   On the control port, a 1,200-byte handshake datagram (Fragments.java):
//   - A0, COOKIE_ASK (kind 1): answered with A0', COOKIE (kind 2), 64 bytes holding the handshake's id and its cookie. Nothing is kept.
//   - A1 (kind 3), in 3 fragments. Each fragment's cookie is checked first, with nothing kept to check it (refusal 5). Then the
//     fragments are put together: one handshake at a time from each address and port, at most 16 from one address and 1,000 in all,
//     each for at most 2 s. When A1 is whole, HandshakeA reads it (refusal 8 if its tag fails), and the relay answers with A2, in 2
//     datagrams. A2 is kept 10 s: the same A1 again gets the same A2, byte for byte, never a new one, which would make a second set of
//     keys (section 6, "Losses").
//   - A3 (kind 5): its cookie checked the same way; then it must be exactly the 16 bytes the game's keys make (HandshakeA.expect), from
//     A1's own address and port (refusal 18). Then the session is the game's.
//   On the control port, a 104-byte sealed control message (Channel.java): opened under its session, and the 64-byte message in it
//   handed to RelayCore, whose answers are each sealed under the session they're for. If A3 was lost, the game's first sealed message
//   that opens under the handshake's keys confirms them instead.
//   On a joiner's port: a 104-byte sealed hello, opened under its sender's session and handed to RelayCore the same way; or the games'
//   own sealed packets (AVPG, section 9), passed on unread. Nothing else goes through (refusal 19): no plaintext, ever.
//   Anything else: the wrong size (1; every version 1 message is one), another magic (2), another version (3), an unknown kind (4).
//
// WHY THIS ORDER: the cheap checks first, and nothing kept before the cookie shows the sender gets packets at its address. The
// expensive work (ECDH and ML-KEM) starts only when the whole of A1 is in, and only within the limits on handshakes started (2 a second
// for one address and port, 200 a second for everyone). The relay never sends more datagrams than it was sent: one smaller for A0, and
// 2 for A1's 3.
//
// HOW LONG A SESSION LASTS: while a game or a joiner's port holds it (its host's, or the two ends of a joiner's port, whose hellos may
// come again from a new address), or for 60 s (sessionIdleMilliseconds) after the last message that opened; and never past 24 hours or
// its other limits (Channel.java). At most 10,000 sessions in all, and 64 for one address, handshakes waiting for A3 among them; more is
// refused at A1 (refusal 20), and no session is ended to make room (CRYPTO.md section 17, settled with Third).
//
// It isn't safe to use from two threads at once, and doesn't need to be: the relay runs on one thread (RelaySockets.java).
public final class SealedRelay implements Relay {
  // Every limit, with its starting value (CRYPTO.md section 17). A test changes some, on a Limits of its own.
  public static final class Limits {
    public long cookieSlotMilliseconds = 10000;       // a cookie is good for 10 to 20 s
    public long assemblyMilliseconds = 2000;          // for A1's fragments all to come
    public int mostAssembliesPerAddress = 16;
    public int mostAssemblies = 1000;
    public double startRate = 2;                      // handshakes started, from one address and port
    public double startBurst = 4;
    public double everyoneStartRate = 200;            // and from everyone
    public double everyoneStartBurst = 400;
    public double askRate = 2000;                     // COOKIE_ASKs answered, from everyone
    public double askBurst = 4000;
    public long answerMilliseconds = 10000;           // A2 kept to send again; the keys kept waiting for A3
    public long sessionIdleMilliseconds = 60000;      // a session nothing holds, with no message that opened for this long, ends
    public int mostSessions = 10000;                  // sessions, and handshakes waiting for A3, in all
    public int mostSessionsPerAddress = 64;           // behind a carrier's NAT many homes share one address (5.1, point 12)
    public int mostSenders = 10000;                   // address-and-ports the limits on handshakes started remember
  }

  // The kinds of handshake datagram (CRYPTO.md section 6's table)
  static final int COOKIE_ASK = 1;
  static final int COOKIE = 2;
  static final int A1 = 3;
  static final int A2 = 4;
  static final int A3 = 5;

  static final int COOKIE_ANSWER_BYTES = 64;
  private static final int MOST_BAD_A3 = 4;
  private static final byte[] TO_RELAY = Fragments.toRelay();
  private static final byte[] GAME_MAGIC = "AVPG".getBytes(StandardCharsets.US_ASCII);
  private static final int GAME_OVERHEAD = 28;
  private static final long COOKIE_KEY_LIFE_MILLISECONDS = 24L * 60 * 60 * 1000;
  private static final int COOKIE_KEY_BYTES = 32;
  private static final int REFUSALS = 20;

  // A1 being put together, from one address and port
  private record Assembling(byte[] id, String address, Fragments.Assembly assembly, long startedAt) {
  }

  // A handshake A2 was sent for: its A2 datagrams, to send again, and the keys, waiting for A3 or the game's first sealed message
  private static final class Answered {
    final byte[] id;
    final String address;
    final int port;
    final byte[] a1Hash;
    final List<byte[]> a2;
    final long madeAt;
    final String sessionKey;
    HandshakeA.Responder.Expected expected;      // null once the keys are taken, or given up on
    int badA3;

    Answered(byte[] id, String address, int port, byte[] a1Hash, List<byte[]> a2, long madeAt, HandshakeA.Responder.Expected expected) {
      this.id = id;
      this.address = address;
      this.port = port;
      this.a1Hash = a1Hash;
      this.a2 = a2;
      this.madeAt = madeAt;
      this.expected = expected;
      this.sessionKey = hex(expected.keys().sessionId());
    }
  }

  // A session: its sealed channel, where its sender last spoke from on the control port, and when a message of it last opened. RelayCore
  // carries it as it is, unopened, on the ends and answers that belong to it.
  static final class Session {
    final Channel channel;
    final String key;
    final String firstAddress;
    String address;
    int port;
    long heardAt;

    Session(Channel channel, String key, String address, int port, long now) {
      this.channel = channel;
      this.key = key;
      this.firstAddress = address;
      this.address = address;
      this.port = port;
      this.heardAt = now;
    }
  }

  // What happened since the last line of counts
  static final class Counts {
    long asked;
    long started;
    long again;
    long finished;
    long ended;
    long opened;
    long overLimit;
    long noSession;
    long dropped;
    final long[] refused = new long[REFUSALS + 1];
  }

  private final RelayCore core;
  private final HandshakeA.RelayKeys keys;
  private final String region;
  private final SecureRandom random;
  private final RandomBytes bytes;
  private final Limits limits;
  private final Set<Integer> joinerPorts;
  private final PerSender starts;
  private final TokenBucket everyoneStarts;
  private final TokenBucket asks;
  private byte[] cookieKey;
  private long cookieKeyMadeAt;

  private final Map<String, Assembling> assembling = new HashMap<>();          // by address and port
  private final Map<String, Integer> assemblingPerAddress = new HashMap<>();
  private final Map<String, Answered> answered = new LinkedHashMap<>();        // by handshake id
  private final Map<String, Answered> waiting = new HashMap<>();               // by session id, until the keys are taken
  final Map<String, Session> sessions = new LinkedHashMap<>();                 // by session id
  private final Map<String, Integer> heldPerAddress = new HashMap<>();             // sessions, and handshakes waiting for A3
  Counts counts = new Counts();

  // controlPort, ports, region, passKey and coreLimits are RelayCore's (its games). keys: this relay's static keys, whose public halves
  // are in the signed directory. bytes: random bytes for the cookie's key and the address hashes (RandomBytes.secure() for the server).
  // random: for each handshake's keys and session id (a new SecureRandom for the server). now: the time, in milliseconds since 1970.
  public SealedRelay(int controlPort, int[] ports, String region, byte[] passKey, HandshakeA.RelayKeys keys, RandomBytes bytes,
      SecureRandom random, RelayCore.Limits coreLimits, Limits limits, long now) {
    this.core = RelayCore.sealed(controlPort, ports, region, passKey, bytes, coreLimits, now);
    this.keys = keys;
    this.region = region;
    this.random = random;
    this.bytes = bytes;
    this.limits = limits;
    this.joinerPorts = new HashSet<>(core.relayPorts());
    this.starts = new PerSender(limits.startRate, limits.startBurst, limits.mostSenders, new AddressHasher(bytes));
    this.everyoneStarts = new TokenBucket(limits.everyoneStartRate, limits.everyoneStartBurst);
    this.asks = new TokenBucket(limits.askRate, limits.askBurst);
    this.cookieKey = bytes.next(COOKIE_KEY_BYTES);
    this.cookieKeyMadeAt = now;
  }

  @Override
  public int controlPort() {
    return core.controlPort();
  }

  @Override
  public List<Integer> relayPorts() {
    return core.relayPorts();
  }

  @Override
  public int mostDatagramBytes() {
    return core.mostDatagramBytes();
  }

  private static String hex(byte[] b) {
    return HexFormat.of().formatHex(b);
  }

  private static boolean startsWith(byte[] d, byte[] magic) {
    return d.length >= magic.length && Arrays.equals(Arrays.copyOf(d, magic.length), magic);
  }

  private List<Out> refused(int number) {
    counts.refused[number]++;
    return List.of();
  }

  // ----- A packet in

  @Override
  public List<Out> receive(int localPort, String address, int port, byte[] data, long now) {
    try {
      if (data == null || data.length > core.mostDatagramBytes()) {
        return refused(1);
      }

      if (localPort == core.controlPort()) {
        if (data.length == Fragments.DATAGRAM_BYTES) {
          return onHandshake(address, port, data, now);
        }

        return data.length == Channel.SEALED_BYTES ? onSealed(localPort, address, port, data, now) : refused(1);
      }

      if (!joinerPorts.contains(localPort)) {
        return List.of();
      }

      if (data.length == Channel.SEALED_BYTES && startsWith(data, TO_RELAY)) {
        return onSealed(localPort, address, port, data, now);
      }

      return data.length >= GAME_OVERHEAD && startsWith(data, GAME_MAGIC) ? core.forward(localPort, address, port, data, now) : refused(19);
    } catch (RuntimeException e) {
      // Nothing a packet holds should get here; if something does, the packet is dropped and the relay goes on
      counts.dropped++;
      return List.of();
    }
  }

  private List<Out> onHandshake(String address, int port, byte[] d, long now) {
    if (!startsWith(d, TO_RELAY)) {
      return refused(2);
    }

    if (d[4] != Fragments.VERSION) {
      return refused(3);
    }

    int kind = d[5] & 0xff;

    if (kind != COOKIE_ASK && kind != A1 && kind != A3) {
      return refused(4);
    }

    Fragments.Fragment f = Fragments.read(TO_RELAY, d);

    if (f == null) {
      return refused(6);
    }

    if (kind == COOKIE_ASK) {
      return cookieAsk(address, port, f, now);
    }

    if (!cookieIsGood(f.cookie(), address, port, f.id(), now)) {
      return refused(5);
    }

    return kind == A1 ? a1Fragment(address, port, f, now) : a3(address, port, f, now);
  }

  // ----- A0 and its cookie

  // A0 is fragment 0 of 1, of no bytes, with no cookie (CRYPTO.md 5.1, point 9). Its answer, A0': 'AVPR', 2, kind 2, 0, 0, the id (8),
  // the cookie (16), then 0 to 64 bytes. Nothing is kept: the cookie is made again to check it.
  private List<Out> cookieAsk(String address, int port, Fragments.Fragment f, long now) {
    if (f.count() != 1 || f.length() != 0 || !Arrays.equals(f.cookie(), new byte[Fragments.COOKIE_BYTES])) {
      return refused(6);
    }

    if (!asks.take(now)) {
      counts.overLimit++;
      return List.of();
    }

    counts.asked++;
    byte[] answer = new byte[COOKIE_ANSWER_BYTES];
    System.arraycopy(TO_RELAY, 0, answer, 0, 4);
    answer[4] = Fragments.VERSION;
    answer[5] = COOKIE;
    System.arraycopy(f.id(), 0, answer, 8, Fragments.ID_BYTES);
    System.arraycopy(cookieFor(address, port, f.id(), now, 0), 0, answer, 16, Fragments.COOKIE_BYTES);
    return List.of(new Out(core.controlPort(), address, port, answer));
  }

  // The cookie: HMAC-SHA-384, with a key of the relay's own made fresh each day, of the address, the port, the 10-second slot now is in
  // (or slotsBack before it) and the handshake's id, cut to 16 bytes (CRYPTO.md section 6). Only someone who gets packets at that address
  // and port can have seen it, and only the relay can make one.
  private byte[] cookieFor(String address, int port, byte[] id, long now, int slotsBack) {
    if (now - cookieKeyMadeAt >= COOKIE_KEY_LIFE_MILLISECONDS || now < cookieKeyMadeAt) {
      Noise.wipe(cookieKey);
      cookieKey = bytes.next(COOKIE_KEY_BYTES);
      cookieKeyMadeAt = now;
    }

    long slot = Math.floorDiv(now, limits.cookieSlotMilliseconds) - slotsBack;
    byte[] where = (address + "|" + port + "|" + slot + "|").getBytes(StandardCharsets.US_ASCII);
    return Arrays.copyOf(Hkdf.hmac(cookieKey, where, id), Fragments.COOKIE_BYTES);
  }

  // A cookie made for this address, port and id in this slot or the one before: 10 to 20 s old at most
  private boolean cookieIsGood(byte[] cookie, String address, int port, byte[] id, long now) {
    return MessageDigest.isEqual(cookie, cookieFor(address, port, id, now, 0)) || MessageDigest.isEqual(cookie, cookieFor(address, port, id, now, 1));
  }

  // ----- A1, A2 and A3

  private List<Out> a1Fragment(String address, int port, Fragments.Fragment f, long now) {
    if (f.length() != HandshakeA.A1_BYTES) {
      return refused(6);
    }

    String from = address + "|" + port;
    Assembling a = assembling.get(from);

    // One handshake at a time from an address and port: a new one there takes the place of the one before
    if (a != null && !Arrays.equals(a.id(), f.id())) {
      stopAssembling(from, a);
      a = null;
    }

    if (a == null) {
      if (assembling.size() >= limits.mostAssemblies || assemblingPerAddress.getOrDefault(address, 0) >= limits.mostAssembliesPerAddress) {
        counts.overLimit++;
        return List.of();
      }

      a = new Assembling(f.id(), address, new Fragments.Assembly(f), now);
      assembling.put(from, a);
      assemblingPerAddress.merge(address, 1, Integer::sum);
    }

    if (!a.assembly().add(f)) {
      stopAssembling(from, a);
      return refused(6);
    }

    if (!a.assembly().complete()) {
      return List.of();
    }

    stopAssembling(from, a);
    return onA1(address, port, f.id(), a.assembly().message(), now);
  }

  private void stopAssembling(String from, Assembling a) {
    assembling.remove(from);
    int left = assemblingPerAddress.getOrDefault(a.address(), 1) - 1;

    if (left > 0) {
      assemblingPerAddress.put(a.address(), left);
    } else {
      assemblingPerAddress.remove(a.address());
    }
  }

  private List<Out> onA1(String address, int port, byte[] id, byte[] a1, long now) {
    byte[] a1Hash = Noise.sha384(a1);
    Answered seen = answered.get(hex(id));

    // The same A1 again, from the same place: the same A2, byte for byte. Another A1 under an id in use: nothing.
    if (seen != null) {
      if (seen.address.equals(address) && seen.port == port && MessageDigest.isEqual(seen.a1Hash, a1Hash)) {
        counts.again++;
        return send(seen.a2, address, port);
      }

      counts.overLimit++;
      return List.of();
    }

    // Too many sessions (refusal 20): refused here, at A1, and no session is ever ended to make room, so a flood can't push out games
    // already playing. A handshake waiting for A3 counts as one of its address's, so one address can't fill the table with A1s it never
    // finishes (CRYPTO.md section 17).
    if (sessions.size() + waiting.size() >= limits.mostSessions || heldPerAddress.getOrDefault(address, 0) >= limits.mostSessionsPerAddress) {
      return refused(20);
    }

    if (!starts.allows(address + "|" + port, now) || !everyoneStarts.take(now)) {
      counts.overLimit++;
      return List.of();
    }

    HandshakeA.Responder responder = HandshakeA.readA1(keys, region, a1, random);

    if (responder == null) {
      return refused(8);
    }

    byte[] a2 = responder.a2();
    HandshakeA.Responder.Expected expected = responder.expect();
    String sessionKey = hex(expected.keys().sessionId());

    // 8 random bytes: two sessions with one id would need luck of 1 in 2 to the 64th, but it costs nothing to refuse it
    if (sessions.containsKey(sessionKey) || waiting.containsKey(sessionKey)) {
      expected.keys().split().wipe();
      counts.overLimit++;
      return List.of();
    }

    List<byte[]> datagrams = Fragments.cut(TO_RELAY, A2, id, new byte[Fragments.COOKIE_BYTES], a2);
    Answered answer = new Answered(id.clone(), address, port, a1Hash, datagrams, now, expected);
    answered.put(hex(id), answer);
    waiting.put(sessionKey, answer);
    heldPerAddress.merge(address, 1, Integer::sum);
    counts.started++;
    return send(datagrams, address, port);
  }

  private List<Out> send(List<byte[]> datagrams, String address, int port) {
    List<Out> out = new ArrayList<>();

    for (byte[] d : datagrams) {
      out.add(new Out(core.controlPort(), address, port, d.clone()));
    }

    return out;
  }

  private List<Out> a3(String address, int port, Fragments.Fragment f, long now) {
    if (f.count() != 1 || f.length() != HandshakeA.A3_BYTES) {
      return refused(6);
    }

    Answered answer = answered.get(hex(f.id()));

    if (answer == null || answer.expected == null) {
      counts.noSession++;
      return List.of();
    }

    // From another address and port than A1's (refusal 18): the cookie alone doesn't stop that, as anyone on the path can ask for a cookie
    // of its own with the game's id and copy the game's A3
    if (!answer.address.equals(address) || answer.port != port) {
      return refused(18);
    }

    // A tag, so compared in a time that says nothing about where it differs
    if (!MessageDigest.isEqual(f.part(), answer.expected.a3())) {
      if (++answer.badA3 >= MOST_BAD_A3) {
        giveUp(answer);
      }

      return refused(8);
    }

    take(answer, Channel.relaySide(answer.expected.keys(), now), address, port, now);
    return List.of();
  }

  // The keys are the game's: a session from them. The channel holds its own copies, so the handshake's are wiped. It keeps the place its
  // handshake held among its address's (A3 comes from A1's own address), so the count isn't changed.
  private Session take(Answered answer, Channel channel, String address, int port, long now) {
    Session s = new Session(channel, answer.sessionKey, address, port, now);
    sessions.put(s.key, s);
    waiting.remove(answer.sessionKey);
    answer.expected.keys().split().wipe();
    answer.expected = null;
    counts.finished++;
    return s;
  }

  private void giveUp(Answered answer) {
    if (answer.expected != null) {
      waiting.remove(answer.sessionKey);
      answer.expected.keys().split().wipe();
      answer.expected = null;
      letGo(answer.address);
    }
  }

  // ----- Sealed messages

  private List<Out> onSealed(int localPort, String address, int port, byte[] d, long now) {
    if (!startsWith(d, TO_RELAY)) {
      return refused(2);
    }

    if (d[4] != Fragments.VERSION) {
      return refused(3);
    }

    byte[] id = Channel.sessionIdOf(d);

    if (id == null) {
      return refused(4);
    }

    String key = hex(id);
    Session s = sessions.get(key);
    byte[] message;

    if (s == null) {
      // A3 lost: the game's first sealed message, if it opens under the handshake's keys, is its confirmation (CRYPTO.md section 6)
      Answered answer = waiting.get(key);

      if (answer == null || localPort != core.controlPort()) {
        counts.noSession++;
        return List.of();
      }

      // As for A3 itself: only from A1's own address and port (refusal 18)
      if (!answer.address.equals(address) || answer.port != port) {
        return refused(18);
      }

      Channel candidate = Channel.relaySide(answer.expected.keys(), now);
      message = candidate.open(d, now);

      if (message == null) {
        Channel.Refusal why = candidate.lastRefusal();
        candidate.wipe();
        return refusedFor(why);
      }

      s = take(answer, candidate, address, port, now);
    } else {
      message = s.channel.open(d, now);

      if (message == null) {
        List<Out> none = refusedFor(s.channel.lastRefusal());

        if (s.channel.over(now)) {
          end(s);
        }

        return none;
      }

      // Where its sender is now, as the control port sees it (a joiner's port keeps its own ends, in RelayCore)
      if (localPort == core.controlPort()) {
        s.address = address;
        s.port = port;
      }
    }

    s.heardAt = now;
    counts.opened++;
    return sealAll(core.fromSession(localPort, address, port, s, message, now), now);
  }

  private List<Out> refusedFor(Channel.Refusal why) {
    switch (why) {
      case REPLAYED:
        return refused(9);
      case OVER:
        return refused(16);
      case SHAPE:
        return refused(4);
      default:
        return refused(8);
    }
  }

  // RelayCore's answers, each sealed under the session it's for. A game's own packet (no session) goes as it is.
  private List<Out> sealAll(List<Out> outs, long now) {
    List<Out> sealed = new ArrayList<>();

    for (Out o : outs) {
      if (o.session() == null) {
        sealed.add(o);
      } else if (o.session() instanceof Session to) {
        byte[] d = to.channel.seal(o.data(), now);

        // A session at its end seals nothing: its end needs a new handshake, and the answer is dropped
        if (d == null) {
          end(to);
        } else {
          sealed.add(new Out(o.from(), o.address(), o.port(), d));
        }
      }
    }

    return sealed;
  }

  private void end(Session s) {
    if (sessions.remove(s.key) != null) {
      letGo(s.firstAddress);
      s.channel.wipe();
      counts.ended++;
    }
  }

  // One fewer session, or handshake waiting for A3, held by an address
  private void letGo(String address) {
    int left = heldPerAddress.getOrDefault(address, 1) - 1;

    if (left > 0) {
      heldPerAddress.put(address, left);
    } else {
      heldPerAddress.remove(address);
    }
  }

  // ----- Time

  @Override
  public List<String> tick(long now) {
    // The games first: one that has just ended no longer holds its host's session below
    List<String> lines = core.tick(now);

    for (Iterator<Map.Entry<String, Assembling>> it = assembling.entrySet().iterator(); it.hasNext();) {
      Assembling a = it.next().getValue();

      if (now - a.startedAt() >= limits.assemblyMilliseconds || now < a.startedAt()) {
        it.remove();
        int left = assemblingPerAddress.getOrDefault(a.address(), 1) - 1;

        if (left > 0) {
          assemblingPerAddress.put(a.address(), left);
        } else {
          assemblingPerAddress.remove(a.address());
        }

        counts.refused[7]++;
      }
    }

    for (Iterator<Answered> it = answered.values().iterator(); it.hasNext();) {
      Answered answer = it.next();

      if (now - answer.madeAt >= limits.answerMilliseconds || now < answer.madeAt) {
        if (answer.expected != null) {
          giveUp(answer);
          counts.refused[7]++;
        }

        it.remove();
      }
    }

    Set<Object> held = core.sessionsInUse();

    for (Session s : new ArrayList<>(sessions.values())) {
      boolean idle = !held.contains(s) && now - s.heardAt >= limits.sessionIdleMilliseconds;

      if (s.channel.over(now) || idle) {
        end(s);
      }
    }

    return lines.isEmpty() ? lines : List.of(lines.get(0) + "; " + line());
  }

  @Override
  public String countsLine(long now) {
    return core.countsLine(now) + "; " + line();
  }

  // Version 2's own counts since the last line, then cleared: counts only, never an address or a key
  private String line() {
    Counts c = counts;
    StringBuilder refusals = new StringBuilder();

    for (int i = 1; i <= REFUSALS; i++) {
      if (c.refused[i] > 0) {
        refusals.append(refusals.length() > 0 ? ", " : "").append(c.refused[i]).append(" of ").append(i);
      }
    }

    counts = new Counts();
    return "version 2: " + c.asked + " cookies asked, " + c.started + " handshakes started, " + c.again + " A2s sent again, " + c.finished
        + " finished, " + c.ended + " sessions ended, " + c.opened + " sealed messages opened; refused (by CRYPTO.md section 16's numbers): "
        + (refusals.length() > 0 ? refusals : "none") + "; " + c.overLimit + " over a limit, " + c.noSession + " for no session, " + c.dropped
        + " dropped. Now " + sessions.size() + " sessions, " + assembling.size() + " A1s being put together, " + waiting.size()
        + " waiting for A3";
  }
}
