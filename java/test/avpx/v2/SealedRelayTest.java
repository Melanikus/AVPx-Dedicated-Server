package avpx.v2;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.relay.Message;
import avpx.relay.Protocol;
import avpx.relay.Protocol.Type;
import avpx.relay.RelayCore;
import avpx.relay.RelayCore.Out;
import avpx.testing.ScriptedRandom;
import avpx.testing.SeededRandom;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// The tests of SealedRelay.java: a version 2 relay, handed datagrams as a game sends them, with no socket opened. Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server. Each refusal is checked by its number in CRYPTO.md section 16, as the relay counts it.
public final class SealedRelayTest {
  private SealedRelayTest() {
  }

  private static final String REGION = "virginia";
  private static final int CONTROL = 27500;
  private static final int[] PORTS = {27501, 27502};
  private static final byte[] PASS_KEY = bytes(32, 0x5a);
  // At the start of a 10-second slot, so a cookie's life (10 to 20 s) can be checked to the millisecond
  private static final long NOW = 1_700_000_000_000L;
  private static final HandshakeA.RelayKeys KEYS = HandshakeA.RelayKeys.of(P384.generate(ScriptedRandom.seeded(20)),
      MlKem.generate(ScriptedRandom.seeded(21)));

  private static SealedRelay relay(SealedRelay.Limits limits, RelayCore.Limits coreLimits) {
    return new SealedRelay(CONTROL, PORTS, REGION, PASS_KEY, KEYS, SeededRandom.of(5), ScriptedRandom.seeded(6), coreLimits, limits, NOW);
  }

  private static SealedRelay relay() {
    return relay(new SealedRelay.Limits(), new RelayCore.Limits());
  }

  private static byte[] changed(byte[] d, int at, int to) {
    byte[] c = d.clone();
    c[at] = (byte) to;
    return c;
  }

  private static List<Out> sendAll(SealedRelay relay, String address, int port, List<byte[]> datagrams, long now) {
    List<Out> out = new ArrayList<>();

    for (byte[] d : datagrams) {
      out.addAll(relay.receive(CONTROL, address, port, d, now));
    }

    return out;
  }

  // A0, COOKIE_ASK: fragment 0 of 1, of no bytes, with no cookie
  private static byte[] a0(byte[] id) {
    return Fragments.cut(Fragments.toRelay(), SealedRelay.COOKIE_ASK, id, new byte[16], new byte[0]).get(0);
  }

  // A handshake begun: A0 sent and A0' read; A1 made, as datagrams carrying the cookie, not yet sent
  private record Begun(byte[] id, byte[] cookie, HandshakeA.Initiator game, List<byte[]> a1) {
    byte[] a3(byte[] tag) {
      return Fragments.cut(Fragments.toRelay(), SealedRelay.A3, id, cookie, tag).get(0);
    }
  }

  private static Begun begin(SealedRelay relay, String address, int port, int seed, long now) {
    byte[] id = new byte[8];
    ScriptedRandom.seeded(seed + 1000).nextBytes(id);
    List<Out> answer = relay.receive(CONTROL, address, port, a0(id), now);
    ok(answer.size() == 1 && answer.get(0).data().length == SealedRelay.COOKIE_ANSWER_BYTES, "A0': one answer, of 64 bytes, for 1,200");
    byte[] cookie = Arrays.copyOfRange(answer.get(0).data(), 16, 32);
    HandshakeA.Initiator game = HandshakeA.writeA1(REGION, KEYS.p384Public(), KEYS.kemPublic(), ScriptedRandom.seeded(seed));
    return new Begun(id, cookie, game, Fragments.cut(Fragments.toRelay(), SealedRelay.A1, id, cookie, game.a1()));
  }

  // A2, put together from the relay's datagrams
  private static byte[] a2Of(List<Out> outs) {
    Fragments.Assembly assembly = new Fragments.Assembly(Fragments.read(Fragments.toRelay(), outs.get(0).data()));

    for (Out o : outs) {
      Fragments.Fragment f = Fragments.read(Fragments.toRelay(), o.data());
      ok(f != null && f.kind() == SealedRelay.A2 && assembly.add(f), "an A2 datagram");
    }

    return assembly.message();
  }

  // Handshake A over the control port, datagram by datagram as a game sends them: the game's channel
  private static Channel handshake(SealedRelay relay, String address, int port, int seed, long now) {
    Begun begun = begin(relay, address, port, seed, now);
    List<Out> a2 = sendAll(relay, address, port, begun.a1(), now);
    same(a2.size(), 2, "A2: 2 datagrams, for A1's 3");

    for (Out o : a2) {
      same(o.data().length, 1200, "each of 1,200 bytes");
    }

    HandshakeA.Initiator.Done done = begun.game().readA2(a2Of(a2));
    ok(done != null, "the game takes A2: the relay is proved");
    same(relay.receive(CONTROL, address, port, begun.a3(done.a3()), now).size(), 0, "A3 has no answer");
    return Channel.gameSide(done.keys(), now);
  }

  // A game, as the relay sees it: where it sends control messages from, and its sealed channel
  private record Player(String address, int port, Channel channel) {
    List<Out> say(SealedRelay relay, int toPort, int fromPort, Message m, long now) {
      return relay.receive(toPort, address, fromPort, channel.seal(Protocol.encode(m), now), now);
    }

    List<Out> say(SealedRelay relay, Message m, long now) {
      return say(relay, CONTROL, port, m, now);
    }

    Message hear(Out o, long now) {
      byte[] message = channel.open(o.data(), now);
      return message == null ? null : Protocol.decode(message);
    }
  }

  private static Player player(SealedRelay relay, String address, int port, int seed) {
    return new Player(address, port, handshake(relay, address, port, seed, NOW));
  }

  // A game's own sealed packet (CRYPTO.md section 9): AVPG, a counter, then bytes the relay never reads
  private static byte[] gamePacket(int n) {
    byte[] p = new byte[60];
    System.arraycopy("AVPG".getBytes(StandardCharsets.US_ASCII), 0, p, 0, 4);
    p[4] = (byte) n;
    Arrays.fill(p, 12, 60, (byte) (0x30 + n));
    return p;
  }

  public static void register() {
    test("a whole game through a version 2 relay: two handshakes, the game opened and joined, both hellos, READY, the games' packets", () -> {
      SealedRelay relay = relay();
      Player host = player(relay, "10.0.0.1", 5000, 30);
      List<Out> opened = host.say(relay, Message.of(Type.HOST_OPEN), NOW);
      same(opened.size(), 1, "one answer");
      same(opened.get(0).data().length, 104, "sealed: 104 bytes, as the question");
      Message hostOpened = host.hear(opened.get(0), NOW);
      same(hostOpened.type(), Type.HOST_OPENED, "HOST_OPENED, at once: no cookie round inside (CRYPTO.md 5.1, point 11)");
      byte[] token = hostOpened.secret();
      same(host.say(relay, Message.of(Type.ECHO).secret(bytes(16, 9)).number(1), NOW).size(), 0,
          "a sealed ECHO isn't answered: version 2's echo is the A0 round trip (5.1, point 11)");

      Player joiner = player(relay, "10.0.0.2", 6000, 31);
      List<Out> joined = joiner.say(relay, Message.of(Type.JOIN).code(hostOpened.code()), NOW);
      same(joined.size(), 2, "JOIN_PORT to the joiner, NEW_JOINER to the host");
      same(joined.get(0).address(), "10.0.0.2", "JOIN_PORT goes to the joiner");
      same(joined.get(1).address(), "10.0.0.1", "NEW_JOINER goes to the host");
      Message joinPort = joiner.hear(joined.get(0), NOW);
      same(joinPort.type(), Type.JOIN_PORT, "the joiner opens JOIN_PORT");
      same(host.hear(joined.get(1), NOW).type(), Type.NEW_JOINER, "the host opens NEW_JOINER: sealed under the host's own session");
      same(host.channel().open(joined.get(0).data(), NOW), null, "and the host can't open what's sealed for the joiner");
      int slot = joinPort.port();

      // The hellos, sealed, each from its game's own socket
      same(host.say(relay, slot, 5001, Message.of(Type.HOST_HELLO).secret(token).port(slot), NOW).size(), 0, "the host's hello: no answer");
      List<Out> ready = joiner.say(relay, slot, 6001, Message.of(Type.JOINER_HELLO).secret(joinPort.secret()), NOW);
      same(ready.size(), 1, "the joiner's hello: one answer");
      ok(ready.get(0).from() == slot && ready.get(0).port() == 6001, "from the joiner's port, to its game's socket");
      same(joiner.hear(ready.get(0), NOW).type(), Type.READY, "READY, sealed for the joiner");

      // The games' own sealed packets go through unread, each way
      List<Out> up = relay.receive(slot, "10.0.0.2", 6001, gamePacket(1), NOW);
      ok(up.size() == 1 && up.get(0).address().equals("10.0.0.1") && up.get(0).port() == 5001, "joiner to host");
      same(up.get(0).data(), gamePacket(1), "byte for byte");
      List<Out> down = relay.receive(slot, "10.0.0.1", 5001, gamePacket(2), NOW);
      ok(down.size() == 1 && down.get(0).address().equals("10.0.0.2") && down.get(0).port() == 6001, "host to joiner");
      same(down.get(0).data(), gamePacket(2), "byte for byte");
      same(relay.receive(slot, "10.0.0.2", 6001, changed(gamePacket(3), 3, 'X'), NOW).size(), 0,
          "a packet that isn't sealed game traffic is never passed on: no plaintext, ever");
      same(relay.receive(slot, "10.0.0.9", 7000, gamePacket(4), NOW).size(), 0, "nor one from a stranger");
      same(relay.counts.refused[19], 1L, "refusal 19, for the one that wasn't version 2's on a joiner's port");
      same(relay.counts.dropped, 0L, "and nothing threw");
    });

    test("every datagram rule: A0 one answer of 64 bytes; A1's 3 datagrams, 2 of A2; A3 none; and nothing kept before A1 is whole", () -> {
      SealedRelay relay = relay();
      Begun begun = begin(relay, "10.0.0.1", 5000, 40, NOW);
      same(relay.receive(CONTROL, "10.0.0.1", 5000, begun.a1().get(0), NOW).size(), 0, "A1's first datagram: no answer");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, begun.a1().get(1), NOW).size(), 0, "its second: none");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, begun.a1().get(2), NOW).size(), 2, "its third: A2's 2");
      same(relay.counts.started, 1L, "one handshake started");
    });

    test("anything that isn't version 2 is refused unanswered, by its number: every version 1 message among them", () -> {
      SealedRelay relay = relay();
      byte[] id = bytes(8, 0x11);
      byte[] a0 = a0(id);
      same(relay.receive(CONTROL, "10.0.0.1", 5000, Protocol.encode(Message.of(Type.HOST_OPEN)), NOW).size(), 0, "a version 1 HOST_OPEN");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, Protocol.encode(Message.of(Type.ECHO)), NOW).size(), 0, "a version 1 ECHO");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, Arrays.copyOf(a0, 1199), NOW).size(), 0, "1,199 bytes");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, new byte[1501], NOW).size(), 0, "1,501 bytes");
      same(relay.counts.refused[1], 4L, "four of refusal 1, the wrong size");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 3, 'X'), NOW).size(), 0, "AVPX");
      same(relay.counts.refused[2], 1L, "refusal 2, another magic");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 4, 1), NOW).size(), 0, "version 1");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 4, 3), NOW).size(), 0, "version 3");
      same(relay.counts.refused[3], 2L, "refusal 3, another version");

      for (int kind : new int[] {0, SealedRelay.COOKIE, SealedRelay.A2, 6, 32, 255}) {
        same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 5, kind), NOW).size(), 0, "kind " + kind);
      }

      same(relay.counts.refused[4], 6L, "refusal 4: unknown kinds, and the relay's own (COOKIE, A2), which it never takes");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 7, 2), NOW).size(), 0, "an A0 of 2 fragments");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 20, 1), NOW).size(), 0, "an A0 with a cookie");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, changed(a0, 1199, 1), NOW).size(), 0, "an A0 with a byte that isn't 0");
      same(relay.counts.refused[6], 3L, "refusal 6, not one fragment read only one way");
      byte[] sealedShape = Arrays.copyOf(Fragments.toRelay(), 104);
      sealedShape[4] = 2;
      sealedShape[5] = 33;
      same(relay.receive(CONTROL, "10.0.0.1", 5000, sealedShape, NOW).size(), 0, "104 bytes, of kind 33");
      sealedShape[5] = 32;
      same(relay.receive(CONTROL, "10.0.0.1", 5000, sealedShape, NOW).size(), 0, "104 bytes, sealed, for no session");
      same(relay.counts.noSession, 1L, "for no session");
      same(relay.counts.dropped, 0L, "nothing threw");
    });

    test("A1's cookie is checked before anything is kept: from another port, changed, or 20 s old, it's refused", () -> {
      SealedRelay relay = relay();
      Begun begun = begin(relay, "10.0.0.1", 5000, 41, NOW);
      same(sendAll(relay, "10.0.0.1", 5001, begun.a1(), NOW).size(), 0, "from another port");
      same(sendAll(relay, "10.0.0.2", 5000, begun.a1(), NOW).size(), 0, "from another address");
      List<byte[]> changedCookie = new ArrayList<>();

      for (byte[] d : begun.a1()) {
        changedCookie.add(changed(d, 16, d[16] ^ 1));
      }

      same(sendAll(relay, "10.0.0.1", 5000, changedCookie, NOW).size(), 0, "with its cookie changed");
      same(relay.counts.refused[5], 9L, "every one of those 9 datagrams is refusal 5");
      same(sendAll(relay, "10.0.0.1", 5000, begun.a1(), NOW + 20000).size(), 0, "20 s on, in the third slot: too old");
      same(sendAll(relay, "10.0.0.1", 5000, begun.a1(), NOW + 19999).size(), 2, "a millisecond less, in the second slot: still good");
    });

    test("the same A1 again gets the same A2, byte for byte; another A1 under that id gets nothing", () -> {
      SealedRelay relay = relay();
      Begun begun = begin(relay, "10.0.0.1", 5000, 42, NOW);
      List<Out> first = sendAll(relay, "10.0.0.1", 5000, begun.a1(), NOW);
      List<Out> again = sendAll(relay, "10.0.0.1", 5000, begun.a1(), NOW + 500);
      same(again.size(), 2, "2 datagrams again");
      same(again.get(0).data(), first.get(0).data(), "the first, byte for byte");
      same(again.get(1).data(), first.get(1).data(), "and the second");
      same(relay.counts.again, 1L, "counted as sent again");
      same(relay.counts.started, 1L, "and only one handshake started: one set of keys");

      HandshakeA.Initiator other = HandshakeA.writeA1(REGION, KEYS.p384Public(), KEYS.kemPublic(), ScriptedRandom.seeded(43));
      List<byte[]> otherA1 = Fragments.cut(Fragments.toRelay(), SealedRelay.A1, begun.id(), begun.cookie(), other.a1());
      same(sendAll(relay, "10.0.0.1", 5000, otherA1, NOW + 600).size(), 0, "another A1 under the same id: nothing");
    });

    test("if A3 is lost, the game's first sealed message confirms the keys; a wrong A3, or one from elsewhere, confirms nothing", () -> {
      SealedRelay relay = relay();
      Begun lost = begin(relay, "10.0.0.1", 5000, 44, NOW);
      HandshakeA.Initiator.Done done = lost.game().readA2(a2Of(sendAll(relay, "10.0.0.1", 5000, lost.a1(), NOW)));
      Player host = new Player("10.0.0.1", 5000, Channel.gameSide(done.keys(), NOW));
      same(relay.sessions.size(), 0, "no session before a confirmation");

      // Someone on the path who copies the game's first sealed message and sends it from elsewhere confirms nothing
      byte[] firstMessage = host.channel().seal(Protocol.encode(Message.of(Type.HOST_OPEN)), NOW);
      same(relay.receive(CONTROL, "10.0.0.9", 5000, firstMessage, NOW).size(), 0, "the game's first sealed message, copied, from elsewhere");
      same(relay.sessions.size(), 0, "confirms nothing");
      List<Out> opened = host.say(relay, Message.of(Type.HOST_OPEN), NOW);
      same(host.hear(opened.get(0), NOW).type(), Type.HOST_OPENED, "the first sealed message, with no A3: answered");
      same(relay.sessions.size(), 1, "it confirmed the keys");

      Begun wrong = begin(relay, "10.0.0.2", 6000, 45, NOW);
      HandshakeA.Initiator.Done second = wrong.game().readA2(a2Of(sendAll(relay, "10.0.0.2", 6000, wrong.a1(), NOW)));
      byte[] badTag = second.a3().clone();
      badTag[0] ^= 1;
      same(relay.receive(CONTROL, "10.0.0.2", 6000, wrong.a3(badTag), NOW).size(), 0, "a wrong A3");
      same(relay.counts.refused[8], 1L, "refusal 8");
      same(relay.receive(CONTROL, "10.0.0.2", 6001, wrong.a3(second.a3()), NOW).size(), 0, "the right A3, from another port");

      // Someone on the path can ask for a cookie for its own port with the game's id (both are sent in the clear) and copy the game's A3:
      // it still confirms nothing, as A3 must come from A1's own address and port (CRYPTO.md 5.1, point 9)
      byte[] theirCookie = Arrays.copyOfRange(relay.receive(CONTROL, "10.0.0.2", 6001, a0(wrong.id()), NOW).get(0).data(), 16, 32);
      byte[] copied = Fragments.cut(Fragments.toRelay(), SealedRelay.A3, wrong.id(), theirCookie, second.a3()).get(0);
      same(relay.receive(CONTROL, "10.0.0.2", 6001, copied, NOW).size(), 0, "the game's A3, copied, with a good cookie for another port");
      same(relay.sessions.size(), 1, "none of them made a session");
      same(relay.counts.refused[18], 2L, "refusal 18, twice: the copied first sealed message, and the copied A3");
      relay.receive(CONTROL, "10.0.0.2", 6000, wrong.a3(second.a3()), NOW);
      same(relay.sessions.size(), 2, "the right A3, from A1's own address and port: the session");
    });

    test("a sealed message is taken once: again, or with a bit changed, it's refused (9, 8); after 65,536 bad tags the session ends", () -> {
      SealedRelay relay = relay();
      Player host = player(relay, "10.0.0.1", 5000, 46);
      byte[] keep = host.channel().seal(Protocol.encode(Message.of(Type.HOST_KEEP).secret(bytes(16, 1))), NOW);
      same(relay.receive(CONTROL, "10.0.0.1", 5000, keep, NOW).size(), 1, "taken: a REFUSED for a token of no game");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, keep, NOW).size(), 0, "again: refused");
      same(relay.counts.refused[9], 1L, "refusal 9");
      byte[] next = host.channel().seal(Protocol.encode(Message.of(Type.HOST_OPEN)), NOW);
      byte[] bad = changed(next, 50, next[50] ^ 1);

      for (int i = 0; i < 65536; i++) {
        relay.receive(CONTROL, "10.0.0.1", 5000, bad, NOW);
      }

      same(relay.counts.refused[8], 65536L, "65,536 of refusal 8");
      same(relay.receive(CONTROL, "10.0.0.1", 5000, next, NOW).size(), 0, "then even a true message is refused: the session is over");
      same(relay.sessions.size(), 0, "and gone, its keys wiped");
    });

    test("the limits: one A1 at a time from an address and port, 16 from one address, handshakes started, and sessions in all", () -> {
      SealedRelay relay = relay();
      Begun one = begin(relay, "10.0.0.1", 5000, 47, NOW);
      Begun two = begin(relay, "10.0.0.1", 5000, 48, NOW);
      relay.receive(CONTROL, "10.0.0.1", 5000, one.a1().get(0), NOW);
      relay.receive(CONTROL, "10.0.0.1", 5000, two.a1().get(0), NOW);
      relay.receive(CONTROL, "10.0.0.1", 5000, one.a1().get(1), NOW);
      same(relay.receive(CONTROL, "10.0.0.1", 5000, one.a1().get(2), NOW).size(), 0,
          "a second handshake from the same address and port took the first's place: the first never finishes");

      SealedRelay many = relay();

      for (int port = 1; port <= 16; port++) {
        many.receive(CONTROL, "10.0.0.3", port, begin(many, "10.0.0.3", port, 100 + port, NOW).a1().get(0), NOW);
      }

      long before = many.counts.overLimit;
      many.receive(CONTROL, "10.0.0.3", 17, begin(many, "10.0.0.3", 17, 117, NOW).a1().get(0), NOW);
      same(many.counts.overLimit, before + 1, "a 17th A1 being put together from one address: refused");

      SealedRelay.Limits slow = new SealedRelay.Limits();
      slow.startRate = 1;
      slow.startBurst = 1;
      SealedRelay limited = relay(slow, new RelayCore.Limits());
      same(sendAll(limited, "10.0.0.1", 5000, begin(limited, "10.0.0.1", 5000, 49, NOW).a1(), NOW).size(), 2, "a first handshake");
      same(sendAll(limited, "10.0.0.1", 5000, begin(limited, "10.0.0.1", 5000, 50, NOW).a1(), NOW).size(), 0,
          "a second from the same address and port in the same moment: over its limit, so no ECDH or ML-KEM is done");
      same(sendAll(limited, "10.0.0.1", 5001, begin(limited, "10.0.0.1", 5001, 51, NOW).a1(), NOW).size(), 2, "from another port, fine");

      SealedRelay.Limits few = new SealedRelay.Limits();
      few.mostSessions = 1;
      SealedRelay full = relay(few, new RelayCore.Limits());
      player(full, "10.0.0.1", 5000, 52);
      same(sendAll(full, "10.0.0.2", 6000, begin(full, "10.0.0.2", 6000, 53, NOW).a1(), NOW).size(), 0, "past the most sessions: refused");
      same(full.counts.refused[20], 1L, "refusal 20, too many sessions, at A1");
      same(full.sessions.size(), 1, "and the session already there wasn't ended to make room");
    });

    // CRYPTO.md section 17's per-address cap, which handshakes waiting for A3 count toward: without that, one address with cookies for
    // its own ports could fill the table with A1s it never finishes
    test("handshakes waiting for A3 count toward an address's most sessions; given up on after 10 s, they free their places", () -> {
      SealedRelay.Limits two = new SealedRelay.Limits();
      two.mostSessionsPerAddress = 2;
      SealedRelay relay = relay(two, new RelayCore.Limits());
      same(sendAll(relay, "10.0.0.5", 1, begin(relay, "10.0.0.5", 1, 60, NOW).a1(), NOW).size(), 2, "one A1, never finished: A2");
      same(sendAll(relay, "10.0.0.5", 2, begin(relay, "10.0.0.5", 2, 61, NOW).a1(), NOW).size(), 2, "a second: A2");
      same(sendAll(relay, "10.0.0.5", 3, begin(relay, "10.0.0.5", 3, 62, NOW).a1(), NOW).size(), 0,
          "a third from the same address, with two waiting for A3 and no session yet: refused");
      same(relay.counts.refused[20], 1L, "refusal 20");
      same(sendAll(relay, "10.0.0.6", 1, begin(relay, "10.0.0.6", 1, 63, NOW).a1(), NOW).size(), 2, "another address: its own count");
      relay.tick(NOW + 10000);
      same(sendAll(relay, "10.0.0.5", 4, begin(relay, "10.0.0.5", 4, 64, NOW + 10000).a1(), NOW + 10000).size(), 2,
          "10 s on, the two never finished are given up on, and their places are free");
    });

    test("time: A1 has 2 s to come whole; A2 is kept 10 s; a session nothing holds ends after 60 s quiet, and one a game holds stays", () -> {
      SealedRelay relay = relay();
      Begun slow = begin(relay, "10.0.0.1", 5000, 54, NOW);
      relay.receive(CONTROL, "10.0.0.1", 5000, slow.a1().get(0), NOW);
      relay.receive(CONTROL, "10.0.0.1", 5000, slow.a1().get(1), NOW);
      relay.tick(NOW + 2000);
      same(relay.receive(CONTROL, "10.0.0.1", 5000, slow.a1().get(2), NOW + 2000).size(), 0, "the last fragment 2 s on: too late");
      same(relay.counts.refused[7], 1L, "refusal 7, not finished in time");

      Begun kept = begin(relay, "10.0.0.2", 6000, 55, NOW);
      List<Out> first = sendAll(relay, "10.0.0.2", 6000, kept.a1(), NOW);
      relay.tick(NOW + 10000);
      List<Out> later = sendAll(relay, "10.0.0.2", 6000, kept.a1(), NOW + 10000);
      ok(later.size() == 2 && !Arrays.equals(later.get(0).data(), first.get(0).data()), "10 s on, the A2 isn't kept: a new handshake");

      RelayCore.Limits longGames = new RelayCore.Limits();
      longGames.gameLifeMilliseconds = 1_000_000;
      SealedRelay idle = relay(new SealedRelay.Limits(), longGames);
      Player quiet = player(idle, "10.0.0.3", 7000, 56);
      Player hosting = player(idle, "10.0.0.4", 8000, 57);
      byte[] token = hosting.hear(hosting.say(idle, Message.of(Type.HOST_OPEN), NOW).get(0), NOW).secret();
      idle.tick(NOW + 59999);
      same(idle.sessions.size(), 2, "59.999 s quiet: both still there");
      idle.tick(NOW + 60000);
      same(idle.sessions.size(), 1, "60 s quiet: the one nothing holds has ended; the host's, which its game holds, stays");
      same(quiet.say(idle, Message.of(Type.HOST_OPEN), NOW + 60001).size(), 0, "the quiet player's session is gone: it needs a new handshake");
      hosting.say(idle, Message.of(Type.HOST_CLOSE).secret(token), NOW + 70000);
      idle.tick(NOW + 129999);
      same(idle.sessions.size(), 1, "its game closed at 70 s: still there at 129.999 s");
      idle.tick(NOW + 130000);
      same(idle.sessions.size(), 0, "and gone 60 s after its last message");
    });

    test("20,000 datagrams of junk, of every size and of version 2's shapes: none answered, and nothing ever throws", () -> {
      SealedRelay relay = relay();
      SeededRandom r = SeededRandom.of(77);
      int[] sizes = {0, 1, 4, 27, 28, 63, 64, 65, 103, 104, 105, 1199, 1200, 1201, 1500, 1501};
      int answers = 0;

      for (int i = 0; i < 20000; i++) {
        byte[] pick = r.next(4);
        int size = (pick[0] & 1) == 0 ? sizes[(pick[1] & 0xff) % sizes.length] : (((pick[1] & 0xff) << 8) | (pick[2] & 0xff)) % 1502;
        byte[] d = r.next(size);

        // Most of them look like version 2 at first: its magic, its version, and one of its kinds
        if (size >= 6 && (pick[3] & 3) != 0) {
          byte[] magic = (pick[3] & 4) == 0 ? Fragments.toRelay() : "AVPG".getBytes(StandardCharsets.US_ASCII);
          System.arraycopy(magic, 0, d, 0, 4);
          d[4] = 2;
          d[5] = (byte) new int[] {1, 3, 5, 32, 2, 4}[(pick[3] & 0xff) % 6];
        }

        int port = (pick[2] & 1) == 0 ? CONTROL : PORTS[0];
        answers += relay.receive(port, "10.0.0." + (pick[0] & 7), 1000 + (pick[1] & 0xff), d, NOW + i).size();
      }

      same(answers, 0, "none answered");
      same(relay.counts.dropped, 0L, "and nothing reached the relay's last catch: every one refused by a check");
    });

    test("a version 2 core takes no bare message, and a version 1 core takes no opened one", () -> {
      RelayCore sealed = RelayCore.sealed(CONTROL, PORTS, REGION, PASS_KEY, SeededRandom.of(8), new RelayCore.Limits(), NOW);
      byte[] open = Protocol.encode(Message.of(Type.HOST_OPEN));
      same(sealed.receive(CONTROL, "10.0.0.1", 5000, open, NOW).size(), 0, "a bare HOST_OPEN, to a version 2 core");
      same(sealed.fromSession(CONTROL, "10.0.0.1", 5000, null, open, NOW).size(), 0, "nor one opened under no session");
      same(sealed.fromSession(CONTROL, "10.0.0.1", 5000, new Object(), open, NOW).size(), 1, "one opened under a session: answered");

      RelayCore plain = new RelayCore(CONTROL, PORTS, REGION, PASS_KEY, SeededRandom.of(9), new RelayCore.Limits(), NOW);
      same(plain.fromSession(CONTROL, "10.0.0.1", 5000, new Object(), open, NOW).size(), 0, "a version 1 core takes nothing opened");
      same(plain.forward(PORTS[0], "10.0.0.1", 5000, gamePacket(1), NOW).size(), 0, "nor anything to pass on but through its own receive");
      same(plain.receive(CONTROL, "10.0.0.1", 5000, open, NOW).get(0).data().length, 64, "its own: a COOKIE, as version 1 has always done");
    });

    test("the relay's line of counts holds counts only: no address, port, id or key", () -> {
      SealedRelay relay = relay();
      player(relay, "10.0.0.1", 5000, 58);
      String line = relay.countsLine(NOW + 1000);
      ok(line.contains("version 2: 1 cookies asked, 1 handshakes started"), "it has version 2's counts: " + line);
      ok(!line.contains("10.0.0.1") && !line.contains("5000"), "and no address or port");
    });
  }
}
