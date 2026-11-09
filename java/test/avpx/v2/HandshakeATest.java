package avpx.v2;

import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsAny;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.testing.ScriptedRandom;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

// The tests of HandshakeA.java (CRYPTO.md sections 6 and 13): the game and the relay agree on every key, the relay is proved, and every
// change to any byte of any message, the region or the relay's keys is refused. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class HandshakeATest {
  private HandshakeATest() {
  }

  private static final String REGION = "virginia";

  private static HandshakeA.RelayKeys relay(int seed) {
    return HandshakeA.RelayKeys.of(P384.generate(ScriptedRandom.seeded(seed)), MlKem.generate(ScriptedRandom.seeded(seed + 1)));
  }

  // The game's side, made the same way every time from its seed
  private static HandshakeA.Initiator game(HandshakeA.RelayKeys relay, int seed) {
    return HandshakeA.writeA1(REGION, relay.p384Public(), relay.kemPublic(), ScriptedRandom.seeded(seed));
  }

  private static byte[] flip(byte[] b, int byteAt, int bit) {
    byte[] c = b.clone();
    c[byteAt] ^= (byte) (1 << bit);
    return c;
  }

  // An A1 made by hand, step by step as CRYPTO.md writes it, around an ephemeral ML-KEM key given as raw bytes that needn't be a good
  // one. Anyone can make an A1 whose tag checks: the game is anonymous, and A1 needs only the relay's public keys. So a relay must
  // refuse a bad key in an A1 even when its tag is right.
  private static byte[] a1Around(HandshakeA.RelayKeys relay, byte[] ephemeralKem, SecureRandom random) {
    Noise noise = HandshakeA.start(REGION, relay.p384Public(), relay.kemPublic());
    KeyPair e = P384.generate(random);
    byte[] eP384 = P384.encode((ECPublicKey) e.getPublic());
    noise.mixHash(eP384);
    noise.mixHash(ephemeralKem);
    noise.mixKey(P384.agree(e.getPrivate(), P384.decode(relay.p384Public())));
    MlKem.Encapsulated toRelay = MlKem.encapsulate(MlKem.decode(relay.kemPublic()), random);
    noise.mixHash(toRelay.ciphertext());
    noise.mixKey(toRelay.secret());
    byte[] tag = noise.encryptAndHash(new byte[0]);
    byte[] a1 = new byte[HandshakeA.A1_BYTES];
    System.arraycopy(eP384, 0, a1, 0, 97);
    System.arraycopy(ephemeralKem, 0, a1, 97, 1568);
    System.arraycopy(toRelay.ciphertext(), 0, a1, 97 + 1568, 1568);
    System.arraycopy(tag, 0, a1, 97 + 2 * 1568, 16);
    return a1;
  }

  public static void register() {
    test("a game and its relay agree on every key, both ways, and on the session id and the transcript", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      HandshakeA.Initiator game = game(relay, 30);
      byte[] a1 = game.a1();
      same(a1.length, 3249, "A1: 3,249 bytes");
      HandshakeA.Responder responder = HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(40));
      ok(responder != null, "the relay takes A1");
      same(responder.a2().length, 1689, "A2: 1,689 bytes");
      HandshakeA.Initiator.Done done = game.readA2(responder.a2());
      ok(done != null, "the game takes A2: the relay is proved");
      same(done.a3().length, 16, "A3: 16 bytes, the game's key confirmation");
      HandshakeA.Keys relayKeys = responder.readA3(done.a3());
      ok(relayKeys != null, "the relay takes A3");
      HandshakeA.Keys gameKeys = done.keys();
      same(relayKeys.split().initiatorKey(), gameKeys.split().initiatorKey(), "the game-to-relay key");
      same(relayKeys.split().responderKey(), gameKeys.split().responderKey(), "the relay-to-game key");
      same(relayKeys.split().initiatorIv(), gameKeys.split().initiatorIv(), "the game-to-relay IV");
      same(relayKeys.split().responderIv(), gameKeys.split().responderIv(), "the relay-to-game IV");
      same(relayKeys.sessionId(), gameKeys.sessionId(), "the session id");
      same(relayKeys.transcript(), gameKeys.transcript(), "the transcript");
      ok(!Arrays.equals(gameKeys.split().initiatorKey(), gameKeys.split().responderKey()), "each direction has its own key");

      // And the sealed channel opens across, both ways
      Channel g = Channel.gameSide(gameKeys, 0);
      Channel r = Channel.relaySide(relayKeys, 0);
      byte[] message = new byte[64];
      message[5] = 1;
      same(r.open(g.seal(message, 0), 0), message, "game to relay");
      same(g.open(r.seal(message, 0), 0), message, "relay to game");
    });

    test("a relay that doesn't hold the keys the game was given can't answer, and a relay told another region refuses A1", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      HandshakeA.RelayKeys other = relay(50);
      byte[] a1 = game(relay, 30).a1();
      same(HandshakeA.readA1(other, REGION, a1, ScriptedRandom.seeded(40)), null, "another relay's keys: its tag fails");
      same(HandshakeA.readA1(relay, "paris", a1, ScriptedRandom.seeded(40)), null, "another region in the prologue: its tag fails");
      throwsAny(() -> HandshakeA.writeA1(REGION, new byte[97], relay.kemPublic(), ScriptedRandom.seeded(1)),
          "the game refuses to start with a relay key that isn't on the curve");
    });

    test("every bit of A1 changed, one at a time (a bit a byte): the relay refuses every one", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a1 = game(relay, 30).a1();

      for (int i = 0; i < a1.length; i++) {
        same(HandshakeA.readA1(relay, REGION, flip(a1, i, i % 8), ScriptedRandom.seeded(40)), null, "A1's byte " + i);
      }

      same(HandshakeA.readA1(relay, REGION, Arrays.copyOf(a1, 3248), ScriptedRandom.seeded(40)), null, "A1 a byte short");
      same(HandshakeA.readA1(relay, REGION, Arrays.copyOf(a1, 3250), ScriptedRandom.seeded(40)), null, "A1 a byte long");
    });

    test("every bit of A2 changed, one at a time (a bit a byte): the game refuses every one, so a relay in the middle is caught", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a2 = HandshakeA.readA1(relay, REGION, game(relay, 30).a1(), ScriptedRandom.seeded(40)).a2();

      for (int i = 0; i < a2.length; i++) {
        same(game(relay, 30).readA2(flip(a2, i, i % 8)), null, "A2's byte " + i);
      }

      same(game(relay, 30).readA2(Arrays.copyOf(a2, 1688)), null, "A2 a byte short");
    });

    test("every bit of A3 changed: the relay refuses every one; and when A3 is lost, the game's first sealed message stands in", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a3 = game(relay, 30).readA2(HandshakeA.readA1(relay, REGION, game(relay, 30).a1(), ScriptedRandom.seeded(40)).a2()).a3();

      for (int bit = 0; bit < a3.length * 8; bit++) {
        HandshakeA.Responder fresh = HandshakeA.readA1(relay, REGION, game(relay, 30).a1(), ScriptedRandom.seeded(40));
        same(fresh.readA3(flip(a3, bit / 8, bit % 8)), null, "A3's bit " + bit);
      }

      HandshakeA.Responder lost = HandshakeA.readA1(relay, REGION, game(relay, 30).a1(), ScriptedRandom.seeded(40));
      HandshakeA.Initiator.Done done = game(relay, 30).readA2(lost.a2());
      HandshakeA.Keys stood = lost.keysWithoutA3();
      same(stood.split().initiatorKey(), done.keys().split().initiatorKey(), "with A3 lost, the relay's keys are the game's all the same");
      same(stood.transcript(), done.keys().transcript(), "and so is the transcript");
    });

    test("an A1 with a correct tag around an ML-KEM key that breaks FIPS 203's check is refused, and nothing is thrown", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] good = MlKem.encode(MlKem.generate(ScriptedRandom.seeded(60)).getPublic());
      ok(HandshakeA.readA1(relay, REGION, a1Around(relay, good, ScriptedRandom.seeded(61)), ScriptedRandom.seeded(62)) != null,
          "first, the hand-made A1 around a good key is taken: so the A1s below differ from a true one only in their key");

      // The key's first number set to q = 3,329 (0xd01: byte 0 is 0x01, byte 1's low half 0xd), its second to 4,095 (the most 12 bits
      // hold: byte 1's high half and byte 2 all ones), and its last, the 1,024th, to q (byte 1,534's high half 0x1, byte 1,535 0xd0)
      byte[] first = good.clone();
      first[0] = 0x01;
      first[1] = (byte) ((first[1] & 0xf0) | 0x0d);
      byte[] second = good.clone();
      second[1] = (byte) (second[1] | 0xf0);
      second[2] = (byte) 0xff;
      byte[] last = good.clone();
      last[1534] = (byte) ((last[1534] & 0x0f) | 0x10);
      last[1535] = (byte) 0xd0;

      for (byte[] bad : new byte[][] {first, second, last}) {
        byte[] a1 = a1Around(relay, bad, ScriptedRandom.seeded(61));
        doesNotThrow(() -> HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(62)), "the relay doesn't throw on it");
        same(HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(62)), null, "it refuses it");
        ok(MlKem.decode(bad) == null, "decode refuses the key, before any other work");
      }
    });

    test("the same A1 read twice gives the same A2 only with the same randomness: so the relay must keep its A2 to send again", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a1 = game(relay, 30).a1();
      byte[] a2 = HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(40)).a2();
      same(HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(40)).a2(), a2, "the same randomness: the same A2");
      ok(!Arrays.equals(HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(41)).a2(), a2),
          "fresh randomness: another A2, another set of keys (CRYPTO.md section 6: so the relay sends its kept A2 again, never a new one)");
    });

    test("the keys are wiped: a Split's arrays are zero after wipe, and a channel wiped seals nothing", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      HandshakeA.Initiator.Done done = game(relay, 30).readA2(HandshakeA.readA1(relay, REGION, game(relay, 30).a1(),
          ScriptedRandom.seeded(40)).a2());
      Noise.Split split = done.keys().split();
      Channel c = Channel.gameSide(done.keys(), 0);
      split.wipe();
      same(split.initiatorKey(), new byte[32], "the game-to-relay key is zero");
      same(split.responderKey(), new byte[32], "the relay-to-game key is zero");
      same(split.initiatorIv(), new byte[12], "and the IVs");
      c.wipe();
      same(c.seal(new byte[64], 0), null, "a wiped channel seals nothing");
    });
  }
}
