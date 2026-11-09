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
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

// The tests of HandshakeA.java (CRYPTO.md sections 6 and 13): the game and the relay agree on every key, the relay is proved to the game,
// the player to the relay (classically by ss, post-quantum by A2's skem), only approved players get an A2, and every change to any byte of
// any message, the region or the relay's keys is refused. Written 2026-11-09 by Melanikus for AVPx Dedicated Server; pqIK the same day.
public final class HandshakeATest {
  private HandshakeATest() {
  }

  private static final String REGION = "virginia";
  private static final Predicate<String> EVERYONE = fp -> true;

  private static HandshakeA.RelayKeys relay(int seed) {
    return HandshakeA.RelayKeys.of(P384.generate(ScriptedRandom.seeded(seed)), MlKem.generate(ScriptedRandom.seeded(seed + 1)));
  }

  private static Identity player(int seed) {
    return Identity.of(P384.generate(ScriptedRandom.seeded(seed)), MlKem.generate(ScriptedRandom.seeded(seed + 1)));
  }

  // The game's side, made the same way every time from its seeds
  private static HandshakeA.Initiator game(HandshakeA.RelayKeys relay, Identity player, int seed) {
    return HandshakeA.writeA1(REGION, relay.p384Public(), relay.kemPublic(), player, ScriptedRandom.seeded(seed));
  }

  private static HandshakeA.Read read(HandshakeA.RelayKeys relay, byte[] a1, Predicate<String> approved) {
    return HandshakeA.readA1(relay, REGION, a1, approved, ScriptedRandom.seeded(40));
  }

  private static HandshakeA.Responder responder(HandshakeA.RelayKeys relay, byte[] a1) {
    return read(relay, a1, EVERYONE).responder();
  }

  private static byte[] flip(byte[] b, int byteAt, int bit) {
    byte[] c = b.clone();
    c[byteAt] ^= (byte) (1 << bit);
    return c;
  }

  // An A1 made by hand, step by step as CRYPTO.md writes it, around an ephemeral ML-KEM key and static keys given as raw bytes that
  // needn't be good ones, with ss made from the P-384 private key given (which needn't be the statics' own). Anyone can make an A1 whose
  // first tags check: A1 up to s needs only the relay's public keys. So a relay must refuse bad keys in s even when its tag is right.
  private static byte[] a1ByHand(HandshakeA.RelayKeys relay, byte[] ephemeralKem, byte[] statics, PrivateKey ssKey, SecureRandom random) {
    Noise noise = HandshakeA.start(REGION, relay.p384Public(), relay.kemPublic());
    KeyPair e = P384.generate(random);
    byte[] eP384 = P384.encode((ECPublicKey) e.getPublic());
    noise.mixHash(eP384);
    noise.mixHash(ephemeralKem);
    noise.mixKey(P384.agree(e.getPrivate(), P384.decode(relay.p384Public())));
    MlKem.Encapsulated toRelay = MlKem.encapsulate(MlKem.decode(relay.kemPublic()), random);
    noise.mixHash(toRelay.ciphertext());
    noise.mixKey(toRelay.secret());
    byte[] sealedStatics = noise.encryptAndHash(statics);
    noise.mixKey(P384.agree(ssKey, P384.decode(relay.p384Public())));
    byte[] tag = noise.encryptAndHash(new byte[0]);
    byte[] a1 = new byte[HandshakeA.A1_BYTES];
    System.arraycopy(eP384, 0, a1, 0, 97);
    System.arraycopy(ephemeralKem, 0, a1, 97, 1568);
    System.arraycopy(toRelay.ciphertext(), 0, a1, 97 + 1568, 1568);
    System.arraycopy(sealedStatics, 0, a1, 97 + 2 * 1568, 1665 + 16);
    System.arraycopy(tag, 0, a1, 97 + 2 * 1568 + 1665 + 16, 16);
    return a1;
  }

  // An ML-KEM key with its first number set to q = 3,329 (0xd01: byte 0 is 0x01, byte 1's low half 0xd): FIPS 203's check refuses it
  private static byte[] pastQ(byte[] good) {
    byte[] bad = good.clone();
    bad[0] = 0x01;
    bad[1] = (byte) ((bad[1] & 0xf0) | 0x0d);
    return bad;
  }

  public static void register() {
    test("a game and its relay agree on every key, both ways, and on the session id and the transcript; A1 names the player", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      HandshakeA.Initiator game = game(relay, player, 30);
      byte[] a1 = game.a1();
      same(a1.length, 4930, "A1: 4,930 bytes");
      List<String> asked = new ArrayList<>();
      HandshakeA.Read read = read(relay, a1, fp -> asked.add(fp));
      HandshakeA.Responder responder = read.responder();
      ok(responder != null, "the relay takes A1");
      same(read.refusal(), 0, "with no refusal");
      same(asked, List.of(Identity.idHex(player.p384Public(), player.kemPublic())), "it asked once, about the player's fingerprint");
      same(responder.player(), asked.get(0), "and A1 named that player");
      same(responder.a2().length, 3257, "A2: 3,257 bytes");
      HandshakeA.Initiator.Done done = game.readA2(responder.a2());
      ok(done != null, "the game takes A2: the relay is proved");
      same(done.a3().length, 16, "A3: 16 bytes, the game's key confirmation");
      HandshakeA.Keys relayKeys = responder.readA3(done.a3());
      ok(relayKeys != null, "the relay takes A3: the player is proved");
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

    test("only an approved player gets an A2 (refusal 22), the relay keeps nothing for one that isn't, and asks before any ss", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      byte[] a1 = game(relay, player, 30).a1();
      HandshakeA.Read refused = read(relay, a1, fp -> false);
      same(refused.responder(), null, "an A1 from a player who isn't approved gets nothing");
      same(refused.refusal(), 22, "refusal 22");
      String other = Identity.idHex(player(80).p384Public(), player(80).kemPublic());
      same(read(relay, a1, fp -> fp.equals(other)).refusal(), 22, "another player's approval is no use");
      String fingerprint = Identity.fingerprintHex(player.p384Public(), player.kemPublic());
      same(read(relay, a1, id -> id.startsWith(fingerprint)).responder() != null, true, "(the id the relay asks about starts with the "
          + "fingerprint)");
      same(read(relay, a1, fingerprint::equals).refusal(), 22, "an approved set holding only the 16-byte fingerprint lets nobody in: "
          + "approval is by the whole id");
      ok(read(relay, a1, fp -> fp.equals(Identity.idHex(player.p384Public(), player.kemPublic()))).responder() != null,
          "the player's own id is");
    });

    test("s that isn't two keys is refused (23) even under good tags, and before approval is asked", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      byte[] ek = MlKem.encode(MlKem.generate(ScriptedRandom.seeded(60)).getPublic());
      PrivateKey ss = player.p384().getPrivate();
      ok(responder(relay, a1ByHand(relay, ek, player.statics(), ss, ScriptedRandom.seeded(61))) != null,
          "first, the hand-made A1 around good keys is taken: so the A1s below differ from a true one only in their keys");
      byte[] offCurve = player.statics();
      offCurve[96] ^= 1;
      byte[] notFour = player.statics();
      notFour[0] = 0x02;
      byte[] badKem = player.statics();
      System.arraycopy(pastQ(player.kemPublic()), 0, badKem, 97, 1568);

      for (byte[] statics : new byte[][] {offCurve, notFour, badKem}) {
        byte[] a1 = a1ByHand(relay, ek, statics, ss, ScriptedRandom.seeded(61));
        List<String> asked = new ArrayList<>();
        doesNotThrow(() -> read(relay, a1, fp -> asked.add(fp)), "the relay doesn't throw on it");
        same(read(relay, a1, fp -> asked.add(fp)).refusal(), 23, "refusal 23");
        same(asked.size(), 0, "and approval was never asked");
      }
    });

    test("someone with only a player's public keys can't make their A1: ss's tag fails (refusal 8)", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      byte[] ek = MlKem.encode(MlKem.generate(ScriptedRandom.seeded(60)).getPublic());
      PrivateKey notTheirs = P384.generate(ScriptedRandom.seeded(90)).getPrivate();
      HandshakeA.Read read = read(relay, a1ByHand(relay, ek, player.statics(), notTheirs, ScriptedRandom.seeded(61)), EVERYONE);
      same(read.responder(), null, "the player's statics, with ss from another key: refused");
      same(read.refusal(), 8, "refusal 8");
    });

    test("a game with the player's P-384 key but not their ML-KEM key can't read A2: the post-quantum half of the player's proof", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      KeyPair otherKem = MlKem.generate(ScriptedRandom.seeded(95));
      // The same public halves on the wire, so A1 names the player, but another ML-KEM private key to open A2's skem with
      Identity half = new Identity(player.p384(), otherKem, player.p384Public(), player.kemPublic());
      HandshakeA.Initiator game = game(relay, half, 30);
      HandshakeA.Responder responder = responder(relay, game.a1());
      ok(responder != null, "the relay takes A1 (ss holds: the P-384 key is theirs)");
      same(game.readA2(responder.a2()), null, "but A2's skem doesn't open, so there's no A3 to send");
    });

    test("a relay that doesn't hold the keys the game was given can't answer, and a relay told another region refuses A1", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      HandshakeA.RelayKeys other = relay(50);
      byte[] a1 = game(relay, player(70), 30).a1();
      same(read(other, a1, EVERYONE).refusal(), 8, "another relay's keys: s doesn't open (refusal 8)");
      same(HandshakeA.readA1(relay, "paris", a1, EVERYONE, ScriptedRandom.seeded(40)).refusal(), 8, "another region in the prologue: 8");
      throwsAny(() -> HandshakeA.writeA1(REGION, new byte[97], relay.kemPublic(), player(70), ScriptedRandom.seeded(1)),
          "the game refuses to start with a relay key that isn't on the curve");
    });

    test("every bit of A1 changed, one at a time (a bit a byte): the relay refuses every one", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a1 = game(relay, player(70), 30).a1();

      for (int i = 0; i < a1.length; i++) {
        same(read(relay, flip(a1, i, i % 8), EVERYONE).responder(), null, "A1's byte " + i);
      }

      same(read(relay, Arrays.copyOf(a1, 4929), EVERYONE).responder(), null, "A1 a byte short");
      same(read(relay, Arrays.copyOf(a1, 4931), EVERYONE).responder(), null, "A1 a byte long");
    });

    test("every bit of A2 changed, one at a time (a bit a byte): the game refuses every one, so a relay in the middle is caught", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      byte[] a2 = responder(relay, game(relay, player, 30).a1()).a2();

      for (int i = 0; i < a2.length; i++) {
        same(game(relay, player, 30).readA2(flip(a2, i, i % 8)), null, "A2's byte " + i);
      }

      same(game(relay, player, 30).readA2(Arrays.copyOf(a2, 3256)), null, "A2 a byte short");
    });

    test("every bit of A3 changed: the relay refuses every one; and when A3 is lost, the game's first sealed message stands in", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      byte[] a3 = game(relay, player, 30).readA2(responder(relay, game(relay, player, 30).a1()).a2()).a3();

      for (int bit = 0; bit < a3.length * 8; bit++) {
        HandshakeA.Responder fresh = responder(relay, game(relay, player, 30).a1());
        same(fresh.readA3(flip(a3, bit / 8, bit % 8)), null, "A3's bit " + bit);
      }

      HandshakeA.Responder lost = responder(relay, game(relay, player, 30).a1());
      HandshakeA.Initiator.Done done = game(relay, player, 30).readA2(lost.a2());
      HandshakeA.Keys stood = lost.keysWithoutA3();
      same(stood.split().initiatorKey(), done.keys().split().initiatorKey(), "with A3 lost, the relay's keys are the game's all the same");
      same(stood.transcript(), done.keys().transcript(), "and so is the transcript");
    });

    test("an A1 with correct tags around an ephemeral ML-KEM key that breaks FIPS 203's check is refused, and nothing is thrown", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      PrivateKey ss = player.p384().getPrivate();
      byte[] good = MlKem.encode(MlKem.generate(ScriptedRandom.seeded(60)).getPublic());

      // Its first number set to q, its second to 4,095 (the most 12 bits hold: byte 1's high half and byte 2 all ones), and its last, the
      // 1,024th, to q (byte 1,534's high half 0x1, byte 1,535 0xd0)
      byte[] second = good.clone();
      second[1] = (byte) (second[1] | 0xf0);
      second[2] = (byte) 0xff;
      byte[] last = good.clone();
      last[1534] = (byte) ((last[1534] & 0x0f) | 0x10);
      last[1535] = (byte) 0xd0;

      for (byte[] bad : new byte[][] {pastQ(good), second, last}) {
        byte[] a1 = a1ByHand(relay, bad, player.statics(), ss, ScriptedRandom.seeded(61));
        doesNotThrow(() -> read(relay, a1, EVERYONE), "the relay doesn't throw on it");
        same(read(relay, a1, EVERYONE).refusal(), 8, "it refuses it");
        ok(MlKem.decode(bad) == null, "decode refuses the key, before any other work");
      }
    });

    test("the same A1 read twice gives the same A2 only with the same randomness: so the relay must keep its A2 to send again", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      byte[] a1 = game(relay, player(70), 30).a1();
      byte[] a2 = responder(relay, a1).a2();
      same(responder(relay, a1).a2(), a2, "the same randomness: the same A2");
      ok(!Arrays.equals(HandshakeA.readA1(relay, REGION, a1, EVERYONE, ScriptedRandom.seeded(41)).responder().a2(), a2),
          "fresh randomness: another A2, another set of keys (CRYPTO.md section 6: so the relay sends its kept A2 again, never a new one)");
    });

    test("the keys are wiped: a Split's arrays are zero after wipe, and a channel wiped seals nothing", () -> {
      HandshakeA.RelayKeys relay = relay(20);
      Identity player = player(70);
      HandshakeA.Initiator.Done done = game(relay, player, 30).readA2(responder(relay, game(relay, player, 30).a1()).a2());
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
