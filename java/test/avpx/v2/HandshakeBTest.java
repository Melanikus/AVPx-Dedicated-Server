package avpx.v2;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.testing.ScriptedRandom;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// The tests of HandshakeB.java (CRYPTO.md section 8, and 5.1 points 17 to 20): a joiner and its host agree on every key and the check
// code; the host is the one the listing named, or the joiner stops; the joiner reveals the nJ it promised, or the host stops; and any
// change to any message is refused. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class HandshakeBTest {
  private HandshakeBTest() {
  }

  private static final String REGION = "virginia";
  private static final int PORT = 27507;

  private static HandshakeB.Identity identity(int seed) {
    return HandshakeB.Identity.of(P384.generate(ScriptedRandom.seeded(seed)), MlKem.generate(ScriptedRandom.seeded(seed + 1)));
  }

  private static final HandshakeB.Identity HOST = identity(70);
  private static final HandshakeB.Identity JOINER = identity(72);

  private static byte[] flip(byte[] b, int at) {
    byte[] c = b.clone();
    c[at] ^= (byte) (1 << (at % 8));
    return c;
  }

  private static HandshakeB.Joiner joiner(int seed) {
    return HandshakeB.writeB1(REGION, PORT, HOST.fingerprint(), JOINER, ScriptedRandom.seeded(seed));
  }

  private static HandshakeB.Host host(byte[] b1, int seed) {
    return HandshakeB.readB1(REGION, PORT, HOST, b1, ScriptedRandom.seeded(seed));
  }

  // A host brought to where it waits for B5: its B4 has gone, from the joiner made from joinerSeed
  private static HandshakeB.Host hostAtB5(int joinerSeed, int hostSeed) {
    HandshakeB.Joiner j = joiner(joinerSeed);
    HandshakeB.Host h = host(j.b1(), hostSeed);
    h.readB3(j.readB2(h.b2()));
    return h;
  }

  public static void register() {
    test("a joiner and its host agree on every key, the transcript and the check code; each learns the other's fingerprint", () -> {
      HandshakeB.Joiner joiner = joiner(80);
      same(joiner.b1().length, 1713, "B1: 1,713 bytes, e's two keys and the commitment");
      HandshakeB.Host host = host(joiner.b1(), 81);
      same(host.b2().length, 3362, "B2: 3,362 bytes");
      byte[] b3 = joiner.readB2(host.b2());
      ok(b3 != null && b3.length == 3265, "the joiner takes B2, from the host the listing named: B3, 3,265 bytes");
      byte[] b4 = host.readB3(b3);
      ok(b4 != null && b4.length == 1616, "the host takes B3: B4, 1,616 bytes, with nH");
      HandshakeB.Joiner.Done done = joiner.readB4(b4);
      ok(done != null && done.b5().length == 48, "the joiner takes B4, the host's key confirmation: B5, 48 bytes, with nJ");
      HandshakeB.Keys h = host.readB5(done.b5());
      ok(h != null, "the host takes B5: the joiner's key confirmation, and the nJ it promised in B1");

      HandshakeB.Keys j = done.keys();
      same(j.split().initiatorKey(), h.split().initiatorKey(), "the joiner-to-host key");
      same(j.split().responderKey(), h.split().responderKey(), "the host-to-joiner key");
      same(j.split().initiatorIv(), h.split().initiatorIv(), "and the IVs");
      same(j.split().responderIv(), h.split().responderIv(), "both ways");
      same(j.transcript(), h.transcript(), "the transcript, h after B5");
      same(j.theirFingerprint(), HOST.fingerprint(), "the joiner has the host's fingerprint");
      same(h.theirFingerprint(), JOINER.fingerprint(), "the host has the joiner's, to welcome back or ban");
      same(HandshakeB.checkCode(j.transcript()), HandshakeB.checkCode(h.transcript()), "the same check code on both screens");
      ok(HandshakeB.checkCode(j.transcript()).matches("[0-9]{6}"), "6 digits");
    });

    test("a host that isn't the one the listing named is refused by the joiner (refusal 10), and so is another region or port", () -> {
      HandshakeB.Identity impostor = identity(74);
      HandshakeB.Joiner joiner = joiner(82);
      HandshakeB.Host wrong = HandshakeB.readB1(REGION, PORT, impostor, joiner.b1(), ScriptedRandom.seeded(83));
      same(joiner.readB2(wrong.b2()), null, "B2 from another identity, whatever its tags: refused, and nothing more is sent");

      HandshakeB.Joiner otherPort = HandshakeB.writeB1(REGION, PORT + 1, HOST.fingerprint(), JOINER, ScriptedRandom.seeded(84));
      same(otherPort.readB2(host(otherPort.b1(), 85).b2()), null, "another relay port in the prologue: refused");
      HandshakeB.Joiner otherRegion = HandshakeB.writeB1("paris", PORT, HOST.fingerprint(), JOINER, ScriptedRandom.seeded(84));
      same(otherRegion.readB2(host(otherRegion.b1(), 85).b2()), null, "another region in the prologue: refused");
    });

    test("a B5 whose nJ isn't the one B1's commitment promised is refused by the host (refusal 21), though its tag is good", () -> {
      HandshakeB.Joiner joiner = joiner(91);
      HandshakeB.Host host = host(joiner.b1(), 92);
      byte[] b4 = host.readB3(joiner.readB2(host.b2()));
      HandshakeB.Joiner.Done lying = joiner.readB4(b4, bytes(32, 0x5e));
      ok(lying != null, "the joiner's side makes the B5, its tag good");
      same(host.readB5(lying.b5()), null, "the host refuses it: SHA-384 of what B5 reveals isn't B1's commitment");
    });

    // One byte in every 7 of the long ones, so every part of every message (keys, commitment, ciphertexts, sealed keys, nonces, tags) is
    // hit, in a few seconds; and every byte of B5
    test("bytes of B1 to B5 changed, a bit a byte: each refused at the next step, every one", () -> {
      byte[] b1 = joiner(86).b1();

      for (int i = 0; i < b1.length; i += 7) {
        HandshakeB.Host host = host(flip(b1, i), 87);
        ok(host == null || joiner(86).readB2(host.b2()) == null, "B1's byte " + i + ": the host can't answer the joiner's real B1");
      }

      byte[] b2 = host(joiner(86).b1(), 87).b2();

      for (int i = 0; i < b2.length; i += 7) {
        same(joiner(86).readB2(flip(b2, i)), null, "B2's byte " + i);
      }

      byte[] b3 = joiner(86).readB2(b2);

      for (int i = 0; i < b3.length; i += 7) {
        same(host(joiner(86).b1(), 87).readB3(flip(b3, i)), null, "B3's byte " + i);
      }

      byte[] b4 = host(joiner(86).b1(), 87).readB3(b3);

      for (int i = 0; i < b4.length; i += 7) {
        HandshakeB.Joiner j = joiner(86);
        j.readB2(b2);
        same(j.readB4(flip(b4, i)), null, "B4's byte " + i);
      }

      HandshakeB.Joiner last = joiner(86);
      last.readB2(b2);
      byte[] b5 = last.readB4(b4).b5();

      for (int i = 0; i < b5.length; i++) {
        same(hostAtB5(86, 87).readB5(flip(b5, i)), null, "B5's byte " + i);
      }

      ok(hostAtB5(86, 87).readB5(b5) != null, "and the untouched B5 is taken");
    });

    test("the same B1 gives the same B2 only with the same randomness: so the host must keep its B2 to send again", () -> {
      byte[] b1 = joiner(88).b1();
      same(host(b1, 89).b2(), host(b1, 89).b2(), "the same randomness: the same B2");
      ok(!Arrays.equals(host(b1, 89).b2(), host(b1, 90).b2()), "fresh randomness: another B2, other keys (section 8: send the kept one again)");
    });

    test("B's datagrams: 2, 3, 3, 2 and 1 of 1,200 bytes, end to end (AVPE), as section 8's table says", () -> {
      byte[] id = new byte[8];
      byte[] noCookie = new byte[16];
      int[] sizes = {HandshakeB.B1_BYTES, HandshakeB.B2_BYTES, HandshakeB.B3_BYTES, HandshakeB.B4_BYTES, HandshakeB.B5_BYTES};
      int[] counts = {2, 3, 3, 2, 1};

      for (int i = 0; i < sizes.length; i++) {
        same(Fragments.cut(Fragments.hostToJoiner(), HandshakeB.B1 + i, id, noCookie, new byte[sizes[i]]).size(), counts[i],
            "B" + (i + 1) + ": " + sizes[i] + " bytes");
      }
    });

    test("the fingerprint is the first 16 bytes of SHA-384 of the words and both keys, and the check code depends on every byte of h", () -> {
      byte[] fp = HOST.fingerprint();
      same(fp.length, 16, "16 bytes");
      same(fp, Arrays.copyOf(Noise.sha384("AVPX-ID-2".getBytes(StandardCharsets.US_ASCII), HOST.p384Public(), HOST.kemPublic()), 16),
          "SHA-384(\"AVPX-ID-2\" || P-384 || ML-KEM), cut to 16");
      ok(!Arrays.equals(fp, JOINER.fingerprint()), "another identity, another fingerprint");
      byte[] h = new byte[48];
      String code = HandshakeB.checkCode(h);
      int differ = 0;

      for (int i = 0; i < 48; i++) {
        differ += HandshakeB.checkCode(flip(h, i)).equals(code) ? 0 : 1;
      }

      ok(differ >= 47, "a byte of h changed changes the code (at most one of 48 the same by chance): " + differ);
    });
  }
}
