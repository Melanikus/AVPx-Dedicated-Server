package avpx.v2;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.testing.ScriptedRandom;
import java.util.Arrays;

// The tests of HandshakeB.java (CRYPTO.md section 8): a joiner and its host agree on every key and the check code; the host is the one
// the listing named, or the joiner stops; and any change to any message is refused. Written 2026-11-09 by Melanikus for AVPx Dedicated
// Server.
public final class HandshakeBTest {
  private HandshakeBTest() {
  }

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
    return HandshakeB.writeB1(PORT, HOST.fingerprint(), JOINER, ScriptedRandom.seeded(seed));
  }

  private static HandshakeB.Host host(byte[] b1, int seed) {
    return HandshakeB.readB1(PORT, HOST, b1, ScriptedRandom.seeded(seed));
  }

  public static void register() {
    test("a joiner and its host agree on every key, the transcript and the check code; each learns the other's fingerprint", () -> {
      HandshakeB.Joiner joiner = joiner(80);
      same(joiner.b1().length, 1665, "B1: 1,665 bytes");
      HandshakeB.Host host = host(joiner.b1(), 81);
      same(host.b2().length, 3362, "B2: 3,362 bytes");
      byte[] b3 = joiner.readB2(host.b2());
      ok(b3 != null && b3.length == 3265, "the joiner takes B2, from the host the listing named: B3, 3,265 bytes");
      byte[] b4 = host.readB3(b3);
      ok(b4 != null && b4.length == 1584, "the host takes B3: B4, 1,584 bytes");
      HandshakeB.Joiner.Done done = joiner.readB4(b4);
      ok(done != null && done.b5().length == 16, "the joiner takes B4, the host's key confirmation: B5, 16 bytes");
      HandshakeB.Host.Expected expected = host.expect();
      same(done.b5(), expected.b5(), "B5 is exactly what the host expects: the joiner's key confirmation");

      HandshakeB.Keys j = done.keys();
      HandshakeB.Keys h = expected.keys();
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

    test("a host that isn't the one the listing named (another identity's keys in B2) is refused by the joiner (refusal 10)", () -> {
      HandshakeB.Identity impostor = identity(74);
      HandshakeB.Joiner joiner = joiner(82);
      HandshakeB.Host wrong = HandshakeB.readB1(PORT, impostor, joiner.b1(), ScriptedRandom.seeded(83));
      same(joiner.readB2(wrong.b2()), null, "B2 from another identity, whatever its tags: refused, and nothing more is sent");

      // And a joiner told another port, or another fingerprint, has another transcript from its first byte
      HandshakeB.Joiner otherPort = HandshakeB.writeB1(PORT + 1, HOST.fingerprint(), JOINER, ScriptedRandom.seeded(84));
      same(otherPort.readB2(host(otherPort.b1(), 85).b2()), null, "another relay port in the prologue: refused");
    });

    // One byte in every 7, so every part of every message (keys, ciphertexts, sealed keys and tags) is hit, in a few seconds
    test("one byte in every 7 of B1, B2, B3 and B4 changed, a bit a byte: refused at the next step, every one", () -> {
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

      HandshakeB.Joiner last = joiner(86);
      byte[] lastB3 = last.readB2(b2);
      byte[] b4 = host(joiner(86).b1(), 87).readB3(lastB3);

      for (int i = 0; i < b4.length; i += 7) {
        HandshakeB.Joiner j = joiner(86);
        j.readB2(b2);
        same(j.readB4(flip(b4, i)), null, "B4's byte " + i);
      }

      byte[] b5 = last.readB4(b4).b5();
      HandshakeB.Host host = host(joiner(86).b1(), 87);
      host.readB3(b3);
      same(b5, host.expect().b5(), "and the untouched run ends with the B5 the host expects");
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
      same(fp, Arrays.copyOf(Noise.sha384("AVPX-ID-2".getBytes(java.nio.charset.StandardCharsets.US_ASCII), HOST.p384Public(),
          HOST.kemPublic()), 16), "SHA-384(\"AVPX-ID-2\" || P-384 || ML-KEM), cut to 16");
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
