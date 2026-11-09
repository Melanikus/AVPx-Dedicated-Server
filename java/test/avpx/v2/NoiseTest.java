package avpx.v2;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

// The tests of Noise.java against CRYPTO.md 5.1's points, each worked out by hand here with Java's own SHA-384 and our HKDF (held to RFC
// 5869 and to Java's own in HkdfTest): the start, MixHash, MixKey, the nonce (little-endian, on purpose), sealing with h as the AAD, and
// Split's order. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class NoiseTest {
  private NoiseTest() {
  }

  private static byte[] sha384(byte[]... parts) throws Exception {
    MessageDigest d = MessageDigest.getInstance("SHA-384");

    for (byte[] p : parts) {
      d.update(p);
    }

    return d.digest();
  }

  private static final byte[] NOTHING = new byte[0];

  public static void register() {
    test("the start: h is SHA-384 of the protocol's name, and ck is h; MixHash is SHA-384 of h then the data", () -> {
      Noise noise = new Noise(HandshakeA.PROTOCOL);
      byte[] h0 = sha384(HandshakeA.PROTOCOL.getBytes(StandardCharsets.US_ASCII));
      same(noise.h(), h0, "h");
      same(noise.ck(), h0, "ck");
      noise.mixHash(bytes(5, 9));
      same(noise.h(), sha384(h0, bytes(5, 9)), "h after a MixHash");
      same(noise.ck(), h0, "ck untouched by it");
    });

    test("the prologue: the region with a 0 after it, then the relay's static P-384 key, then its ML-KEM key, as Noise's pre-message", () -> {
      byte[] p384 = bytes(97, 4);
      byte[] kem = bytes(1568, 5);
      Noise noise = HandshakeA.start("virginia", p384, kem);
      byte[] h = sha384(HandshakeA.PROTOCOL.getBytes(StandardCharsets.US_ASCII));
      h = sha384(h, "virginia\0".getBytes(StandardCharsets.US_ASCII));
      h = sha384(h, p384);
      h = sha384(h, kem);
      same(noise.h(), h, "h after the start");
    });

    test("MixKey: HKDF-SHA-384 of the secret with ck as its salt and no info, 80 bytes, ck the first 48 and k the next 32", () -> {
      Noise noise = new Noise(HandshakeA.PROTOCOL);
      byte[] ck0 = noise.ck();
      byte[] secret = bytes(48, 0x33);
      noise.mixKey(secret.clone());
      byte[] out = Hkdf.derive(ck0, secret, NOTHING, 80);
      same(noise.ck(), Arrays.copyOf(out, 48), "the new ck");

      // k isn't handed out, so it's seen by what it seals: the first seal is under k, nonce 0, with h as the AAD
      byte[] h = noise.h();
      byte[] sealed = noise.encryptAndHash(bytes(10, 7));
      same(sealed, Gcm.seal(Arrays.copyOfRange(out, 48, 80), new byte[12], h, bytes(10, 7)), "sealed under k, nonce 0, h as AAD");
      same(noise.h(), sha384(h, sealed), "and what's sent is mixed into h");
    });

    test("the nonce is the IV XOR (4 zero bytes, then n as 8 bytes LITTLE-endian): on purpose, unlike Noise's own (5.1, point 2)", () -> {
      byte[] zero = new byte[12];
      byte[] one = new byte[12];
      one[4] = 1;
      same(Noise.nonce(zero, 1), one, "n = 1: the 1 at byte 4");
      byte[] big = new byte[12];
      big[4] = 0x08;
      big[5] = 0x07;
      big[6] = 0x06;
      big[7] = 0x05;
      big[8] = 0x04;
      big[9] = 0x03;
      big[10] = 0x02;
      big[11] = 0x01;
      same(Noise.nonce(zero, 0x0102030405060708L), big, "the low byte first");
      byte[] iv = bytes(12, 0xff);
      byte[] want = iv.clone();
      want[4] ^= 1;
      same(Noise.nonce(iv, 1), want, "XOR with the IV, which is left as it was");
      same(iv, bytes(12, 0xff), "the IV given isn't changed");
    });

    test("the second seal under the same k uses nonce 1, and a fresh MixKey starts again at 0", () -> {
      Noise noise = new Noise(HandshakeA.PROTOCOL);
      byte[] ck0 = noise.ck();
      noise.mixKey(bytes(32, 1));
      byte[] k = Arrays.copyOfRange(Hkdf.derive(ck0, bytes(32, 1), NOTHING, 80), 48, 80);
      noise.encryptAndHash(NOTHING);
      byte[] h = noise.h();
      byte[] nonce1 = new byte[12];
      nonce1[4] = 1;
      same(noise.encryptAndHash(NOTHING), Gcm.seal(k, nonce1, h, NOTHING), "the second seal: nonce 1");

      byte[] ck1 = noise.ck();
      noise.mixKey(bytes(32, 2));
      byte[] k2 = Arrays.copyOfRange(Hkdf.derive(ck1, bytes(32, 2), NOTHING, 80), 48, 80);
      byte[] h2 = noise.h();
      same(noise.encryptAndHash(NOTHING), Gcm.seal(k2, new byte[12], h2, NOTHING), "after a new MixKey: the new k, at nonce 0 again");
    });

    test("with no k yet, encryptAndHash sends the text as it is, and decryptAndHash takes it so; with a k, a wrong tag is refused", () -> {
      Noise a = new Noise(HandshakeA.PROTOCOL);
      Noise b = new Noise(HandshakeA.PROTOCOL);
      same(a.encryptAndHash(bytes(4, 2)), bytes(4, 2), "no k: the text itself");
      same(b.decryptAndHash(bytes(4, 2)), bytes(4, 2), "and read as it is");
      same(a.h(), b.h(), "both mixed it in");
      a.mixKey(bytes(32, 3));
      b.mixKey(bytes(32, 3));
      byte[] sealed = a.encryptAndHash(bytes(4, 5));
      byte[] wrong = sealed.clone();
      wrong[0] ^= 1;
      same(b.decryptAndHash(wrong), null, "a changed seal is refused");
      same(b.decryptAndHash(sealed), bytes(4, 5), "and the true one, after it, still opens: a refusal changed nothing");
    });

    test("Split: HKDF-SHA-384 with ck as its salt, no input, the info \"AVPX split v2\", 88 bytes, in 5.1's order", () -> {
      Noise noise = new Noise(HandshakeA.PROTOCOL);
      noise.mixKey(bytes(32, 8));
      byte[] ck = noise.ck();
      byte[] out = Hkdf.derive(ck, NOTHING, "AVPX split v2".getBytes(StandardCharsets.US_ASCII), 88);
      Noise.Split s = noise.split();
      same(s.initiatorKey(), Arrays.copyOfRange(out, 0, 32), "the game-to-relay key, first");
      same(s.responderKey(), Arrays.copyOfRange(out, 32, 64), "the relay-to-game key");
      same(s.initiatorIv(), Arrays.copyOfRange(out, 64, 76), "the game-to-relay IV");
      same(s.responderIv(), Arrays.copyOfRange(out, 76, 88), "the relay-to-game IV, last");
    });

    test("wiping: ck and h are zero after, and so is k (seen by what it seals: the all-zero key's seal)", () -> {
      Noise noise = new Noise(HandshakeA.PROTOCOL);
      noise.mixKey(bytes(32, 8));
      noise.wipe();
      same(noise.ck(), new byte[48], "ck is zero");
      same(noise.h(), new byte[48], "h is zero");
      same(noise.encryptAndHash(NOTHING), Gcm.seal(new byte[32], new byte[12], new byte[48], NOTHING), "k is zero");
      doesNotThrow(() -> Noise.wipe(null), "wiping nothing is fine");
    });
  }
}
