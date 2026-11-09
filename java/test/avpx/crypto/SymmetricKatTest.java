package avpx.crypto;

import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.Kat;
import java.util.Arrays;
import java.util.List;

// AES-256-GCM, HKDF-SHA-384 and HMAC-SHA-384 (Gcm.java, Hkdf.java) against every published case in test-vectors/crypto-kat: NIST's
// and Wycheproof's. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class SymmetricKatTest {
  private SymmetricKatTest() {
  }

  private static byte[] join(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  // What a check says when two byte strings should be alike
  private static String unless(boolean right, String what) {
    return right ? null : what;
  }

  public static void register() {
    test("AES-256-GCM, NIST CAVP's 375 encryptions: each seals to exactly its ciphertext and tag", () -> {
      String file = "aes-256-gcm/nist-cavp-encrypt.json";
      List<Kat.Case> cases = Kat.read(file);
      same(Kat.each(file, cases, c -> unless(Arrays.equals(Gcm.seal(c.bytes("key"), c.bytes("iv"), c.bytes("aad"), c.bytes("pt")),
          join(c.bytes("ct"), c.bytes("tag"))), "another ciphertext or tag")), 375, "all 375");
    });

    test("AES-256-GCM, NIST CAVP's 375 decryptions: the good ones open to exactly their plaintext, and every FAIL is refused", () -> {
      String file = "aes-256-gcm/nist-cavp-decrypt.json";
      same(Kat.each(file, Kat.read(file), c -> {
        byte[] opened = Gcm.open(c.bytes("key"), c.bytes("iv"), c.bytes("aad"), join(c.bytes("ct"), c.bytes("tag")));
        return c.valid() ? unless(Arrays.equals(opened, c.bytes("pt")), "not its plaintext") : unless(opened == null, "it opened");
      }), 375, "all 375");
    });

    test("AES-256-GCM, Wycheproof's 66: the good ones seal and open exactly, and the bad ones never open", () -> {
      String file = "aes-256-gcm/wycheproof.json";
      same(Kat.each(file, Kat.read(file), c -> {
        byte[] sealed = join(c.bytes("ct"), c.bytes("tag"));
        byte[] opened = Gcm.open(c.bytes("key"), c.bytes("iv"), c.bytes("aad"), sealed);

        if (!c.valid()) {
          return unless(opened == null, "it opened");
        }

        return unless(Arrays.equals(Gcm.seal(c.bytes("key"), c.bytes("iv"), c.bytes("aad"), c.bytes("msg")), sealed)
            && Arrays.equals(opened, c.bytes("msg")), "not sealed or opened exactly");
      }), 66, "all 66");
    });

    test("HKDF-SHA-384, Wycheproof's 83: each gives exactly its bytes, and a size past 255 times 48 is refused", () -> {
      String file = "hkdf-sha384/wycheproof.json";
      same(Kat.each(file, Kat.read(file), c -> {
        int size = (int) c.number("size");

        if (!c.valid()) {
          try {
            Hkdf.derive(c.bytes("salt"), c.bytes("ikm"), c.bytes("info"), size);
            return "a size of " + size + " wasn't refused";
          } catch (IllegalArgumentException e) {
            return null;
          }
        }

        return unless(Arrays.equals(Hkdf.derive(c.bytes("salt"), c.bytes("ikm"), c.bytes("info"), size), c.bytes("okm")), "other bytes");
      }), 83, "all 83");
    });

    test("HKDF-SHA-384, NIST ACVP's 100 (KDA, written as plain HKDF): the right okm comes out, and the wrong ones given aren't it", () -> {
      String file = "hkdf-sha384/nist-acvp-kda.json";
      same(Kat.each(file, Kat.read(file), c -> {
        boolean alike = Arrays.equals(Hkdf.derive(c.bytes("salt"), c.bytes("ikm"), c.bytes("info"), (int) c.number("size")), c.bytes("okm"));
        return c.valid() ? unless(alike, "other bytes") : unless(!alike, "it gave the okm marked wrong");
      }), 100, "all 100");
    });

    test("HKDF by hand, RFC 5869's 7 cases (SHA-256 and SHA-1, as it has no SHA-384): each PRK and each output exactly", () -> {
      String file = "hkdf-sha384/rfc5869.json";
      same(Kat.each(file, Kat.read(file), c -> {
        String hash = c.text("hash");
        String alg = hash.equals("SHA-256") ? "HmacSHA256" : hash.equals("SHA-1") ? "HmacSHA1" : null;
        int bytes = hash.equals("SHA-256") ? 32 : 20;

        if (alg == null) {
          return "a hash this test doesn't know: " + hash;
        }

        boolean prk = Arrays.equals(Hkdf.hmac(alg, c.bytes("salt"), c.bytes("ikm")), c.bytes("prk"));
        boolean okm = Arrays.equals(Hkdf.derive(alg, bytes, c.bytes("salt"), c.bytes("ikm"), c.bytes("info"), (int) c.number("size")),
            c.bytes("okm"));
        return unless(prk && okm, "PRK " + prk + ", OKM " + okm);
      }), 7, "all 7");
    });

    test("HMAC-SHA-384, Wycheproof's 174: every right tag comes out, cut to its size, and every wrong one doesn't", () -> {
      String file = "hmac-sha384/wycheproof.json";
      same(Kat.each(file, Kat.read(file), c -> {
        byte[] tag = Arrays.copyOf(Hkdf.hmac(c.bytes("key"), c.bytes("msg")), (int) c.number("tagSize") / 8);
        boolean alike = Arrays.equals(tag, c.bytes("tag"));
        return c.valid() ? unless(alike, "another tag") : unless(!alike, "the tag marked wrong came out");
      }), 174, "all 174");
    });
  }
}
