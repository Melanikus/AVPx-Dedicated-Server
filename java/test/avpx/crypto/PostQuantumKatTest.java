package avpx.crypto;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.Kat;
import avpx.testing.ScriptedRandom;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

// ML-KEM-1024 (MlKem.java) against every published case in test-vectors/crypto-kat: NIST's ACVP and Wycheproof's. Written 2026-11-09
// by Melanikus for AVPx Dedicated Server. These are the first real check of those files' post-quantum cases (Secondary checked their
// sizes only). ML-DSA-87's cases went with Signatures.java, 2026-11-09: nothing in the server signs or checks a signature until the
// signed relays directory (CRYPTO.md section 12), and they come back with it. git keeps both.
//
// Key generation is held to the cases by giving Java the case's own seeds as its "randomness" (ScriptedRandom): FIPS 203's d then z.
// An ML-KEM decapsulation key in its long form (FIPS 203's dk, 3,168 bytes) comes in through MlKem.decodePrivate, as a relay's own key
// does, which makes FIPS 203 section 7.3's check (Java 25 doesn't).
//
// ONE KIND OF CASE IS COUNTED, NOT CHECKED, and its test says how many, so a change in the files is noticed:
// - Wycheproof's ML-KEM decapsulation cases whose private seed is the wrong length: they test a way of taking a seed from outside,
//   which neither Java nor version 2 has.
public final class PostQuantumKatTest {
  private PostQuantumKatTest() {
  }

  private static String unless(boolean right, String what) {
    return right ? null : what;
  }

  private static byte[] join(byte[]... parts) {
    int n = 0;

    for (byte[] p : parts) {
      n += p.length;
    }

    byte[] out = new byte[n];
    int at = 0;

    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, at, p.length);
      at += p.length;
    }

    return out;
  }

  // ----- ML-KEM-1024

  // A key pair made from seeds d and z: its encapsulation key must be ek; and the long-form dk, taken through MlKem.decodePrivate, must
  // open what's sealed to that key exactly as the pair's own decapsulation key does (so dk is the pair's, in all it does)
  private static String kemKeys(byte[] dz, byte[] ek, byte[] dk) throws Exception {
    KeyPair pair = MlKem.generate(ScriptedRandom.of(dz));

    if (!Arrays.equals(MlKem.encode(pair.getPublic()), ek)) {
      return "another encapsulation key";
    }

    PrivateKey fromDk = MlKem.decodePrivate(dk);

    if (fromDk == null) {
      return "the case's dk was refused";
    }

    MlKem.Encapsulated sealed = MlKem.encapsulate(pair.getPublic(), ScriptedRandom.seeded(5));
    byte[] byPair = MlKem.decapsulate(pair.getPrivate(), sealed.ciphertext());
    byte[] byDk = MlKem.decapsulate(fromDk, sealed.ciphertext());
    return unless(Arrays.equals(byPair, sealed.secret()) && Arrays.equals(byDk, sealed.secret()), "dk doesn't open what the pair seals");
  }

  public static void register() {
    test("ML-KEM-1024 key generation, NIST ACVP's 25: from d and z, exactly ek, and a dk that works exactly as the pair's own", () -> {
      String file = "ml-kem-1024/nist-acvp-keygen.json";
      same(Kat.each(file, Kat.read(file), c -> kemKeys(join(c.bytes("d"), c.bytes("z")), c.bytes("ek"), c.bytes("dk"))), 25, "all 25");
    });

    test("ML-KEM-1024 key generation, Wycheproof's 100 from seeds (d then z): exactly ek, and a dk that works as the pair's own", () -> {
      String file = "ml-kem-1024/wycheproof-keygen-seed.json";
      same(Kat.each(file, Kat.read(file), c -> kemKeys(c.bytes("seed"), c.bytes("ek"), c.bytes("dk"))), 100, "all 100");
    });

    test("ML-KEM-1024, NIST ACVP's 55: encapsulation and decapsulation exactly, and FIPS 203's key checks decided as NIST does", () -> {
      String file = "ml-kem-1024/nist-acvp-encapdecap.json";
      same(Kat.each(file, Kat.read(file), c -> {
        switch (c.text("function")) {
          case "encapsulation": {
            PublicKey ek = MlKem.decode(c.bytes("ek"));

            if (ek == null) {
              return "the encapsulation key was refused";
            }

            MlKem.Encapsulated made = MlKem.encapsulate(ek, ScriptedRandom.of(c.bytes("m")));
            return unless(Arrays.equals(made.ciphertext(), c.bytes("c")) && Arrays.equals(made.secret(), c.bytes("k")), "another c or k");
          }
          case "decapsulation": {
            PrivateKey dk = MlKem.decodePrivate(c.bytes("dk"));
            return dk == null ? "the dk was refused" : unless(Arrays.equals(MlKem.decapsulate(dk, c.bytes("c")), c.bytes("k")), "another k");
          }
          case "encapsulationKeyCheck": {
            boolean taken = MlKem.decode(c.bytes("ek")) != null;
            return c.valid() ? unless(taken, "a good key refused") : unless(!taken, "a bad key taken");
          }
          case "decapsulationKeyCheck": {
            boolean taken = MlKem.decodePrivate(c.bytes("dk")) != null;
            return c.valid() ? unless(taken, "a good dk refused") : unless(!taken, "a bad dk taken");
          }
          default:
            return "a function this test doesn't know: " + c.text("function");
        }
      }), 55, "all 55");
    });

    test("ML-KEM-1024 encapsulation, Wycheproof's 269: exactly c and K from ek and m, and every key past FIPS 203's check refused at decode", () -> {
      String file = "ml-kem-1024/wycheproof-encaps.json";
      same(Kat.each(file, Kat.read(file), c -> {
        PublicKey ek = MlKem.decode(c.bytes("ek"));

        if (!c.valid()) {
          return unless(ek == null, "a bad key taken");
        }

        if (ek == null) {
          return "a good key refused";
        }

        MlKem.Encapsulated made = MlKem.encapsulate(ek, ScriptedRandom.of(c.bytes("m")));
        return unless(Arrays.equals(made.ciphertext(), c.bytes("c")) && Arrays.equals(made.secret(), c.bytes("K")), "another c or K");
      }), 269, "all 269");
    });

    test("ML-KEM-1024 decapsulation, Wycheproof's 202: exactly K, changed ciphertexts included (implicit rejection), and every wrong size refused", () -> {
      String file = "ml-kem-1024/wycheproof-decaps.json";
      int[] seedCases = new int[1];
      same(Kat.each(file, Kat.read(file), c -> {
        byte[] seed = c.bytes("seed");

        if (seed.length != 64) {
          // Taking a seed from outside isn't something version 2 does (see the top): counted, and it must be a refused case
          seedCases[0]++;
          return unless(!c.valid(), "a good case with a seed of " + seed.length + " bytes");
        }

        KeyPair pair = MlKem.generate(ScriptedRandom.of(seed));

        if (c.has("ek") && !c.text("ek").isEmpty() && !Arrays.equals(MlKem.encode(pair.getPublic()), c.bytes("ek"))) {
          return "another encapsulation key from the seed";
        }

        byte[] k = MlKem.decapsulate(pair.getPrivate(), c.bytes("c"));
        return c.valid() ? unless(Arrays.equals(k, c.bytes("K")), "another K") : unless(k == null, "a ciphertext of the wrong size taken");
      }), 202, "all 202");
      same(seedCases[0], 20, "20 cases test a seed of the wrong length, which nothing here takes");
    });

    test("ML-KEM-1024 decapsulation with a long-form dk, Wycheproof's 9: exactly K, and a dk or c that's wrong refused", () -> {
      String file = "ml-kem-1024/wycheproof-decaps-checked.json";
      same(Kat.each(file, Kat.read(file), c -> {
        PrivateKey dk = MlKem.decodePrivate(c.bytes("dk"));

        if (dk == null) {
          return c.valid() ? "a good dk refused" : null;
        }

        byte[] k = MlKem.decapsulate(dk, c.bytes("c"));
        return c.valid() ? unless(Arrays.equals(k, c.bytes("K")), "another K") : unless(k == null, "a bad dk or c taken");
      }), 9, "all 9");
    });

  }
}
