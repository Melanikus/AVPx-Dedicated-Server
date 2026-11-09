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

// ML-KEM-1024 and ML-DSA-87 (MlKem.java, Signatures.java) against every published case in test-vectors/crypto-kat: NIST's ACVP and
// Wycheproof's. Written 2026-11-09 by Melanikus for AVPx Dedicated Server. These are the first real check of those files' post-quantum
// cases (Secondary checked their sizes only).
//
// Key generation is held to the cases by giving Java the case's own seeds as its "randomness" (ScriptedRandom): FIPS 203's d then z,
// FIPS 204's seed. An ML-KEM decapsulation key in its long form (FIPS 203's dk, 3,168 bytes) comes in through MlKem.decodePrivate, as a
// relay's own key does, which makes FIPS 203 section 7.3's check (Java 25 doesn't). An ML-DSA private key in its long form (FIPS 204's
// sk), which version 2 never takes from anywhere, is given to Java inside PKCS#8 by this test alone (see longForm).
//
// TWO KINDS OF CASE ARE COUNTED, NOT CHECKED, and each test says how many, so a change in the files is noticed:
// - ML-DSA with a context: Java 25 has no way to give ML-DSA a context (its Signature signs and checks with the empty one only), so a
//   case with a context can't be checked for its own answer. Version 2 uses the empty context only (CRYPTO.md 5.1, point 16). Those
//   signatures are checked the other way instead, where they have a public key: each must be REFUSED with the empty context (the test
//   "all 21 ... made with a context are refused"), which is what keeps version 2's signatures to the one context.
// - Wycheproof's ML-KEM decapsulation cases whose private seed is the wrong length: they test a way of taking a seed from outside,
//   which neither Java nor version 2 has.
public final class PostQuantumKatTest {
  private PostQuantumKatTest() {
  }

  private static final byte[] DSA_OID = HexFormat.of().parseHex("0609608648016503040313");

  private static String unless(boolean right, String what) {
    return right ? null : what;
  }

  // A DER length: under 128 in one byte, else 0x82 and two bytes (all these keys are under 64 KB)
  private static byte[] length(int n) {
    return n < 128 ? new byte[] {(byte) n} : new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
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

  // An ML-DSA-87 private key in its long form (FIPS 204's sk, 4,896 bytes), inside PKCS#8 as the IETF's draft for ML-DSA in
  // certificates writes it ("expandedKey"):
  //   SEQUENCE { INTEGER 0, SEQUENCE { ML-DSA-87's OID }, OCTET STRING { OCTET STRING { the key } } }
  private static PrivateKey longForm(byte[] sk) throws Exception {
    byte[] inner = join(new byte[] {0x04}, length(sk.length), sk);
    byte[] outer = join(new byte[] {0x04}, length(inner.length), inner);
    byte[] id = join(new byte[] {0x30}, length(DSA_OID.length), DSA_OID);
    byte[] body = join(new byte[] {0x02, 0x01, 0x00}, id, outer);
    byte[] der = join(new byte[] {0x30}, length(body.length), body);
    return KeyFactory.getInstance("ML-DSA").generatePrivate(new PKCS8EncodedKeySpec(der));
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

  // ----- ML-DSA-87

  // The signature Java makes with this key, message and FIPS 204 "rnd" (32 zero bytes is the deterministic signature)
  private static byte[] sign(PrivateKey key, byte[] message, byte[] rnd) {
    return Signatures.mlDsaSign(key, message, ScriptedRandom.of(rnd));
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

    test("ML-DSA-87 key generation, NIST ACVP's 25: from the seed, exactly pk, and an sk that signs exactly as the pair's own", () -> {
      String file = "ml-dsa-87/nist-acvp-keygen.json";
      same(Kat.each(file, Kat.read(file), c -> {
        KeyPair pair = Signatures.mlDsaKeys(ScriptedRandom.of(c.bytes("seed")));

        if (!Arrays.equals(Signatures.mlDsaEncode(pair.getPublic()), c.bytes("pk"))) {
          return "another public key";
        }

        byte[] message = c.bytes("seed");
        byte[] byPair = sign(pair.getPrivate(), message, new byte[32]);
        byte[] bySk = sign(longForm(c.bytes("sk")), message, new byte[32]);
        return unless(Arrays.equals(byPair, bySk) && Signatures.mlDsaVerify(pair.getPublic(), message, bySk), "sk signs otherwise");
      }), 25, "all 25");
    });

    test("ML-DSA-87 SigVer, NIST ACVP's 15: the one with the empty context checked; the 14 with a context counted (Java 25 has no context)", () -> {
      String file = "ml-dsa-87/nist-acvp-sigver.json";
      List<Kat.Case> all = Kat.read(file);
      List<Kat.Case> empty = Kat.where(all, "context", "", true);
      same(Kat.each(file, empty, c -> {
        PublicKey pk = Signatures.mlDsaDecode(c.bytes("pk"));
        boolean checks = pk != null && Signatures.mlDsaVerify(pk, c.bytes("message"), c.bytes("signature"));
        return c.valid() ? unless(checks, "it doesn't check") : unless(!checks, "it checks");
      }), 1, "1 with the empty context");
      same(all.size() - empty.size(), 14, "14 with a context");
    });

    test("ML-DSA-87 SigGen, NIST ACVP's 30: the 3 with the empty context signed exactly, deterministic and hedged; the 27 with one counted", () -> {
      String file = "ml-dsa-87/nist-acvp-siggen.json";
      List<Kat.Case> all = Kat.read(file);
      List<Kat.Case> empty = Kat.where(all, "context", "", true);
      same(Kat.each(file, empty, c -> {
        byte[] rnd = c.text("mode").equals("deterministic") ? new byte[32] : c.bytes("rnd");
        return unless(Arrays.equals(sign(longForm(c.bytes("sk")), c.bytes("message"), rnd), c.bytes("signature")),
            "another signature");
      }), 3, "3 with the empty context");
      same(all.size() - empty.size(), 27, "27 with a context");
    });

    test("ML-DSA-87 verify, Wycheproof's 241: the 234 with the empty context, good ones check and bad ones (or bad keys) don't; 7 counted", () -> {
      String file = "ml-dsa-87/wycheproof-verify.json";
      List<Kat.Case> all = Kat.read(file);
      List<Kat.Case> empty = Kat.where(all, "context", "", true);
      same(Kat.each(file, empty, c -> {
        PublicKey pk = Signatures.mlDsaDecode(c.bytes("pk"));
        boolean checks = pk != null && Signatures.mlDsaVerify(pk, c.bytes("msg"), c.bytes("sig"));
        return c.valid() ? unless(checks, pk == null ? "a good key refused" : "it doesn't check") : unless(!checks, "it checks");
      }), 234, "234 with the empty context");
      same(all.size() - empty.size(), 7, "7 with a context");
    });

    // Version 2 signs and checks ML-DSA with the empty context only (CRYPTO.md 5.1, point 16, and section 12). These are signatures
    // made WITH a context, and a good one is good only under its own: FIPS 204 signs the context's length and bytes before the message.
    // So checking with the empty context must refuse every one, the ones good under theirs included, or a signature made for another
    // purpose, under another context, could pass here. (NIST's SigGen cases with a context carry no public key, so they can't be checked.)
    test("ML-DSA-87: all 21 NIST and Wycheproof signatures made with a context are refused, the 5 good under their own included", () -> {
      int checked = 0;
      int goodUnderTheirs = 0;

      for (String file : List.of("ml-dsa-87/nist-acvp-sigver.json", "ml-dsa-87/wycheproof-verify.json")) {
        boolean nist = file.contains("nist");
        List<Kat.Case> withContext = Kat.where(Kat.read(file), "context", "", false);

        for (Kat.Case c : withContext) {
          goodUnderTheirs += c.valid() ? 1 : 0;
        }

        checked += Kat.each(file, withContext, c -> {
          PublicKey pk = Signatures.mlDsaDecode(c.bytes("pk"));
          boolean checks = pk != null && Signatures.mlDsaVerify(pk, c.bytes(nist ? "message" : "msg"), c.bytes(nist ? "signature" : "sig"));
          return unless(!checks, "a signature made with a context checks with the empty one");
        });
      }

      same(checked, 21, "14 of NIST's and 7 of Wycheproof's");
      same(goodUnderTheirs, 5, "5 of them good under their own context (3 of NIST's, 2 of Wycheproof's)");
    });

    // Java's ML-DSA takes no parameter at all (JDK 25), so a context can't be given to it. Nothing in Signatures.java may look as if it
    // gave one: the next reader would take it for a context the signatures have, which CRYPTO.md says they haven't.
    test("Signatures.java gives its signatures no parameter, so ML-DSA has the empty context the spec names", () -> {
      String code = Files.readString(Path.of("src", "avpx", "crypto", "Signatures.java"), StandardCharsets.US_ASCII);
      ok(code.contains("Signature.getInstance(ML_DSA)"), "Signatures.java makes its ML-DSA signatures, so this looks at the right file");
      ok(!code.contains("setParameter("), "no setParameter( in Signatures.java");
    });
  }
}
