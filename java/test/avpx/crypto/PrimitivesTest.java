package avpx.crypto;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.ScriptedRandom;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;

// The tests of the primitives' own behaviour (Gcm, P384, MlKem, Signatures): what each seals, agrees or signs comes back only exactly as
// it was made, and anything else is refused. Written 2026-11-09 by Melanikus for AVPx Dedicated Server. NIST's and Wycheproof's own
// known answers are in their own tests, read from test-vectors/crypto-kat; these hold the code's edges.
public final class PrimitivesTest {
  private PrimitivesTest() {
  }

  // The same message with one bit changed
  private static byte[] flip(byte[] b, int bit) {
    byte[] c = b.clone();
    c[bit / 8] ^= (byte) (1 << (bit % 8));
    return c;
  }

  public static void register() {
    test("AES-256-GCM opens exactly what it sealed, and nothing with a bit changed anywhere", () -> {
      byte[] key = bytes(32, 7);
      byte[] nonce = bytes(12, 9);
      byte[] aad = "the header".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      byte[] message = "a control message of some bytes".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
      byte[] sealed = Gcm.seal(key, nonce, aad, message);
      same(sealed.length, message.length + Gcm.TAG_BYTES, "the message, then a 16-byte tag");
      same(Gcm.open(key, nonce, aad, sealed), message, "it opens");

      for (int bit = 0; bit < sealed.length * 8; bit++) {
        same(Gcm.open(key, nonce, aad, flip(sealed, bit)), null, "a bit changed in the sealed bytes, bit " + bit);
      }

      for (int bit = 0; bit < aad.length * 8; bit++) {
        same(Gcm.open(key, nonce, flip(aad, bit), sealed), null, "a bit changed in the AAD, bit " + bit);
      }

      same(Gcm.open(flip(key, 0), nonce, aad, sealed), null, "another key");
      same(Gcm.open(key, flip(nonce, 0), aad, sealed), null, "another nonce");
      same(Gcm.open(key, nonce, aad, Arrays.copyOf(sealed, 15)), null, "less than a tag");
      same(Gcm.seal(key, nonce, new byte[0], new byte[0]).length, 16, "an empty message seals to its tag alone");
    });

    test("P-384: both sides agree on the same 48 bytes, and a key from outside must be a point on the curve", () -> {
      KeyPair a = P384.generate(ScriptedRandom.seeded(1));
      KeyPair b = P384.generate(ScriptedRandom.seeded(2));
      byte[] aPublic = P384.encode((ECPublicKey) a.getPublic());
      same(aPublic.length, 97, "97 bytes");
      same(aPublic[0], (byte) 0x04, "uncompressed: 0x04, then x and y");
      ECPublicKey aBack = P384.decode(aPublic);
      ok(aBack != null, "a key it wrote, it reads");
      same(P384.encode(aBack), aPublic, "and writes back the same");
      byte[] ab = P384.agree(a.getPrivate(), (ECPublicKey) b.getPublic());
      byte[] ba = P384.agree(b.getPrivate(), aBack);
      same(ab.length, 48, "48 bytes: the x coordinate");
      same(ab, ba, "both sides agree");

      byte[] offCurve = aPublic.clone();
      offCurve[96] ^= 1;
      same(P384.decode(offCurve), null, "a point off the curve (y changed by one bit)");
      byte[] compressed = aPublic.clone();
      compressed[0] = 0x02;
      same(P384.decode(compressed), null, "another form than uncompressed");
      same(P384.decode(Arrays.copyOf(aPublic, 96)), null, "96 bytes");
      same(P384.decode(new byte[97]), null, "all zeros");
      byte[] tooBig = aPublic.clone();
      Arrays.fill(tooBig, 1, 49, (byte) 0xff);
      same(P384.decode(tooBig), null, "an x past the field's prime");
      ok(!P384.onCurve(BigInteger.ZERO, BigInteger.ZERO), "(0, 0) isn't on P-384");
    });

    test("ML-KEM-1024: what one side encapsulates, only the other's decapsulation key opens; its sizes are FIPS 203's", () -> {
      KeyPair kem = MlKem.generate(ScriptedRandom.seeded(3));
      byte[] ek = MlKem.encode(kem.getPublic());
      same(ek.length, 1568, "an encapsulation key of 1,568 bytes");
      ok(MlKem.decode(ek) != null, "it reads back");
      same(MlKem.encode(MlKem.decode(ek)), ek, "the same bytes");

      MlKem.Encapsulated made = MlKem.encapsulate(MlKem.decode(ek), ScriptedRandom.seeded(4));
      same(made.ciphertext().length, 1568, "a ciphertext of 1,568 bytes");
      same(made.secret().length, 32, "a secret of 32 bytes");
      same(MlKem.decapsulate(kem.getPrivate(), made.ciphertext()), made.secret(), "the decapsulation key opens it");

      KeyPair other = MlKem.generate(ScriptedRandom.seeded(5));
      notSame(MlKem.decapsulate(other.getPrivate(), made.ciphertext()), made.secret(), "another key gets another secret, not this one");
      notSame(MlKem.decapsulate(kem.getPrivate(), flip(made.ciphertext(), 100)), made.secret(),
          "a ciphertext with a bit changed gives another secret (FIPS 203's implicit rejection), never this one");
      same(MlKem.decapsulate(kem.getPrivate(), Arrays.copyOf(made.ciphertext(), 1567)), null, "a ciphertext of 1,567 bytes");
      same(MlKem.decode(Arrays.copyOf(ek, 1567)), null, "an encapsulation key of 1,567 bytes");
    });

    test("FIPS 203's encapsulation key check, at its edges: a 12-bit number up to 3,328 is taken, 3,329 and up refused, either half of a pair", () -> {
      byte[] zero = new byte[1568];
      ok(MlKem.inRange(zero), "all zeros");
      byte[] seedOnes = zero.clone();
      Arrays.fill(seedOnes, 1536, 1568, (byte) 0xff);
      ok(MlKem.inRange(seedOnes), "the last 32 bytes, the seed, can be anything");

      for (int pair : new int[] {0, 511}) {
        int at = pair * 3;

        for (int value : new int[] {3328, 3329, 4095}) {
          byte[] low = zero.clone();
          low[at] = (byte) value;
          low[at + 1] = (byte) (value >> 8);
          byte[] high = zero.clone();
          high[at + 1] = (byte) ((value & 0x0f) << 4);
          high[at + 2] = (byte) (value >> 4);
          same(MlKem.inRange(low), value < 3329, "pair " + pair + ", its first number " + value);
          same(MlKem.inRange(high), value < 3329, "pair " + pair + ", its second number " + value);
          same(MlKem.decode(low) != null, value < 3329, "and decode agrees, pair " + pair + ", first number " + value);
        }
      }
    });

    test("ML-KEM-1024's randomness can be fixed from outside, so a whole handshake can be written down as vectors", () -> {
      byte[] seeds = bytes(64, 0x42);
      byte[] ek1 = MlKem.encode(MlKem.generate(ScriptedRandom.of(seeds)).getPublic());
      byte[] ek2 = MlKem.encode(MlKem.generate(ScriptedRandom.of(seeds)).getPublic());
      same(ek1, ek2, "the same seeds d and z give the same key");
      byte[] m = bytes(32, 0x17);
      MlKem.Encapsulated one = MlKem.encapsulate(MlKem.decode(ek1), ScriptedRandom.of(m));
      MlKem.Encapsulated two = MlKem.encapsulate(MlKem.decode(ek1), ScriptedRandom.of(m));
      same(one.ciphertext(), two.ciphertext(), "the same m gives the same ciphertext");
      same(one.secret(), two.secret(), "and the same secret");
    });

    test("ECDSA P-384 (96 bytes, r then s) and ML-DSA-87 (4,627 bytes): each checks what it signed, and nothing changed", () -> {
      byte[] message = bytes(48, 0x5d);
      KeyPair ec = Signatures.ecdsaKeys(ScriptedRandom.seeded(6));
      byte[] ecSig = Signatures.ecdsaSign(ec.getPrivate(), message, ScriptedRandom.seeded(7));
      same(ecSig.length, 96, "ECDSA: 96 bytes");
      ok(Signatures.ecdsaVerify(ec.getPublic(), message, ecSig), "it checks");
      ok(!Signatures.ecdsaVerify(ec.getPublic(), flip(message, 3), ecSig), "not for another message");
      ok(!Signatures.ecdsaVerify(ec.getPublic(), message, flip(ecSig, 3)), "not with a bit of it changed");
      ok(!Signatures.ecdsaVerify(ec.getPublic(), message, Arrays.copyOf(ecSig, 95)), "not at 95 bytes");
      ok(!Signatures.ecdsaVerify(Signatures.ecdsaKeys(ScriptedRandom.seeded(8)).getPublic(), message, ecSig), "not under another key");

      KeyPair ml = Signatures.mlDsaKeys(ScriptedRandom.seeded(9));
      byte[] mlPublic = Signatures.mlDsaEncode(ml.getPublic());
      same(mlPublic.length, 2592, "an ML-DSA-87 public key of 2,592 bytes");
      same(Signatures.mlDsaEncode(Signatures.mlDsaDecode(mlPublic)), mlPublic, "it reads back the same");
      byte[] mlSig = Signatures.mlDsaSign(ml.getPrivate(), message, ScriptedRandom.seeded(10));
      same(mlSig.length, 4627, "ML-DSA-87: 4,627 bytes");
      ok(Signatures.mlDsaVerify(Signatures.mlDsaDecode(mlPublic), message, mlSig), "it checks, under the key as it went on the wire");
      ok(!Signatures.mlDsaVerify(ml.getPublic(), flip(message, 3), mlSig), "not for another message");
      ok(!Signatures.mlDsaVerify(ml.getPublic(), message, flip(mlSig, 30)), "not with a bit of it changed");
      ok(!Signatures.mlDsaVerify(ml.getPublic(), message, Arrays.copyOf(mlSig, 4626)), "not at 4,626 bytes");
      same(Signatures.mlDsaDecode(Arrays.copyOf(mlPublic, 2591)), null, "a public key of 2,591 bytes");
    });

    test("every key Java gives out is in the raw form the wire uses, with nothing hidden in front", () -> {
      byte[] kemKey = MlKem.encode(MlKem.generate(ScriptedRandom.seeded(11)).getPublic());
      byte[] dsaKey = Signatures.mlDsaEncode(Signatures.mlDsaKeys(ScriptedRandom.seeded(12)).getPublic());
      ok(kemKey.length == 1568 && dsaKey.length == 2592, "FIPS 203's and FIPS 204's sizes");
      ok(!hex(kemKey).startsWith("3082"), "no DER left in front of the ML-KEM key");
      ok(!hex(dsaKey).startsWith("3082"), "nor the ML-DSA key");
    });

    test("P384.pair takes the two halves of one key only: never a number with another key's point, 0, the order, or a point off the curve", () -> {
      KeyPair a = P384.generate(ScriptedRandom.seeded(30));
      KeyPair b = P384.generate(ScriptedRandom.seeded(31));
      BigInteger order = ((ECPublicKey) a.getPublic()).getParams().getOrder();
      byte[] number = HexFormat.of().parseHex(String.format("%096x", ((ECPrivateKey) a.getPrivate()).getS()));
      byte[] point = P384.encode((ECPublicKey) a.getPublic());
      KeyPair back = P384.pair(number, point);
      ok(back != null, "its own two halves");
      same(P384.agree(back.getPrivate(), (ECPublicKey) b.getPublic()), P384.agree(a.getPrivate(), (ECPublicKey) b.getPublic()),
          "and the pair agrees just as the key itself does");
      same(P384.pair(number, P384.encode((ECPublicKey) b.getPublic())), null, "a number with another key's point");
      same(P384.pair(new byte[48], point), null, "0");
      same(P384.pair(HexFormat.of().parseHex(String.format("%096x", order)), point), null, "the curve's order itself");
      same(P384.pair(Arrays.copyOf(number, 47), point), null, "47 bytes");
      byte[] off = point.clone();
      off[96] ^= 1;
      same(P384.pair(number, off), null, "a point off the curve");
    });

    test("MlKem.fromSeed makes FIPS 203's KeyGen(d, z) pair, the same every time, and nothing from a seed that isn't 64 bytes", () -> {
      byte[] seed = bytes(64, 0x42);
      KeyPair made = MlKem.fromSeed(seed);
      same(MlKem.encode(made.getPublic()), MlKem.encode(MlKem.generate(ScriptedRandom.of(seed)).getPublic()),
          "the pair d and z make (PostQuantumKatTest holds that to NIST's own)");
      same(MlKem.encode(MlKem.fromSeed(seed).getPublic()), MlKem.encode(made.getPublic()), "the same seed, the same pair, every time");
      same(seed, bytes(64, 0x42), "the seed given is left as it was");
      MlKem.Encapsulated sealed = MlKem.encapsulate(made.getPublic(), ScriptedRandom.seeded(32));
      same(MlKem.decapsulate(made.getPrivate(), sealed.ciphertext()), sealed.secret(), "and its private half opens what's sealed to it");
      same(MlKem.fromSeed(new byte[63]), null, "a seed of 63 bytes");
      same(MlKem.fromSeed(null), null, "no seed");
    });
  }
}
