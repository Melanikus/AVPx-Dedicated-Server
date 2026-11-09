package avpx.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;

// ML-KEM-1024 (FIPS 203): the post-quantum half of version 2's key exchange. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// One side has a key pair: an encapsulation key, which it gives out, and a decapsulation key, which it keeps. The other side uses the
// encapsulation key to make a random 32-byte secret and a ciphertext of it (encapsulation), and sends the ciphertext; only the
// decapsulation key turns the ciphertext back into the same secret. No known computer, quantum or not, can get the secret from the
// encapsulation key and the ciphertext alone. It's Java's own (JEP 496, through javax.crypto.KEM).
//
// An encapsulation key goes on the wire as its raw 1,568 bytes. Java gives and takes it inside an X.509 "SubjectPublicKeyInfo" (DER),
// which for ML-KEM-1024 is always the same 22 bytes and then the raw key: those 22 bytes are checked, not assumed.
public final class MlKem {
  private MlKem() {
  }

  public static final int ENCAPSULATION_KEY_BYTES = 1568;
  public static final int DECAPSULATION_KEY_BYTES = 3168;
  public static final int CIPHERTEXT_BYTES = 1568;
  public static final int SECRET_BYTES = 32;

  // DER: SEQUENCE (1,586 bytes) { SEQUENCE { OID 2.16.840.1.101.3.4.4.3, ML-KEM-1024 }, BIT STRING (1,569 bytes, no unused bits) { the key } }
  private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("30820632" + "300b0609608648016503040403" + "0382062100");

  // DER for a decapsulation key in its long form, as PKCS#8 holds it ("expandedKey", in the IETF's draft for ML-KEM in certificates):
  // SEQUENCE (3,192 bytes) { INTEGER 0, SEQUENCE { OID ML-KEM-1024 }, OCTET STRING (3,172) { OCTET STRING (3,168) { the key } } }
  private static final byte[] PKCS8_PREFIX = HexFormat.of().parseHex("30820c78" + "020100" + "300b0609608648016503040403" + "04820c64"
      + "04820c60");

  // Where a decapsulation key holds its encapsulation key, and that key's SHA3-256 hash (FIPS 203 section 7.1: dk is the secret
  // polynomials, 1,536 bytes; then ek, 1,568; then H(ek), 32; then z, 32)
  private static final int DK_EK_AT = 1536;
  private static final int DK_HASH_AT = DK_EK_AT + ENCAPSULATION_KEY_BYTES;
  private static final int HASH_BYTES = 32;

  // Java's own name for the one parameter set version 2 uses ("ML-KEM-1024"), never the family's ("ML-KEM"): what Java makes under the
  // family's name takes a key of any size (ML-KEM-512, -768 or -1024), and under this one, only ML-KEM-1024 (PrimitivesTest checks it)
  private static final String KEM_NAME = NamedParameterSpec.ML_KEM_1024.getName();

  // A new key pair, its randomness from random. FIPS 203's key generation draws d, then z, 32 bytes each.
  public static KeyPair generate(SecureRandom random) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(KEM_NAME);
      generator.initialize(NamedParameterSpec.ML_KEM_1024, random);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't make an ML-KEM-1024 key", e);
    }
  }

  public static final int SEED_BYTES = 64;

  // A key pair made again from its 64-byte seed, FIPS 203's d then z (ML-KEM.KeyGen_internal(d, z)), as a relay's settings keep it: the
  // seed is the whole secret, and one seed always makes the same pair. Java takes d and z from the SecureRandom it's given, so it's given
  // one that holds exactly those 64 bytes and refuses to give more (NIST's own key generation cases hold Java to this: PostQuantumKatTest).
  // Null if the seed isn't 64 bytes, or this Java asks for other than d and z.
  public static KeyPair fromSeed(byte[] seed) {
    if (seed == null || seed.length != SEED_BYTES) {
      return null;
    }

    Fixed given = new Fixed(seed);

    try {
      KeyPair pair = generate(given);
      return given.allTaken() ? pair : null;
    } catch (IllegalStateException | ProviderException e) {
      return null;
    } finally {
      given.wipe();
    }
  }

  // A SecureRandom that gives exactly the bytes it was made with, once, in order, and then refuses: so Java makes FIPS 203's own
  // functions from given inputs (KeyGen from d and z, Encaps from m). Never for anything that needs real randomness.
  private static final class Fixed extends SecureRandom {
    private static final long serialVersionUID = 1L;
    private final Bytes bytes;

    Fixed(byte[] seed) {
      this(new Bytes(seed.clone()));
    }

    private Fixed(Bytes bytes) {
      super(bytes, null);
      this.bytes = bytes;
    }

    boolean allTaken() {
      return bytes.at == bytes.seed.length;
    }

    void wipe() {
      Arrays.fill(bytes.seed, (byte) 0);
    }

    private static final class Bytes extends SecureRandomSpi {
      private static final long serialVersionUID = 1L;
      private final byte[] seed;
      private int at;

      Bytes(byte[] seed) {
        this.seed = seed;
      }

      @Override
      protected void engineSetSeed(byte[] more) {
        // The seed is fixed: nothing is mixed in
      }

      @Override
      protected void engineNextBytes(byte[] out) {
        if (at + out.length > seed.length) {
          throw new IllegalStateException("MlKem: Java asked for more bytes than FIPS 203's inputs it was given");
        }

        System.arraycopy(seed, at, out, 0, out.length);
        at += out.length;
      }

      @Override
      protected byte[] engineGenerateSeed(int n) {
        throw new IllegalStateException("MlKem: Java asked for a seed of its own");
      }
    }
  }

  // An encapsulation key's raw 1,568 bytes
  public static byte[] encode(PublicKey key) {
    byte[] der = key.getEncoded();

    if (der.length != SPKI_PREFIX.length + ENCAPSULATION_KEY_BYTES
        || !Arrays.equals(Arrays.copyOf(der, SPKI_PREFIX.length), SPKI_PREFIX)) {
      throw new IllegalStateException("this Java's ML-KEM-1024 encapsulation key isn't in the form FIPS 203 and RFC 5280 give it");
    }

    return Arrays.copyOfRange(der, SPKI_PREFIX.length, der.length);
  }

  // The encapsulation key in 1,568 raw bytes from outside, or null if it isn't a good one. FIPS 203 section 7.2's check is made here, on
  // the bytes, before Java is given them (see inRange): Java 25 takes a key that fails it, and refuses it only later, when it's used.
  public static PublicKey decode(byte[] raw) {
    if (raw == null || raw.length != ENCAPSULATION_KEY_BYTES || !inRange(raw)) {
      return null;
    }

    byte[] der = Arrays.copyOf(SPKI_PREFIX, SPKI_PREFIX.length + ENCAPSULATION_KEY_BYTES);
    System.arraycopy(raw, 0, der, SPKI_PREFIX.length, ENCAPSULATION_KEY_BYTES);

    try {
      return KeyFactory.getInstance(KEM_NAME).generatePublic(new X509EncodedKeySpec(der));
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  // FIPS 203 section 7.2, the encapsulation key check. A key is four polynomials of 256 numbers each, then 32 bytes of seed. Each number
  // is 12 bits, packed two to every 3 bytes, low bits first: from bytes b0, b1, b2 come (b0, plus b1's low 4 bits on top) and (b1's high
  // 4 bits, plus b2 on top). Every number must be below q = 3,329, the prime the polynomials are worked in: 12 bits can hold up to 4,095,
  // and a key holding a number past q isn't one any honest key generation makes. The 32 seed bytes at the end can be anything.
  private static final int Q = 3329;
  private static final int PACKED_POLYNOMIALS_BYTES = 4 * 384;

  static boolean inRange(byte[] raw) {
    for (int i = 0; i < PACKED_POLYNOMIALS_BYTES; i += 3) {
      int b0 = raw[i] & 0xff;
      int b1 = raw[i + 1] & 0xff;
      int b2 = raw[i + 2] & 0xff;

      if ((b0 | ((b1 & 0x0f) << 8)) >= Q || ((b1 >> 4) | (b2 << 4)) >= Q) {
        return false;
      }
    }

    return true;
  }

  // A decapsulation key in its long form, 3,168 raw bytes (as a relay's settings or a game's sealed store hold it, CRYPTO.md section
  // 12), or null if it isn't a good one. FIPS 203 section 7.3's check is made here: the hash it holds must be its own encapsulation
  // key's. Java 25 takes a key that fails the check, and refuses it only when it's used, by throwing; so it's checked as it comes in.
  public static PrivateKey decodePrivate(byte[] dk) {
    if (dk == null || dk.length != DECAPSULATION_KEY_BYTES) {
      return null;
    }

    try {
      byte[] hash = MessageDigest.getInstance("SHA3-256").digest(Arrays.copyOfRange(dk, DK_EK_AT, DK_HASH_AT));

      if (!MessageDigest.isEqual(hash, Arrays.copyOfRange(dk, DK_HASH_AT, DK_HASH_AT + HASH_BYTES))) {
        return null;
      }

      byte[] der = Arrays.copyOf(PKCS8_PREFIX, PKCS8_PREFIX.length + DECAPSULATION_KEY_BYTES);
      System.arraycopy(dk, 0, der, PKCS8_PREFIX.length, DECAPSULATION_KEY_BYTES);
      return KeyFactory.getInstance(KEM_NAME).generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  // What encapsulation gives: the ciphertext to send, and the secret, which stays here
  public record Encapsulated(byte[] ciphertext, byte[] secret) {
  }

  // A fresh secret for whoever holds key's decapsulation key, its randomness (FIPS 203's m, 32 bytes) from random
  public static Encapsulated encapsulate(PublicKey key, SecureRandom random) {
    try {
      KEM.Encapsulated made = KEM.getInstance(KEM_NAME).newEncapsulator(key, random).encapsulate();
      byte[] secret = made.key().getEncoded();
      byte[] ciphertext = made.encapsulation();

      if (secret.length != SECRET_BYTES || ciphertext.length != CIPHERTEXT_BYTES) {
        throw new IllegalStateException("this Java's ML-KEM-1024 gave the wrong sizes");
      }

      return new Encapsulated(ciphertext, secret);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't encapsulate with ML-KEM-1024", e);
    }
  }

  // An encapsulation from a given m (FIPS 203's Encaps_internal(ek, m)): the same m always gives the same ciphertext and secret. Only for
  // checking the code against known answers (Smoke's pin to crypto-v2.json): a real encapsulation's m must be fresh (the one above).
  public static Encapsulated encapsulate(PublicKey key, byte[] m) {
    if (m == null || m.length != SECRET_BYTES) {
      throw new IllegalArgumentException("MlKem.encapsulate: m is 32 bytes");
    }

    Fixed given = new Fixed(m);

    try {
      Encapsulated made = encapsulate(key, given);

      if (!given.allTaken()) {
        throw new IllegalStateException("this Java's ML-KEM-1024 didn't take m as FIPS 203 says");
      }

      return made;
    } finally {
      given.wipe();
    }
  }

  // The secret in a ciphertext from outside, or null if it isn't 1,568 bytes. A ciphertext of the right size always gives a secret: FIPS
  // 203 has a changed ciphertext give a different, unpredictable one ("implicit rejection"), so the handshake fails at its next tag.
  public static byte[] decapsulate(PrivateKey key, byte[] ciphertext) {
    if (ciphertext == null || ciphertext.length != CIPHERTEXT_BYTES) {
      return null;
    }

    try {
      byte[] secret = KEM.getInstance(KEM_NAME).newDecapsulator(key).decapsulate(ciphertext).getEncoded();
      return secret.length == SECRET_BYTES ? secret : null;
    } catch (DecapsulateException e) {
      return null;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't decapsulate with ML-KEM-1024", e);
    }
  }
}
