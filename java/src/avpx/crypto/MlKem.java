package avpx.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.NamedParameterSpec;
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
  public static final int CIPHERTEXT_BYTES = 1568;
  public static final int SECRET_BYTES = 32;

  // DER: SEQUENCE (1,586 bytes) { SEQUENCE { OID 2.16.840.1.101.3.4.4.3, ML-KEM-1024 }, BIT STRING (1,569 bytes, no unused bits) { the key } }
  private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("30820632" + "300b0609608648016503040403" + "0382062100");

  private static final String KEM_NAME = "ML-KEM";

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

  // An encapsulation key's raw 1,568 bytes
  public static byte[] encode(PublicKey key) {
    byte[] der = key.getEncoded();

    if (der.length != SPKI_PREFIX.length + ENCAPSULATION_KEY_BYTES
        || !Arrays.equals(Arrays.copyOf(der, SPKI_PREFIX.length), SPKI_PREFIX)) {
      throw new IllegalStateException("this Java's ML-KEM-1024 encapsulation key isn't in the form FIPS 203 and RFC 5280 give it");
    }

    return Arrays.copyOfRange(der, SPKI_PREFIX.length, der.length);
  }

  // The encapsulation key in 1,568 raw bytes from outside, or null if Java won't take it as one
  public static PublicKey decode(byte[] raw) {
    if (raw == null || raw.length != ENCAPSULATION_KEY_BYTES) {
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
