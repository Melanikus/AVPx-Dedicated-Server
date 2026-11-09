package avpx.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;

// Version 2's two signatures, made and checked together: ECDSA on P-384 with SHA-384, and ML-DSA-87 (FIPS 204). Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server.
//
// A signature proves a file came from whoever holds a private key: anyone with the public key can check it, and nobody without the
// private key can make one. CRYPTO.md section 12: every signed thing carries both kinds, and both must check, so a forger has to break both.
// - ECDSA P-384 with SHA-384: its signature goes on the wire as r then s, 48 bytes each, biggest byte first (96 bytes, IEEE P1363), which
//   Java gives and takes as "SHA384withECDSAinP1363Format".
// - ML-DSA-87, pure (not the pre-hashed HashML-DSA): Java's own (JEP 497). Its public key goes on the wire as its raw 2,592 bytes, inside
//   Java's X.509 form whose 22 bytes before it are checked, not assumed; its signature is 4,627 bytes.
// Both are Java's own; the randomness for making them comes from random.
public final class Signatures {
  private Signatures() {
  }

  public static final int ECDSA_BYTES = 96;
  public static final int ML_DSA_PUBLIC_BYTES = 2592;
  public static final int ML_DSA_BYTES = 4627;
  private static final String ECDSA = "SHA384withECDSAinP1363Format";
  // Java's own name for the one parameter set version 2 uses ("ML-DSA-87"), never the family's ("ML-DSA"): what Java makes under the
  // family's name takes a key of any set (ML-DSA-44, -65 or -87), and under this one, only ML-DSA-87 (PrimitivesTest checks it)
  private static final String ML_DSA = NamedParameterSpec.ML_DSA_87.getName();

  // DER: SEQUENCE (2,610 bytes) { SEQUENCE { OID 2.16.840.1.101.3.4.3.19, ML-DSA-87 }, BIT STRING (2,593 bytes, no unused bits) { the key } }
  private static final byte[] ML_DSA_SPKI_PREFIX = HexFormat.of().parseHex("30820a32" + "300b0609608648016503040313" + "03820a2100");

  // ----- ECDSA P-384, SHA-384

  public static KeyPair ecdsaKeys(SecureRandom random) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp384r1"), random);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't make a P-384 key", e);
    }
  }

  public static byte[] ecdsaSign(PrivateKey key, byte[] message, SecureRandom random) {
    try {
      Signature s = Signature.getInstance(ECDSA);
      s.initSign(key, random);
      s.update(message);
      return s.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't sign with ECDSA P-384", e);
    }
  }

  // Whether a 96-byte signature from outside is good for message under key (a P-384 key that came through P384.decode)
  public static boolean ecdsaVerify(PublicKey key, byte[] message, byte[] signature) {
    if (signature == null || signature.length != ECDSA_BYTES) {
      return false;
    }

    try {
      Signature s = Signature.getInstance(ECDSA);
      s.initVerify(key);
      s.update(message);
      return s.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  // ----- ML-DSA-87

  public static KeyPair mlDsaKeys(SecureRandom random) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(ML_DSA);
      generator.initialize(NamedParameterSpec.ML_DSA_87, random);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't make an ML-DSA-87 key", e);
    }
  }

  // A public key's raw 2,592 bytes
  public static byte[] mlDsaEncode(PublicKey key) {
    byte[] der = key.getEncoded();

    if (der.length != ML_DSA_SPKI_PREFIX.length + ML_DSA_PUBLIC_BYTES
        || !Arrays.equals(Arrays.copyOf(der, ML_DSA_SPKI_PREFIX.length), ML_DSA_SPKI_PREFIX)) {
      throw new IllegalStateException("this Java's ML-DSA-87 public key isn't in the form FIPS 204 and RFC 5280 give it");
    }

    return Arrays.copyOfRange(der, ML_DSA_SPKI_PREFIX.length, der.length);
  }

  // The public key in 2,592 raw bytes from outside, or null if Java won't take it as one
  public static PublicKey mlDsaDecode(byte[] raw) {
    if (raw == null || raw.length != ML_DSA_PUBLIC_BYTES) {
      return null;
    }

    byte[] der = Arrays.copyOf(ML_DSA_SPKI_PREFIX, ML_DSA_SPKI_PREFIX.length + ML_DSA_PUBLIC_BYTES);
    System.arraycopy(raw, 0, der, ML_DSA_SPKI_PREFIX.length, ML_DSA_PUBLIC_BYTES);

    try {
      return KeyFactory.getInstance(ML_DSA).generatePublic(new X509EncodedKeySpec(der));
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  public static byte[] mlDsaSign(PrivateKey key, byte[] message, SecureRandom random) {
    try {
      Signature s = Signature.getInstance(ML_DSA);
      s.initSign(key, random);
      s.update(message);
      return s.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't sign with ML-DSA-87", e);
    }
  }

  // Whether a 4,627-byte signature from outside is good for message under key (pure ML-DSA, with an empty context)
  public static boolean mlDsaVerify(PublicKey key, byte[] message, byte[] signature) {
    if (signature == null || signature.length != ML_DSA_BYTES) {
      return false;
    }

    try {
      Signature s = Signature.getInstance(ML_DSA);
      s.initVerify(key);
      s.update(message);
      return s.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }
}
