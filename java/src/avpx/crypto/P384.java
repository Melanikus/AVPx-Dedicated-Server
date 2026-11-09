package avpx.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

// ECDH on the curve P-384: the classical half of version 2's key exchange. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// Each side has a private number and a public point on the curve made from it. Each multiplies the other's public point by its own
// private number, and both get the same point: its x coordinate, 48 bytes, is the shared secret, which nobody who saw only the two public
// points can work out.
//
// A public key goes on the wire as 97 bytes: 0x04, then x and y, 48 bytes each, biggest byte first (SEC 1's uncompressed form). Every
// public key that comes from outside is checked to be a point on this curve before it's used (AVP Tao 3): a point off the curve can make
// the other side's secret leak, a bit at a time (an "invalid curve" attack). P-384's cofactor is 1, so a point on the curve that isn't
// the point at infinity (which the 97-byte form can't even write) is a good one.
public final class P384 {
  private P384() {
  }

  public static final int PUBLIC_BYTES = 97;
  public static final int SECRET_BYTES = 48;
  private static final int COORDINATE_BYTES = 48;
  private static final ECParameterSpec CURVE = curve();
  private static final BigInteger P = ((ECFieldFp) CURVE.getCurve().getField()).getP();

  private static ECParameterSpec curve() {
    try {
      AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
      parameters.init(new ECGenParameterSpec("secp384r1"));
      return parameters.getParameterSpec(ECParameterSpec.class);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java has no P-384", e);
    }
  }

  // A new key pair, its randomness from random (SecureRandom for the server; a test's own for test vectors)
  public static KeyPair generate(SecureRandom random) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp384r1"), random);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java can't make a P-384 key", e);
    }
  }

  // A public key's 97 bytes
  public static byte[] encode(ECPublicKey key) {
    byte[] out = new byte[PUBLIC_BYTES];
    out[0] = 0x04;
    put(key.getW().getAffineX(), out, 1);
    put(key.getW().getAffineY(), out, 1 + COORDINATE_BYTES);
    return out;
  }

  // A number as 48 bytes, biggest first
  private static void put(BigInteger value, byte[] out, int at) {
    byte[] bytes = value.toByteArray();
    int skip = bytes.length > COORDINATE_BYTES ? bytes.length - COORDINATE_BYTES : 0;
    int pad = COORDINATE_BYTES - (bytes.length - skip);
    System.arraycopy(bytes, skip, out, at + pad, bytes.length - skip);
  }

  // The public key in 97 bytes from outside, or null if they aren't a point on P-384
  public static ECPublicKey decode(byte[] bytes) {
    if (bytes == null || bytes.length != PUBLIC_BYTES || bytes[0] != 0x04) {
      return null;
    }

    BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1, 1 + COORDINATE_BYTES));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(bytes, 1 + COORDINATE_BYTES, PUBLIC_BYTES));

    if (!onCurve(x, y)) {
      return null;
    }

    try {
      return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), CURVE));
    } catch (GeneralSecurityException e) {
      return null;
    }
  }

  // Whether (x, y) is a point on the curve: both less than p, and y squared equal to x cubed plus a times x plus b, all modulo p
  static boolean onCurve(BigInteger x, BigInteger y) {
    if (x.signum() < 0 || y.signum() < 0 || x.compareTo(P) >= 0 || y.compareTo(P) >= 0) {
      return false;
    }

    BigInteger left = y.multiply(y).mod(P);
    BigInteger right = x.pow(3).add(CURVE.getCurve().getA().multiply(x)).add(CURVE.getCurve().getB()).mod(P);
    return left.equals(right);
  }

  // The shared secret, 48 bytes: our private key with their public key, which must have come through decode (or be our own)
  public static byte[] agree(PrivateKey mine, ECPublicKey theirs) {
    try {
      KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
      agreement.init(mine);
      agreement.doPhase(theirs, true);
      byte[] secret = agreement.generateSecret();

      if (secret.length != SECRET_BYTES) {
        throw new IllegalStateException("P-384's shared secret isn't 48 bytes");
      }

      return secret;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java's P-384 agreement failed", e);
    }
  }
}
