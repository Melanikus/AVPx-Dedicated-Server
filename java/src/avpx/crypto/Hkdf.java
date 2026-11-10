package avpx.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// HKDF (RFC 5869) with HMAC-SHA-384: how version 2 makes every key from the ones before it. Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server.
//
// HKDF takes a secret that may not be evenly random (an ECDH result, say) and makes from it as many evenly random bytes as are asked for,
// in two steps:
//   Extract: PRK = HMAC(salt, input). The salt is the chaining key in a handshake (CRYPTO.md section 5).
//   Expand:  T(1) = HMAC(PRK, info || 1), T(2) = HMAC(PRK, T(1) || info || 2), ...; the output is T(1) || T(2) || ..., cut to its length.
// With an empty info, Extract-then-Expand to two outputs is exactly the HKDF of the Noise framework, which CRYPTO.md builds on.
//
// It's written here, over Java's own HMAC (javax.crypto.Mac), rather than through Java 25's KDF API, so one short piece of code we can
// read does both the whole of HKDF and the Expand alone (the epoch keys, CRYPTO.md section 9), and takes the empty inputs version 2 uses
// (Split's input is empty). HkdfTest holds it to RFC 5869's own vectors, and to Java 25's own "HKDF-SHA384", which must give the same bytes.
//
// What it refuses: a key (or salt) of no bytes. RFC 5869 allows "no salt", and reads it as a salt of all zeros, but version 2 never has
// one: every salt it uses is the chaining key ck or the transcript h, 48 bytes each, and every other key is 32 bytes or more (CRYPTO.md
// sections 5, 8 and 9). So a key of no bytes can only be a mistake somewhere before here, and keying an HMAC with it would quietly give
// bytes anyone could make. It's refused, loudly, instead.
public final class Hkdf {
  private Hkdf() {
  }

  private static final String HMAC = "HmacSHA384";

  // SHA-384's output: 48 bytes
  public static final int HASH_BYTES = 48;

  // RFC 5869 allows at most 255 blocks
  private static final int MOST_BLOCKS = 255;

  // What a key of no bytes is refused with (HkdfTest and SymmetricKatTest check these words)
  static final String NO_KEY = "an HMAC key of no bytes: version 2 never keys anything with nothing, so this is a mistake";

  // HMAC-SHA-384 of data with key. A key of no bytes is refused (see the top of this file).
  public static byte[] hmac(byte[] key, byte[]... data) {
    return hmac(HMAC, key, data);
  }

  static byte[] hmac(String algorithm, byte[] key, byte[]... data) {
    if (key.length == 0) {
      throw new IllegalArgumentException(NO_KEY);
    }

    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(new SecretKeySpec(key, algorithm));

      for (byte[] part : data) {
        mac.update(part);
      }

      return mac.doFinal();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HMAC isn't working in this Java", e);
    }
  }

  // Extract: the pseudo-random key, from a salt and the input secret
  public static byte[] extract(byte[] salt, byte[] input) {
    return hmac(salt, input);
  }

  // Expand: length bytes from a pseudo-random key and an info
  public static byte[] expand(byte[] prk, byte[] info, int length) {
    return expand(HMAC, HASH_BYTES, prk, info, length);
  }

  static byte[] expand(String algorithm, int hashBytes, byte[] prk, byte[] info, int length) {
    if (length < 0 || length > MOST_BLOCKS * hashBytes) {
      throw new IllegalArgumentException("HKDF gives at most 255 blocks of its hash");
    }

    // The output's own array, its length known from the start, filled block by block: so no copy of a key is left anywhere but in it and
    // the blocks, and each block is wiped as soon as it's copied (Secondary's read of the server, 6.1: a growing stream used to leave
    // copies of every key HKDF made in arrays nobody could wipe)
    byte[] result = new byte[length];
    byte[] block = new byte[0];
    int done = 0;

    for (int i = 1; done < length; i++) {
      byte[] next = hmac(algorithm, prk, block, info, new byte[] {(byte) i});
      Arrays.fill(block, (byte) 0);
      block = next;
      int take = Math.min(block.length, length - done);
      System.arraycopy(block, 0, result, done, take);
      done += take;
    }

    Arrays.fill(block, (byte) 0);
    return result;
  }

  // Extract, then Expand: length bytes from a salt, a secret and an info
  public static byte[] derive(byte[] salt, byte[] input, byte[] info, int length) {
    byte[] prk = extract(salt, input);

    try {
      return expand(prk, info, length);
    } finally {
      Arrays.fill(prk, (byte) 0);
    }
  }

  // The same with another HMAC (HkdfTest holds the construction to RFC 5869's SHA-256 vectors this way)
  static byte[] derive(String algorithm, int hashBytes, byte[] salt, byte[] input, byte[] info, int length) {
    byte[] prk = hmac(algorithm, salt, input);

    try {
      return expand(algorithm, hashBytes, prk, info, length);
    } finally {
      Arrays.fill(prk, (byte) 0);
    }
  }
}
