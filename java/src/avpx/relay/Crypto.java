package avpx.relay;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// The few pieces of cryptography the server uses, all of them Java's own. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// HMAC-SHA-256 is a stamp made from a message and a secret key: anyone with the key can make the same stamp again from the same message,
// and nobody without the key can make it at all, or tell the key from it. The server uses it for cookies, passes and the hashes of
// addresses (PROTOCOL.md sections 3 and 5).
public final class Crypto {
  private Crypto() {
  }

  private static final String HMAC_SHA_256 = "HmacSHA256";

  // The HMAC-SHA-256 of data with key: 32 bytes
  public static byte[] hmacSha256(byte[] key, byte[] data) {
    try {
      Mac mac = Mac.getInstance(HMAC_SHA_256);
      mac.init(new SecretKeySpec(key, HMAC_SHA_256));
      return mac.doFinal(data);
    } catch (GeneralSecurityException e) {
      // Every Java has HMAC-SHA-256, and every key here is 32 bytes, so this would be a broken Java: stop rather than go on without it
      throw new IllegalStateException("HMAC-SHA-256 isn't working in this Java", e);
    }
  }

  // Whether two secrets are the same, taking as long to say so whatever they hold, so how long it takes says nothing about how much of a
  // guess was right. Nothing is the same as nothing else, not even another nothing.
  public static boolean same(byte[] a, byte[] b) {
    return a != null && b != null && a.length == b.length && MessageDigest.isEqual(a, b);
  }

  // Bytes as hex digits, small letters
  public static String hex(byte[] bytes) {
    return HexFormat.of().formatHex(bytes);
  }
}
