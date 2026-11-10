package avpx.v2;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

// The running state of a Noise handshake (CRYPTO.md section 5): what both sides keep as they go, so each key depends on every byte said
// before it. Written 2026-11-09 by Melanikus for AVPx Dedicated Server, from the Noise framework (revision 34) as CRYPTO.md adapts it.
//
//   h   the transcript: SHA-384 of everything said so far, 48 bytes. Every seal's tag covers it (it's the AAD), so changing any byte of
//       any message, earlier or now, makes the next tag fail.
//   ck  the chaining key, 48 bytes: every secret (each ECDH and ML-KEM result) is mixed into it, one after another, so every key after
//       depends on all of them. That's how the hybrid holds unless both halves are broken.
//   k   the key that seals now, 32 bytes, or none yet; n counts what k has sealed.
//
// Settled with Third and Fifth, 2026-11-09 (CRYPTO.md section 5.1):
// - MixKey is RFC 5869 HKDF-SHA-384 with an empty info, 80 bytes: ck is the first 48, k the next 32.
// - Before Split there's no IV: the nonce is 4 zero bytes, then n as 8 bytes LITTLE-endian. Noise's own AESGCM puts n big-endian; this
//   differs on purpose, to match the sealed channel's nonces (section 5's nonce(n)). Don't "fix" it.
// - Split is HKDF-SHA-384(salt = ck, input = nothing, info "AVPX split v2"), 120 bytes: the initiator-to-responder secret (48), the
//   responder-to-initiator secret (48), the initiator-to-responder IV (12), the responder-to-initiator IV (12). A secret never seals
//   anything itself: every key that seals is made from it, one for each epoch, epoch 0's too (Channel.java, CRYPTO.md section 9). Since
//   2026-11-09 (Secondary's reads, finding 2.1): it used to be two 32-byte keys, and epoch 0 sealed with the very key the later epochs
//   were made from, one key with two jobs. A secret is the hash's own length, 48 bytes, as RFC 5869 asks of a key HKDF expands.
final class Noise {
  static final int HASH_BYTES = 48;
  static final int KEY_BYTES = 32;
  static final int SECRET_BYTES = HASH_BYTES;
  static final int IV_BYTES = 12;
  private static final int MIX_KEY_BYTES = HASH_BYTES + KEY_BYTES;
  private static final int SPLIT_BYTES = 2 * SECRET_BYTES + 2 * IV_BYTES;
  private static final byte[] NOTHING = new byte[0];
  private static final byte[] SPLIT_INFO = "AVPX split v2".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] ZERO_IV = new byte[IV_BYTES];

  private byte[] h;
  private byte[] ck;
  private byte[] k;
  private long n;

  // The start: h = SHA-384(the protocol's name), and ck = h
  Noise(String protocolName) {
    h = sha384(protocolName.getBytes(StandardCharsets.US_ASCII));
    ck = h.clone();
  }

  static byte[] sha384(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-384");

      for (byte[] part : parts) {
        digest.update(part);
      }

      return digest.digest();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("this Java has no SHA-384", e);
    }
  }

  // nonce(n): the IV, XOR 4 zero bytes then n as 8 bytes little-endian (CRYPTO.md section 5)
  static byte[] nonce(byte[] iv, long n) {
    byte[] out = iv.clone();

    for (int i = 0; i < 8; i++) {
      out[4 + i] ^= (byte) (n >>> (8 * i));
    }

    return out;
  }

  void mixHash(byte[] data) {
    h = sha384(h, data);
  }

  void mixKey(byte[] secret) {
    byte[] out = Hkdf.derive(ck, secret, NOTHING, MIX_KEY_BYTES);
    wipe(ck);
    wipe(k);
    ck = Arrays.copyOfRange(out, 0, HASH_BYTES);
    k = Arrays.copyOfRange(out, HASH_BYTES, MIX_KEY_BYTES);
    n = 0;
    wipe(out);
  }

  // The text sealed under k (with h as its AAD), or the text as it is while there's no k; then MixHash of what's sent
  byte[] encryptAndHash(byte[] text) {
    byte[] sent = k == null ? text.clone() : Gcm.seal(k, nonce(ZERO_IV, n), h, text);

    if (k != null) {
      n++;
    }

    mixHash(sent);
    return sent;
  }

  // The text, if what came opens under k with h as its AAD (or as it is, with no k yet); null if its tag fails, which ends the handshake
  byte[] decryptAndHash(byte[] received) {
    byte[] text = k == null ? received.clone() : Gcm.open(k, nonce(ZERO_IV, n), h, received);

    if (text == null) {
      return null;
    }

    if (k != null) {
      n++;
    }

    mixHash(received);
    return text;
  }

  // The secrets and IVs for each direction, once the handshake is done: what each direction's epoch keys are made from (Channel.java)
  record Split(byte[] initiatorSecret, byte[] responderSecret, byte[] initiatorIv, byte[] responderIv) {
    void wipe() {
      Noise.wipe(initiatorSecret);
      Noise.wipe(responderSecret);
      Noise.wipe(initiatorIv);
      Noise.wipe(responderIv);
    }
  }

  Split split() {
    byte[] out = Hkdf.derive(ck, NOTHING, SPLIT_INFO, SPLIT_BYTES);
    Split split = new Split(Arrays.copyOfRange(out, 0, SECRET_BYTES), Arrays.copyOfRange(out, SECRET_BYTES, 2 * SECRET_BYTES),
        Arrays.copyOfRange(out, 2 * SECRET_BYTES, 2 * SECRET_BYTES + IV_BYTES),
        Arrays.copyOfRange(out, 2 * SECRET_BYTES + IV_BYTES, SPLIT_BYTES));
    wipe(out);
    return split;
  }

  // The transcript and the chaining key now, as copies: for the test vectors (CRYPTO.md section 15 lists every h and ck)
  byte[] h() {
    return h.clone();
  }

  byte[] ck() {
    return ck.clone();
  }

  // Every secret this held, wiped: done when the handshake ends, finished or not
  void wipe() {
    wipe(ck);
    wipe(k);
    wipe(h);
  }

  static void wipe(byte[] secret) {
    if (secret != null) {
      Arrays.fill(secret, (byte) 0);
    }
  }
}
