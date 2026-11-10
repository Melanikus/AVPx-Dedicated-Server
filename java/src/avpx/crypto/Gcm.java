package avpx.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// AES-256-GCM: how version 2 seals every message. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// Sealing a message with a key and a nonce gives the message enciphered, then a 16-byte tag. The tag proves both the message and the
// associated data (AAD: bytes sent in the clear that the tag still covers, such as a header) are exactly what was sealed; opening anything
// changed by even one bit fails. A nonce must never seal twice under one key, which CRYPTO.md's counters make sure of (sections 5 and 9).
// Only Java's own AES is used.
public final class Gcm {
  private Gcm() {
  }

  public static final int KEY_BYTES = 32;
  public static final int NONCE_BYTES = 12;
  public static final int TAG_BYTES = 16;
  private static final String AES_GCM = "AES/GCM/NoPadding";

  private static Cipher cipher(int mode, byte[] key, byte[] nonce, byte[] aad) throws GeneralSecurityException {
    if (key.length != KEY_BYTES || nonce.length != NONCE_BYTES) {
      throw new IllegalArgumentException("AES-256-GCM takes a 32-byte key and a 12-byte nonce");
    }

    Cipher c = Cipher.getInstance(AES_GCM);
    c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BYTES * 8, nonce));
    c.updateAAD(aad);
    return c;
  }

  // The message sealed: its bytes enciphered, then the 16-byte tag
  public static byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] message) {
    try {
      return cipher(Cipher.ENCRYPT_MODE, key, nonce, aad).doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("AES-256-GCM isn't working in this Java", e);
    }
  }

  // The message, if the sealed bytes and the AAD are exactly what was sealed with this key and nonce; null if not (the tag fails)
  public static byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] sealed) {
    if (sealed.length < TAG_BYTES) {
      return null;
    }

    try {
      return cipher(Cipher.DECRYPT_MODE, key, nonce, aad).doFinal(sealed);
    } catch (AEADBadTagException e) {
      return null;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("AES-256-GCM isn't working in this Java", e);
    }
  }
}
