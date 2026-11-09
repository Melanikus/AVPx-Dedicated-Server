package avpx.access;

import java.util.HexFormat;

// The access code: what the game shows a player beside their request, and what they read to the owner by a way the owner knows is them
// (PROTOCOL.md's access requests). Written 2026-11-09 by Melanikus for AVPx Dedicated Server, by Fourth's rule, and held to his vectors
// (AccessStoreTest).
//
// The fingerprint's first 10 bytes are read as one 80-bit number, highest byte first, cut into sixteen 5-bit pieces from the top, and
// each piece written as a letter of 23456789ABCDEFGHJKLMNPQRSTUVWXYZ (the same 32 letters as a room's code: no 0, 1, I or O to misread),
// in four groups of four with dashes between: XXXX-XXXX-XXXX-XXXX.
//
// It's never sent anywhere: the owner's approval takes it as typed, and refuses unless exactly one waiting request has it. So a key swapped
// on the way to the list (there's no pin on the list yet, #175) makes another code, which matches nothing the player said, and is never
// approved. The owner's own tools work it out for themselves; here it's for Smoke, which shows it beside the identities it makes, so they
// can be approved the very way a player is.
public final class AccessCode {
  private AccessCode() {
  }

  private static final String LETTERS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  private static final int PIECES = 16;
  private static final int BITS = 5;

  // The code of a fingerprint (32 hex digits, small letters)
  public static String of(String fingerprint) {
    if (!AccessStore.isFingerprint(fingerprint)) {
      throw new IllegalArgumentException("AccessCode.of: a fingerprint, 32 small hex digits");
    }

    byte[] b = HexFormat.of().parseHex(fingerprint);
    StringBuilder out = new StringBuilder();

    for (int piece = 0; piece < PIECES; piece++) {
      int value = 0;

      // The piece's 5 bits, one at a time, from the top of the 80: bit k of the number is bit (7 - k % 8) of byte k / 8
      for (int bit = 0; bit < BITS; bit++) {
        int k = piece * BITS + bit;
        value = (value << 1) | ((b[k / 8] >> (7 - k % 8)) & 1);
      }

      if (piece > 0 && piece % 4 == 0) {
        out.append('-');
      }

      out.append(LETTERS.charAt(value));
    }

    return out.toString();
  }
}
