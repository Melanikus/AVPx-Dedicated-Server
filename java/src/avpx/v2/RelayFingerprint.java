package avpx.v2;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

// A version 2 relay's fingerprint: a short name for its two static public keys, that a person can read aloud and a game can be told in
// its settings (CRYPTO.md section 12.1). Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// It's the first 16 bytes of SHA-384 of three things one after another:
//   the 18 ASCII letters "AVPX relay keys v2", with nothing after them;
//   the relay's static P-384 public key, 97 bytes (04, then x and y);
//   its static ML-KEM-1024 encapsulation key, 1,568 bytes;
// written as 32 hex digits, small letters. The words at the front keep it apart from every other hash in version 2: a player's
// fingerprint starts "AVPX-ID-2" instead (section 8), so the one can never be taken for the other.
//
// The game holds the keys the list gives it (GET /v1/relay-keys) to the fingerprint it was told, before it sends the relay anything. So a
// list that lied about a relay's keys is caught, even if the list's own machine is the one lying. The relay never needs its own
// fingerprint: MakeRelayKeys prints it, for whoever sets the game up, and the tests hold it to a hash made outside Java.
public final class RelayFingerprint {
  private RelayFingerprint() {
  }

  public static final int BYTES = 16;
  private static final byte[] WORDS = "AVPX relay keys v2".getBytes(StandardCharsets.US_ASCII);

  // The fingerprint of these two public keys, as 32 hex digits. The keys must be their right sizes; anything else is a mistake in the
  // caller, so it throws rather than naming something that isn't a relay's keys.
  public static String of(byte[] p384Public, byte[] kemPublic) {
    if (p384Public == null || p384Public.length != P384.PUBLIC_BYTES || kemPublic == null
        || kemPublic.length != MlKem.ENCAPSULATION_KEY_BYTES) {
      throw new IllegalArgumentException("RelayFingerprint: the keys are 97 and 1,568 bytes");
    }

    try {
      MessageDigest sha = MessageDigest.getInstance("SHA-384");
      sha.update(WORDS);
      sha.update(p384Public);
      sha.update(kemPublic);
      return HexFormat.of().formatHex(Arrays.copyOf(sha.digest(), BYTES));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("this Java has no SHA-384", e);
    }
  }
}
