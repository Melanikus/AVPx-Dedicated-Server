package avpx.v2;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

// A version 2 relay's id: the name of its two static public keys that a game is told in its settings, and holds the keys the list gives
// it to (CRYPTO.md section 12.1). Written 2026-11-09 by Melanikus for AVPx Dedicated Server, as RelayFingerprint (16 bytes); made the
// whole hash the same day, by PO's ruling that whatever a machine compares is the full SHA-384 (CRYPTO.md section 8).
//
// It's the SHA-384 of three things one after another, all 48 bytes of it, written as 96 hex digits, small letters:
//   the 18 ASCII letters "AVPX relay keys v2", with nothing after them;
//   the relay's static P-384 public key, 97 bytes (04, then x and y);
//   its static ML-KEM-1024 encapsulation key, 1,568 bytes.
// The words at the front keep it apart from every other hash in version 2: a player's id starts "AVPX-ID-2" instead (Identity.java), so
// the one can never be taken for the other.
//
// WHY THE WHOLE HASH: a game uses a relay only if the keys it's given hash to this. Someone who could make keys of their own with the same
// hash could stand in for the relay. With 16 bytes that's a search of 2 to the 128th, which a quantum computer could cut to about 2 to the
// 64th; with all 48 it's beyond reach either way, as everything else in version 2 is (CRYPTO.md section 3).
//
// The relay never needs its own id: MakeRelayKeys prints it, for whoever sets the game up (the game's -dev setting relaykey=<region>:<id>),
// and the tests hold it to a hash made outside Java, and to the game's own.
public final class RelayId {
  private RelayId() {
  }

  public static final int BYTES = 48;
  private static final byte[] WORDS = "AVPX relay keys v2".getBytes(StandardCharsets.US_ASCII);

  // The id of these two public keys, as 96 hex digits. The keys must be their right sizes; anything else is a mistake in the caller, so it
  // throws rather than naming something that isn't a relay's keys.
  public static String of(byte[] p384Public, byte[] kemPublic) {
    if (p384Public == null || p384Public.length != P384.PUBLIC_BYTES || kemPublic == null
        || kemPublic.length != MlKem.ENCAPSULATION_KEY_BYTES) {
      throw new IllegalArgumentException("RelayId: the keys are 97 and 1,568 bytes");
    }

    try {
      MessageDigest sha = MessageDigest.getInstance("SHA-384");
      sha.update(WORDS);
      sha.update(p384Public);
      sha.update(kemPublic);
      return HexFormat.of().formatHex(sha.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("this Java has no SHA-384", e);
    }
  }
}
