package avpx.relay;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;

// Passes: how the list knows a room is real when the room's relay is another machine. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server, from relay/pass.js.
//
// The list and a relay may be in different countries, and never talk to each other: no connection between them, no port open. So the
// relay hands its room's host a PASS in every HOST_OPENED and HOST_KEPT (Protocol.java), and the host shows it to the list. A pass is an
// HMAC-SHA-256 (Crypto.java), with the relay's own pass key, of these bytes one after another:
//
//     the 11 letters AVPX-PASS-1, the relay's region name, one 0 byte, the room's code (8 bytes), the pass time (8 bytes, little-endian)
//
// cut to its first 16 bytes. The pass time is when the relay made it, in whole seconds since 1970-01-01 UTC. The list holds every relay's
// pass key, makes the pass again from what the host sent, and takes it only if it matches and is less than a minute old (Listings.java).
//
// Each relay has its own key, so a relay machine broken into can make passes only for its own region; and a pass key makes passes and
// nothing else, so it can't open, end or touch a room. PROTOCOL.md section 3 says all this for any language.
public final class Pass {
  private Pass() {
  }

  public static final int PASS_BYTES = 16;
  public static final int PASS_KEY_BYTES = 32;
  private static final byte[] LABEL = "AVPX-PASS-1".getBytes(StandardCharsets.US_ASCII);

  // A region's name: 1 to 16 small letters, digits and -, such as "virginia". It goes into every pass and every listing, so it's held to
  // letters nobody could read two ways.
  private static final Pattern REGION = Pattern.compile("[a-z0-9-]{1,16}");

  public static boolean isRegion(String value) {
    return value != null && REGION.matcher(value).matches();
  }

  // The pass for a room: key (32 bytes), region (a region name), code (the room's 8 code letters, as bytes), passTime (whole seconds, 0
  // to Protocol.MOST_PASS_TIME). Throws on anything else: only our own code calls this, with what it has already checked.
  public static byte[] make(byte[] key, String region, byte[] code, long passTime) {
    if (key == null || key.length != PASS_KEY_BYTES || !isRegion(region) || code == null || code.length != Protocol.CODE_BYTES
        || passTime < 0 || passTime > Protocol.MOST_PASS_TIME) {
      throw new IllegalArgumentException("Pass.make: a 32-byte key, a region name, an 8-byte code and a whole number of seconds");
    }

    byte[] time = new byte[8];
    Protocol.putEightBytes(time, 0, passTime);

    ByteArrayOutputStream what = new ByteArrayOutputStream();
    what.writeBytes(LABEL);
    what.writeBytes(region.getBytes(StandardCharsets.US_ASCII));
    what.write(0);
    what.writeBytes(code);
    what.writeBytes(time);

    return Arrays.copyOf(Crypto.hmacSha256(key, what.toByteArray()), PASS_BYTES);
  }
}
