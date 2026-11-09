package avpx.v2;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// Handshake messages in 1,200-byte datagrams (CRYPTO.md section 5, "Big messages over UDP"). Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server.
//
// Handshake messages are 1.6 to 3.4 KB, more than one datagram should carry, so each is cut into fragments. Every handshake datagram,
// either way, is exactly 1,200 bytes: the smallest size the internet carries whole (QUIC uses it too). So nobody can be sent more than they
// sent, and nothing is ever cut in two on the way.
//
//   bytes 0-3      'AVPR' (to and from the relay) or 'AVPE' (host to joiner)
//   byte  4        the version, 2
//   byte  5        the kind (CRYPTO.md sections 6 and 8)
//   byte  6        this fragment's number, from 0
//   byte  7        how many fragments, 1 to 4
//   bytes 8-15     the handshake's id: 8 random bytes the initiator chose
//   bytes 16-31    the cookie (to the relay), or 0
//   bytes 32-33    the whole message's length, little-endian
//   bytes 34-35    where this fragment starts in it, little-endian
//   bytes 36-1199  up to 1,164 bytes of the message, then 0
//
// STRICT (settled with Third, 2026-11-09), so a fragment can be read only one way: every fragment but the last carries exactly 1,164 bytes;
// fragment k starts at k times 1,164; the count is the length divided by 1,164, rounded up (1 for a message of no bytes), 1 to 4; every
// fragment of a message says the same kind, count and length; and every byte after the fragment's part is 0. Anything else isn't a
// fragment (refusal 6).
public final class Fragments {
  private Fragments() {
  }

  public static final int DATAGRAM_BYTES = 1200;
  public static final int HEADER_BYTES = 36;
  public static final int PART_BYTES = DATAGRAM_BYTES - HEADER_BYTES;
  public static final int MOST_FRAGMENTS = 4;
  public static final int MOST_MESSAGE_BYTES = MOST_FRAGMENTS * PART_BYTES;
  public static final int ID_BYTES = 8;
  public static final int COOKIE_BYTES = 16;
  public static final int VERSION = 2;
  private static final byte[] TO_RELAY = "AVPR".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] HOST_TO_JOINER = "AVPE".getBytes(StandardCharsets.US_ASCII);

  // The two magics, as copies, so nobody can change the ones here
  public static byte[] toRelay() {
    return TO_RELAY.clone();
  }

  public static byte[] hostToJoiner() {
    return HOST_TO_JOINER.clone();
  }

  // How many fragments a message of length bytes takes
  static int count(int length) {
    return Math.max(1, (length + PART_BYTES - 1) / PART_BYTES);
  }

  // A message as its datagrams
  public static List<byte[]> cut(byte[] magic, int kind, byte[] id, byte[] cookie, byte[] message) {
    if (message.length > MOST_MESSAGE_BYTES || id.length != ID_BYTES || cookie.length != COOKIE_BYTES || magic.length != 4) {
      throw new IllegalArgumentException("Fragments.cut: a message of at most 4,656 bytes, an 8-byte id and a 16-byte cookie");
    }

    int count = count(message.length);
    List<byte[]> out = new ArrayList<>();

    for (int index = 0; index < count; index++) {
      int start = index * PART_BYTES;
      int part = Math.min(PART_BYTES, message.length - start);
      byte[] d = new byte[DATAGRAM_BYTES];
      System.arraycopy(magic, 0, d, 0, 4);
      d[4] = VERSION;
      d[5] = (byte) kind;
      d[6] = (byte) index;
      d[7] = (byte) count;
      System.arraycopy(id, 0, d, 8, ID_BYTES);
      System.arraycopy(cookie, 0, d, 16, COOKIE_BYTES);
      d[32] = (byte) message.length;
      d[33] = (byte) (message.length >>> 8);
      d[34] = (byte) start;
      d[35] = (byte) (start >>> 8);
      System.arraycopy(message, start, d, HEADER_BYTES, part);
      out.add(d);
    }

    return out;
  }

  // One fragment, as read from a datagram
  public record Fragment(int kind, int index, int count, byte[] id, byte[] cookie, int length, byte[] part) {
  }

  // The fragment in a datagram from outside, or null if it isn't exactly one, as the rules above say
  public static Fragment read(byte[] magic, byte[] d) {
    if (d == null || d.length != DATAGRAM_BYTES || !Arrays.equals(Arrays.copyOf(d, 4), magic) || d[4] != VERSION) {
      return null;
    }

    int kind = d[5] & 0xff;
    int index = d[6] & 0xff;
    int count = d[7] & 0xff;
    int length = (d[32] & 0xff) | ((d[33] & 0xff) << 8);
    int start = (d[34] & 0xff) | ((d[35] & 0xff) << 8);

    if (count < 1 || count > MOST_FRAGMENTS || index >= count || length > MOST_MESSAGE_BYTES || count != count(length)
        || start != index * PART_BYTES || start > length) {
      return null;
    }

    int part = Math.min(PART_BYTES, length - start);

    // A fragment but the last must be full, which count(length) and start already make so; every byte after its part must be 0
    for (int i = HEADER_BYTES + part; i < DATAGRAM_BYTES; i++) {
      if (d[i] != 0) {
        return null;
      }
    }

    return new Fragment(kind, index, count, Arrays.copyOfRange(d, 8, 16), Arrays.copyOfRange(d, 16, 32), length,
        Arrays.copyOfRange(d, HEADER_BYTES, HEADER_BYTES + part));
  }

  // A message being put together from its fragments, which may come in any order, and again
  public static final class Assembly {
    private final int kind;
    private final int count;
    private final int length;
    private final byte[][] parts;
    private int have;

    public Assembly(Fragment first) {
      this.kind = first.kind();
      this.count = first.count();
      this.length = first.length();
      this.parts = new byte[count][];
    }

    // Takes a fragment; false if it doesn't belong (another kind, count or length: refusal 6). A fragment that comes again is taken
    // only if it's the same bytes as before.
    public boolean add(Fragment f) {
      if (f.kind() != kind || f.count() != count || f.length() != length) {
        return false;
      }

      if (parts[f.index()] != null) {
        return Arrays.equals(parts[f.index()], f.part());
      }

      parts[f.index()] = f.part();
      have++;
      return true;
    }

    public boolean complete() {
      return have == count;
    }

    // The whole message, once every fragment is in
    public byte[] message() {
      if (!complete()) {
        throw new IllegalStateException("Assembly.message: not every fragment is in");
      }

      byte[] out = new byte[length];

      for (int i = 0; i < count; i++) {
        System.arraycopy(parts[i], 0, out, i * PART_BYTES, parts[i].length);
      }

      return out;
    }

    // How many bytes it holds, for the limit on what the relay keeps (4 KB, CRYPTO.md section 17)
    public int bytesHeld() {
      int n = 0;

      for (byte[] p : parts) {
        n += p == null ? 0 : p.length;
      }

      return n;
    }
  }
}
