package avpx.v2;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

// The sealed control channel (CRYPTO.md section 7): every 64-byte control message of PROTOCOL.md, sealed, after handshake A. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   bytes 0-3     'AVPR'
//   byte  4       2
//   byte  5       32, SEALED
//   bytes 6-7     0
//   bytes 8-15    the relay's session id, from A2
//   bytes 16-23   the counter, 8 bytes little-endian
//   bytes 24-87   the 64-byte message, sealed
//   bytes 88-103  the tag
//
// 104 bytes every time, questions and answers alike, so no answer is bigger than its question. Bytes 0-23 are the AAD: the tag covers them.
// Each direction has its own key, IV and counter, from Split (the game sends with the initiator's, the relay with the responder's), and
// the nonce is that direction's IV XOR the counter (Noise.nonce). Counters start at 0, and go up by one a message.
//
// KEYS CHANGE BY THEMSELVES (CRYPTO.md section 9, settled for this channel too with Third): an epoch is 2^20 messages. Epoch 0's key is
// Split's key itself; epoch e from 1 is HKDF-Expand(Split's key, "AVPX epoch v2" || e as 4 bytes little-endian, 32 bytes). Both sides
// change at the same counter, with no message. A session ends at 2^32 messages either way, or 24 hours, or after FAILED_TAGS tags that
// fail: then a new handshake is needed.
//
// The relay never answers anything that fails its tag; it only counts it.
public final class Channel {
  public static final int SEALED_BYTES = 104;
  public static final int MESSAGE_BYTES = 64;
  public static final int KIND = 32;
  public static final int EPOCH_SHIFT = 20;
  public static final long MOST_MESSAGES = 1L << 32;
  public static final long SESSION_MILLISECONDS = 24L * 60 * 60 * 1000;
  public static final long FAILED_TAGS = 65536;
  private static final int AAD_BYTES = 24;
  private static final byte[] EPOCH_INFO = "AVPX epoch v2".getBytes(StandardCharsets.US_ASCII);

  // One direction's key and IV, and the epoch key now in use
  private static final class Way {
    private final byte[] key;
    private final byte[] iv;
    private long epoch = -1;
    private byte[] epochKey;

    Way(byte[] key, byte[] iv) {
      this.key = key.clone();
      this.iv = iv.clone();
    }

    byte[] keyFor(long counter) {
      long e = counter >>> EPOCH_SHIFT;

      if (e != epoch) {
        Noise.wipe(epochKey);
        epochKey = e == 0 ? key.clone() : Hkdf.expand(key, epochInfo(e), Noise.KEY_BYTES);
        epoch = e;
      }

      return epochKey;
    }

    void wipe() {
      Noise.wipe(key);
      Noise.wipe(iv);
      Noise.wipe(epochKey);
    }
  }

  static byte[] epochInfo(long epoch) {
    byte[] info = Arrays.copyOf(EPOCH_INFO, EPOCH_INFO.length + 4);

    for (int i = 0; i < 4; i++) {
      info[EPOCH_INFO.length + i] = (byte) (epoch >>> (8 * i));
    }

    return info;
  }

  private final byte[] sessionId;
  private final Way out;
  private final Way in;
  private final ReplayWindow window = new ReplayWindow();
  private final long startedAt;
  private long sent;
  private long failedTags;
  private boolean over;

  // ourKey and ourIv seal what this side sends; theirKey and theirIv open what it's sent. now is when the session started.
  public Channel(byte[] sessionId, byte[] ourKey, byte[] ourIv, byte[] theirKey, byte[] theirIv, long now) {
    this.sessionId = sessionId.clone();
    this.out = new Way(ourKey, ourIv);
    this.in = new Way(theirKey, theirIv);
    this.startedAt = now;
  }

  // The relay's side of a session, from handshake A's keys: it sends with the responder's, and opens the game's with the initiator's
  public static Channel relaySide(HandshakeA.Keys keys, long now) {
    Noise.Split s = keys.split();
    return new Channel(keys.sessionId(), s.responderKey(), s.responderIv(), s.initiatorKey(), s.initiatorIv(), now);
  }

  // The game's side, the other way round
  public static Channel gameSide(HandshakeA.Keys keys, long now) {
    Noise.Split s = keys.split();
    return new Channel(keys.sessionId(), s.initiatorKey(), s.initiatorIv(), s.responderKey(), s.responderIv(), now);
  }

  public byte[] sessionId() {
    return sessionId.clone();
  }

  // Whether this session is over: at its most messages, its 24 hours, or its failed tags. A session over seals and opens nothing more.
  public boolean over(long now) {
    return over || now - startedAt >= SESSION_MILLISECONDS || now < startedAt;
  }

  private static byte[] header(byte[] sessionId, long counter) {
    byte[] h = new byte[AAD_BYTES];
    h[0] = 'A';
    h[1] = 'V';
    h[2] = 'P';
    h[3] = 'R';
    h[4] = 2;
    h[5] = KIND;
    System.arraycopy(sessionId, 0, h, 8, HandshakeA.SESSION_ID_BYTES);

    for (int i = 0; i < 8; i++) {
      h[16 + i] = (byte) (counter >>> (8 * i));
    }

    return h;
  }

  // A 64-byte message sealed into its 104 bytes, or null if the session is over
  public byte[] seal(byte[] message, long now) {
    if (message.length != MESSAGE_BYTES) {
      throw new IllegalArgumentException("Channel.seal: a control message is 64 bytes");
    }

    if (over(now) || sent >= MOST_MESSAGES) {
      over = true;
      return null;
    }

    long counter = sent++;
    byte[] aad = header(sessionId, counter);
    byte[] sealed = Gcm.seal(out.keyFor(counter), Noise.nonce(out.iv, counter), aad, message);
    byte[] d = Arrays.copyOf(aad, SEALED_BYTES);
    System.arraycopy(sealed, 0, d, AAD_BYTES, sealed.length);
    return d;
  }

  // The session id a sealed datagram names, or null if it isn't the shape of one (for finding its session)
  public static byte[] sessionIdOf(byte[] d) {
    if (d == null || d.length != SEALED_BYTES || d[0] != 'A' || d[1] != 'V' || d[2] != 'P' || d[3] != 'R' || d[4] != 2 || d[5] != KIND
        || d[6] != 0 || d[7] != 0) {
      return null;
    }

    return Arrays.copyOfRange(d, 8, 16);
  }

  // Why a sealed datagram was refused, if it was (CRYPTO.md section 16's numbers)
  public enum Refusal { NONE, SHAPE, REPLAYED, TAG, OVER }

  private Refusal last = Refusal.NONE;

  public Refusal lastRefusal() {
    return last;
  }

  // The 64-byte message in a sealed datagram from outside, or null, with lastRefusal saying why: not this session's shape (1, 2, 3, 4), a
  // counter taken or below the window (9), a tag that fails (8), or the session over (16).
  public byte[] open(byte[] d, long now) {
    byte[] id = sessionIdOf(d);

    if (id == null || !Arrays.equals(id, sessionId)) {
      last = Refusal.SHAPE;
      return null;
    }

    if (over(now)) {
      last = Refusal.OVER;
      return null;
    }

    long counter = 0;

    for (int i = 7; i >= 0; i--) {
      counter = (counter << 8) | (d[16 + i] & 0xff);
    }

    if (counter < 0 || counter >= MOST_MESSAGES || !window.isNew(counter)) {
      last = Refusal.REPLAYED;
      return null;
    }

    byte[] message = Gcm.open(in.keyFor(counter), Noise.nonce(in.iv, counter), Arrays.copyOf(d, AAD_BYTES),
        Arrays.copyOfRange(d, AAD_BYTES, SEALED_BYTES));

    if (message == null) {
      last = Refusal.TAG;

      if (++failedTags >= FAILED_TAGS) {
        over = true;
      }

      return null;
    }

    window.take(counter);
    last = Refusal.NONE;
    return message;
  }

  // Every key this held, wiped: when the session ends
  public void wipe() {
    out.wipe();
    in.wipe();
    over = true;
  }
}
