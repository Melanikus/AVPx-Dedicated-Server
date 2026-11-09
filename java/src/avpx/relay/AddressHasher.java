package avpx.relay;

import java.nio.charset.StandardCharsets;

// How one sender is told from another without keeping its address. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, from
// relay/limits.js.
//
// The user's ruling: no IPs. But a limit for each sender has to know which sender is which. So it keys its buckets by a hash of the
// address, made with a secret only this run of the server has, made at random and changed every day. The hash can't be turned back into
// the address, and once the secret is gone nobody can even check a guess against it. Nothing here is written anywhere: the secret lives in
// memory, and the hashes are forgotten when it changes (PerSender.java).
//
// A hasher isn't safe to use from two threads at once: the relay has one of its own, on its one thread, and the list one of its own.
public final class AddressHasher {
  public static final long KEY_LIFE_MILLISECONDS = 24L * 60 * 60 * 1000;
  private static final int KEY_BYTES = 32;
  private static final int HASH_DIGITS = 32;

  private final RandomBytes random;
  private byte[] key;
  private long madeAt;
  private int generation;

  public AddressHasher(RandomBytes random) {
    this.random = random;
  }

  // A short name for an address (32 hex digits), the same for the same address until the secret changes. A clock that goes back makes a
  // new secret too, so a secret is never kept longer than a day, whatever the clock does.
  public String keyOf(String address, long now) {
    if (key == null || now - madeAt >= KEY_LIFE_MILLISECONDS || now < madeAt) {
      key = random.next(KEY_BYTES);
      madeAt = now;
      generation++;
    }

    return Crypto.hex(Crypto.hmacSha256(key, String.valueOf(address).getBytes(StandardCharsets.UTF_8))).substring(0, HASH_DIGITS);
  }

  // Which secret the hashes are made with now, counting from 1, so whatever is keyed by them can forget the old ones
  public int generation() {
    return generation;
  }
}
