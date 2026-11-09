package avpx.relay;

import java.util.LinkedHashMap;

// A limit for each sender, keyed by the hash of its address (AddressHasher.java), with at most `most` senders remembered. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server, from relay/limits.js.
//
// When it's full, the sender heard from longest ago is forgotten: a crowd of made-up senders can push real ones out, but each of those
// starts again with its own limit, and the limit for everyone (a TokenBucket of its own, kept by whoever uses this) still holds.
//
// Not safe to use from two threads at once, like the hasher it uses.
public final class PerSender {
  private final double rate;
  private final double burst;
  private final int most;
  private final AddressHasher hasher;

  // Each sender's bucket, the one heard from longest ago first: a sender heard from is taken out and put back at the end
  private final LinkedHashMap<String, TokenBucket> buckets = new LinkedHashMap<>();
  private int generation = -1;

  public PerSender(double rate, double burst, int most, AddressHasher hasher) {
    if (most < 1) {
      throw new IllegalArgumentException("PerSender: room for at least one sender");
    }

    this.rate = rate;
    this.burst = burst;
    this.most = most;
    this.hasher = hasher;
  }

  public boolean allows(String address, long now) {
    return allows(address, now, 1);
  }

  // Whether this sender may have amount more, at now
  public boolean allows(String address, long now, double amount) {
    String key = hasher.keyOf(address, now);

    // A new secret: every key made with the old one means nothing now
    if (generation != hasher.generation()) {
      buckets.clear();
      generation = hasher.generation();
    }

    TokenBucket bucket = buckets.remove(key);

    if (bucket == null) {
      bucket = new TokenBucket(rate, burst);

      if (buckets.size() >= most) {
        buckets.remove(buckets.keySet().iterator().next());
      }
    }

    // Heard from now: to the end of the line, the last to be forgotten
    buckets.put(key, bucket);
    return bucket.take(now, amount);
  }

  // How many senders it remembers now
  public int size() {
    return buckets.size();
  }
}
