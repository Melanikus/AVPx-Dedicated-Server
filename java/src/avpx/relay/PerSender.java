package avpx.relay;

import java.util.LinkedHashMap;
import java.util.Map;

// A limit for each sender, keyed by the hash of its address (AddressHasher.java), with at most `most` senders remembered. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server, from relay/limits.js.
//
// WHEN IT'S FULL, there are two ways to go, and each limit takes the one that suits where its senders come from:
//   - THE RELAY'S WAY (new PerSender): the sender heard from longest ago is forgotten. A crowd of made-up senders can push real ones out,
//     but each of those starts again with its own limit, and the limit for everyone (a TokenBucket of its own, kept by whoever uses this)
//     still holds. This is right where an address can be made up (UDP, the relay): the other way would let a flood of made-up addresses
//     lock every real one out.
//   - THE ACCESS CALL'S WAY (keepingDrained): the sender heard from longest ago is forgotten only if its bucket has filled up again, since
//     a full bucket is just what a new one would be. If it hasn't, the new sender is refused. So a crowd of more than `most` senders can't
//     have each one started afresh, with a full bucket, by pushing it out (Secondary's review of the access store, 1.1, 2026-11-09):
//     every sender is held to its own limit, and what the crowd costs is new senders refused while it lasts. This is right only where an
//     address can't be made up: the list's HTTPS, where a TCP connection proves the sender gets packets at its address.
//
// Not safe to use from two threads at once, like the hasher it uses.
public final class PerSender {
  private final double rate;
  private final double burst;
  private final int most;
  private final AddressHasher hasher;
  private final boolean keepDrained;

  // Each sender's bucket, the one heard from longest ago first: a sender heard from is taken out and put back at the end
  private final LinkedHashMap<String, TokenBucket> buckets = new LinkedHashMap<>();
  private int generation = -1;

  // The relay's way, above
  public PerSender(double rate, double burst, int most, AddressHasher hasher) {
    this(rate, burst, most, hasher, false);
  }

  // The access call's way, above
  public static PerSender keepingDrained(double rate, double burst, int most, AddressHasher hasher) {
    return new PerSender(rate, burst, most, hasher, true);
  }

  private PerSender(double rate, double burst, int most, AddressHasher hasher, boolean keepDrained) {
    if (most < 1) {
      throw new IllegalArgumentException("PerSender: room for at least one sender");
    }

    this.rate = rate;
    this.burst = burst;
    this.most = most;
    this.hasher = hasher;
    this.keepDrained = keepDrained;
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
      if (buckets.size() >= most) {
        Map.Entry<String, TokenBucket> oldest = buckets.entrySet().iterator().next();

        // The access call's way: one that still holds part of its limit is kept, and the new sender is refused
        if (keepDrained && !oldest.getValue().full(now)) {
          return false;
        }

        buckets.remove(oldest.getKey());
      }

      bucket = new TokenBucket(rate, burst);
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
