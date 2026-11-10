package avpx.relay;

// One limit on how fast something may be asked for. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, from relay/limits.js.
//
// The relay and the list are on the internet, so anyone can send them anything, as fast as they like, from an address that isn't even
// theirs (AVP Tao 3: input is hostile). Every kind of asking has a limit, so no one sender, and no crowd of them, can use up the server
// for everyone else.
//
// A TOKEN BUCKET is how each limit is kept: it holds up to `burst` tokens and fills at `rate` a second; each thing asked for takes one
// (or, for bytes, as many as the packet has). An empty bucket says no until it fills again. So a sender can go as fast as `rate` for
// ever, and faster for a moment, up to `burst`.
//
// A bucket isn't safe to use from two threads at once: each one belongs to one part of the server, which keeps it to one thread.
public final class TokenBucket {
  private final double rate;
  private final double burst;
  private double tokens;
  private long at;
  private boolean started;

  // rate: tokens a second; burst: the most it holds. It starts full.
  public TokenBucket(double rate, double burst) {
    // Written as "not above 0" rather than "at most 0", so a rate that isn't a number at all (NaN) is refused too
    if (!(rate > 0) || !(burst >= 1)) {
      throw new IllegalArgumentException("TokenBucket: a rate above 0 and a burst of at least 1");
    }

    this.rate = rate;
    this.burst = burst;
    this.tokens = burst;
  }

  public boolean take(long now) {
    return take(now, 1);
  }

  // Takes amount tokens at now (milliseconds) if there are that many, and says whether it did. A clock that goes back is taken as no time.
  public boolean take(long now, double amount) {
    if (started && now > at) {
      tokens = Math.min(burst, tokens + ((now - at) / 1000.0) * rate);
    }

    if (!started || now > at) {
      at = now;
      started = true;
    }

    if (tokens < amount) {
      return false;
    }

    tokens -= amount;
    return true;
  }

  // Whether it would be full at now, without taking anything: a full bucket is the same as a new one, so forgetting it loses nothing
  // (PerSender.keepingDrained). A clock that goes back is taken as no time, as in take.
  public boolean full(long now) {
    double held = started && now > at ? Math.min(burst, tokens + ((now - at) / 1000.0) * rate) : tokens;
    return held >= burst;
  }
}
