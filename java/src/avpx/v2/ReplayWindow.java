package avpx.v2;

import java.util.Arrays;

// Which counters have come already, so no sealed message can be taken twice (CRYPTO.md section 9: the replay window). Written 2026-11-09
// by Melanikus for AVPx Dedicated Server.
//
// Datagrams can come late, twice, or out of order, so "only higher than the last" would drop honest ones. Instead the window remembers the
// highest counter taken, and which of the WINDOW counters just below it have been taken, as one bit each. A counter is new if it's above
// the highest, or inside the window with its bit not set. Anything older than the window, or taken already, is refused. A counter is
// marked taken only after its message's tag has checked, so a forged datagram can't use up an honest counter.
public final class ReplayWindow {
  public static final int WINDOW = 1024;
  private static final int WORDS = WINDOW / 64;

  private final long[] seen = new long[WORDS];
  private long highest = -1;

  // Whether a counter could be taken now
  public boolean isNew(long counter) {
    if (counter < 0) {
      return false;
    }

    if (counter > highest) {
      return true;
    }

    long behind = highest - counter;
    return behind < WINDOW && !bit(counter);
  }

  // Marks a counter taken (call only once its message's tag has checked, and isNew said yes)
  public void take(long counter) {
    if (counter > highest) {
      long ahead = highest < 0 ? WINDOW : counter - highest;

      // The counters that fall out of the window as it moves up are cleared. The move is counted in steps, fewer than WINDOW, and
      // never as "c <= counter": with a counter of the largest long, that is always true, so the loop would never end. Channel takes no
      // counter past 2^32, so nothing reaches that today; this keeps the window safe by itself, whoever uses it (the game's own does
      // the same, 3dc/net_v2_replay.h).
      if (ahead >= WINDOW) {
        Arrays.fill(seen, 0L);
      } else {
        for (long step = 1; step <= ahead; step++) {
          clear(highest + step);
        }
      }

      highest = counter;
    }

    set(counter);
  }

  private boolean bit(long counter) {
    int slot = (int) (counter % WINDOW);
    return (seen[slot / 64] & (1L << (slot % 64))) != 0;
  }

  private void set(long counter) {
    int slot = (int) (counter % WINDOW);
    seen[slot / 64] |= 1L << (slot % 64);
  }

  private void clear(long counter) {
    int slot = (int) (counter % WINDOW);
    seen[slot / 64] &= ~(1L << (slot % 64));
  }
}
