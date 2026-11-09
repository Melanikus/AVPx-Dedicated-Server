package avpx.v2;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.SeededRandom;
import java.util.HashSet;
import java.util.Set;

// The tests of ReplayWindow.java (CRYPTO.md section 9): no counter is taken twice, honest datagrams that come late or out of order are
// still taken while they're inside the 1,024 below the highest, and anything older is refused. Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server.
public final class ReplayWindowTest {
  private ReplayWindowTest() {
  }

  public static void register() {
    test("the very top: the window moves to the largest long and the call comes back, the counters between still new", () -> {
      ReplayWindow w = new ReplayWindow();
      w.take(Long.MAX_VALUE - 5);
      w.take(Long.MAX_VALUE);
      ok(!w.isNew(Long.MAX_VALUE) && !w.isNew(Long.MAX_VALUE - 5), "both taken");
      ok(w.isNew(Long.MAX_VALUE - 1), "one between, still new");
    });

    test("a counter is new once: taken, it's refused after", () -> {
      ReplayWindow w = new ReplayWindow();
      ok(w.isNew(0), "0, at the start");
      w.take(0);
      ok(!w.isNew(0), "0, again");
      ok(w.isNew(1), "1");
      ok(!w.isNew(-1), "never a counter below 0");
      ok(!w.isNew(Long.MIN_VALUE), "nor the lowest long");
    });

    test("out of order: a counter below the highest is taken while it's in the window, and only once", () -> {
      ReplayWindow w = new ReplayWindow();
      w.take(5);
      ok(w.isNew(3), "3, after 5");
      w.take(3);
      ok(!w.isNew(3), "3 again");
      ok(w.isNew(4), "4, which never came");
      ok(!w.isNew(5), "5 again");
      ok(w.isNew(0), "0, which never came");
    });

    test("the window's edge: 1,023 below the highest is in it, 1,024 below isn't", () -> {
      ReplayWindow w = new ReplayWindow();
      w.take(2000);
      ok(w.isNew(2000 - 1023), "1,023 below");
      ok(!w.isNew(2000 - 1024), "1,024 below: too old, refused");
      ok(!w.isNew(0), "far below");
      w.take(2000 - 1023);
      ok(!w.isNew(2000 - 1023), "taken at the edge, then refused");
    });

    test("as the window moves up, the places of counters that fell out are cleared, and those still in it kept", () -> {
      ReplayWindow w = new ReplayWindow();
      w.take(3);
      w.take(3 + 1023);
      ok(!w.isNew(3), "3 is still in the window (1,023 below), and taken");
      w.take(3 + 1024);
      ok(!w.isNew(3), "3 is out of the window now");
      ok(!w.isNew(3 + 1024), "and 1,027, which uses 3's place, is taken, not cleared by 3's going");
      ok(!w.isNew(3 + 1023), "1,026, taken above, is still taken");
      ok(w.isNew(3 + 1022), "1,025, never taken, is new");

      ReplayWindow jump = new ReplayWindow();
      jump.take(10);
      jump.take(10 + 5000);
      ok(jump.isNew(10 + 5000 - 1), "after a jump past the window, every place below is cleared");
      ok(!jump.isNew(10 + 5000), "but the counter jumped to is taken");
    });

    // Every answer the window gives, against the plainest way to say the rule: a set of every counter taken, and the highest. 200,000
    // counters, near the highest and far below it, so every case above comes up many times, in orders nobody wrote by hand.
    test("200,000 counters at random: the window answers exactly as the rule says, every time", () -> {
      ReplayWindow w = new ReplayWindow();
      Set<Long> taken = new HashSet<>();
      long highest = -1;
      byte[] r = SeededRandom.of(1024).next(200000 * 3);

      for (int i = 0; i < 200000; i++) {
        int kind = r[3 * i] & 0xff;
        int step = ((r[3 * i + 1] & 0xff) << 8) | (r[3 * i + 2] & 0xff);
        // Mostly near the highest, both sides of it; sometimes a big jump up; sometimes far below
        long c;

        if (kind < 200) {
          c = Math.max(0, highest + (step % 2100) - 1050);
        } else if (kind < 230) {
          c = highest + 1 + step;
        } else {
          c = Math.max(0, highest - step);
        }

        boolean rule = c >= 0 && !taken.contains(c) && (c > highest || highest - c < ReplayWindow.WINDOW);
        same(w.isNew(c), rule, "counter " + c + " with the highest at " + highest);

        if (rule) {
          w.take(c);
          taken.add(c);
          highest = Math.max(highest, c);
        }
      }
    });
  }
}
