package avpx.relay;

import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsAny;

import avpx.testing.SeededRandom;
import java.util.regex.Pattern;

// The tests of TokenBucket.java, AddressHasher.java and PerSender.java: buckets fill and empty as they say, senders are told apart by a
// hash that changes daily, and the most senders remembered is kept to. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, ported
// test for test from test/limits.test.js.
public final class LimitsTest {
  private LimitsTest() {
  }

  public static void register() {
    test("a bucket starts full, empties, and fills at its rate", () -> {
      TokenBucket b = new TokenBucket(2, 3);
      ok(b.take(0) && b.take(0) && b.take(0), "its burst");
      ok(!b.take(0), "then nothing");
      ok(!b.take(499), "not yet one token after 0.499 s at 2 a second");
      ok(b.take(500), "one after 0.5 s");
      ok(!b.take(500), "and not two");
      ok(b.take(100000) && b.take(100000) && b.take(100000) && !b.take(100000), "it never holds more than its burst");
    });

    test("a bucket takes amounts, and a clock going back gives nothing", () -> {
      TokenBucket b = new TokenBucket(1000, 1000);
      ok(b.take(10, 600), "600 of 1000");
      ok(!b.take(10, 600), "not 600 more");
      ok(!b.take(5, 600), "and going back in time fills nothing");
      ok(b.take(310, 600), "300 ms at 1000 a second is 300 more: 700");
    });

    test("a bucket refuses a rate or burst it cannot keep", () -> {
      throwsAny(() -> new TokenBucket(0, 10), "a rate of 0");
      throwsAny(() -> new TokenBucket(1, 0), "a burst of 0");
      throwsAny(() -> new TokenBucket(Double.NaN, 1), "a rate that isn't a number");
    });

    test("an address hashes the same until the secret changes, and never shows the address", () -> {
      AddressHasher h = new AddressHasher(SeededRandom.of(7));
      String a = h.keyOf("203.0.113.7", 0);
      same(h.keyOf("203.0.113.7", 1000), a, "the same a second later");
      notSame(h.keyOf("203.0.113.8", 1000), a, "another address, another hash");
      ok(!a.contains("203") && Pattern.matches("[0-9a-f]{32}", a), "a hash, not the address");
      int generation = h.generation();
      notSame(h.keyOf("203.0.113.7", AddressHasher.KEY_LIFE_MILLISECONDS), a, "a day later the same address has another hash");
      same(h.generation(), generation + 1, "with a new secret");
    });

    test("each sender has its own limit", () -> {
      PerSender s = new PerSender(1, 2, 100, new AddressHasher(SeededRandom.of(1)));
      ok(s.allows("198.51.100.1", 0) && s.allows("198.51.100.1", 0), "the first sender's burst");
      ok(!s.allows("198.51.100.1", 0), "the first sender has used its burst");
      ok(s.allows("198.51.100.2", 0), "the second has its own");
    });

    test("the senders remembered stop at the most, forgetting the one heard from longest ago", () -> {
      PerSender s = new PerSender(1, 1, 3, new AddressHasher(SeededRandom.of(1)));
      s.allows("a", 0);
      s.allows("b", 0);
      s.allows("c", 0);
      ok(!s.allows("a", 0), "a has used its one, and is heard from last now");
      s.allows("d", 0);
      same(s.size(), 3, "still 3");
      ok(s.allows("b", 0), "b was the one heard from longest ago, so it was forgotten, and starts again");
      ok(!s.allows("a", 0), "a was kept");
    });

    test("a new secret forgets every sender", () -> {
      AddressHasher h = new AddressHasher(SeededRandom.of(1));
      PerSender s = new PerSender(1, 1, 10, h);
      ok(s.allows("a", 0), "its one");
      ok(!s.allows("a", 1), "then nothing");
      ok(s.allows("a", AddressHasher.KEY_LIFE_MILLISECONDS), "a day on, the old limits are gone");
      same(s.size(), 1, "only the one sender heard from since");
    });
  }
}
