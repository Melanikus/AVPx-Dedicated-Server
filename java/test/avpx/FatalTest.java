package avpx;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import java.util.ArrayList;
import java.util.List;

// The tests of Fatal.java: a turn of a loop that throws is caught, an Error as well as an exception, and said in one line with the
// error's kind and where, never its words. Written 2026-11-09 by Melanikus for AVPx Dedicated Server, for the independent review's V1-3.
// LiveTest shows the relay's loop and the list's timers stopping on such a turn.
public final class FatalTest {
  private FatalTest() {
  }

  public static void register() {
    test("a turn that goes as expected says nothing and gives true", () -> {
      List<String> lines = new ArrayList<>();
      int[] ran = {0};
      ok(Fatal.turn("relay", () -> ran[0]++, lines::add), "true");
      same(ran[0], 1, "the turn ran");
      same(lines.size(), 0, "and nothing was said");
    });

    test("a turn that throws gives false, with one line naming the error's kind and where, and never its words", () -> {
      List<String> lines = new ArrayList<>();
      ok(!Fatal.turn("relay", () -> {
        throw new IllegalStateException("words that must never be written: 198.51.100.10");
      }, lines::add), "false");
      same(lines.size(), 1, "one line");
      String line = lines.get(0);
      ok(line.startsWith("relay: stopped by an error nobody expected, java.lang.IllegalStateException at avpx.FatalTest"), "its kind and where: " + line);
      ok(!line.contains("198.51.100.10") && !line.contains("must never"), "none of its words");
      ok(line.endsWith("the server stops, for systemd to start it again"), "and what happens next");
    });

    test("an Error is caught as well: the loop stops on it, rather than its thread dying with nobody told", () -> {
      List<String> lines = new ArrayList<>();
      ok(!Fatal.turn("list", () -> {
        throw new StackOverflowError();
      }, lines::add), "false");
      ok(lines.size() == 1 && lines.get(0).startsWith("list: stopped by an error nobody expected, java.lang.StackOverflowError"), "said");
    });
  }
}
