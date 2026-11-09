package avpx.testing;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

// The tests' own runner, and the checks they make. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// The tests need nothing but Java itself: no test library, because every library is code we didn't write and can't keep an eye on (AVP
// Tao 1). So this is a small one of our own, made to read like Node's (node:test), which the first version of the server was tested
// with: a test file adds each test with test("what it shows", () -> { ... }), and each test here reads line for line against the Node
// test it was ported from.
//
// A check that fails throws a Failure, with the reason. The runner says, for each test, its name and whether it passed, and if it didn't,
// why. At the end it says how many passed. It fails (exit code 1) if any test failed, or if there were no tests at all, which would mean
// nothing was checked.
//
// Tests that open real sockets on the loopback address (liveTest) run only when AVPX_LIVE=1 is set. GitHub's check sets it, and when it's
// set, a live test that didn't run counts as a failure, so the check can never pass with them quietly left out.
public final class Tests {
  private Tests() {
  }

  // A test's body. It may throw anything: whatever it throws fails that test, and the next one runs.
  @FunctionalInterface
  public interface Body {
    void run() throws Exception;
  }

  // A check that didn't hold
  public static final class Failure extends RuntimeException {
    private static final long serialVersionUID = 1L;

    Failure(String why) {
      super(why);
    }
  }

  private record Entry(String file, String name, Body body, boolean live) {
  }

  private static final List<Entry> ENTRIES = new ArrayList<>();
  private static String file = "";

  // Which test file the tests added next belong to, for the report
  public static void file(String name) {
    file = name;
  }

  public static void test(String name, Body body) {
    ENTRIES.add(new Entry(file, name, body, false));
  }

  // A test with real sockets, on the loopback address only (see above)
  public static void liveTest(String name, Body body) {
    ENTRIES.add(new Entry(file, name, body, true));
  }

  // Runs every test added, and gives back the exit code: 0 if all passed, 1 if not
  public static int runAll() {
    boolean live = "1".equals(System.getenv("AVPX_LIVE"));
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    for (Entry e : ENTRIES) {
      if (e.live() && !live) {
        skipped++;
        System.out.println("skipped (it opens sockets: set AVPX_LIVE=1): " + e.file() + ": " + e.name());
        continue;
      }

      try {
        e.body().run();
        passed++;
        System.out.println("ok: " + e.file() + ": " + e.name());
      } catch (Throwable t) {
        // Anything at all a test throws fails it, an Error too, so one broken test can't stop the others from running
        failed++;
        System.out.println("FAILED: " + e.file() + ": " + e.name() + ": " + describe(t));
      }
    }

    System.out.println(ENTRIES.size() + " tests: " + passed + " passed, " + failed + " failed, " + skipped + " skipped");

    if (ENTRIES.isEmpty()) {
      System.out.println("FAILED: no tests were found, which would mean nothing was checked");
      return 1;
    }

    return failed == 0 ? 0 : 1;
  }

  private static String describe(Throwable t) {
    if (t instanceof Failure) {
      return t.getMessage();
    }

    StackTraceElement[] where = t.getStackTrace();
    return t.getClass().getName() + ": " + t.getMessage() + (where.length > 0 ? " (at " + where[0] + ")" : "");
  }

  // ----- The checks

  public static void ok(boolean value, String why) {
    if (!value) {
      throw new Failure(why);
    }
  }

  public static void ok(boolean value) {
    ok(value, "it should be true");
  }

  // That two things are alike: numbers by their value, byte arrays and lists by what they hold, maps by their keys and values
  public static void same(Object actual, Object expected, String why) {
    if (!alike(actual, expected)) {
      throw new Failure(why + ": it is " + show(actual) + ", not " + show(expected));
    }
  }

  public static void same(Object actual, Object expected) {
    same(actual, expected, "not what was expected");
  }

  public static void notSame(Object actual, Object unexpected, String why) {
    if (alike(actual, unexpected)) {
      throw new Failure(why + ": both are " + show(actual));
    }
  }

  // That the body throws something, anything but a Failure of its own
  public static void throwsAny(Body body, String why) {
    throwsWith(body, "", why);
  }

  // That the body throws something whose words have these in them
  public static void throwsWith(Body body, String words, String why) {
    try {
      body.run();
    } catch (Failure f) {
      throw f;
    } catch (Exception e) {
      String said = String.valueOf(e.getMessage());

      if (!said.contains(words)) {
        throw new Failure(why + ": it threw, but its words (" + said + ") don't have \"" + words + "\" in them");
      }

      return;
    }

    throw new Failure(why + ": nothing was thrown");
  }

  public static void doesNotThrow(Body body, String why) {
    try {
      body.run();
    } catch (Exception e) {
      throw new Failure(why + ": it threw " + e);
    }
  }

  // That a pattern (a regular expression) is found somewhere in a text
  public static void matches(String text, String pattern, String why) {
    if (text == null || !Pattern.compile(pattern).matcher(text).find()) {
      throw new Failure(why + ": \"" + text + "\" doesn't have " + pattern + " in it");
    }
  }

  static boolean alike(Object a, Object b) {
    if (a == b) {
      return true;
    }

    if (a == null || b == null) {
      return false;
    }

    if (a instanceof Number x && b instanceof Number y && whole(x) && whole(y)) {
      return x.longValue() == y.longValue();
    }

    if (a instanceof byte[] x && b instanceof byte[] y) {
      return Arrays.equals(x, y);
    }

    if (a instanceof int[] x && b instanceof int[] y) {
      return Arrays.equals(x, y);
    }

    if (a instanceof List<?> x && b instanceof List<?> y) {
      if (x.size() != y.size()) {
        return false;
      }

      for (int i = 0; i < x.size(); i++) {
        if (!alike(x.get(i), y.get(i))) {
          return false;
        }
      }

      return true;
    }

    if (a instanceof Map<?, ?> x && b instanceof Map<?, ?> y) {
      if (x.size() != y.size()) {
        return false;
      }

      for (Map.Entry<?, ?> entry : x.entrySet()) {
        if (!y.containsKey(entry.getKey()) || !alike(entry.getValue(), y.get(entry.getKey()))) {
          return false;
        }
      }

      return true;
    }

    return a.equals(b);
  }

  private static boolean whole(Number n) {
    return n instanceof Long || n instanceof Integer || n instanceof Short || n instanceof Byte;
  }

  private static String show(Object value) {
    if (value instanceof byte[] bytes) {
      return "bytes " + HexFormat.of().formatHex(bytes);
    }

    if (value instanceof int[] numbers) {
      return Arrays.toString(numbers);
    }

    return String.valueOf(value);
  }

  // ----- Helpers the tests share

  // n bytes, each of them `fill` (Node's Buffer.alloc(n, fill))
  public static byte[] bytes(int n, int fill) {
    byte[] out = new byte[n];
    Arrays.fill(out, (byte) fill);
    return out;
  }

  // A text's letters as bytes, one byte each (Node's Buffer.from(text, 'latin1'), for the ASCII the tests use)
  public static byte[] latin1(String text) {
    return text.getBytes(StandardCharsets.ISO_8859_1);
  }

  // Bytes as a text, one letter each
  public static String text(byte[] bytes) {
    return new String(bytes, StandardCharsets.ISO_8859_1);
  }

  public static String hex(byte[] bytes) {
    return HexFormat.of().formatHex(bytes);
  }

  // A text repeated n times ('x'.repeat(n))
  public static String repeat(String text, int n) {
    return text.repeat(n);
  }
}
