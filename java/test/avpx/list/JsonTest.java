package avpx.list;

import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsAny;

import avpx.testing.SeededRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// The tests of Json.java: it reads the plainest JSON and refuses everything else, it writes what Node's JSON.stringify writes, and nothing
// at all, however broken, gets anything but a refusal out of it. Written 2026-11-08 by Melanikus for AVPx Dedicated Server. New for the
// Java version: Node had JSON of its own, so it had no tests like these.
public final class JsonTest {
  private JsonTest() {
  }

  private static Object read(String text, int depth) throws Json.Bad {
    return Json.read(latin1(text), depth);
  }

  // That a text is refused, with any reason
  private static void refused(String text, int depth, String why) {
    try {
      read(text, depth);
    } catch (Json.Bad e) {
      return;
    }

    ok(false, why + ": it was read");
  }

  // A listing's body as the game writes it: no spaces, the fields in PROTOCOL.md's order
  private static final String GOOD = "{\"region\":\"virginia\",\"code\":\"ABCD2345\",\"pass\":\"00112233445566778899aabbccddeeff\","
      + "\"passTime\":1794268800,\"name\":\"Ripley's \\\"game\\\"\",\"level\":\"Genshd1\",\"mode\":\"Coop\",\"gameStyle\":3,"
      + "\"levelNumber\":12,\"coopLobby\":0,\"players\":1,\"maxPlayers\":4,\"version\":7,\"hostMs\":40}";

  // The bytes JSON gives a meaning to, for the changes the last test makes
  private static final String MEANINGFUL = "{}[]\":,\\-.e0 9tfn";

  public static void register() {
    test("it reads objects, lists, texts and whole numbers, with JSON's spaces between", () -> {
      Map<String, Object> want = new LinkedHashMap<>();
      want.put("a", "x");
      want.put("b", 0L);
      want.put("c", Json.MOST_WHOLE);
      want.put("d", "say \"hi\" \\ there");
      same(read("{\"a\":\"x\",\"b\":0,\"c\":9007199254740991,\"d\":\"say \\\"hi\\\" \\\\ there\"}", 1), want, "an object");
      same(read(" \t\r\n{ \"a\" : \"x\" , \"b\" : 0 , \"c\" : 9007199254740991 , \"d\" : \"say \\\"hi\\\" \\\\ there\" } \n", 1), want,
          "the same with every kind of space");
      same(read("[1,\"two\",3]", 1), List.of(1L, "two", 3L), "a list");
      same(read("{}", 1), Map.of(), "an empty object");
      same(read("[]", 1), List.of(), "an empty list");
      same(read("{\"list\":[{\"a\":1}]}", 3), Map.of("list", List.of(Map.of("a", 1L))), "nested as deep as allowed");
      same(read("\"just a text\"", 1), "just a text", "a text alone");
      same(read("42", 1), 42L, "a number alone");
    });

    test("it keeps an object's fields in the order they came", () -> {
      Map<String, Object> got = Json.readObject(latin1("{\"z\":1,\"a\":2,\"m\":3}"), 1);
      same(List.copyOf(got.keySet()), List.of("z", "a", "m"), "z, a, m");
    });

    test("it refuses everything but the plainest JSON, with a reason", () -> {
      refused("{\"a\":1,\"a\":2}", 1, "a field given twice");
      refused("{\"a\":\"x\\ny\"}", 1, "an escape other than \\\" and \\\\: a line break");
      refused("{\"a\":\"\\/\"}", 1, "an escaped /");
      refused("{\"a\":\"\\" + "u0041\"}", 1, "a unicode escape");
      refused("{\"a\":\"tab\there\"}", 1, "a tab inside a text");
      refused("{\"a\":\"caf" + (char) 0xe9 + "\"}", 1, "a letter outside ASCII, written as a number so this file stays ASCII");
      refused("{\"a\":1.5}", 1, "a fraction");
      refused("{\"a\":1.0}", 1, "a whole number written with a fraction");
      refused("{\"a\":1e3}", 1, "an exponent");
      refused("{\"a\":1E3}", 1, "an exponent, in capitals");
      refused("{\"a\":-1}", 1, "a minus");
      refused("{\"a\":-0}", 1, "minus 0");
      refused("{\"a\":01}", 1, "a 0 in front");
      refused("{\"a\":9007199254740992}", 1, "one more than a JSON number holds exactly");
      refused("{\"a\":12345678901234567}", 1, "17 digits");
      refused("{\"a\":true}", 1, "true");
      refused("{\"a\":false}", 1, "false");
      refused("{\"a\":null}", 1, "null");
      refused("null", 1, "null alone");
      refused("{\"a\":{\"b\":1}}", 1, "an object inside a body");
      refused("{\"a\":[1]}", 1, "a list inside a body");
      refused("[[1]]", 1, "a list inside a list, at depth 1");
      refused("{\"a\":1,}", 1, "a comma before the end");
      refused("[1,]", 1, "a comma before a list's end");
      refused("{\"a\" 1}", 1, "no colon");
      refused("{\"a\":1}x", 1, "more after the end");
      refused("{\"a\":1}{}", 1, "two objects");
      refused("{a:1}", 1, "a name that isn't a text");
      refused("{\"a\":'x'}", 1, "single quotes");
      refused("{\"a\":\"x", 1, "a text that doesn't end");
      refused("{\"a\":\"x\\", 1, "an escape that doesn't end");
      refused("{\"a\":1", 1, "an object that doesn't end");
      refused("", 1, "nothing");
      refused("   ", 1, "only spaces");
      refused((char) 0xef + "" + (char) 0xbb + (char) 0xbf + "{}", 1, "a byte order mark in front");
      refused("{\"a\":1}" + (char) 0, 1, "a 0 byte after the end");
      refused("{\f\"a\":1}", 1, "a form feed, which isn't one of JSON's four spaces");
      refused("{\"a\":1 2}", 1, "two numbers");
    });

    test("a number from outside is read by adding its digits up, and nothing it holds can make that throw", () -> {
      same(Json.digitsValue("0", 10), 0L, "0");
      same(Json.digitsValue("42", 42), 42L, "at its most");
      same(Json.digitsValue("9999999999999999", Json.MOST_WHOLE), 9999999999999999L, "16 digits");
      same(Json.digitsValue("43", 42), -1L, "past its most");
      same(Json.digitsValue("12345678901234567", Long.MAX_VALUE), -1L, "17 digits, refused before any adding");
      same(Json.digitsValue("99999999999999999999999999999999", Long.MAX_VALUE), -1L, "far more digits than a long holds");
      same(Json.digitsValue("", 10), -1L, "nothing");
      same(Json.digitsValue(null, 10), -1L, "no text at all");
      same(Json.digitsValue("1x", 10), -1L, "a letter");
      same(Json.digitsValue("-1", 10), -1L, "a minus");
      same(Json.digitsValue(" 1", 10), -1L, "a space");
      same(Json.digitsValue("1.0", 10), -1L, "a fraction");
    });

    test("readObject takes only an object", () -> {
      throwsAny(() -> Json.readObject(latin1("[1]"), 1), "a list");
      throwsAny(() -> Json.readObject(latin1("\"x\""), 1), "a text");
      throwsAny(() -> Json.readObject(latin1("{} {}"), 1), "two objects");
      same(Json.readObject(latin1(" {\"a\":1} "), 1), Map.of("a", 1L), "an object, with spaces round it");
    });

    test("it writes what Node's JSON.stringify writes for the same things", () -> {
      Map<String, Object> game = new LinkedHashMap<>();
      game.put("region", "virginia");
      game.put("code", "ABCD2345");
      game.put("pass", "00112233445566778899aabbccddeeff");
      game.put("passTime", 1794268800L);
      game.put("name", "Ripley's \"game\"");
      game.put("level", "Genshd1");
      game.put("mode", "Coop");
      game.put("gameStyle", 3);
      game.put("levelNumber", 12);
      game.put("coopLobby", 0);
      game.put("players", 1);
      game.put("maxPlayers", 4);
      game.put("version", 7);
      game.put("hostMs", 40);
      same(Json.write(game), GOOD, "a listing's body");
      same(Json.write(Map.of("games", List.of())), "{\"games\":[]}", "an empty list");
      same(Json.write(Map.of("path", "C:\\x")), "{\"path\":\"C:\\\\x\"}", "a backslash");
      same(Json.read(latin1(GOOD), 1), game, "and it reads back what it wrote");
    });

    test("it refuses to write anything it couldn't read back the same", () -> {
      throwsAny(() -> Json.write(Map.of("a", "line\nbreak")), "a line break");
      throwsAny(() -> Json.write(Map.of("a", "caf" + (char) 0xe9)), "a letter outside ASCII");
      throwsAny(() -> Json.write(Map.of("a", 1.5)), "a fraction");
      throwsAny(() -> Json.write(Map.of("a", true)), "true");
      throwsAny(() -> Json.write(Map.of(1, "x")), "a field name that isn't a text");
    });

    test("however broken a body is, it gets a refusal or a value, never anything else, and a value reads back the same", () -> {
      SeededRandom random = SeededRandom.of(42);
      byte[] good = latin1(GOOD);
      int read = 0;
      int refusedCount = 0;

      for (int i = 0; i < 20000; i++) {
        byte[] b = good.clone();
        int changes = 1 + (random.next(1)[0] & 3);

        for (int k = 0; k < changes; k++) {
          byte[] two = random.next(2);
          int where = (((two[0] & 0xff) << 8) | (two[1] & 0xff)) % b.length;
          int how = random.next(1)[0] & 3;

          if (how == 0) {
            // one byte changed to anything
            b[where] = random.next(1)[0];
          } else if (how == 1) {
            // one byte changed to one JSON gives a meaning to
            b[where] = (byte) MEANINGFUL.charAt((random.next(1)[0] & 0xff) % MEANINGFUL.length());
          } else if (how == 2 && b.length > 1) {
            // one byte taken out
            byte[] shorter = new byte[b.length - 1];
            System.arraycopy(b, 0, shorter, 0, where);
            System.arraycopy(b, where + 1, shorter, where, b.length - where - 1);
            b = shorter;
          } else {
            // the rest cut off
            byte[] cut = new byte[where + 1];
            System.arraycopy(b, 0, cut, 0, where + 1);
            b = cut;
          }
        }

        Object value;

        try {
          value = Json.read(b, 1);
        } catch (Json.Bad e) {
          refusedCount++;
          continue;
        }

        read++;

        // What it read, it writes, and what it writes it reads back as the same
        String written = Json.write(value);
        same(Json.read(latin1(written), 1), value, "body " + i + " reads back the same");
      }

      ok(refusedCount > 10000, refusedCount + " refused");
      ok(read > 0, read + " read: some changes still make JSON");
    });
  }
}
