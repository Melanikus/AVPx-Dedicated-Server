package avpx.list;

import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.SeededRandom;
import avpx.testing.Stringify;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

// The tests of how a body is read (Json.readObject with nothing nested, as Requests.java reads every body): it takes exactly what
// PROTOCOL.md section 4 ("How a request is read") says, refuses everything else, and reads every body it takes as it was written. Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server, ported test for test from test/strict-json.test.js.
public final class StrictJsonTest {
  private StrictJsonTest() {
  }

  // A body is one object with nothing nested in it
  private static final int BODY = 1;

  private static final String BS = "\\";
  private static final String Q = "\"";

  // What the reader makes of a text, or null if it refuses it
  private static Map<String, Object> read(String text) {
    try {
      return Json.readObject(latin1(text), BODY);
    } catch (Json.Bad e) {
      return null;
    }
  }

  private static Map<String, Object> object(Object... fields) {
    Map<String, Object> out = new LinkedHashMap<>();

    for (int i = 0; i < fields.length; i += 2) {
      out.put((String) fields[i], fields[i + 1]);
    }

    return out;
  }

  public static void register() {
    test("it takes a flat object of strings and whole numbers, with JSON's whitespace", () -> {
      same(read("{\"a\":\"b\",\"n\":7}"), object("a", "b", "n", 7), "an object");
      same(read(" \t\r\n{ \"a\" : \"b\" ,\n \"n\" : 0 }\r\n "), object("a", "b", "n", 0), "with whitespace");
      same(read("{}"), object(), "an empty one");
      same(read("{\"q\":\"" + BS + Q + BS + BS + "\"}"), object("q", Q + BS), "the two escapes");
      same(read("{\"n\":9007199254740991}").get("n"), 9007199254740991L, "the most a number holds exactly");
      // Node's test checked that "__proto__" is only a key there; a Java map has no prototype at all, so it is only a key here too
      same(read("{\"__proto__\":\"x\"}"), object("__proto__", "x"), "\"__proto__\" is only a key");
    });

    test("it refuses everything else", () -> {
      String[][] refused = {
        {"{\"a\":1,\"a\":2}", "a key twice"},
        {"{\"a\":\"b\",\"a\":\"b\"}", "a key twice, the same both times"},
        {"{\"a\":\"" + BS + "u0041\"}", "a unicode escape"},
        {"{\"a\":\"" + BS + "n\"}", "a \\n escape"},
        {"{\"a\":\"" + BS + "/\"}", "a \\/ escape"},
        {"{\"a\":\"" + BS + "\"}", "a backslash at the end of a string"},
        {"{\"a\":1.0}", "a fraction, even .0"},
        {"{\"a\":1e0}", "an exponent"},
        {"{\"a\":-1}", "a minus"},
        {"{\"a\":+1}", "a plus"},
        {"{\"a\":01}", "a leading 0"},
        {"{\"a\":9007199254740992}", "past the most a number holds exactly"},
        {"{\"a\":12345678901234567}", "17 digits"},
        {"{\"a\":{\"b\":1}}", "an object inside"},
        {"{\"a\":[1]}", "a list inside"},
        {"{\"a\":true}", "true"},
        {"{\"a\":null}", "null"},
        {"{\"a\":\"x\ty\"}", "a tab inside a string"},
        {"{\"a\":\"x\ny\"}", "a line break inside a string"},
        {"{\"a\":\"caf" + (char) 0xe9 + "\"}", "a byte past ASCII"},
        {"{\"a\":\"" + (char) 0x7f + "\"}", "DEL"},
        {"{\"a\":1,}", "a comma at the end"},
        {"{,\"a\":1}", "a comma at the start"},
        {"{\"a\" 1}", "no colon"},
        {"{\"a\":1 \"b\":2}", "no comma"},
        {"{a:1}", "a key without quotes"},
        {"{\"a\":'b'}", "single quotes"},
        {"{\"a\":1}x", "something after the object"},
        {"{\"a\":1}{}", "a second object"},
        {"{\"a\":1", "no closing brace"},
        {"{\"a\":\"b", "no closing quote"},
        {"[]", "a list"},
        {"\"a\"", "a string"},
        {"7", "a number"},
        {"", "nothing"},
        {"   ", "only spaces"},
        {"" + (char) 0xef + (char) 0xbb + (char) 0xbf + "{}", "a byte-order mark before it"},
        {"{\"a\":1}\f", "a form feed, which JSON doesn't count as whitespace"},
      };

      for (String[] r : refused) {
        same(read(r[0]), null, r[1]);
      }

      // Node's test also gave it text where bytes go; a Java body can only be bytes, so there's nothing like that to try here
    });

    test("on every body it takes, it reads each key and value as it was written", () -> {
      SeededRandom random = SeededRandom.of(21);
      String letters = "abcxyz 019" + Q + BS + "!~";

      for (int i = 0; i < 2000; i++) {
        int[] r = new int[16];
        byte[] made = random.next(16);

        for (int k = 0; k < 16; k++) {
          r[k] = made[k] & 0xff;
        }

        Set<String> keys = new HashSet<>();
        List<String> parts = new ArrayList<>();
        Map<String, Object> want = new LinkedHashMap<>();

        for (int k = 0; k < r[0] % 6; k++) {
          StringBuilder key = new StringBuilder();

          for (int c = 0; c < 1 + (r[k + 1] % 5); c++) {
            key.append(letters.charAt((r[k + c + 2] + c) % letters.length()));
          }

          if (!keys.add(key.toString())) {
            continue;
          }

          // A whole number, or the key written backwards
          Object value;

          if (r[k + 8] % 2 == 1) {
            value = Long.valueOf(r[k + 9] * 1000L + r[k + 10]);
          } else {
            value = new StringBuilder(key).reverse().toString();
          }

          parts.add(Stringify.text(key.toString()) + ":" + Stringify.text(value));
          want.put(key.toString(), value);
        }

        String text = "{" + String.join(",", parts) + "}";
        same(read(text), want, text);
      }
    });

    test("nothing a body holds can throw out of it", () -> {
      SeededRandom random = SeededRandom.of(22);

      for (int i = 0; i < 5000; i++) {
        byte[] junk = random.next((random.next(1)[0] & 0xff) % 64);

        if (junk.length > 0) {
          junk[0] = 0x7b;
        }

        try {
          ok(Json.readObject(junk, BODY) != null, "a body it takes is an object");
        } catch (Json.Bad e) {
          // refused, as it should be: anything else thrown fails the test
        }
      }
    });
  }
}
