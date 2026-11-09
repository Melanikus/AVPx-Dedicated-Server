package avpx.list;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// JSON, read strictly and written plainly: our own, because Java has none of its own, and every library is code we didn't write (AVP Tao
// 1). Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// WHAT IT READS. What comes from the network is hostile (AVP Tao 3), and two programs that read one body two ways is a way in for an
// attacker. So this reads only the plainest JSON, the JSON every honest sender writes for what the list takes (PROTOCOL.md section 4),
// and refuses everything else, with the reason:
// - objects { }, lists [ ], texts " " and whole numbers, nested no deeper than the caller allows (a body: one object, nothing inside it);
// - a text holds printable ASCII only (0x20 to 0x7E), with only two escapes, \" and \\: the only two printable ASCII needs;
// - a whole number is digits only, 0 and up, with no 0 in front of another digit, no fraction, no exponent and no minus, at most
//   MOST_WHOLE (the most a JSON number holds exactly, 2 to the 53rd less 1);
// - no field twice in one object, and nothing after the end;
// - between the parts, only JSON's own four spaces: space, tab, carriage return and line feed.
// No true, false or null: nothing the server reads has them.
//
// The reasons it gives never hold any of the text it was given, so they can go back to whoever sent it.
//
// WHAT IT WRITES: objects (in the order their fields were put in), lists, texts and whole numbers, with no spaces, exactly as Node's
// JSON.stringify writes the same things. Every text it writes must be printable ASCII, so the only escapes it ever writes are \" and \\
// (which is what a reader of the list may hold the list to, PROTOCOL.md section 4). The sizes the list promises are counted on this.
public final class Json {
  private Json() {
  }

  // The most a whole number may be: the most a JSON number holds exactly, so every reader of it reads the same number
  public static final long MOST_WHOLE = 9007199254740991L;
  private static final int MOST_WHOLE_DIGITS = 16;

  // A text that isn't JSON as this reads it, with the reason
  public static final class Bad extends Exception {
    private static final long serialVersionUID = 1L;

    Bad(String why) {
      super(why);
    }
  }

  // One JSON value, read from bytes: a Map (an object, its fields in the order they came), a List, a String or a Long. mostDepth is how
  // deep objects and lists may be nested: 1 is one object or list with nothing but texts and numbers in it.
  public static Object read(byte[] bytes, int mostDepth) throws Bad {
    Reader r = new Reader(bytes, mostDepth);
    Object value = r.value(0);
    r.space();

    if (r.at != bytes.length) {
      throw new Bad("there is more after the end");
    }

    return value;
  }

  // One JSON object, read from bytes, its fields in the order they came; anything that isn't one object is refused
  public static Map<String, Object> readObject(byte[] bytes, int mostDepth) throws Bad {
    Reader r = new Reader(bytes, mostDepth);
    r.space();

    if (r.peek() != '{') {
      throw new Bad("it isn't a JSON object");
    }

    Map<String, Object> value = r.object(1);
    r.space();

    if (r.at != bytes.length) {
      throw new Bad("there is more after the end");
    }

    return value;
  }

  // A value read by this, as an object with text field names, or null if it isn't one
  public static Map<String, Object> object(Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      return null;
    }

    Map<String, Object> out = new LinkedHashMap<>();

    for (Map.Entry<?, ?> field : map.entrySet()) {
      out.put(String.valueOf(field.getKey()), field.getValue());
    }

    return out;
  }

  // A value read by this, as a list, or null if it isn't one
  public static List<Object> list(Object value) {
    return value instanceof List<?> list ? new ArrayList<Object>(list) : null;
  }

  private static final class Reader {
    private final byte[] b;
    private final int mostDepth;
    private int at;

    Reader(byte[] bytes, int mostDepth) {
      this.b = bytes;
      this.mostDepth = mostDepth;
    }

    // The next byte, without moving past it, or -1 at the end
    private int peek() {
      return at < b.length ? b[at] & 0xff : -1;
    }

    // The next byte, moving past it; the end here is a text that stops too soon
    private int next() throws Bad {
      if (at >= b.length) {
        throw new Bad("it stops before its end");
      }

      return b[at++] & 0xff;
    }

    // JSON's four spaces between the parts
    void space() {
      while (at < b.length && (b[at] == ' ' || b[at] == '\t' || b[at] == '\r' || b[at] == '\n')) {
        at++;
      }
    }

    // A value, at depth (how many objects and lists it is inside)
    Object value(int depth) throws Bad {
      space();
      int c = peek();

      if (c == '{') {
        return object(depth + 1);
      }

      if (c == '[') {
        return list(depth + 1);
      }

      if (c == '"') {
        return text();
      }

      if (c >= '0' && c <= '9') {
        return whole();
      }

      if (c < 0) {
        throw new Bad("it stops before its end");
      }

      throw new Bad("something that isn't an object, a list, a text or a whole number of 0 or more");
    }

    private Map<String, Object> object(int depth) throws Bad {
      if (depth > mostDepth) {
        throw new Bad("objects or lists nested deeper than they may be here");
      }

      at++;
      Map<String, Object> out = new LinkedHashMap<>();
      space();

      if (peek() == '}') {
        at++;
        return out;
      }

      while (true) {
        space();

        if (peek() != '"') {
          throw new Bad("a field's name that isn't a text");
        }

        String name = text();
        space();

        if (next() != ':') {
          throw new Bad("something else where a : has to be");
        }

        Object value = value(depth);

        if (out.containsKey(name)) {
          throw new Bad("a field given twice");
        }

        out.put(name, value);
        space();
        int c = next();

        if (c == '}') {
          return out;
        }

        if (c != ',') {
          throw new Bad("something else where a , or } has to be");
        }
      }
    }

    private List<Object> list(int depth) throws Bad {
      if (depth > mostDepth) {
        throw new Bad("objects or lists nested deeper than they may be here");
      }

      at++;
      List<Object> out = new ArrayList<>();
      space();

      if (peek() == ']') {
        at++;
        return out;
      }

      while (true) {
        out.add(value(depth));
        space();
        int c = next();

        if (c == ']') {
          return out;
        }

        if (c != ',') {
          throw new Bad("something else where a , or ] has to be");
        }
      }
    }

    private String text() throws Bad {
      at++;
      StringBuilder out = new StringBuilder();

      while (true) {
        int c = next();

        if (c == '"') {
          return out.toString();
        }

        if (c == '\\') {
          int escaped = next();

          if (escaped != '"' && escaped != '\\') {
            throw new Bad("a text with an escape other than \\\" and \\\\");
          }

          out.append((char) escaped);
        } else if (c < 0x20 || c > 0x7e) {
          throw new Bad("a text with a character that isn't printable ASCII");
        } else {
          out.append((char) c);
        }
      }
    }

    private Long whole() throws Bad {
      int start = at;

      while (at < b.length && b[at] >= '0' && b[at] <= '9') {
        at++;
      }

      int digits = at - start;
      int after = peek();

      if (after == '.' || after == 'e' || after == 'E' || after == '-' || after == '+') {
        throw new Bad("a number that isn't a whole number written plainly (no fraction or exponent)");
      }

      if (digits > 1 && b[start] == '0') {
        throw new Bad("a number with a 0 in front of its other digits");
      }

      if (digits > MOST_WHOLE_DIGITS) {
        throw new Bad("a number bigger than a JSON number holds exactly");
      }

      long value = Long.parseLong(new String(b, start, digits, StandardCharsets.US_ASCII));

      if (value > MOST_WHOLE) {
        throw new Bad("a number bigger than a JSON number holds exactly");
      }

      return value;
    }
  }

  // ----- Writing

  // A value as JSON text: a Map with text keys, a List, a String, or a whole number (Long or Integer). Throws on anything else, or on a
  // text that isn't printable ASCII: only our own code calls this, so that would be a bug to find at once.
  public static String write(Object value) {
    StringBuilder out = new StringBuilder();
    write(out, value);
    return out.toString();
  }

  private static void write(StringBuilder out, Object value) {
    if (value instanceof String text) {
      writeText(out, text);
    } else if (value instanceof Long || value instanceof Integer) {
      out.append(value);
    } else if (value instanceof Map<?, ?> object) {
      out.append('{');
      boolean first = true;

      for (Map.Entry<?, ?> field : object.entrySet()) {
        if (!(field.getKey() instanceof String name)) {
          throw new IllegalArgumentException("Json.write: an object's field names are texts");
        }

        if (!first) {
          out.append(',');
        }

        first = false;
        writeText(out, name);
        out.append(':');
        write(out, field.getValue());
      }

      out.append('}');
    } else if (value instanceof List<?> list) {
      out.append('[');

      for (int i = 0; i < list.size(); i++) {
        if (i > 0) {
          out.append(',');
        }

        write(out, list.get(i));
      }

      out.append(']');
    } else {
      throw new IllegalArgumentException("Json.write: only objects, lists, texts and whole numbers");
    }
  }

  private static void writeText(StringBuilder out, String text) {
    out.append('"');

    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);

      if (c < 0x20 || c > 0x7e) {
        throw new IllegalArgumentException("Json.write: a text that isn't printable ASCII");
      }

      if (c == '"' || c == '\\') {
        out.append('\\');
      }

      out.append(c);
    }

    out.append('"');
  }
}
