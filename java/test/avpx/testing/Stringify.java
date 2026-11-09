package avpx.testing;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

// What Node's JSON.stringify writes, for the values the list's tests send. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// The list's tests were written in Node, and send bodies made by JSON.stringify, some of them on purpose with things the list must refuse:
// a fraction, a line break, a letter outside ASCII. The server's own writer (Json.write) refuses to write those, as it should, so the tests
// make their bodies with this instead, and send exactly the bytes the Node tests sent. Only for tests.
public final class Stringify {
  private Stringify() {
  }

  // The text as UTF-8 bytes, as Node's Buffer.from(JSON.stringify(value)) gives them
  public static byte[] bytes(Object value) {
    return text(value).getBytes(StandardCharsets.UTF_8);
  }

  public static String text(Object value) {
    StringBuilder out = new StringBuilder();
    write(out, value);
    return out.toString();
  }

  private static void write(StringBuilder out, Object value) {
    if (value == null) {
      out.append("null");
    } else if (value instanceof String text) {
      quote(out, text);
    } else if (value instanceof Number || value instanceof Boolean) {
      out.append(value);
    } else if (value instanceof Map<?, ?> object) {
      out.append('{');
      boolean first = true;

      for (Map.Entry<?, ?> field : object.entrySet()) {
        if (!first) {
          out.append(',');
        }

        first = false;
        quote(out, String.valueOf(field.getKey()));
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
      throw new IllegalArgumentException("Stringify: not a value JSON.stringify would write");
    }
  }

  // A text in quotes, escaped as JSON.stringify escapes it: " and \, and the control characters the tests use, by their short escapes
  private static void quote(StringBuilder out, String text) {
    out.append('"');

    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);

      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) {
            throw new IllegalArgumentException("Stringify: a control character the tests don't use");
          }

          out.append(c);
        }
      }
    }

    out.append('"');
  }
}
