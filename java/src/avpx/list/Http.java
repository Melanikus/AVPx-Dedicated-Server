package avpx.list;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

// The head of an HTTP request (its first line and its headers), read strictly. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// Java's own HTTP server can't refuse a connection by its address (PROTOCOL.md section 5 needs 10 at most from one), so the list reads
// requests itself, and reads them strictly, the way the list's game sends them (PROTOCOL.md section 4, "How a request is read"):
// - the head is at most MOST_HEAD_BYTES, every line ends with CR LF, and the head ends with an empty line; more is 431;
// - the first line is METHOD /target HTTP/1.1 (or 1.0), with one space between each, the method in capitals;
// - a header is name: value, the name made of the letters HTTP allows, the value printable ASCII; so a line that starts with a space (an
//   old way of folding one header onto two lines) is refused, and no header can be read two ways;
// - every byte of the head is printable ASCII, a tab in a value, or a line's CR LF. Anything else is 400.
// It never answers itself: it gives back the head, or a Refused with the status the list answers with.
public final class Http {
  private Http() {
  }

  // A request's head, as read: the method, the path (before the first ?), the query (everything after it, a second ? and all), and every
  // header by its name in small letters, each with its values in the order they came
  public record Head(String method, String path, String query, Map<String, List<String>> headers) {
    public List<String> values(String name) {
      return headers.getOrDefault(name, List.of());
    }
  }

  // A request that's refused before the list sees it, with its status
  public static final class Refused extends Exception {
    private static final long serialVersionUID = 1L;
    private final int status;

    Refused(int status, String words) {
      super(words);
      this.status = status;
    }

    public int status() {
      return status;
    }
  }

  private static final Pattern METHOD = Pattern.compile("[A-Z]{1,16}");
  private static final Pattern TARGET = Pattern.compile("/[\\x21-\\x7e]*");
  private static final Pattern NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

  // Reads a head from in, byte by byte, up to its empty line: at most most bytes, or 431. Throws EOFException if the connection ends
  // first, so there's no one to answer.
  public static Head read(InputStream in, int most) throws IOException, Refused {
    ByteArrayOutputStream head = new ByteArrayOutputStream();

    // How much of the CR LF CR LF that ends a head has just been read: 0 to 4
    int seen = 0;

    while (seen < 4) {
      int b = in.read();

      if (b < 0) {
        throw new EOFException("the connection ended before the request's head did");
      }

      head.write(b);

      if (head.size() > most) {
        throw new Refused(431, "the request's headers are over 8 KB");
      }

      if (b == '\r') {
        seen = seen == 2 ? 3 : 1;
      } else if (b == '\n' && (seen == 1 || seen == 3)) {
        seen++;
      } else {
        seen = 0;
      }
    }

    return parse(head.toByteArray());
  }

  // A head from its bytes, ending with its CR LF CR LF
  public static Head parse(byte[] bytes) throws Refused {
    for (byte b : bytes) {
      int c = b & 0xff;

      if ((c < 0x20 || c > 0x7e) && c != '\t' && c != '\r' && c != '\n') {
        throw new Refused(400, "the request's head has a byte that isn't printable ASCII");
      }
    }

    String text = new String(bytes, StandardCharsets.US_ASCII);

    if (!text.endsWith("\r\n\r\n")) {
      throw new Refused(400, "the request's head doesn't end with an empty line");
    }

    // Every line, without the empty one at the end: split only at CR LF, so a CR or LF alone stays in its line, and is refused there
    String[] lines = text.substring(0, text.length() - 4).split("\r\n", -1);

    for (String line : lines) {
      if (line.indexOf('\r') >= 0 || line.indexOf('\n') >= 0) {
        throw new Refused(400, "a line in the request's head doesn't end with CR LF");
      }
    }

    String[] first = lines[0].split(" ", -1);

    if (first.length != 3 || !METHOD.matcher(first[0]).matches() || !TARGET.matcher(first[1]).matches()
        || !(first[2].equals("HTTP/1.1") || first[2].equals("HTTP/1.0"))) {
      throw new Refused(400, "the request's first line must be METHOD /path HTTP/1.1");
    }

    Map<String, List<String>> headers = new LinkedHashMap<>();

    for (int i = 1; i < lines.length; i++) {
      String line = lines[i];

      // A line folded onto the one before starts with a space or a tab, and no header's name can: so the name's own rule refuses it
      int colon = line.indexOf(':');

      if (colon <= 0 || !NAME.matcher(line.substring(0, colon)).matches()) {
        throw new Refused(400, "a header that isn't name: value");
      }

      String name = line.substring(0, colon).toLowerCase(Locale.ROOT);
      String value = line.substring(colon + 1).strip();
      headers.computeIfAbsent(name, n -> new ArrayList<>()).add(value);
    }

    String target = first[1];
    int mark = target.indexOf('?');
    String path = mark < 0 ? target : target.substring(0, mark);
    String query = mark < 0 ? "" : target.substring(mark + 1);
    return new Head(first[0], path, query, headers);
  }
}
