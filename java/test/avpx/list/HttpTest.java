package avpx.list;

import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.util.List;

// The tests of Http.java: a request's head is read strictly, and anything that could be read two ways is refused with its status.
// Written 2026-11-08 by Melanikus for AVPx Dedicated Server. New for the Java version: Node's own HTTP server read the heads there.
public final class HttpTest {
  private HttpTest() {
  }

  private static Http.Head read(String head) throws Exception {
    return Http.read(new ByteArrayInputStream(latin1(head)), ListServer.MOST_HEAD_BYTES);
  }

  // The status a head is refused with, or 0 if it's read
  private static int refusal(String head) throws Exception {
    try {
      read(head);
      return 0;
    } catch (Http.Refused r) {
      return r.status();
    }
  }

  public static void register() {
    test("a head as the game sends it is read: its method, path, query and headers", () -> {
      Http.Head h = read("POST /v1/games?version=7 HTTP/1.1\r\nHost: list.example.net\r\nContent-Type: application/json\r\n"
          + "Content-Length: 12\r\nX-Two: one\r\nx-two:  two \r\n\r\n");
      same(h.method(), "POST", "the method");
      same(h.path(), "/v1/games", "the path");
      same(h.query(), "version=7", "the query");
      same(h.values("content-length"), List.of("12"), "a header, by its name in small letters");
      same(h.values("x-two"), List.of("one", "two"), "a header given twice keeps both values, in order, without their spaces");
      same(h.values("transfer-encoding"), List.of(), "a header not given");
      same(read("GET /v1/relays HTTP/1.0\r\n\r\n").path(), "/v1/relays", "HTTP/1.0 too, with no headers");
    });

    test("the query is everything after the first ?", () -> {
      same(read("GET /v1/games?version=7?x HTTP/1.1\r\n\r\n").query(), "version=7?x", "a second ? and all");
      same(read("GET /v1/games HTTP/1.1\r\n\r\n").query(), "", "none");
    });

    test("a head that could be read two ways is refused", () -> {
      same(refusal("GET /v1/games HTTP/1.1\r\nX: a\r\n b\r\n\r\n"), 400, "a header folded onto two lines");
      same(refusal("GET /v1/games HTTP/1.1\r\nX: a\nY: b\r\n\r\n"), 400, "a line ending with LF alone");
      same(refusal("GET /v1/games HTTP/1.1\r\nX: a\rY: b\r\n\r\n"), 400, "a CR alone inside a line");
      same(refusal("GET /v1/games HTTP/1.1\r\nX : a\r\n\r\n"), 400, "a space before a header's colon");
      same(refusal("GET /v1/games HTTP/1.1\r\n: a\r\n\r\n"), 400, "a header with no name");
      same(refusal("GET /v1/games HTTP/1.1\r\nX\r\n\r\n"), 400, "a header with no colon");
      same(refusal("GET /v1/games HTTP/1.1\r\nX: caf" + (char) 0xe9 + "\r\n\r\n"), 400, "a byte past ASCII");
      same(refusal("GET /v1/games HTTP/1.1\r\nX: a" + (char) 0 + "b\r\n\r\n"), 400, "a 0 byte");
      same(refusal("get /v1/games HTTP/1.1\r\n\r\n"), 400, "a method in small letters");
      same(refusal("GET  /v1/games HTTP/1.1\r\n\r\n"), 400, "two spaces");
      same(refusal("GET v1/games HTTP/1.1\r\n\r\n"), 400, "a path that doesn't start with /");
      same(refusal("GET http://x/v1/games HTTP/1.1\r\n\r\n"), 400, "a whole address for a path");
      same(refusal("GET /v1/games HTTP/2\r\n\r\n"), 400, "another version of HTTP");
      same(refusal("GET /v1/games\r\n\r\n"), 400, "no version");
    });

    test("a head over 8 KB is 431, and one that never ends is no request", () -> {
      same(refusal("GET /v1/games HTTP/1.1\r\nX: " + "a".repeat(ListServer.MOST_HEAD_BYTES) + "\r\n\r\n"), 431, "over 8 KB");
      same(refusal("GET /v1/games HTTP/1.1\r\nX: " + "a".repeat(ListServer.MOST_HEAD_BYTES - 64) + "\r\n\r\n"), 0, "just under 8 KB");
      same(refusal("GET /v1/games HTTP/1.1\n\n" + "a".repeat(ListServer.MOST_HEAD_BYTES)), 431,
          "LF alone never ends a head, so it runs over 8 KB");

      boolean ended = false;

      try {
        read("GET /v1/games HTTP/1.1\r\nX: a\r\n");
      } catch (EOFException e) {
        ended = true;
      }

      ok(ended, "a connection that ends before the head does has no one to answer");
    });
  }
}
