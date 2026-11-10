package avpx.testing;

import avpx.list.Json;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

// The published known answers in test-vectors/crypto-kat (from NIST and Wycheproof; its README.md and each folder's PROVENANCE.md say
// where every case came from), read for the tests. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// They're read with the server's own strict JSON reader, so nothing here takes more than the server would. Each case is run through
// the server's own code (avpx.crypto), and a case that gives the wrong answer, OR THROWS, fails its test by its id: input from outside
// must be refused by an answer, never by an exception (AVP Tao 3), so a published case that makes our code throw is a bug.
public final class Kat {
  private Kat() {
  }

  // The tests run in java/ (build.sh), so the vectors are one folder up
  private static final Path FOLDER = Path.of("..", "test-vectors", "crypto-kat");

  // The top object (1), its cases list (2), and each case (3): nothing deeper
  private static final int DEPTH = 3;

  // How many wrong cases a failure names, so its line stays readable (the count says how many in all)
  private static final int NAMED = 8;

  // One case: its fields, as the file has them
  public static final class Case {
    private final Map<String, Object> fields;

    Case(Map<String, Object> fields) {
      this.fields = fields;
    }

    public String id() {
      return text("id");
    }

    public String result() {
      return text("result");
    }

    public boolean valid() {
      return "valid".equals(result());
    }

    public boolean has(String name) {
      return fields.containsKey(name);
    }

    public String text(String name) {
      Object v = fields.get(name);

      if (!(v instanceof String s)) {
        throw new IllegalArgumentException("case " + fields.get("id") + " has no text field " + name);
      }

      return s;
    }

    // A field of hex digits, as bytes ("" is no bytes)
    public byte[] bytes(String name) {
      return HexFormat.of().parseHex(text(name));
    }

    public long number(String name) {
      Object v = fields.get(name);

      if (!(v instanceof Long n)) {
        throw new IllegalArgumentException("case " + fields.get("id") + " has no number field " + name);
      }

      return n;
    }
  }

  // Every case in a file (its path below test-vectors/crypto-kat), after checking the file says how many it holds, and holds that many
  public static List<Case> read(String file) throws IOException, Json.Bad {
    Map<String, Object> top = Json.readObject(Files.readAllBytes(FOLDER.resolve(file)), DEPTH);
    List<Case> cases = new ArrayList<>();

    for (Object item : Json.list(top.get("cases"))) {
      cases.add(new Case(Json.object(item)));
    }

    Object count = top.get("count");
    Tests.ok(count instanceof Long n && n == cases.size(), file + " says it holds " + count + " cases, and holds " + cases.size());
    Tests.ok(!cases.isEmpty(), file + " holds no cases, so nothing would be checked");
    return cases;
  }

  // What a case's check says: null when the code gave the case's own answer, or why not
  public interface Check {
    String wrong(Case c) throws Exception;
  }

  // Runs the check on every case, and fails naming the cases that came out wrong or threw. Returns how many were checked.
  public static int each(String file, List<Case> cases, Check check) {
    List<String> wrong = new ArrayList<>();

    for (Case c : cases) {
      String why;

      try {
        why = check.wrong(c);
      } catch (Exception e) {
        why = "THREW " + e;
      }

      if (why != null) {
        wrong.add(c.id() + " (" + c.result() + "): " + why);
      }
    }

    Tests.ok(wrong.isEmpty(), file + ": " + wrong.size() + " of " + cases.size() + " cases wrong: "
        + String.join("; ", wrong.subList(0, Math.min(NAMED, wrong.size()))));
    return cases.size();
  }

  // The cases where a field has this value, and the rest
  public static List<Case> where(List<Case> cases, String name, String value, boolean equal) {
    List<Case> out = new ArrayList<>();

    for (Case c : cases) {
      if (c.text(name).equals(value) == equal) {
        out.add(c);
      }
    }

    return out;
  }
}
