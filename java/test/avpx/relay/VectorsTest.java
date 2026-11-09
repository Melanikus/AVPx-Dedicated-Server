package avpx.relay;

import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.text;

import avpx.list.Json;
import avpx.testing.SeededRandom;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

// The same bytes as every other implementation, byte for byte. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// test-vectors/relay-v1.json, at the top of the repository, holds the relay's messages as exact bytes, with their fields; byte strings
// that are no message, each with the reason; and passes, with what they were made from. The Node version made it and checks it, and the
// game reads it too, so all three hold to the one file and can't drift apart. Here it's read with the server's own strict JSON reader,
// and every vector is checked both ways: the bytes read back as the fields, and the fields write the bytes.
//
// The last test holds the tests' own seeded random, and the codes and address hashes made from it, to what the Node version's code made
// from the same seeds (at f37b495), so a ported test that relies on them means what its Node original meant.
public final class VectorsTest {
  private VectorsTest() {
  }

  // The tests run in java/, so the file is one folder up
  private static final Path FILE = Path.of("..", "test-vectors", "relay-v1.json");

  // Root object, the lists in it, the vectors in those, and a message's fields
  private static final int FILE_DEPTH = 4;

  private static Map<String, Object> vectors() throws Exception {
    return Json.readObject(Files.readAllBytes(FILE), FILE_DEPTH);
  }

  private static List<Map<String, Object>> all(Map<String, Object> v, String name) {
    List<Map<String, Object>> out = new ArrayList<>();

    for (Object item : Json.list(v.get(name))) {
      out.add(Json.object(item));
    }

    return out;
  }

  private static byte[] hexOrNull(Object value) {
    String text = (String) value;
    return text.isEmpty() ? null : HexFormat.of().parseHex(text);
  }

  private static int whole(Object value) {
    return ((Long) value).intValue();
  }

  public static void register() {
    test("every message in test-vectors/relay-v1.json reads back as its fields, and its fields write it", () -> {
      Set<Integer> types = new HashSet<>();

      for (Map<String, Object> m : all(vectors(), "messages")) {
        String name = (String) m.get("name");
        byte[] bytes = HexFormat.of().parseHex((String) m.get("hex"));
        same(bytes.length, 64, name);
        Message d = Protocol.decode(bytes);
        ok(d != null, name + " is a message");

        Map<String, Object> got = new LinkedHashMap<>();
        got.put("type", d.type());
        got.put("secret", d.secret() == null ? "" : hex(d.secret()));
        got.put("code", d.code() == null ? "" : text(d.code()));
        got.put("port", d.port());
        got.put("number", d.number());
        got.put("pass", d.pass() == null ? "" : hex(d.pass()));
        got.put("passTime", d.passTime());
        Map<String, Object> fields = Json.object(m.get("fields"));
        same(got, fields, name + ": its fields");

        String code = (String) fields.get("code");
        Message written = Message.of(whole(fields.get("type"))).secret(hexOrNull(fields.get("secret")))
            .code(code.isEmpty() ? null : latin1(code)).port(whole(fields.get("port"))).number(whole(fields.get("number")))
            .pass(hexOrNull(fields.get("pass")), (Long) fields.get("passTime"));
        same(hex(Protocol.encode(written)), m.get("hex"), name + ": written from its fields");
        types.add(d.type());
      }

      same(types.size(), Protocol.types().size(), "every type has a message");
    });

    test("every refused vector is not a message, and every reason is one of the eight words", () -> {
      Set<String> whys = Set.of("size", "magic", "version", "type", "zero", "unused", "code", "passtime");
      int unused = 0;

      for (Map<String, Object> r : all(vectors(), "refused")) {
        ok(whys.contains((String) r.get("why")), r.get("name") + ": its reason");
        same(Protocol.decode(HexFormat.of().parseHex((String) r.get("hex"))), null, (String) r.get("name"));

        if ("unused".equals(r.get("why"))) {
          unused++;
        }
      }

      ok(unused > 40, "every unused field of every type");
    });

    test("every pass in test-vectors/relay-v1.json is the one a relay makes", () -> {
      List<Map<String, Object>> passes = all(vectors(), "passes");
      ok(!passes.isEmpty(), "there are passes");

      for (Map<String, Object> p : passes) {
        byte[] made = Pass.make(HexFormat.of().parseHex((String) p.get("key")), (String) p.get("region"), latin1((String) p.get("code")),
            (Long) p.get("passTime"));
        same(hex(made), p.get("pass"), "the pass for " + p.get("region") + " " + p.get("code"));
      }
    });

    test("the tests' seeded random, the codes it makes, and an address's hash are the Node version's", () -> {
      same(hex(SeededRandom.of(3).next(8)), "3c8cdfc762dda363", "seed 3's first 8 bytes");

      SeededRandom random = SeededRandom.of(11);
      List<String> codes = new ArrayList<>();

      for (int i = 0; i < 4; i++) {
        codes.add(text(RelayCore.makeCode(random)));
      }

      same(codes, List.of("9P57L6XR", "V2CVG8KQ", "T74PQQN6", "NKL9PCV8"), "seed 11's first 4 codes");
      same(new AddressHasher(SeededRandom.of(7)).keyOf("203.0.113.7", 0), "a90f9e29b26d810d49ab8c6a07eca276", "an address's hash");
    });
  }
}
