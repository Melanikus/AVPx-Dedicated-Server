package avpx.list;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.access.AccessStore;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Routes.Answer;
import avpx.testing.ScriptedRandom;
import avpx.v2.Identity;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

// The tests of AccessRequests.java, POST /v1/access-requests: the request read to its exact shape, the fingerprint worked out from the
// keys, and each refusal in the game's own words. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class AccessRequestsTest {
  private AccessRequestsTest() {
  }

  private static final long NOW = 1794268800000L;

  private static Identity identity(int seed) {
    return Identity.of(P384.generate(ScriptedRandom.seeded(seed)), MlKem.generate(ScriptedRandom.seeded(seed + 1)));
  }

  private static String key(Identity id) {
    return Base64.getEncoder().encodeToString(id.statics());
  }

  private static String body(String name, String key) {
    return "{\"v\":1,\"name\":\"" + name + "\",\"key\":\"" + key + "\"}";
  }

  private static Answer post(AccessStore store, String body) {
    return AccessRequests.handle(store, "POST", "", body.getBytes(StandardCharsets.ISO_8859_1), NOW);
  }

  private static Map<String, Object> said(String field, String value) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("v", 1L);
    m.put(field, value);
    return m;
  }

  private static void refused(AccessStore store, String body, int status, String word, String why) {
    Answer a = post(store, body);
    same(a.status(), status, why + ": its status");
    same(a.body(), said("error", word), why + ": " + word);
  }

  private static Path folder() throws IOException {
    return Files.createTempDirectory("avpx-access-requests-test-");
  }

  private static void remove(Path folder) throws IOException {
    try (Stream<Path> all = Files.walk(folder)) {
      for (Path p : all.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(p);
      }
    }
  }

  public static void register() {
    test("a request is kept as waiting, and its answer is the fingerprint worked out from the keys, and the state", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        Identity id = identity(10);
        String key = key(id);
        same(key.length(), 2220, "the key is 2,220 base64 letters");
        ok(!key.contains("="), "with no =");
        Answer a = post(store, body("Melanikus", key));
        same(a.status(), 200, "200");
        Map<String, Object> want = said("fp", Identity.fingerprintHex(id.p384Public(), id.kemPublic()));
        want.put("state", "waiting");
        same(a.body(), want, "{v, fp, state}: the fingerprint is the keys' own, small letters");
        ok(Json.write(a.body()).length() <= AccessRequests.MOST_ANSWER_BYTES, "at most 512 bytes");
        same(post(store, body("Someone", key)).body(), want, "asking again: the same answer");
        Path decisions = folder.resolve("decisions.1");
        Files.writeString(decisions, want.get("fp") + " approved\n", StandardCharsets.US_ASCII);

        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
          Files.setPosixFilePermissions(decisions, PosixFilePermissions.fromString("rw-------"));
        }

        store.turn(NOW);
        same(post(store, body("Melanikus", key)).body().get("state"), "approved", "once the owner approves: approved");
        ok(store.approved(Identity.idHex(id.p384Public(), id.kemPublic())), "and the relay, asking by the whole id, finds them approved");
      } finally {
        remove(folder);
      }
    });

    test("a key whose fingerprint is another player's (the same first 16 bytes of hash, another id) is \"key\"", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        Identity id = identity(10);
        String fp = Identity.fingerprintHex(id.p384Public(), id.kemPublic());
        // No two real key pairs share a fingerprint within reach, so the record that holds it with another id is put in by hand
        same(store.request(fp, fp + "0".repeat(64), "Someone", NOW), AccessStore.Reply.WAITING, "(another id under this fingerprint)");
        refused(store, body("Melanikus", key(id)), 400, "key", "the real keys of that fingerprint");
      } finally {
        remove(folder);
      }
    });

    test("no store: closed (503); any method but POST: 405", () -> {
      refused(null, body("Melanikus", key(identity(10))), 503, "closed", "a list with no access store");
      same(AccessRequests.handle(null, "GET", "", new byte[0], NOW).status(), 405, "GET");
    });

    test("the request is exactly {v: 1, name, key}, or it's \"shape\"", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        String key = key(identity(10));

        for (String bad : List.of("", "x", "[]", "{}", "{\"v\":1,\"name\":\"A\"}", "{\"v\":1,\"key\":\"" + key + "\"}",
            "{\"v\":2,\"name\":\"A\",\"key\":\"" + key + "\"}", "{\"v\":\"1\",\"name\":\"A\",\"key\":\"" + key + "\"}",
            "{\"v\":1,\"name\":\"A\",\"key\":\"" + key + "\",\"fp\":\"00\"}", "{\"v\":1,\"name\":7,\"key\":\"" + key + "\"}",
            "{\"v\":1,\"name\":\"A\",\"key\":7}", "{\"v\":1,\"name\":\"A\",\"key\":{\"x\":1}}", body("A", key) + " x",
            "{\"v\":1,\"name\":\"A\",\"key\":\"" + key + "\",\"v\":1}")) {
          refused(store, bad, 400, "shape", "body " + (bad.length() > 40 ? bad.substring(0, 40) : bad));
        }

        same(AccessRequests.handle(store, "POST", "x=1", body("A", key).getBytes(StandardCharsets.US_ASCII), NOW).body(),
            said("error", "shape"), "a query");
        refused(store, body("A", key) + " ".repeat(4096), 400, "shape", "a body over 4,096 bytes");
      } finally {
        remove(folder);
      }
    });

    test("a name that breaks the rules is \"name\", and is never fixed", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        String key = key(identity(10));

        for (String bad : List.of("", "x".repeat(16), " A", "A ", "A\\\"B", "A\\\\B")) {
          refused(store, body(bad, key), 400, "name", "the name " + bad);
        }

        // The JSON reader itself refuses a control character, or anything outside ASCII, in a text, even written as an escape: so those
        // are the body's shape
        refused(store, body("A\\u0007B", key), 400, "shape", "the name A, a bell, B");
        refused(store, body("A\\nB", key), 400, "shape", "the name A, a line end, B");
        refused(store, body("A\\u00e9B", key), 400, "shape", "the name A, an e with an accent, B");

        ok(post(store, body("x".repeat(15), key)).status() == 200, "15 letters is fine");
      } finally {
        remove(folder);
      }
    });

    test("a key that isn't 2,220 base64 letters, or isn't a P-384 and an ML-KEM key, is \"key\"", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        Identity id = identity(10);
        String key = key(id);
        byte[] offCurve = id.statics();
        offCurve[96] ^= 1;
        byte[] pastQ = id.statics();
        pastQ[97] = 0x01;
        pastQ[98] = (byte) ((pastQ[98] & 0xf0) | 0x0d);

        for (String bad : List.of(key.substring(1), key + "A", key.substring(0, 2218) + "==", key.substring(0, 2219) + "-",
            key.substring(0, 2219) + "_", key.substring(0, 2219) + " ", Base64.getEncoder().encodeToString(offCurve),
            Base64.getEncoder().encodeToString(pastQ))) {
          refused(store, body("A", bad), 400, "key", "a key of " + bad.length() + " letters");
        }

        same(post(store, body("A", key)).status(), 200, "and the good one, after all of those: 200");
      } finally {
        remove(folder);
      }
    });

    test("a full store is \"busy\" (429), in the call's own shape", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);

        for (int i = 0; i < AccessStore.MOST_WAITING; i++) {
          String fp = String.format("%032x", i + 1L);
          store.request(fp, fp + "0".repeat(64), "Player", NOW);
        }

        refused(store, body("A", key(identity(10))), 429, "busy", "the 1,001st waiting");
        same(AccessRequests.busy().body(), said("error", "busy"), "and the same shape as an address over its limit gets");
      } finally {
        remove(folder);
      }
    });

    test("the answers never hold what the request sent but its fingerprint", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        String evil = "<script>";
        ok(!Json.write(post(store, body(evil, key(identity(10)))).body()).contains(evil), "a name that's taken isn't said back");
        ok(!Json.write(post(store, body(evil + "x".repeat(10), "nope")).body()).contains(evil), "nor one that's refused");
      } finally {
        remove(folder);
      }
    });
  }
}
