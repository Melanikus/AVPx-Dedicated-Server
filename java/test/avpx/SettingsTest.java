package avpx;

import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import avpx.list.Json;
import avpx.list.Listings;
import avpx.testing.Stringify;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

// The tests of Settings.java and Log.java. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, ported test for test from
// test/settings.test.js.
public final class SettingsTest {
  private SettingsTest() {
  }

  private static final String KEY = "5a".repeat(32);
  private static final String PARIS_KEY = "7b".repeat(32);

  // Stands for a field left out ({ ...x, field: undefined } in the Node tests)
  private static final Object LEAVE_OUT = new Object();

  // An object from name, value pairs; a pair whose value is LEAVE_OUT takes that name out
  private static Map<String, Object> with(Map<String, Object> from, Object... changes) {
    Map<String, Object> out = new LinkedHashMap<>(from);

    for (int i = 0; i < changes.length; i += 2) {
      if (changes[i + 1] == LEAVE_OUT) {
        out.remove((String) changes[i]);
      } else {
        out.put((String) changes[i], changes[i + 1]);
      }
    }

    return out;
  }

  private static Map<String, Object> object(Object... fields) {
    return with(new LinkedHashMap<>(), fields);
  }

  private static Map<String, Object> relayOnly() {
    return object("region", "virginia", "passKey", KEY);
  }

  private static Map<String, Object> own() {
    return object("region", "virginia", "host", "virginia.relay.example.net", "port", 27500);
  }

  private static Map<String, Object> paris() {
    return object("region", "paris", "host", "paris.relay.example.net", "port", 27500, "passKey", PARIS_KEY);
  }

  private static Map<String, Object> listOf(Object relays) {
    return object("certFile", "C:\\AVPx\\cert.pem", "keyFile", "C:\\AVPx\\key.pem", "relays", relays);
  }

  private static Map<String, Object> withList() {
    return with(relayOnly(), "list", listOf(List.of(own(), paris())));
  }

  private static Map<String, Object> listWith(Object... changes) {
    return with(withList(), "list", with(listOf(List.of(own(), paris())), changes));
  }

  private static Map<String, Object> relaysWith(List<Object> relays) {
    return listWith("relays", relays);
  }

  private static Settings parse(Map<String, Object> o) throws Settings.Refused {
    return Settings.parse(Stringify.bytes(o));
  }

  private static void refused(Map<String, Object> o, String why) {
    throwsWith(() -> parse(o), "settings: ", why);
  }

  public static void register() {
    test("a relay-only machine needs only its region and pass key; the rest are defaults", () -> {
      Settings s = parse(relayOnly());
      same(s.region(), "virginia", "its region");
      same(s.passKey(), HexFormat.of().parseHex(KEY), "its pass key");
      same(s.controlPort(), 27500, "the control port");
      same(s.relayPorts().length, 64, "64 relay ports");
      same(s.relayPorts()[0], 27501, "from 27501");
      same(s.relayAddress(), "0.0.0.0", "every address of the machine");
      same(s.logFile(), "", "the screen only");
      same(s.list(), null, "and no list");
    });

    test("the list machine names every relay, and its own relay's key is its own pass key, written once", () -> {
      Settings s = parse(withList());
      same(s.list().port(), 443, "port 443");
      same(s.list().address(), "0.0.0.0", "every address");
      same(s.list().relays().size(), 2, "two relays");
      same(s.list().relays().get(0).passKey(), s.passKey(), "its own relay uses the passKey above");
      same(s.list().relays().get(1).passKey(), HexFormat.of().parseHex(PARIS_KEY), "the other relay's own key");
      List<Object> shown = new ArrayList<>();

      for (Listings.Relay r : s.list().relays()) {
        shown.add(List.of(r.region(), r.host(), r.port()));
      }

      same(shown, List.of(List.of("virginia", "virginia.relay.example.net", 27500), List.of("paris", "paris.relay.example.net", 27500)),
          "each relay's region, name and port");
    });

    test("every setting is held to its limits", () -> {
      refused(object("passKey", KEY), "no region");
      refused(with(relayOnly(), "region", "Virginia"), "a region with a capital");
      refused(object("region", "virginia"), "no pass key");
      refused(with(relayOnly(), "passKey", "0".repeat(64)), "a pass key of all 0, as one left unset would be");
      refused(with(relayOnly(), "passKey", KEY.substring(2)), "a pass key of 31 bytes");
      refused(with(relayOnly(), "passKey", KEY.toUpperCase()), "a pass key in capitals");
      refused(with(relayOnly(), "passKey", "make it with: openssl rand -hex 32"), "the example file's words, left in");
      refused(with(relayOnly(), "controlPort", 80), "a control port below 1024");
      refused(with(relayOnly(), "controlPort", 70000), "a port over 65535");
      refused(with(relayOnly(), "controlPort", "27500"), "a port as text");
      refused(with(relayOnly(), "relayPorts", "27501"), "one number");
      refused(with(relayOnly(), "relayPorts", "27564-27501"), "going down");
      refused(with(relayOnly(), "relayPorts", "20000-30000"), "over 4000 ports");
      refused(with(relayOnly(), "relayPorts", "27400-27600"), "the control port among them");
      refused(with(relayOnly(), "relayAddress", "localhost"), "a name, not an address");
      refused(with(relayOnly(), "relayAddress", "::1"), "IPv6");
      refused(with(relayOnly(), "logFile", "a\nb"), "a line break in a path");
      refused(with(relayOnly(), "relayport", 1), "a name it doesn't know");
      refused(with(relayOnly(), "list", "yes"), "a list that isn't an object");

      refused(listWith("certFile", ""), "no certificate");
      refused(listWith("keyFile", LEAVE_OUT), "no key");
      refused(listWith("certFile", "x".repeat(261)), "a path over 260");
      refused(listWith("address", "300.1.1.1"), "not an address");
      refused(listWith("port", 0), "port 0");
      refused(listWith("listPort", 443), "a name the list doesn't know");
      refused(listWith("relays", LEAVE_OUT), "no relays");
      refused(relaysWith(List.of()), "no relays at all");
      List<Object> many = new ArrayList<>();

      for (int i = 0; i < 17; i++) {
        Map<String, Object> r = object("region", i == 0 ? "virginia" : "r" + i, "host", "r" + i + ".example.net", "port", 27500);
        many.add(i == 0 ? r : with(r, "passKey", PARIS_KEY));
      }

      refused(relaysWith(many), "17 relays");
      doesNotThrow(() -> parse(relaysWith(many.subList(0, 16))), "16 is allowed");

      refused(relaysWith(List.of(with(own(), "passKey", KEY), paris())), "its own relay with a passKey of its own: the secret would be "
          + "written twice");
      refused(relaysWith(List.of(own(), with(paris(), "passKey", LEAVE_OUT))), "another relay with no passKey");
      refused(relaysWith(List.of(paris())), "a list that doesn't name its own region");
      refused(relaysWith(List.of(own(), paris(), with(paris(), "host", "other.example.net"))), "one region twice");
      refused(relaysWith(List.of(own(), with(paris(), "host", "203.0.113.5"))), "an address for a host, not a name");
      refused(relaysWith(List.of(own(), with(paris(), "host", "0x7f.0.0.1"))), "an address some resolvers read from a name with a letter");
      refused(relaysWith(List.of(own(), with(paris(), "host", "fe80::1"))), "an IPv6 address");
      refused(relaysWith(List.of(own(), with(paris(), "host", "paris.example.123"))), "a last part that starts with a digit");
      doesNotThrow(() -> parse(relaysWith(List.of(own(), with(paris(), "host", "1e100.example.net")))),
          "a name may start with a digit; only its last part may not");
      refused(relaysWith(List.of(own(), with(paris(), "host", "x".repeat(64)))), "a host of 64");
      refused(relaysWith(List.of(own(), with(paris(), "host", "paris..example.net"))), "an empty part in a name");
      refused(relaysWith(List.of(own(), with(paris(), "host", "paris example.net"))), "a space in a name");
      refused(relaysWith(List.of(own(), with(paris(), "port", 0))), "a relay on port 0");
      refused(relaysWith(List.of(own(), with(paris(), "extra", 1))), "a name a relay doesn't know");
      refused(relaysWith(List.of(own(), "paris")), "a relay that isn't an object");

      throwsWith(() -> Settings.parse(latin1("{")), "must be JSON", "not JSON");
      throwsWith(() -> Settings.parse(latin1("[]")), "JSON object", "not an object");
      throwsWith(() -> Settings.parse(latin1(" ".repeat(16 * 1024 + 1))), "at most 16 KB", "too big");
    });

    test("deploy/settings.example.json is refused as it is, until a real pass key is put in", () -> {
      byte[] example = Files.readAllBytes(Path.of("..", "deploy", "settings.example.json"));
      throwsWith(() -> Settings.parse(example), "passKey must be 64 hex digits", "the example's words for the key");

      Map<String, Object> filled = Json.readObject(example, 4);
      filled.put("passKey", KEY);
      throwsWith(() -> parse(filled), "host must be a DNS name", "nor until the domain is put in");

      Map<String, Object> list = Json.object(filled.get("list"));
      List<Object> relays = Json.list(list.get("relays"));
      relays.set(0, with(Json.object(relays.get(0)), "host", "virginia.relay.example.net"));
      list.put("relays", relays);
      filled.put("list", list);
      same(parse(filled).region(), "virginia", "with one, it is the Virginia machine: its relay and the list");
      same(parse(filled).list().relays().size(), 1, "with its one relay");
    });

    test("the log writes a line with its time, keeps the file to its size, and turns a line break into a space", () -> {
      Path dir = Files.createTempDirectory("avpx-log-");
      Path file = dir.resolve("server.log");
      Log log = new Log(file, () -> Instant.EPOCH, new PrintStream(OutputStream.nullOutputStream(), true, StandardCharsets.UTF_8));

      try {
        log.line("first\nsecond");
        same(Files.readString(file, StandardCharsets.UTF_8), "1970-01-01T00:00:00.000Z first second\n", "one line, with its time");
        String longLine = "x".repeat(1024 * 1024);

        for (int i = 0; i < 12; i++) {
          log.line(longLine);
        }

        ok(Files.size(file) <= Log.MOST_FILE_BYTES, "the file stays under its size");
        ok(Files.exists(dir.resolve("server.log.1")), "and the old lines moved to .1");
      } finally {
        log.close();

        try (Stream<Path> files = Files.list(dir)) {
          for (Path f : files.toList()) {
            Files.delete(f);
          }
        }

        Files.delete(dir);
      }
    });
  }
}
