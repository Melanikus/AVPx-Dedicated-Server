package avpx;

import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import avpx.list.Listings;
import avpx.testing.ScriptedRandom;
import avpx.testing.Stringify;
import avpx.v2.HandshakeA;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
    if (changes.length % 2 != 0) {
      throw new IllegalArgumentException("changes come in name, value pairs");
    }

    Map<String, Object> out = new LinkedHashMap<>(from);

    for (int i = 0; i + 1 < changes.length; i += 2) {
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

  // A version 2 relay's staticKeys, as MakeRelayKeys prints them, from fixed seeds
  private static Map<String, Object> v2Keys() {
    KeyPair p384 = P384.generate(ScriptedRandom.seeded(60));
    String number = String.format("%096x", ((ECPrivateKey) p384.getPrivate()).getS());
    String point = HexFormat.of().formatHex(P384.encode((ECPublicKey) p384.getPublic()));
    return object("p384Private", number, "p384Public", point, "mlkemSeed", "6e".repeat(64));
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
      refused(with(relayOnly(), "relayPorts", "70000-70001"), "ports past 65535, read without anything that could throw");
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
      throwsWith(() -> Settings.parse(latin1(" ".repeat(64 * 1024 + 1))), "at most 64 KB", "too big");
    });

    test("protocol 2: its static keys are needed, each held to what it must be, and the relay's keys are the ones written", () -> {
      KeyPair p384 = P384.generate(ScriptedRandom.seeded(40));
      byte[] number = HexFormat.of().parseHex(String.format("%096x", ((ECPrivateKey) p384.getPrivate()).getS()));
      String point = HexFormat.of().formatHex(P384.encode((ECPublicKey) p384.getPublic()));
      String seed = "3c".repeat(64);
      Map<String, Object> keys = object("p384Private", HexFormat.of().formatHex(number), "p384Public", point, "mlkemSeed", seed);
      Settings s = parse(with(relayOnly(), "protocol", 2, "staticKeys", keys));
      same(s.protocol(), 2, "protocol 2");
      same(HexFormat.of().formatHex(s.staticKeys().p384Public()), point, "its P-384 public key, as written");
      same(s.staticKeys().kemPublic(), MlKem.encode(MlKem.fromSeed(HexFormat.of().parseHex(seed)).getPublic()),
          "its ML-KEM key, made from the seed");
      HandshakeA.Initiator game = HandshakeA.writeA1("virginia", s.staticKeys().p384Public(), s.staticKeys().kemPublic(),
          ScriptedRandom.seeded(41));
      ok(HandshakeA.readA1(s.staticKeys(), "virginia", game.a1(), ScriptedRandom.seeded(42)) != null,
          "and they work: a game's A1 to those public keys is read with them");
      same(parse(relayOnly()).protocol(), 1, "protocol 1 when none is named");
      same(parse(relayOnly()).staticKeys(), null, "with no static keys");

      Map<String, Object> two = with(relayOnly(), "protocol", 2);
      String other = HexFormat.of().formatHex(P384.encode((ECPublicKey) P384.generate(ScriptedRandom.seeded(43)).getPublic()));
      refused(with(relayOnly(), "protocol", 3), "protocol 3");
      refused(with(relayOnly(), "protocol", "2"), "protocol as text");
      throwsWith(() -> parse(two), "staticKeys are needed for protocol 2", "protocol 2 with no static keys, said plainly");
      throwsWith(() -> parse(with(relayOnly(), "staticKeys", keys)), "for protocol 2 only", "static keys with protocol 1");
      refused(with(two, "staticKeys", "keys"), "static keys that aren't an object");
      refused(with(two, "staticKeys", with(keys, "p384Public", other)), "a P-384 number with another key's point");
      refused(with(two, "staticKeys", with(keys, "p384Private", "00".repeat(48))), "a P-384 number of 0");
      refused(with(two, "staticKeys", with(keys, "p384Private", "ff".repeat(48))), "a P-384 number past the curve's order");
      refused(with(two, "staticKeys", with(keys, "p384Private", HexFormat.of().formatHex(number).toUpperCase())), "capitals");
      // All 194 digits, the last one changed (until 2026-11-09 this kept only 193, so it was refused for its length, never its point)
      throwsWith(() -> parse(with(two, "staticKeys", with(keys, "p384Public", point.substring(0, 193) + (point.endsWith("0") ? "1" : "0")))),
          "two halves of one P-384 key", "a point off the curve (its last digit changed)");
      refused(with(two, "staticKeys", with(keys, "mlkemSeed", "00".repeat(64))), "an ML-KEM seed of all 0, as one left unset would be");
      refused(with(two, "staticKeys", with(keys, "mlkemSeed", seed.substring(2))), "a seed of 63 bytes");
      refused(with(two, "staticKeys", with(keys, "mlkemPrivate", "ab")), "a name staticKeys doesn't have");
      refused(with(two, "staticKeys", with(keys, "mlkemSeed", LEAVE_OUT)), "no seed");
    });

    test("a version 2 relay's public keys in list.relays: both or neither, each a real key, and the list's own from staticKeys", () -> {
      HexFormat hex = HexFormat.of();
      String parisP384 = hex.formatHex(P384.encode((ECPublicKey) P384.generate(ScriptedRandom.seeded(50)).getPublic()));
      String parisKem = hex.formatHex(MlKem.encode(MlKem.fromSeed(hex.parseHex("4d".repeat(64))).getPublic()));
      Map<String, Object> paris2 = with(paris(), "p384", parisP384, "mlkem", parisKem);
      Settings s = parse(relaysWith(List.of(own(), paris2)));
      same(s.list().relays().get(1).p384(), hex.parseHex(parisP384), "paris's P-384 key, as written");
      same(s.list().relays().get(1).mlkem(), hex.parseHex(parisKem), "paris's ML-KEM key, as written");
      same(s.list().relays().get(0).p384(), null, "the list's own relay, on protocol 1, has no P-384 key");
      same(s.list().relays().get(0).mlkem(), null, "nor an ML-KEM one");
      same(parse(withList()).list().relays().get(1).p384(), null, "a relay given neither is a version 1 relay");

      Map<String, Object> keys = v2Keys();
      Settings own2 = parse(with(relaysWith(List.of(own(), paris2)), "protocol", 2, "staticKeys", keys));
      same(own2.list().relays().get(0).p384(), own2.staticKeys().p384Public(), "on protocol 2, the list's own relay's P-384 key is "
          + "staticKeys' public half");
      same(own2.list().relays().get(0).mlkem(), own2.staticKeys().kemPublic(), "and its ML-KEM key too");

      refused(relaysWith(List.of(with(own(), "p384", parisP384, "mlkem", parisKem), paris2)), "its own relay with keys written again");
      refused(relaysWith(List.of(with(own(), "mlkem", parisKem), paris2)), "its own relay with one key written again");
      // These four say why in their own words, so a person putting in one key and not the other, or a wrong key, is told which
      throwsWith(() -> parse(relaysWith(List.of(own(), with(paris2, "mlkem", LEAVE_OUT)))), "both p384 and mlkem",
          "a P-384 key with no ML-KEM key");
      throwsWith(() -> parse(relaysWith(List.of(own(), with(paris2, "p384", LEAVE_OUT)))), "both p384 and mlkem",
          "an ML-KEM key with no P-384 key");
      throwsWith(() -> parse(relaysWith(List.of(own(), with(paris2, "p384", parisP384.substring(0, 193)
          + (parisP384.endsWith("0") ? "1" : "0"))))), "a point on the curve", "a P-384 point off the curve (its last digit changed)");
      throwsWith(() -> parse(relaysWith(List.of(own(), with(paris2, "p384", "02" + parisP384.substring(2))))), "a point on the curve",
          "a P-384 key that doesn't start 04");
      refused(relaysWith(List.of(own(), with(paris2, "p384", parisP384.toUpperCase()))), "a P-384 key in capitals");
      refused(relaysWith(List.of(own(), with(paris2, "p384", parisP384.substring(2)))), "a P-384 key of 96 bytes");
      refused(relaysWith(List.of(own(), with(paris2, "p384", 4))), "a P-384 key that isn't text");
      // The first number of the key's first polynomial made 4,095: past q = 3,329, so FIPS 203's check refuses it
      throwsWith(() -> parse(relaysWith(List.of(own(), with(paris2, "mlkem", "ff0f" + parisKem.substring(4))))), "FIPS 203's check",
          "an ML-KEM key with a number past q");
      refused(relaysWith(List.of(own(), with(paris2, "mlkem", parisKem.substring(2)))), "an ML-KEM key of 1,567 bytes");
      refused(relaysWith(List.of(own(), with(paris2, "mlkem", "00".repeat(1568)))), "an ML-KEM key of all 0, as one left unset would be");
    });

    test("the biggest settings file there can be fits under the size limit, with room for a person's spaces and line ends", () -> {
      // Every field at its longest: 16 relays, 15 of them version 2 relays with both keys, each region 16 characters and each host 63
      Map<String, Object> keys = v2Keys();
      String longPath = "C:\\" + "p".repeat(257);
      List<Object> relays = new ArrayList<>();
      relays.add(object("region", "virginia-longest", "host", "h".repeat(63), "port", 65535));
      String p384 = (String) keys.get("p384Public");
      String kem = HexFormat.of().formatHex(MlKem.encode(MlKem.fromSeed(HexFormat.of().parseHex((String) keys.get("mlkemSeed")))
          .getPublic()));

      for (int i = 1; i < 16; i++) {
        relays.add(object("region", String.format("region-%09d", i), "host", "h".repeat(60) + String.format("%03d", i), "port", 65535,
            "passKey", PARIS_KEY, "p384", p384, "mlkem", kem));
      }

      Map<String, Object> most = object("region", "virginia-longest", "passKey", KEY, "relayAddress", "255.255.255.255", "controlPort",
          65535, "relayPorts", "61000-64999", "logFile", longPath, "protocol", 2, "staticKeys", keys, "list", object("address",
              "255.255.255.255", "port", 65535, "certFile", longPath, "keyFile", longPath, "relays", relays));
      String compact = Stringify.text(most);
      same(compact.length(), 54840, "the worst case Settings.java gives, written with no spaces");
      doesNotThrow(() -> Settings.parse(compact.getBytes(StandardCharsets.US_ASCII)), "it's read");

      // The same with a line end and 8 spaces after every { and every comma: more than a person writing it by hand would put in
      String spaced = compact.replace("{", "{\n        ").replace(",", ",\n        ");
      ok(spaced.length() < 64 * 1024, "and with spaces and line ends too");
      doesNotThrow(() -> Settings.parse(spaced.getBytes(StandardCharsets.US_ASCII)), "which is read too");
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

    test("deploy/settings.relay-only.example.json is refused as it is, until a real region and pass key are put in; then it has no list", () -> {
      byte[] example = Files.readAllBytes(Path.of("..", "deploy", "settings.relay-only.example.json"));
      throwsWith(() -> Settings.parse(example), "settings: ", "the example's made-up region and key");

      Map<String, Object> filled = Json.readObject(example, 2);
      filled.put("region", "saopaulo");
      throwsWith(() -> parse(filled), "passKey must be 64 hex digits", "nor with a region, and the example's words for the key");

      filled.put("passKey", KEY);
      Settings s = parse(filled);
      same(s.region(), "saopaulo", "with both, it is the relay for its region");
      ok(s.list() == null, "and it has no list: a relay-only machine, which Smoke --installed checks as one");
    });

    test("the log writes a line with its time, keeps the file to its size, and turns a line break into a space", () -> {
      Path dir = Files.createTempDirectory("avpx-log-");
      Path file = dir.resolve("server.log");
      try (PrintStream nowhere = new PrintStream(OutputStream.nullOutputStream(), true, StandardCharsets.UTF_8)) {
        Log log = new Log(file, () -> Instant.EPOCH, nowhere);
        logTest(dir, file, log);
      }
    });
  }

  // The log test's body, with the log written to nowhere on the screen
  private static void logTest(Path dir, Path file, Log log) throws Exception {
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
  }
}
