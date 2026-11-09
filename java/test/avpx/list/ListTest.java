package avpx.list;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.matches;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.list.Routes.Answer;
import avpx.relay.Pass;
import avpx.relay.Protocol;
import avpx.testing.SeededRandom;
import avpx.testing.Stringify;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

// The tests of Requests.java, Listings.java and Routes.java: every call of PROTOCOL.md section 4, every pass check of section 3, every
// field's limits, and every refusal, by handing it requests. No socket is opened. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server, ported test for test from test/list.test.js. Each body is the bytes the Node test sent (Stringify.java).
public final class ListTest {
  private ListTest() {
  }

  private static final Map<String, byte[]> KEYS = new LinkedHashMap<>();

  static {
    KEYS.put("virginia", bytes(32, 1));
    KEYS.put("paris", bytes(32, 2));
    KEYS.put("longest-region-1", bytes(32, 3));
  }

  private static final List<Listings.Relay> RELAYS = relays();
  private static final long NOW = 1794268800000L;   // 2026-11-11, in milliseconds
  private static final String QUOTE = "\"";
  private static final String BACKSLASH = "\\";

  private static List<Listings.Relay> relays() {
    List<Listings.Relay> out = new ArrayList<>();

    for (Map.Entry<String, byte[]> key : KEYS.entrySet()) {
      out.add(new Listings.Relay(key.getKey(), key.getKey() + ".relay.example.net", 27500, key.getValue()));
    }

    return out;
  }

  private static long at(long ms) {
    return NOW + ms;
  }

  private static Listings listings(List<Listings.Relay> relays) {
    return new Listings(relays, SeededRandom.of(5), NOW);
  }

  private static Listings listings() {
    return listings(RELAYS);
  }

  // The code of game number n: 8 code letters, different for every n
  private static String codeOf(int n) {
    StringBuilder out = new StringBuilder();
    int left = n;

    for (int i = 0; i < 8; i++) {
      out.insert(0, Protocol.CODE_LETTERS.charAt(left % 32));
      left /= 32;
    }

    return out.toString();
  }

  // What a host's game would POST, with a pass its relay made then. The changes are name, value pairs: "region", "code", "now" and
  // "passKey" change how the pass is made (and region and code what's listed); any other name is a field of the body, put in or changed.
  private static Map<String, Object> game(Object... changes) {
    String region = "virginia";
    String code = "ABCD2345";
    long now = NOW;
    byte[] passKey = null;
    Map<String, Object> others = new LinkedHashMap<>();

    if (changes.length % 2 != 0) {
      throw new IllegalArgumentException("changes come in name, value pairs");
    }

    for (int i = 0; i + 1 < changes.length; i += 2) {
      String name = (String) changes[i];
      Object value = changes[i + 1];

      switch (name) {
        case "region" -> region = (String) value;
        case "code" -> code = (String) value;
        case "now" -> now = (Long) value;
        case "passKey" -> passKey = (byte[]) value;
        default -> others.put(name, value);
      }
    }

    byte[] key = passKey != null ? passKey : KEYS.get(region);
    long passTime = Math.floorDiv(now, 1000);
    Map<String, Object> g = new LinkedHashMap<>();
    g.put("region", region);
    g.put("code", code);
    g.put("pass", hex(Pass.make(key, region, latin1(code), passTime)));
    g.put("passTime", passTime);
    g.put("name", "Ripley's game");
    g.put("level", "Genshd1");
    g.put("mode", "Coop");
    g.put("gameStyle", 3);
    g.put("levelNumber", 12);
    g.put("coopLobby", 0);
    g.put("players", 1);
    g.put("maxPlayers", 4);
    g.put("version", 7);
    g.put("hostMs", 40);
    g.putAll(others);
    return g;
  }

  // A copy of a body with one field put in or changed ({ ...body, field: value })
  private static Map<String, Object> with(Map<String, Object> body, String field, Object value) {
    Map<String, Object> out = new LinkedHashMap<>(body);
    out.put(field, value);
    return out;
  }

  // A body with an owner key first ({ owner, ...body })
  private static Map<String, Object> owned(String owner, Map<String, Object> body) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("owner", owner);
    out.putAll(body);
    return out;
  }

  private static Map<String, Object> ending(String region, String code, String owner) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("region", region);
    out.put("code", code);
    out.put("owner", owner);
    return out;
  }

  // A request: o is a body to write as JSON, bytes to send as they are, or null for none
  private static Answer call(Listings l, String method, Object o, String query, long now, String path) {
    byte[] body = o == null ? new byte[0] : (o instanceof byte[] raw ? raw : Stringify.bytes(o));
    return Routes.handle(l, method, path, query, body, now);
  }

  private static Answer call(Listings l, String method, Object o, String query, long now) {
    return call(l, method, o, query, now, "/v1/games");
  }

  private static Answer call(Listings l, String method, Object o) {
    return call(l, method, o, "", NOW);
  }

  // The games a GET /v1/games gives, each as its fields
  private static List<Map<String, Object>> list(Listings l, long now, int version) {
    Answer answer = call(l, "GET", null, "version=" + version, now);
    same(answer.status(), 200, "GET /v1/games");
    List<Map<String, Object>> out = new ArrayList<>();

    for (Object game : Json.list(answer.body().get("games"))) {
      out.add(Json.object(game));
    }

    return out;
  }

  private static List<Map<String, Object>> list(Listings l, long now) {
    return list(l, now, 7);
  }

  private static List<Map<String, Object>> list(Listings l) {
    return list(l, NOW, 7);
  }

  private static String ownerOf(Answer answer) {
    return (String) answer.body().get("owner");
  }

  private static boolean listed(List<Map<String, Object>> games, String code) {
    for (Map<String, Object> g : games) {
      if (code.equals(g.get("code"))) {
        return true;
      }
    }

    return false;
  }

  public static void register() {
    test("a game goes on the list with its relay's pass, shows in it, is renewed and changed, and comes off", () -> {
      Listings l = listings();
      Answer posted = call(l, "POST", game());
      same(posted.status(), 201, "POST");
      ok(Pattern.matches("[0-9a-f]{32}", ownerOf(posted)), "an owner key");
      String owner = ownerOf(posted);

      Map<String, Object> shown = new LinkedHashMap<>();
      shown.put("region", "virginia");
      shown.put("code", "ABCD2345");
      shown.put("name", "Ripley's game");
      shown.put("level", "Genshd1");
      shown.put("mode", "Coop");
      shown.put("gameStyle", 3);
      shown.put("levelNumber", 12);
      shown.put("coopLobby", 0);
      shown.put("players", 1);
      shown.put("maxPlayers", 4);
      shown.put("version", 7);
      shown.put("hostMs", 40);
      shown.put("seconds", 5);
      same(list(l, at(5000)), List.of(shown), "the game as the list shows it");

      Answer renewed = call(l, "PUT", owned(owner, game("now", at(15000), "players", 3)), "", at(15000));
      same(renewed.status(), 204, "PUT");
      same(renewed.body(), null, "with no body");
      List<Map<String, Object>> after = list(l, at(20000));
      same(after.get(0).get("players"), 3, "what it shows is changed");
      same(after.get(0).get("seconds"), 20, "how long it has been listed counts from the POST, not the PUT");

      same(call(l, "DELETE", ending("virginia", "ABCD2345", owner), "", at(21000)).status(), 204, "DELETE");
      same(list(l, at(21000)).size(), 0, "it's gone");
      same(call(l, "DELETE", ending("virginia", "ABCD2345", owner), "", at(21000)).status(), 404, "gone already");
    });

    test("a pass is good only from its own relay's key, for its region and code, for a minute", () -> {
      Listings l = listings();
      same(call(l, "POST", game("passKey", KEYS.get("paris")), "", NOW).status(), 403, "made with another relay's key");
      same(call(l, "POST", with(game(), "pass", game("code", "ABCD2346").get("pass")), "", NOW).status(), 403, "made for another code");
      same(call(l, "POST", with(game(), "region", "paris"), "", NOW).status(), 403, "made for another region");
      same(call(l, "POST", with(game(), "passTime", (Long) game().get("passTime") + 1), "", NOW).status(), 403,
          "a pass time it wasn't made with");
      same(call(l, "POST", game("now", at(-60001)), "", NOW).status(), 403, "made 60.001 s ago");
      same(call(l, "POST", game("now", at(6000)), "", NOW).status(), 403, "made 6 s ahead of the list's clock");
      same(call(l, "POST", with(game(), "region", "tokyo")).status(), 400, "a region the list has no relay for");

      same(call(l, "POST", game("code", "AAAA2222", "now", at(-60000))).status(), 201, "made exactly 60 s ago is still good");
      same(call(l, "POST", game("code", "AAAA3333", "now", at(5000))).status(), 201, "and 5 s ahead is allowed for the clocks");
      same(call(l, "POST", game("region", "paris")).status(), 201, "a game on another relay, with that relay's pass");
    });

    test("only the owner key, with a fresh pass, changes or takes down a listing", () -> {
      Listings l = listings();
      String owner = ownerOf(call(l, "POST", game()));
      String wrong = "f".repeat(32);
      same(call(l, "POST", game()).status(), 409, "listed already");
      same(call(l, "PUT", owned(wrong, game())).status(), 403, "a PUT with the wrong owner key");
      same(call(l, "DELETE", ending("virginia", "ABCD2345", wrong)).status(), 403, "a DELETE with the wrong owner key");
      same(call(l, "PUT", owned(owner, game("now", at(-61000)))).status(), 403, "the right owner, but a stale pass");
      same(call(l, "PUT", owned(owner, game("code", "ZZZZ2222"))).status(), 404, "a game not listed");
      same(call(l, "DELETE", ending("paris", "ABCD2345", owner)).status(), 404, "the same code in another region is another game");
      same(list(l).size(), 1, "and none of that changed it");
    });

    test("a listing not renewed for 45 s goes, and a renewed one stays", () -> {
      Listings l = listings();
      String owner = ownerOf(call(l, "POST", game()));
      same(list(l, at(44999)).size(), 1, "alive at 44.999 s");
      same(list(l, at(45000)).size(), 0, "unrenewed for 45 s");
      same(call(l, "PUT", owned(owner, game("now", at(45000))), "", at(45000)).status(), 404, "and can't be renewed after");
      l.tick(at(45000));
      same(l.byGame.size(), 0, "the tick takes it out");
      same(call(l, "POST", game("now", at(46000)), "", at(46000)).status(), 201, "its code can be listed again");

      String second = ownerOf(call(l, "POST", game("code", "BBBB2222", "now", at(46000)), "", at(46000)));
      same(call(l, "PUT", owned(second, game("code", "BBBB2222", "now", at(76000))), "", at(76000)).status(), 204, "renewed at 76 s");
      ok(listed(list(l, at(120999)), "BBBB2222"), "renewed at 76 s, alive at 121 s");
      ok(!listed(list(l, at(121000)), "BBBB2222"), "and gone at 121 s");
    });

    test("the list holds at most 2,000 games", () -> {
      Listings l = listings();

      for (int i = 0; i < Listings.MOST_LISTINGS; i++) {
        same(call(l, "POST", game("code", codeOf(i))).status(), 201, "game " + i);
      }

      same(call(l, "POST", game("code", codeOf(Listings.MOST_LISTINGS))).status(), 503, "one more");
      same(Listings.MOST_LISTINGS, 2000, "2,000");
    });

    test("the list gives at most 100 games, the newest first, of the version asked for", () -> {
      Listings l = listings();

      for (int i = 0; i < 120; i++) {
        call(l, "POST", game("code", codeOf(i), "name", "game " + i, "now", at(i)), "", at(i));
      }

      call(l, "POST", game("code", codeOf(500), "version", 8));
      List<Map<String, Object>> games = list(l, at(200));
      same(games.size(), Routes.MOST_GAMES, "100");
      same(games.get(0).get("name"), "game 119", "the newest first");
      same(games.get(99).get("name"), "game 20", "and the 100th newest last");
      same(list(l, at(200), 8).size(), 1, "version 8 has only its own");
    });

    test("the largest list answer is 51,511 bytes, under 56 KB; it uses only the escapes \\\" and \\\\, and says a year at most", () -> {
      Listings l = listings();

      // Version 65535 is a version-2 game's (FIRST_V2_VERSION is at most that), so each row has a host's id too: 96 hex digits
      for (int i = 0; i < 120; i++) {
        Map<String, Object> worst = game("region", "longest-region-1", "code", codeOf(i), "name", QUOTE.repeat(32), "level",
            BACKSLASH.repeat(39), "mode", QUOTE.repeat(32), "gameStyle", 255, "levelNumber", 100, "coopLobby", 255, "players", 8,
            "maxPlayers", 8, "version", 65535, "hostMs", 9999, "id", "f".repeat(96));
        same(call(l, "POST", worst).status(), 201, "game " + i);
      }

      // Two years on, with every game still renewed
      long later = NOW + 2 * Routes.MOST_SECONDS * 1000;

      for (Listings.Entry g : l.byGame.values()) {
        g.renewedAt = later;
      }

      Answer answer = call(l, "GET", null, "version=65535", later);
      String text = Json.write(answer.body());
      same(Json.list(answer.body().get("games")).size(), 100, "100 games");
      same(text.length(), 51511, "the worst case PROTOCOL.md section 4 gives");
      ok(text.length() <= Routes.MOST_LIST_BYTES, "under 56 KB");

      for (Object g : Json.list(answer.body().get("games"))) {
        same(Json.object(g).get("seconds"), Routes.MOST_SECONDS, "seconds stops at a year");
      }

      StringBuilder printable = new StringBuilder();

      for (char c = 0x20; c <= 0x7e; c++) {
        printable.append(c);
      }

      Map<String, Object> all = new LinkedHashMap<>();
      all.put("name", printable.toString());
      String written = Json.write(all);
      Set<String> escapes = new TreeSet<>();

      for (int i = 0; i < written.length(); i++) {
        if (written.charAt(i) == '\\') {
          escapes.add(written.substring(i, i + 2));
          i++;
        }
      }

      same(List.copyOf(escapes), List.copyOf(new TreeSet<>(List.of(BACKSLASH + QUOTE, BACKSLASH + BACKSLASH))),
          "printable ASCII only ever needs these two");
    });

    test("GET /v1/relays gives each relay's region, name and port, never a key, and at most 4 KB", () -> {
      Answer answer = call(listings(), "GET", null, "", NOW, "/v1/relays");
      same(answer.status(), 200, "GET /v1/relays");
      List<Object> want = new ArrayList<>();

      for (Listings.Relay r : RELAYS) {
        Map<String, Object> shown = new LinkedHashMap<>();
        shown.put("region", r.region());
        shown.put("host", r.host());
        shown.put("port", r.port());
        want.add(shown);
      }

      same(answer.body().get("relays"), want, "every relay, in order");

      for (byte[] key : KEYS.values()) {
        ok(!Json.write(answer.body()).contains(hex(key)), "no key");
      }

      // The worst case: 16 relays (Settings.java allows no more), every region and host name at its longest
      List<Listings.Relay> most = new ArrayList<>();

      for (int i = 0; i < 16; i++) {
        most.add(new Listings.Relay(String.format("region-%09d", i), "h".repeat(60) + String.format("%03d", i), 65535, KEYS.get("paris")));
      }

      String text = Json.write(call(listings(most), "GET", null, "", NOW, "/v1/relays").body());
      same(text.length(), 1868, "the worst case PROTOCOL.md section 4 gives");
      ok(text.length() <= Routes.MOST_RELAYS_BYTES, "under 4 KB");
    });

    test("GET /v1/relay-keys gives a version 2 relay's two public keys and nothing else; 404 for a version 1 relay or an unknown region",
        () -> {
      byte[] p384 = bytes(97, 4);
      byte[] kem = bytes(1568, 9);
      List<Listings.Relay> relays = new ArrayList<>(RELAYS);
      relays.set(1, new Listings.Relay("paris", "paris.relay.example.net", 27500, KEYS.get("paris"), p384, kem));
      Listings l = listings(relays);
      Answer answer = call(l, "GET", null, "region=paris", NOW, "/v1/relay-keys");
      same(answer.status(), 200, "paris is a version 2 relay");
      Map<String, Object> want = new LinkedHashMap<>();
      want.put("region", "paris");
      want.put("p384", hex(p384));
      want.put("mlkem", hex(kem));
      same(answer.body(), want, "its region and its two keys, in hex, small letters");
      ok(!Json.write(answer.body()).contains(hex(KEYS.get("paris"))), "never its pass key");
      same(call(l, "GET", null, "region=virginia", NOW, "/v1/relay-keys").status(), 404, "virginia is a version 1 relay: no keys");
      same(call(l, "GET", null, "region=tokyo", NOW, "/v1/relay-keys").status(), 404, "a region the list doesn't know");
      ok(!Json.write(call(l, "GET", null, "region=tokyo", NOW, "/v1/relay-keys").body()).contains("tokyo"),
          "and its refusal doesn't say back what was asked");
      List<String> lines = l.tick(at(60000));
      matches(lines.get(0), "relay keys given 1 times, and 3 times not found", "the counts line counts them");
      ok(!lines.get(0).contains("paris") && !lines.get(0).contains(hex(p384)), "with no region and no key");

      // The worst case: the longest region, and the two keys
      List<Listings.Relay> longest = List.of(new Listings.Relay("r".repeat(16), "h.example.net", 27500, KEYS.get("paris"), p384, kem));
      String text = Json.write(call(listings(longest), "GET", null, "region=" + "r".repeat(16), NOW, "/v1/relay-keys").body());
      same(text.length(), 3380, "the worst case Routes.java gives");
      ok(text.length() <= Routes.MOST_RELAY_KEYS_BYTES, "under 4 KB");
    });

    test("GET /v1/relay-keys's query is exactly region= and a region, with no body, and GET is its only call", () -> {
      List<Listings.Relay> relays = new ArrayList<>(RELAYS);
      relays.set(1, new Listings.Relay("paris", "paris.relay.example.net", 27500, KEYS.get("paris"), bytes(97, 4), bytes(1568, 9)));
      Listings l = listings(relays);

      for (String q : List.of("", "region=", "paris", "region=Paris", "region=paris&x=1", "x=1&region=paris", "region=paris&region=paris",
          "region= paris", "region=paris ", "region=%70aris", "region=par is", "region=" + "r".repeat(17), "Region=paris", "region==paris",
          "region=paris#", "region=paris/", "region=pa\nris")) {
        same(call(l, "GET", null, q, NOW, "/v1/relay-keys").status(), 400, "query \"" + q + "\"");
      }

      same(call(l, "GET", null, "region=paris", NOW, "/v1/relay-keys").status(), 200, "the one form");
      same(call(l, "GET", latin1("x"), "region=paris", NOW, "/v1/relay-keys").status(), 400, "with a body");

      for (String method : List.of("POST", "PUT", "DELETE", "HEAD", "PATCH")) {
        same(call(l, method, null, "region=paris", NOW, "/v1/relay-keys").status(), 405, method);
      }

      same(call(l, "GET", null, "region=paris", NOW, "/v1/relay-keys/").status(), 404, "/v1/relay-keys/");
      same(call(l, "GET", null, "region=paris", NOW, "/v1/relay-key").status(), 404, "/v1/relay-key");
      same(call(l, "GET", null, "region=paris", NOW, "/v2/relay-keys").status(), 404, "/v2/relay-keys");
    });

    test("the list never gives an address, an owner key or a pass", () -> {
      Listings l = listings();
      Map<String, Object> posted = game();
      String owner = ownerOf(call(l, "POST", posted));
      String text = Json.write(call(l, "GET", null, "version=7", NOW).body());
      ok(!text.contains(owner) && !text.contains((String) posted.get("pass")), "no owner key and no pass");
      ok(!Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+").matcher(text).find(), "nothing that looks like an address");
    });

    test("every field is held to its limits", () -> {
      Listings l = listings();
      Object[][] refused = {
        {"name", "", "an empty name"},
        {"name", "x".repeat(33), "a name of 33"},
        {"name", "line\nbreak", "a line break"},
        {"name", "caf" + (char) 0xe9, "a letter outside printable ASCII (an e with an accent), written as a number so this file stays ASCII"},
        {"name", "tab\there", "a tab"},
        {"name", 7, "a number for a name"},
        {"level", "", "an empty level"},
        {"level", "x".repeat(40), "a level of 40"},
        {"mode", "x".repeat(33), "a mode of 33"},
        {"players", 0, "no players"},
        {"players", 5, "more players than maxPlayers"},
        {"maxPlayers", 9, "maxPlayers over 8"},
        {"players", 1.5, "a fraction"},
        {"players", "1", "a number as text"},
        {"version", 0, "version 0"},
        {"version", 65536, "version over 65535"},
        {"gameStyle", 256, "gameStyle over 255"},
        {"gameStyle", -1, "gameStyle below 0"},
        {"levelNumber", 101, "levelNumber over 100"},
        {"coopLobby", 256, "coopLobby over 255"},
        {"hostMs", 10000, "hostMs over 9999"},
        {"hostMs", -1, "hostMs below 0"},
        {"region", "Virginia", "a region with a capital"},
        {"region", "x".repeat(17), "a region of 17"},
        {"code", "ABCD234", "a code of 7"},
        {"code", "ABCD234I", "a code with an I"},
        {"code", "abcd2345", "a code in small letters"},
        {"pass", ((String) game().get("pass")).toUpperCase(), "a pass in capitals"},
        {"pass", ((String) game().get("pass")).substring(1), "a pass of 31"},
        {"passTime", -1, "a pass time below 0"},
        {"passTime", 1.5, "a fraction of a second"},
        {"passTime", Protocol.MOST_PASS_TIME + 1, "a pass time past the most a number holds exactly"},
        {"passTime", String.valueOf(game().get("passTime")), "a pass time as text"},
      };

      for (Object[] r : refused) {
        same(call(l, "POST", with(game(), (String) r[0], r[1])).status(), 400, (String) r[2]);
      }

      same(call(l, "POST", game("name", "x".repeat(32), "level", "y".repeat(39))).status(), 201, "32 and 39 are allowed");
      same(call(l, "POST", game("code", "ABCD2346", "gameStyle", 0, "levelNumber", 0, "coopLobby", 0, "hostMs", 0)).status(), 201,
          "and 0 for each number that may be 0");

      String owner = ownerOf(call(l, "POST", game("code", "ABCD2347")));
      same(call(l, "PUT", owned(owner.toUpperCase(), game("code", "ABCD2347"))).status(), 400, "an owner key in capitals");
      same(call(l, "DELETE", ending("virginia", "ABCD2347", owner.substring(2))).status(), 400, "an owner key of 30");
    });

    test("a body is exactly its call's fields, as JSON, at most 1 KB", () -> {
      Listings l = listings();
      same(call(l, "POST", with(game(), "extra", 1)).status(), 400, "a field no call has");
      same(call(l, "POST", with(game(), "owner", "a".repeat(32))).status(), 400, "a POST with an owner");
      Map<String, Object> missing = game();
      missing.remove("mode");
      same(call(l, "POST", missing).status(), 400, "a field missing");
      same(call(l, "PUT", game()).status(), 400, "a PUT with no owner");
      Map<String, Object> noOwner = new LinkedHashMap<>();
      noOwner.put("region", "virginia");
      noOwner.put("code", "ABCD2345");
      same(call(l, "DELETE", noOwner).status(), 400, "a DELETE with no owner");

      // A good listing with spaces after it, which JSON allows: 1,024 bytes in all is taken, and 1,025 refused for its size alone
      same(call(l, "POST", padded("ABCD2398", 1024)).status(), 201, "a good listing of 1,024 bytes");
      same(call(l, "POST", padded("ABCD2399", 1025)).status(), 400, "a good listing of 1,025 bytes");
      same(call(l, "POST", latin1("{\"region\":")).status(), 400, "not JSON");
      same(call(l, "POST", latin1("[1,2]")).status(), 400, "not an object");
      same(call(l, "POST", latin1("null")).status(), 400, "null");
      same(call(l, "POST", new byte[0]).status(), 400, "no body");
      same(call(l, "POST", new byte[] {(byte) 0xff, (byte) 0xfe}).status(), 400, "not UTF-8");
      same(call(l, "POST", bytes(1025, 0x20)).status(), 400, "over 1 KB");
      same(call(l, "POST", latin1("{\"__proto__\":{\"x\":1}," + Stringify.text(game()).substring(1))).status(), 400,
          "a __proto__ field is just an extra field");
      Map<String, Object> largest = owned("f".repeat(32), game("name", QUOTE.repeat(32), "level", QUOTE.repeat(39), "mode", QUOTE.repeat(32)));
      ok(Stringify.bytes(largest).length < 1024, "the largest PUT a game sends fits");
    });

    test("a body is read strictly, as PROTOCOL.md section 4 writes it: what JSON.parse would take is refused", () -> {
      Listings l = listings();
      String text = Stringify.text(game());
      String[][] refused = {
        {"{\"name\":\"first\"," + text.substring(1), "a key twice (JSON.parse would keep the second)"},
        {text.replace("\"players\":1", "\"players\":1.0"), "a whole number written with .0"},
        {text.replace("\"players\":1", "\"players\":1e0"), "a whole number written with an exponent"},
        {text.replace("\"hostMs\":40", "\"hostMs\":040"), "a leading 0"},
        {text.replace("\"Coop\"", "\"C" + BACKSLASH + "u006fop\""), "a unicode escape, even of a plain letter"},
        {text.replace("{", "{\"extra\":{\"x\":1},"), "an object inside"},
      };

      for (String[] r : refused) {
        same(call(l, "POST", latin1(r[0])).status(), 400, r[1]);
      }

      same(call(l, "POST", latin1(" \r\n" + text.replace(",", " ,\t") + "\n ")).status(), 201, "JSON's own whitespace is fine");
    });

    test("a GET's query is exactly version=N, and GET /v1/relays has none", () -> {
      Listings l = listings();

      for (String q : List.of("", "version=", "version=0", "version=65536", "version=07", "version=1&x=2", "x=1", "version=1e3", "version=-1", "version=99999",
          "version= 1", "version=7?x")) {
        same(call(l, "GET", null, q, NOW).status(), 400, "query \"" + q + "\"");
      }

      same(call(l, "GET", null, "version=65535", NOW).status(), 200, "version=65535");
      same(call(l, "GET", latin1("x"), "version=1", NOW).status(), 400, "a GET with a body");
      same(call(l, "GET", null, "version=1", NOW, "/v1/relays").status(), 400, "GET /v1/relays with a query");
      same(call(l, "GET", latin1("x"), "", NOW, "/v1/relays").status(), 400, "GET /v1/relays with a body");
    });

    test("only the six calls are there", () -> {
      Listings l = listings();
      same(call(l, "GET", null, "version=1", NOW, "/v1/games/").status(), 404, "/v1/games/");
      same(call(l, "GET", null, "version=1", NOW, "/v2/games").status(), 404, "/v2/games");
      same(call(l, "GET", null, "version=1", NOW, "/../v1/games").status(), 404, "/../v1/games");
      same(call(l, "GET", null, "", NOW, "/v1/relays/").status(), 404, "/v1/relays/");
      Map<String, Object> patch = new LinkedHashMap<>();
      patch.put("owner", "a".repeat(32));
      same(call(l, "PATCH", patch).status(), 405, "PATCH");
      same(call(l, "HEAD", null).status(), 405, "HEAD");
      same(call(l, "POST", game(), "", NOW, "/v1/relays").status(), 405, "nothing but GET on /v1/relays");
      same(call(l, "POST", game(), "version=1", NOW).status(), 400, "a POST with a query");
    });

    test("what a refusal says never holds what the request sent", () -> {
      Listings l = listings();
      String evil = "<script>alert(1)</script>";
      Map<String, Object> evilField = new LinkedHashMap<>();
      evilField.put(evil, 1);
      List<Answer> answers = List.of(
          call(l, "POST", game("name", evil + "\n")),
          call(l, "GET", null, "version=" + evil, NOW),
          call(l, "POST", evilField),
          call(l, "POST", game("region", "script", "passKey", KEYS.get("paris"))),
          call(l, "POST", game("passKey", KEYS.get("paris"), "name", evil)));

      for (Answer answer : answers) {
        ok(!Json.write(answer.body()).contains("script"), Json.write(answer.body()));
      }
    });

    test("the list's log line is counts only, once a minute: no code, name, owner key or pass", () -> {
      Listings l = listings();
      Map<String, Object> posted = game();
      String owner = ownerOf(call(l, "POST", posted));
      call(l, "POST", game("passKey", KEYS.get("paris")));
      same(l.tick(at(59999)).size(), 0, "not before a minute");
      List<String> lines = l.tick(at(60000));
      same(lines.size(), 1, "one line");
      matches(lines.get(0), "1 games listed", "the game listed");
      matches(lines.get(0), "1 passes refused", "the pass refused");

      for (String secret : List.of("ABCD2345", "Ripley", owner, (String) posted.get("pass"))) {
        ok(!lines.get(0).contains(secret), "the line has no " + secret);
      }

      same(l.tick(at(60001)).size(), 0, "and the next only a minute later");
    });

    test("as the list stops, its counts so far are a line at once, and the next minute counts from there", () -> {
      Listings l = listings();
      call(l, "POST", game());
      String line = l.countsLine(at(2000));
      matches(line, "^list: in the last 2 s: 1 games listed,", "two seconds' counts, made now");
      ok(!line.contains("ABCD2345") && !line.contains("Ripley"), "with no code or name");
      same(l.tick(at(61000)).size(), 0, "and the next line comes a minute after this one");
      matches(l.tick(at(62000)).get(0), "^list: in the last 60 s: 0 games listed,", "counting only what came after");
    });

    test("a version-2 game gives its host's whole id (96 hex digits) and keeps it for the listing's life; an older game can't give one",
        () -> {
          Listings l = listings();
          int v2 = Requests.FIRST_V2_VERSION;
          int older = v2 - 1;
          String id = "0123456789abcdef".repeat(6);

          same(call(l, "POST", game("version", v2)).status(), 400, "a version-2 game without one");
          same(call(l, "POST", game("version", older, "id", id)).status(), 400, "an older game with one");

          // Never the 16-byte fingerprint in its place (SERVER-BLOCKERS.md item 6): not as the id, and not under the old field's name
          for (Object bad : List.of(id.toUpperCase(java.util.Locale.ROOT), id.substring(1), id + "0", id.substring(1) + "g", id.substring(0, 32),
              "", 7L)) {
            same(call(l, "POST", game("version", v2, "id", bad)).status(), 400, "id " + bad);
          }

          same(call(l, "POST", game("version", v2, "fingerprint", id.substring(0, 32))).status(), 400, "the old fingerprint field");
          same(call(l, "POST", game("version", v2, "id", id, "fingerprint", id.substring(0, 32))).status(), 400, "the id and the old field");

          Map<String, Object> posted = game("version", v2, "id", id);
          String owner = ownerOf(call(l, "POST", posted));
          List<Map<String, Object>> v2Games = list(l, NOW, v2);
          same(v2Games.size(), 1, "it's listed");
          same(v2Games.get(0).get("id"), id, "with its host's id");
          ok(!v2Games.get(0).containsKey("fingerprint"), "and no fingerprint field");

          Map<String, Object> older1 = game("version", older, "code", "WXYZ6789");
          same(call(l, "POST", older1).status(), 201, "an older game with none is listed");
          ok(!list(l, NOW, older).get(0).containsKey("id"), "and its row has no id field at all");

          same(call(l, "PUT", owned(owner, with(posted, "players", 2))).status(), 204, "a PUT with the same id");
          same(call(l, "PUT", owned(owner, with(posted, "id", "f".repeat(96)))).status(), 403, "a PUT with another");
          Map<String, Object> without = new LinkedHashMap<>(posted);
          without.remove("id");
          same(call(l, "PUT", owned(owner, without)).status(), 400, "a PUT without one");
          same(call(l, "PUT", owned(owner, with(without, "version", older))).status(), 403, "a PUT that changes it to an older version, without one");
          same(list(l, NOW, v2).get(0).get("id"), id, "it still has the one it was listed with");
        });

    test("&code= gives only that code's games of that version, from every region, and nothing if there are none", () -> {
      Listings l = listings();
      same(call(l, "POST", game("code", "ABCD2345")).status(), 201, "virginia's ABCD2345");
      same(call(l, "POST", game("region", "paris", "code", "ABCD2345")).status(), 201, "paris's ABCD2345");
      same(call(l, "POST", game("code", "WXYZ6789")).status(), 201, "another code");
      same(call(l, "POST", game("region", "paris", "code", "ABCD2345", "version", 8)).status(), 409, "the same game again, of another version");

      Answer both = call(l, "GET", null, "version=7&code=ABCD2345", NOW);
      same(both.status(), 200, "a code's games");
      List<Object> found = Json.list(both.body().get("games"));
      same(found.size(), 2, "both regions' games with that code");

      for (Object g : found) {
        same(Json.object(g).get("code"), "ABCD2345", "only that code");
      }

      Answer none = call(l, "GET", null, "version=7&code=QRST2345", NOW);
      same(none.status(), 200, "a code nobody listed is no error");
      same(Json.list(none.body().get("games")).size(), 0, "just no games");
      same(Json.list(call(l, "GET", null, "version=8&code=ABCD2345", NOW).body().get("games")).size(), 0, "nor of another version");

      for (String q : List.of("version=7&code=", "version=7&code=abcd2345", "version=7&code=ABCD234", "version=7&code=ABCD23456",
          "version=7&code=ABCD2340", "version=7&code=ABCD2345&x=1", "version=7&code=ABCD2345&code=ABCD2345", "code=ABCD2345",
          "code=ABCD2345&version=7")) {
        same(call(l, "GET", null, q, NOW).status(), 400, "query \"" + q + "\"");
      }
    });

    // The number every version-2 game and this list agree on (Requests.java says where it comes from). Changing it changes which games
    // must carry their host's id, so it changes only with the game's own
    test("the first version-2 network version is 115, the one Secondary reserved for the relay v2 game side", () -> {
      same(Requests.FIRST_V2_VERSION, 115, "FIRST_V2_VERSION");
    });
  }

  // A good listing's body with spaces after it, to size bytes in all
  private static byte[] padded(String code, int size) {
    byte[] b = Stringify.bytes(game("code", code));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(b);
    out.writeBytes(bytes(size - b.length, 0x20));
    return out.toByteArray();
  }
}
