package avpx.list;

import avpx.relay.Pass;
import avpx.relay.Protocol;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// What the list accepts from a request, field by field, as PROTOCOL.md section 4 writes it. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server, from list/requests.js.
//
// Everything here comes from anyone on the internet (AVP Tao 3: input is hostile). So each function takes what came, checks every byte of
// it against a written limit, and gives back either exactly what it allows or the reason it doesn't, never anything half-checked:
// - a body is at most MOST_BODY_BYTES, and must be one JSON object (read by Json.java, which refuses anything but the plainest JSON) with
//   only the fields its call names, each of its own type and range;
// - a name or mode is 1 to 32 printable ASCII characters (0x20 to 0x7E), and a level's name 1 to 39, so nothing in it can be a line break,
//   a control character or anything a screen or a log could take for something else;
// - a number is a whole number in its range, never text, a fraction or something huge;
// - a pass and an owner key are exactly 32 hex digits, a host's id exactly 96, a code exactly 8 code letters, a region a region name
//   (Pass.java);
// - a host's id comes with a game of network version FIRST_V2_VERSION or newer, and with no other.
// Nothing here writes anything anywhere.
public final class Requests {
  private Requests() {
  }

  public static final int MOST_BODY_BYTES = 1024;
  static final int MOST_TEXT_LENGTH = 32;
  static final int MOST_LEVEL_LENGTH = 39;           // the game's own level names go to kLevelNameSize - 1 (networking.h)
  static final int MOST_PLAYERS = 8;
  static final int MOST_VERSION = 65535;
  static final int MOST_GAME_STYLE = 255;            // the game's NGT_ numbers
  static final int MOST_LEVEL_NUMBER = 100;          // 0 to 99 a stock level, 100 a custom one
  static final int MOST_COOP_LOBBY = 255;            // coop_lobby.h's states
  static final int MOST_HOST_MILLISECONDS = 9999;    // 0 means the host didn't measure it

  // The first network version whose games speak handshake B (CRYPTO.md section 8), where a joiner checks the host is the one the list
  // named. A game of this version or a newer one must give its host's id, and one of an older version can't: it couldn't use one, and
  // an older game's reader refuses a field it doesn't know. The game names the same number.
  // 115 was reserved by Secondary, who keeps the network versions, on 2026-11-09 for the relay v2 game side: today's games are 114, and a
  // used network version is never used again. The game's kMultiplayerVersion becomes 115 when that side lands.
  public static final int FIRST_V2_VERSION = 115;

  // A body is one object with nothing nested in it
  private static final int BODY_DEPTH = 1;

  private static final Pattern HEX_16_BYTES = Pattern.compile("[0-9a-f]{32}");
  private static final Pattern HEX_48_BYTES = Pattern.compile("[0-9a-f]{96}");

  // version=N, and for a code someone typed, &code= and its 8 code letters. The code is matched loosely here and checked by checkCode,
  // so a code has one rule everywhere.
  private static final Pattern LIST_QUERY = Pattern.compile("version=([1-9][0-9]{0,4})(?:&code=([^&]*))?");

  // A reason a request is refused, with the HTTP status it gets. The words go back to the asker, so they never hold anything it sent.
  public static final class Refusal extends Exception {
    private static final long serialVersionUID = 1L;
    private final int status;

    public Refusal(int status, String words) {
      super(words);
      this.status = status;
    }

    public int status() {
      return status;
    }
  }

  // What a game's listing shows, as a POST or PUT sent it, every field checked. hostId is the host identity's whole id for this run, as
  // 96 hex digits (CRYPTO.md section 8: SHA-384 of "AVPX-ID-2" and its two public keys), on a game of version FIRST_V2_VERSION or
  // newer, and null on an older one. The joiner's game compares it with the keys in handshake B's B2, so it's the whole digest, never
  // the 16-byte fingerprint people read (SERVER-BLOCKERS.md item 6; until 2026-11-09 it was the fingerprint, as "fingerprint").
  public record Listing(String region, String code, long passTime, String name, String level, String mode, int gameStyle,
      int levelNumber, int coopLobby, int players, int maxPlayers, int version, int hostMs, String hostId) {
  }

  // What a GET /v1/games asks for: the games of one network version, and only those with this code, or all of them if code is null
  public record ListQuery(int version, String code) {
  }

  // What a POST or PUT may put on the list: the owner key (a PUT's only, null for a POST), the pass, and the listing. Only the pass's
  // shape is checked here: whether it's good is Listings.java's to say, which has the relays' keys.
  public record Posted(byte[] owner, byte[] pass, Listing listing) {
  }

  // What a DELETE may take down
  public record Ending(String region, String code, byte[] owner) {
  }

  static final List<String> LISTING_FIELDS = List.of("region", "code", "pass", "passTime", "name", "level", "mode", "gameStyle",
      "levelNumber", "coopLobby", "players", "maxPlayers", "version", "hostMs");

  // Every text a body holds is already printable ASCII (0x20 to 0x7E): Json.java takes no other byte, so that rule lives there, once,
  // and this checks only the length
  static boolean isPlainText(Object value, int most) {
    return value instanceof String text && !text.isEmpty() && text.length() <= most;
  }

  static boolean isWhole(Object value, long least, long most) {
    return value instanceof Long n && n >= least && n <= most;
  }

  // The body of a POST, PUT or DELETE, from its bytes: one JSON object with exactly the fields named in `fields`, all of them there,
  // and also `optional` if that isn't null and the body has it
  static Map<String, Object> parseBody(byte[] bytes, List<String> fields) throws Refusal {
    return parseBody(bytes, fields, null);
  }

  static Map<String, Object> parseBody(byte[] bytes, List<String> fields, String optional) throws Refusal {
    if (bytes == null || bytes.length == 0 || bytes.length > MOST_BODY_BYTES) {
      throw new Refusal(400, "the body must be JSON, 1 to 1024 bytes");
    }

    Map<String, Object> value;

    try {
      value = Json.readObject(bytes, BODY_DEPTH);
    } catch (Json.Bad e) {
      // Json's reasons are its own fixed words, never anything from the body
      throw new Refusal(400, "the body must be one JSON object, as PROTOCOL.md section 4 writes it: " + e.getMessage());
    }

    int expected = fields.size() + (optional != null && value.containsKey(optional) ? 1 : 0);

    if (value.size() != expected || !value.keySet().containsAll(fields)) {
      throw new Refusal(400, "the body must have exactly these fields: " + String.join(", ", fields)
          + (optional != null ? ", and " + optional + " where PROTOCOL.md section 4 says" : ""));
    }

    return value;
  }

  // A host identity's whole id: 96 hex digits, small letters, kept as that text
  static String checkHostId(Object value) throws Refusal {
    if (!(value instanceof String text) || !HEX_48_BYTES.matcher(text).matches()) {
      throw new Refusal(400, "id must be 96 hex digits, small letters: the host's whole id");
    }

    return text;
  }

  // 16 bytes written as 32 hex digits, small letters (a pass, or an owner key), as bytes
  static byte[] parseHex16(Object value, String name) throws Refusal {
    if (!(value instanceof String text) || !HEX_16_BYTES.matcher(text).matches()) {
      throw new Refusal(400, name + " must be 32 hex digits, small letters");
    }

    return HexFormat.of().parseHex(text);
  }

  static String checkRegion(Object value) throws Refusal {
    if (!(value instanceof String text) || !Pass.isRegion(text)) {
      throw new Refusal(400, "region must be 1 to 16 small letters, digits and -");
    }

    return text;
  }

  static String checkCode(Object value) throws Refusal {
    if (!(value instanceof String text) || text.length() != Protocol.CODE_BYTES
        || !Protocol.isCode(text.getBytes(StandardCharsets.ISO_8859_1))) {
      throw new Refusal(400, "code must be 8 code letters");
    }

    return text;
  }

  // A field already checked to be a whole number in a range that fits in an int
  private static int whole(Map<String, Object> v, String field) {
    return ((Long) v.get(field)).intValue();
  }

  // What a POST (or, with withOwner, a PUT) may put on the list
  public static Posted parseListing(byte[] bytes, boolean withOwner) throws Refusal {
    Map<String, Object> v;

    if (withOwner) {
      List<String> fields = new ArrayList<>();
      fields.add("owner");
      fields.addAll(LISTING_FIELDS);
      v = parseBody(bytes, fields, "id");
    } else {
      v = parseBody(bytes, LISTING_FIELDS, "id");
    }

    byte[] owner = withOwner ? parseHex16(v.get("owner"), "owner") : null;
    String region = checkRegion(v.get("region"));
    String code = checkCode(v.get("code"));
    byte[] pass = parseHex16(v.get("pass"), "pass");

    if (!isWhole(v.get("passTime"), 0, Protocol.MOST_PASS_TIME)) {
      throw new Refusal(400, "passTime must be a whole number of seconds");
    }

    if (!isPlainText(v.get("level"), MOST_LEVEL_LENGTH)) {
      throw new Refusal(400, "level must be 1 to " + MOST_LEVEL_LENGTH + " printable ASCII characters");
    }

    for (String field : List.of("name", "mode")) {
      if (!isPlainText(v.get(field), MOST_TEXT_LENGTH)) {
        throw new Refusal(400, field + " must be 1 to 32 printable ASCII characters");
      }
    }

    if (!isWhole(v.get("maxPlayers"), 1, MOST_PLAYERS) || !isWhole(v.get("players"), 1, (Long) v.get("maxPlayers"))) {
      throw new Refusal(400, "players and maxPlayers must be whole numbers, 1 to 8, players no more than maxPlayers");
    }

    if (!isWhole(v.get("gameStyle"), 0, MOST_GAME_STYLE) || !isWhole(v.get("levelNumber"), 0, MOST_LEVEL_NUMBER)
        || !isWhole(v.get("coopLobby"), 0, MOST_COOP_LOBBY)) {
      throw new Refusal(400, "gameStyle must be 0 to 255, levelNumber 0 to 100 and coopLobby 0 to 255, whole numbers");
    }

    if (!isWhole(v.get("version"), 1, MOST_VERSION)) {
      throw new Refusal(400, "version must be a whole number, 1 to 65535");
    }

    if (!isWhole(v.get("hostMs"), 0, MOST_HOST_MILLISECONDS)) {
      throw new Refusal(400, "hostMs must be a whole number, 0 to 9999");
    }

    // A host's id goes with a game that speaks handshake B, and only with one: a joiner of that version refuses a host it can't check,
    // and an older game couldn't use one
    boolean speaksHandshakeB = whole(v, "version") >= FIRST_V2_VERSION;
    String hostId = null;

    if (v.containsKey("id")) {
      if (!speaksHandshakeB) {
        throw new Refusal(400, "id is only for a game of network version " + FIRST_V2_VERSION + " or newer");
      }

      hostId = checkHostId(v.get("id"));
    } else if (speaksHandshakeB) {
      throw new Refusal(400, "a game of network version " + FIRST_V2_VERSION + " or newer must give its host's id");
    }

    Listing listing = new Listing(region, code, (Long) v.get("passTime"), (String) v.get("name"), (String) v.get("level"),
        (String) v.get("mode"), whole(v, "gameStyle"), whole(v, "levelNumber"), whole(v, "coopLobby"), whole(v, "players"),
        whole(v, "maxPlayers"), whole(v, "version"), whole(v, "hostMs"), hostId);
    return new Posted(owner, pass, listing);
  }

  // What a DELETE may take down: { region, code, owner }
  public static Ending parseEnding(byte[] bytes) throws Refusal {
    Map<String, Object> v = parseBody(bytes, List.of("region", "code", "owner"));
    return new Ending(checkRegion(v.get("region")), checkCode(v.get("code")), parseHex16(v.get("owner"), "owner"));
  }

  // A GET has no body
  public static void checkNoBody(byte[] body) throws Refusal {
    if (body != null && body.length > 0) {
      throw new Refusal(400, "a GET has no body");
    }
  }

  // What a GET's query may say: version=N, the game's network version, 1 to 65535, and after it, for a code someone typed, &code= and
  // its 8 code letters. Anything else in it is refused.
  public static ListQuery parseListQuery(String query) throws Refusal {
    Matcher match = LIST_QUERY.matcher(query == null ? "" : query);
    long version = match.matches() ? Json.digitsValue(match.group(1), MOST_VERSION) : -1;

    if (version < 1) {
      throw new Refusal(400, "the query must be version=N, N from 1 to 65535, and may go on with &code= and 8 code letters");
    }

    String code = match.group(2) == null ? null : checkCode(match.group(2));
    return new ListQuery((int) version, code);
  }
}
