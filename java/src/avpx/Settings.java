package avpx;

import avpx.list.Json;
import avpx.list.Listings;
import avpx.relay.Pass;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// The server's settings, from a JSON file, each one checked against its limits before anything starts. Written 2026-11-08 by Melanikus
// for AVPx Dedicated Server, from settings.js.
//
// The file is the machine owner's, not the internet's, but a wrong setting must still stop the server with a plain reason, never start
// it half-right. Every setting is named here with what it may be; a setting the file doesn't name takes its default, and a name this
// doesn't know is refused (it's most likely a typing mistake). The file is read with the same strict JSON reader as the list's bodies
// (Json.java), only allowed to nest, so it's ASCII, with no true, false or null.
//
// Every machine runs the same code, and every machine runs a relay. The settings say which region its relay is, and whether this machine
// runs the list too ("list" there) or not (no "list"). PROTOCOL.md says what a region and a pass key are.
//
//   region         this relay's region name                          1 to 16 small letters, digits and -, such as "virginia"; required
//   passKey        this relay's pass key, as 64 hex digits           32 random bytes (openssl rand -hex 32); required, never all 0
//   relayAddress   the address the relay listens on                  an IPv4 address, default "0.0.0.0" (all of the machine's)
//   controlPort    the relay's control port                          1024 to 65535, default 27500
//   relayPorts     the relay's ports for joiners, "first-last"       1024 to 65535, 1 to 4000 of them, default "27501-27564"
//   logFile        where the log goes as well as the screen          a path, or "" for the screen only; default ""
//   list           the list, if this machine runs it                 an object, below; leave it out on a machine that doesn't
//
// The list:
//   address        the address the HTTPS list listens on             an IPv4 address, default "0.0.0.0"
//   port           the HTTPS list's port                             1 to 65535, default 443
//   certFile       the certificate, with its chain, PEM              a path; required
//   keyFile        its private key, PEM                              a path; required
//   relays         every relay the list knows, 1 to 16 of them:      required, and must name this machine's own region
//                  { region, host (its DNS name, never an address), port (its control port), passKey (that relay's pass key) }.
//                  This machine's own relay leaves passKey out: it's the passKey above, so the one secret is written once.
//
// The file holds pass keys, so it's readable only by root and the server's own user (deploy/README.md).
public final class Settings {
  private static final Set<String> NAMES = Set.of("region", "passKey", "relayAddress", "controlPort", "relayPorts", "logFile", "list");
  private static final Set<String> LIST_NAMES = Set.of("address", "port", "certFile", "keyFile", "relays");
  private static final Set<String> RELAY_NAMES = Set.of("region", "host", "port", "passKey");

  private static final String DEFAULT_ADDRESS = "0.0.0.0";
  private static final int DEFAULT_CONTROL_PORT = 27500;
  private static final String DEFAULT_RELAY_PORTS = "27501-27564";
  private static final int DEFAULT_LIST_PORT = 443;
  private static final int LEAST_RELAY_PORT = 1024;
  private static final int MOST_RELAY_PORTS = 4000;
  private static final int MOST_RELAYS = 16;
  private static final int MOST_HOST_LENGTH = 63;
  private static final int MOST_PATH_LENGTH = 260;
  private static final int MOST_SETTINGS_BYTES = 16 * 1024;
  private static final int MOST_NAME_SHOWN = 40;

  // The file's own object, the list's object in it, the list of relays in that, and each relay's object
  private static final int FILE_DEPTH = 4;

  private static final Pattern PASS_KEY = Pattern.compile("[0-9a-f]{64}");
  private static final Pattern ALL_ZERO = Pattern.compile("0+");
  private static final Pattern RANGE = Pattern.compile("([0-9]{4,5})-([0-9]{4,5})");
  // An IPv4 address as four numbers 0 to 255 with no 0 in front, as Node's net.isIPv4 takes them
  private static final Pattern IPV4 = Pattern.compile("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}"
      + "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])");
  private static final Pattern HOST = Pattern.compile("[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*");
  // Its last part starts with a letter; \z is the very end (Java's $ would also match before a line break at the end)
  private static final Pattern HOST_LAST_PART = Pattern.compile("(^|\\.)[A-Za-z][A-Za-z0-9-]*\\z");

  // A setting that isn't right, with the reason, which always starts "settings: "
  public static final class Refused extends Exception {
    private static final long serialVersionUID = 1L;

    Refused(String words) {
      super("settings: " + words);
    }
  }

  // The list's own settings, if this machine runs the list
  public record ListSettings(String address, int port, String certFile, String keyFile, List<Listings.Relay> relays) {
  }

  private final String region;
  private final byte[] passKey;
  private final String relayAddress;
  private final int controlPort;
  private final int[] relayPorts;
  private final String logFile;
  private final ListSettings list;

  private Settings(String region, byte[] passKey, String relayAddress, int controlPort, int[] relayPorts, String logFile,
      ListSettings list) {
    this.region = region;
    this.passKey = passKey;
    this.relayAddress = relayAddress;
    this.controlPort = controlPort;
    this.relayPorts = relayPorts;
    this.logFile = logFile;
    this.list = list;
  }

  public String region() {
    return region;
  }

  public byte[] passKey() {
    return passKey.clone();
  }

  public String relayAddress() {
    return relayAddress;
  }

  public int controlPort() {
    return controlPort;
  }

  public int[] relayPorts() {
    return relayPorts.clone();
  }

  public String logFile() {
    return logFile;
  }

  // The list's settings, or null on a machine that doesn't run the list
  public ListSettings list() {
    return list;
  }

  // ----- Each kind of setting

  // Refuses any name in `given` that `known` doesn't have
  private static void onlyKnown(Map<String, Object> given, Set<String> known, String where) throws Refused {
    for (String name : given.keySet()) {
      if (!known.contains(name)) {
        String shown = Json.write(name);
        throw new Refused("there's no setting called " + shown.substring(0, Math.min(shown.length(), MOST_NAME_SHOWN)) + where);
      }
    }
  }

  private static int port(Object value, String name, int least) throws Refused {
    if (!(value instanceof Long n) || n < least || n > 65535) {
      throw new Refused(name + " must be a whole number from " + least + " to 65535");
    }

    return n.intValue();
  }

  private static String path(Object value, String name, boolean required) throws Refused {
    if (value == null || (value instanceof String empty && empty.isEmpty())) {
      if (required) {
        throw new Refused(name + " is required");
      }

      return "";
    }

    // The reader takes no control character, so a path can't hold one
    if (!(value instanceof String text) || text.length() > MOST_PATH_LENGTH) {
      throw new Refused(name + " must be a path, at most 260 characters");
    }

    return text;
  }

  private static String region(Object value, String name) throws Refused {
    if (!(value instanceof String text) || !Pass.isRegion(text)) {
      throw new Refused(name + " must be 1 to 16 small letters, digits and -");
    }

    return text;
  }

  // A pass key from its 64 hex digits, as 32 bytes. All zeros is refused: it's what a key left unset would look like.
  private static byte[] passKey(Object value, String name) throws Refused {
    if (!(value instanceof String text) || !PASS_KEY.matcher(text).matches() || ALL_ZERO.matcher(text).matches()) {
      throw new Refused(name + " must be 64 hex digits, small letters, made at random (openssl rand -hex 32)");
    }

    return HexFormat.of().parseHex(text);
  }

  private static String address(Object value, String name) throws Refused {
    if (!(value instanceof String text) || !IPV4.matcher(text).matches()) {
      throw new Refused(name + " must be an IPv4 address");
    }

    return text;
  }

  // A relay's DNS name, never an address, so a relay can move to another machine without a game update: letters, digits and -, in parts
  // joined by dots, and the last part starts with a letter. No real top-level domain starts with a digit, while every way of writing an
  // IPv4 address ends in a number (1.2.3.4, and forms some resolvers also take as addresses, such as 0x7f.0.0.1), so this refuses them
  // all, and IPv6 has colons, which no name has.
  private static String host(Object value, String name) throws Refused {
    if (!(value instanceof String text) || text.length() > MOST_HOST_LENGTH || !HOST.matcher(text).matches()
        || !HOST_LAST_PART.matcher(text).find()) {
      throw new Refused(name + " must be a DNS name, 1 to " + MOST_HOST_LENGTH + " characters, not an address");
    }

    return text;
  }

  private static ListSettings parseList(Object value, String ownRegion, byte[] ownKey) throws Refused {
    Map<String, Object> given = Json.object(value);

    if (given == null) {
      throw new Refused("list must be an object, or left out");
    }

    onlyKnown(given, LIST_NAMES, " in list");
    String listAddress = address(given.getOrDefault("address", DEFAULT_ADDRESS), "list.address");
    List<Object> relays = Json.list(given.get("relays"));

    if (relays == null || relays.isEmpty() || relays.size() > MOST_RELAYS) {
      throw new Refused("list.relays must be a list of 1 to " + MOST_RELAYS + " relays");
    }

    List<Listings.Relay> out = new ArrayList<>();
    Set<String> regions = new HashSet<>();

    for (int k = 0; k < relays.size(); k++) {
      String where = "list.relays[" + k + "]";
      Map<String, Object> r = Json.object(relays.get(k));

      if (r == null) {
        throw new Refused(where + " must be an object");
      }

      onlyKnown(r, RELAY_NAMES, " in " + where);
      String itsRegion = region(r.get("region"), where + ".region");
      boolean own = itsRegion.equals(ownRegion);

      if (own && r.containsKey("passKey")) {
        throw new Refused(where + " is this machine's own relay, so it leaves passKey out (it's the passKey above)");
      }

      String itsHost = host(r.get("host"), where + ".host");
      int itsPort = port(r.get("port"), where + ".port", 1);
      byte[] itsKey = own ? ownKey.clone() : passKey(r.get("passKey"), where + ".passKey");

      if (!regions.add(itsRegion)) {
        throw new Refused("list.relays must name each region once");
      }

      out.add(new Listings.Relay(itsRegion, itsHost, itsPort, itsKey));
    }

    if (!regions.contains(ownRegion)) {
      throw new Refused("list.relays must name this machine's own region, or its own games could not be listed");
    }

    return new ListSettings(listAddress, port(given.getOrDefault("port", (long) DEFAULT_LIST_PORT), "list.port", 1),
        path(given.get("certFile"), "list.certFile", true), path(given.get("keyFile"), "list.keyFile", true), List.copyOf(out));
  }

  // The settings from a file's bytes, every setting checked, or Refused with the reason
  public static Settings parse(byte[] bytes) throws Refused {
    if (bytes.length > MOST_SETTINGS_BYTES) {
      throw new Refused("the file must be text, at most 16 KB");
    }

    Object value;

    try {
      value = Json.read(bytes, FILE_DEPTH);
    } catch (Json.Bad e) {
      throw new Refused("the file must be JSON as this server reads it (ASCII, no true, false or null): " + e.getMessage());
    }

    Map<String, Object> given = Json.object(value);

    if (given == null) {
      throw new Refused("the file must be a JSON object");
    }

    onlyKnown(given, NAMES, "");
    String ownRegion = region(given.get("region"), "region");
    byte[] ownKey = passKey(given.get("passKey"), "passKey");
    String relayAddress = address(given.getOrDefault("relayAddress", DEFAULT_ADDRESS), "relayAddress");
    int controlPort = port(given.getOrDefault("controlPort", (long) DEFAULT_CONTROL_PORT), "controlPort", LEAST_RELAY_PORT);
    Object ports = given.getOrDefault("relayPorts", DEFAULT_RELAY_PORTS);
    Matcher range = ports instanceof String text ? RANGE.matcher(text) : null;

    if (range == null || !range.matches()) {
      throw new Refused("relayPorts must be \"first-last\", such as \"27501-27564\"");
    }

    // Each is 4 or 5 digits (RANGE), read without anything that could throw; port() then holds it to its range
    int first = port(Json.digitsValue(range.group(1), Json.MOST_WHOLE), "relayPorts' first", LEAST_RELAY_PORT);
    int last = port(Json.digitsValue(range.group(2), Json.MOST_WHOLE), "relayPorts' last", LEAST_RELAY_PORT);

    if (last < first || last - first + 1 > MOST_RELAY_PORTS) {
      throw new Refused("relayPorts must go up, and be at most " + MOST_RELAY_PORTS + " ports");
    }

    if (controlPort >= first && controlPort <= last) {
      throw new Refused("controlPort must not be one of relayPorts");
    }

    int[] relayPorts = new int[last - first + 1];

    for (int p = first; p <= last; p++) {
      relayPorts[p - first] = p;
    }

    String logFile = path(given.get("logFile"), "logFile", false);
    ListSettings list = given.containsKey("list") ? parseList(given.get("list"), ownRegion, ownKey) : null;
    return new Settings(ownRegion, ownKey, relayAddress, controlPort, relayPorts, logFile, list);
  }

  // The settings from a file. At most MOST_SETTINGS_BYTES are read, so a file that's far too big is never read whole.
  public static Settings read(Path file) throws Refused, IOException {
    try (InputStream in = Files.newInputStream(file)) {
      return parse(in.readNBytes(MOST_SETTINGS_BYTES + 1));
    }
  }
}
