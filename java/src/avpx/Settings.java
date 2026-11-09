package avpx;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import avpx.list.Listings;
import avpx.relay.Pass;
import avpx.v2.HandshakeA;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
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
//   protocol       which protocol the relay speaks                   1 (PROTOCOL.md) or 2 (CRYPTO.md); default 1. One only: version 2
//                                                                    is a new deployment, with no mixing of the two
//   staticKeys     the relay's static keys, for protocol 2           an object, below; required for protocol 2, refused for 1
//   list           the list, if this machine runs it                 an object, below; leave it out on a machine that doesn't
//
// The static keys (CRYPTO.md section 4) prove the relay in handshake A; their public halves go in the signed directory.
// java/tools/MakeRelayKeys.java makes them, all three at once:
//   p384Private    its P-384 private key's number                    96 hex digits, small letters
//   p384Public     its P-384 public key (04, then x and y)           194 hex digits; it must be p384Private's own (P384.pair)
//   mlkemSeed      its ML-KEM-1024 key's seed, FIPS 203's d then z   128 hex digits: the key pair is made from it each start
//
// The list:
//   address        the address the HTTPS list listens on             an IPv4 address, default "0.0.0.0"
//   port           the HTTPS list's port                             1 to 65535, default 443
//   certFile       the certificate, with its chain, PEM              a path; required
//   keyFile        its private key, PEM                              a path; required
//   relays         every relay the list knows, 1 to 16 of them:      required, and must name this machine's own region
//                  { region, host (its DNS name, never an address), port (its control port), passKey (that relay's pass key),
//                    p384 and mlkem (a version 2 relay's static PUBLIC keys, 194 and 3,136 hex digits, both or neither) }.
//                  This machine's own relay leaves passKey out: it's the passKey above, so the one secret is written once. It leaves
//                  p384 and mlkem out too: with protocol 2 they're the public halves of staticKeys above, and with 1 it has none.
//                  Another version 2 relay's come from MakeRelayKeys's PUBLIC lines, run on that relay. Each is checked as a key
//                  before anything starts: the P-384 key a point on the curve, the ML-KEM key FIPS 203's modulus check. GET
//                  /v1/relay-keys gives a game exactly these (CRYPTO.md section 12.1).
//
// The file holds pass keys, so it's readable only by root and the server's own user (deploy/README.md).
public final class Settings {
  private static final Set<String> NAMES = Set.of("region", "passKey", "relayAddress", "controlPort", "relayPorts", "logFile", "protocol",
      "staticKeys", "list");
  private static final Set<String> STATIC_KEY_NAMES = Set.of("p384Private", "p384Public", "mlkemSeed");
  private static final Pattern HEX = Pattern.compile("[0-9a-f]*");
  private static final Set<String> LIST_NAMES = Set.of("address", "port", "certFile", "keyFile", "relays");
  private static final Set<String> RELAY_NAMES = Set.of("region", "host", "port", "passKey", "p384", "mlkem");

  private static final String DEFAULT_ADDRESS = "0.0.0.0";
  private static final int DEFAULT_CONTROL_PORT = 27500;
  private static final String DEFAULT_RELAY_PORTS = "27501-27564";
  private static final int DEFAULT_LIST_PORT = 443;
  private static final int LEAST_RELAY_PORT = 1024;
  private static final int MOST_RELAY_PORTS = 4000;
  private static final int MOST_RELAYS = 16;
  private static final int MOST_HOST_LENGTH = 63;
  private static final int MOST_PATH_LENGTH = 260;
  // 16 relays, each with every field at its longest and both public keys (15 of them: the list's own takes its keys from staticKeys),
  // and every other setting at its longest, come to 54,840 bytes written with no spaces. 64 KB leaves room for the spaces and line ends
  // a person puts in (SettingsTest.java checks both fit).
  private static final int MOST_SETTINGS_BYTES = 64 * 1024;
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
  private final int protocol;
  private final HandshakeA.RelayKeys staticKeys;
  private final ListSettings list;

  private Settings(String region, byte[] passKey, String relayAddress, int controlPort, int[] relayPorts, String logFile, int protocol,
      HandshakeA.RelayKeys staticKeys, ListSettings list) {
    this.region = region;
    this.passKey = passKey;
    this.relayAddress = relayAddress;
    this.controlPort = controlPort;
    this.relayPorts = relayPorts;
    this.logFile = logFile;
    this.protocol = protocol;
    this.staticKeys = staticKeys;
    this.list = list;
  }

  // 1 or 2
  public int protocol() {
    return protocol;
  }

  // The relay's static keys, for protocol 2; null for protocol 1
  public HandshakeA.RelayKeys staticKeys() {
    return staticKeys;
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

  // A key's bytes, from exactly 2 hex digits (small letters) for each, and never all 0
  private static byte[] keyBytes(Object value, String name, int bytes) throws Refused {
    if (!(value instanceof String text) || text.length() != 2 * bytes || !HEX.matcher(text).matches() || ALL_ZERO.matcher(text).matches()) {
      throw new Refused(name + " must be " + (2 * bytes) + " hex digits, small letters, and not all 0 (java/tools/MakeRelayKeys.java makes it)");
    }

    return HexFormat.of().parseHex(text);
  }

  // A version 2 relay's static keys, each held to what it must be before the relay could use it
  private static HandshakeA.RelayKeys staticKeys(Object value) throws Refused {
    Map<String, Object> given = value instanceof Map ? Json.object(value) : null;

    if (given == null) {
      throw new Refused("staticKeys must be an object");
    }

    onlyKnown(given, STATIC_KEY_NAMES, " in staticKeys");
    byte[] number = keyBytes(given.get("p384Private"), "staticKeys.p384Private", P384.SECRET_BYTES);
    byte[] point = keyBytes(given.get("p384Public"), "staticKeys.p384Public", P384.PUBLIC_BYTES);
    byte[] seed = keyBytes(given.get("mlkemSeed"), "staticKeys.mlkemSeed", MlKem.SEED_BYTES);

    try {
      KeyPair p384 = P384.pair(number, point);

      if (p384 == null) {
        throw new Refused("staticKeys.p384Private and staticKeys.p384Public must be the two halves of one P-384 key");
      }

      KeyPair kem = MlKem.fromSeed(seed);

      if (kem == null) {
        throw new Refused("staticKeys.mlkemSeed: this Java can't make an ML-KEM-1024 key from a seed as FIPS 203 says");
      }

      return HandshakeA.RelayKeys.of(p384, kem);
    } finally {
      Arrays.fill(number, (byte) 0);
      Arrays.fill(seed, (byte) 0);
    }
  }

  // Another version 2 relay's two static public keys, from its list.relays entry: both or neither (neither is a version 1 relay). Each
  // must be a key the game could use: P384.decode and MlKem.decode make the same checks handshake A's own reading does.
  private static byte[][] publicKeys(Map<String, Object> r, String where) throws Refused {
    boolean hasP384 = r.containsKey("p384");
    boolean hasKem = r.containsKey("mlkem");

    if (!hasP384 && !hasKem) {
      return new byte[][] {null, null};
    }

    if (!hasP384 || !hasKem) {
      throw new Refused(where + " must give both p384 and mlkem (a version 2 relay), or neither (a version 1 relay)");
    }

    byte[] p384 = keyBytes(r.get("p384"), where + ".p384", P384.PUBLIC_BYTES);
    byte[] kem = keyBytes(r.get("mlkem"), where + ".mlkem", MlKem.ENCAPSULATION_KEY_BYTES);

    if (P384.decode(p384) == null) {
      throw new Refused(where + ".p384 must be a P-384 public key: 04, then x and y, a point on the curve");
    }

    if (MlKem.decode(kem) == null) {
      throw new Refused(where + ".mlkem must be an ML-KEM-1024 encapsulation key that passes FIPS 203's check");
    }

    return new byte[][] {p384, kem};
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

  // ownKeys: this machine's own relay's static keys with protocol 2, or null with protocol 1
  private static ListSettings parseList(Object value, String ownRegion, byte[] ownKey, HandshakeA.RelayKeys ownKeys) throws Refused {
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

      if (own && (r.containsKey("p384") || r.containsKey("mlkem"))) {
        throw new Refused(where + " is this machine's own relay, so it leaves p384 and mlkem out (with protocol 2 they come from "
            + "staticKeys above)");
      }

      String itsHost = host(r.get("host"), where + ".host");
      int itsPort = port(r.get("port"), where + ".port", 1);
      byte[] itsKey = own ? ownKey.clone() : passKey(r.get("passKey"), where + ".passKey");
      byte[][] itsPublic = own ? (ownKeys == null ? new byte[][] {null, null} : new byte[][] {ownKeys.p384Public().clone(),
          ownKeys.kemPublic().clone()}) : publicKeys(r, where);

      if (!regions.add(itsRegion)) {
        throw new Refused("list.relays must name each region once");
      }

      out.add(new Listings.Relay(itsRegion, itsHost, itsPort, itsKey, itsPublic[0], itsPublic[1]));
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
      throw new Refused("the file must be text, at most 64 KB");
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
    Object protocolGiven = given.getOrDefault("protocol", 1L);

    if (!(protocolGiven instanceof Long p) || (p != 1 && p != 2)) {
      throw new Refused("protocol must be 1 or 2");
    }

    int protocol = p.intValue();

    if (protocol == 2 && !given.containsKey("staticKeys")) {
      throw new Refused("staticKeys are needed for protocol 2: java/tools/MakeRelayKeys.java makes them");
    }

    if (protocol == 1 && given.containsKey("staticKeys")) {
      throw new Refused("staticKeys are for protocol 2 only");
    }

    HandshakeA.RelayKeys keys = protocol == 2 ? staticKeys(given.get("staticKeys")) : null;
    ListSettings list = given.containsKey("list") ? parseList(given.get("list"), ownRegion, ownKey, keys) : null;
    return new Settings(ownRegion, ownKey, relayAddress, controlPort, relayPorts, logFile, protocol, keys, list);
  }

  // The settings from a file. At most MOST_SETTINGS_BYTES are read, so a file that's far too big is never read whole.
  public static Settings read(Path file) throws Refused, IOException {
    try (InputStream in = Files.newInputStream(file)) {
      return parse(in.readNBytes(MOST_SETTINGS_BYTES + 1));
    }
  }
}
