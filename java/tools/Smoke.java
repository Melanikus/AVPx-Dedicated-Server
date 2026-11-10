package avpx.tools;

import avpx.Settings;
import avpx.access.AccessCode;
import avpx.list.Listings;
import avpx.v2.Identity;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

// The smoke test of a running AVPx Dedicated Server, from outside its process, the way the game talks to it: 38 checks, each PASS or FAIL.
// Written 2026-11-09 by Melanikus for AVPx Dedicated Server, ported check for check from the Node version's smoke.js (sha256 a902ecc9...).
//
//   cd <folder>; java -cp java/build/tools avpx.tools.Smoke          (it exits 1 if any check fails)
//
// The folder it's run in holds list-test.pem, the list's certificate, and server.log, the server's log: nothing given on its command line
// points it anywhere. Add --without-log to leave out the last 6 checks, which read the log (for a server whose log goes to the journal).
//
//   java -jar avpx-smoke.jar --installed [--name <DNS name>]     deploy's health check, on the server's own machine (exit 0: healthy)
//
// With --installed it reads the server's own settings, /etc/avpx/settings.json, as the server does: the ports, the region, the relays the
// list should name, and the certificate file. It trusts only that certificate, checks it is for this machine's own relay host in the
// settings (or the DNS name --name gives), and leaves out the 6 log checks (its log is the journal). Its one game is listed, and taken
// down, under network version 65535, which no game uses, so no player ever sees it. That's at or past the first version-2 network
// version, whatever number that is, so the listing comes with a host's id (a made-up one: nobody joins it by handshake B).
//
// A RELAY-ONLY MACHINE (a later region's: its settings have no list, deploy/settings.relay-only.example.json) gets the relay's checks
// only: the control port answering, a whole game through the relay's ports, and the pass in HOST_OPENED being this relay's own, for its
// region, made again here with the pass key in its settings (PROTOCOL.md section 3). The list's checks over HTTPS can't run there, and
// the output says so at its end, so a relay-only run never reads as a full one. It exits 0 only if every check that ran passed.
//
// A VERSION 2 RELAY (its settings say "protocol": 2) speaks version 2 only, so with --installed it gets SmokeV2.java's checks instead:
// handshake A, then a whole game sealed. That file says how it's held to the known answers before it's trusted. A version 2 relay takes
// approved players only, so its whole game needs two the owner approved (SmokeIdentities.java):
//   java -jar avpx-smoke.jar --make-identities <file>              makes two, writes them to file, and prints their fingerprints
//   java -jar avpx-smoke.jar --installed --identities <file>       plays the whole game with them; without, it checks only that a
//                                                                  player nobody approved gets nothing
//
// SAFE TO RUN ANYWHERE: it sends only to 127.0.0.1, and binds only there, so it can test only a server on the same machine and can never be
// pointed at anyone else's. HTTPS trusts only list-test.pem, and checks the certificate is for "localhost" (the name the relays' list gives).
//
// INDEPENDENT OF THE SERVER: it uses none of the server's code but its settings reader (for --installed). Its messages are written by
// hand from PROTOCOL.md section 2, a pass is made by hand from section 3, and the list's answers are compared as exact text, so a fault
// in the server's own encoder or JSON can't hide itself here. Three things of the server's are used, each said where: version 2's game
// side (SmokeV2.java, pinned to the known answers first), the identity's keys (Identity, only to hold them), and the access code, only to
// show it to the owner, whose own tools work it out for themselves. An access request's fingerprint is worked out here, by hand.
//
// Without --installed, it expects the server started with the settings CI uses: region "virginia", the list on 8443, the control port
// 27500, relay ports 27501 to 27564, a relay whose host is "localhost", and the log in server.log (java.yml's smoke job).
public final class Smoke {
  private Smoke() {
  }

  private static final String HOST = "127.0.0.1";
  // The network version its game is listed under: one no game uses, so a player never sees it
  private static final int VERSION = 65535;
  // The host's id its listing gives, 96 hex digits, as a version-2 game's must (PROTOCOL.md section 4). Made up, and plainly so
  private static final String HOST_ID = "00112233445566778899aabbccddeeff".repeat(3);
  private static final Path INSTALLED_SETTINGS = Path.of("/etc/avpx/settings.json");
  private static final Pattern DNS_NAME = Pattern.compile("[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*");

  // Where the server is, and what it should say: name is the DNS name its certificate must be for, relaysText the exact answer to
  // GET /v1/relays, log the server's log file (null: no log checks)
  private record Config(String name, int list, int control, int firstRelayPort, int lastRelayPort, String region, String relaysText,
      Path certificate, Path log) {
  }

  // CI's: java.yml's smoke job starts the server with these
  private static final Config CI = new Config("localhost", 8443, 27500, 27501, 27564, "virginia",
      "{\"relays\":[{\"region\":\"virginia\",\"host\":\"localhost\",\"port\":27500}]}", Path.of("list-test.pem"), Path.of("server.log"));

  private static Config c = CI;

  // A relay-only machine's pass key, from its settings, to make its passes again by hand (null otherwise: the list checks those)
  private static byte[] passKey;

  // The relay's message types, by their numbers (PROTOCOL.md section 2)
  static final int ECHO = 14;
  private static final int ECHO_BACK = 15;
  static final int HOST_OPEN = 1;
  static final int HOST_OPENED = 2;
  static final int HOST_KEEP = 3;
  static final int HOST_KEPT = 4;
  static final int HOST_CLOSE = 5;
  static final int JOIN = 6;
  static final int JOIN_PORT = 7;
  static final int NEW_JOINER = 8;
  static final int HOST_HELLO = 9;
  static final int JOINER_HELLO = 10;
  static final int READY = 11;
  static final int REFUSED = 12;
  private static final int COOKIE = 13;

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Pattern CODE = Pattern.compile("[2-9A-HJ-NP-Z]{8}");
  private static final Pattern OWNER = Pattern.compile("\\{\"owner\":\"([0-9a-f]{32})\"\\}");

  private static int passed;
  private static int failed;
  static int notLoopback;

  // The host's round trip to the relay, from its best echo, which its listing says (hostMs)
  private static long hostMs = 1;

  static void check(boolean ok, String name, String more) {
    if (ok) {
      passed++;
    } else {
      failed++;
    }

    System.out.println((ok ? "PASS" : "FAIL") + "  " + name + (more.isEmpty() ? "" : "  (" + more + ")"));
  }

  static void check(boolean ok, String name) {
    check(ok, name, "");
  }

  static void pause(long ms) throws InterruptedException {
    Thread.sleep(ms);
  }

  static byte[] random(int n) {
    byte[] out = new byte[n];
    RANDOM.nextBytes(out);
    return out;
  }

  // ----- The relay's 64-byte messages, by hand (PROTOCOL.md section 2): little-endian numbers

  static byte[] msg(int type, byte[] secret, String code, int port, int number) {
    byte[] b = new byte[64];
    System.arraycopy("AVPR".getBytes(StandardCharsets.US_ASCII), 0, b, 0, 4);
    b[4] = 1;
    b[5] = (byte) type;

    if (secret != null) {
      System.arraycopy(secret, 0, b, 8, 16);
    }

    if (code != null) {
      System.arraycopy(code.getBytes(StandardCharsets.US_ASCII), 0, b, 24, 8);
    }

    b[32] = (byte) port;
    b[33] = (byte) (port >>> 8);
    b[34] = (byte) number;
    b[35] = (byte) (number >>> 8);
    return b;
  }

  static byte[] msg(int type) {
    return msg(type, null, null, 0, 0);
  }

  // A message's fields, read by hand; null if it isn't one
  record Read(int type, byte[] secret, String code, int port, int number, byte[] pass, long passTime, byte[] tail) {
  }

  static Read read(byte[] b) {
    if (b == null || b.length != 64 || !new String(b, 0, 4, StandardCharsets.US_ASCII).equals("AVPR") || b[4] != 1) {
      return null;
    }

    long passTime = 0;

    for (int i = 7; i >= 0; i--) {
      passTime = (passTime << 8) | (b[52 + i] & 0xff);
    }

    return new Read(b[5] & 0xff, Arrays.copyOfRange(b, 8, 24), new String(b, 24, 8, StandardCharsets.US_ASCII),
        (b[32] & 0xff) | ((b[33] & 0xff) << 8), (b[34] & 0xff) | ((b[35] & 0xff) << 8), Arrays.copyOfRange(b, 36, 52), passTime,
        Arrays.copyOfRange(b, 60, 64));
  }

  static boolean allZero(byte[] b) {
    for (byte x : b) {
      if (x != 0) {
        return false;
      }
    }

    return true;
  }

  // ----- UDP, on 127.0.0.1 only

  record Got(byte[] data, int fromPort) {
  }

  static DatagramSocket udp() throws IOException {
    DatagramSocket s = new DatagramSocket(new InetSocketAddress(loopback(), 0));
    s.setReceiveBufferSize(1 << 20);
    return s;
  }

  static InetAddress loopback() {
    return Inet4Address.ofLiteral(HOST);
  }

  static void send(DatagramSocket s, int port, byte[] data) throws IOException {
    s.send(new DatagramPacket(data, data.length, new InetSocketAddress(loopback(), port)));
  }

  // The next packet s gets within ms, or null
  static Got next(DatagramSocket s, int ms) throws IOException {
    DatagramPacket packet = new DatagramPacket(new byte[2048], 2048);
    s.setSoTimeout(ms);

    try {
      s.receive(packet);
    } catch (SocketTimeoutException e) {
      return null;
    }

    if (!packet.getAddress().equals(loopback())) {
      notLoopback++;
    }

    return new Got(Arrays.copyOf(packet.getData(), packet.getLength()), packet.getPort());
  }

  static Got ask(DatagramSocket s, int port, byte[] data) throws IOException {
    send(s, port, data);
    return next(s, 1000);
  }

  // The message in what came back, or an empty one (type 0) if nothing did, so a check fails rather than the run stopping
  static Read readOrNothing(Got got) {
    Read r = got == null ? null : read(got.data());
    return r != null ? r : new Read(0, new byte[16], "", 0, 0, new byte[16], 0, new byte[4]);
  }

  // ----- HTTPS, trusting only the test certificate

  private record Reply(int status, Map<String, String> headers, String body, String error) {
  }

  private static SSLContext trustingOnly(Path pem) throws Exception {
    Certificate certificate;

    try (InputStream in = Files.newInputStream(pem)) {
      certificate = CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    KeyStore trusted = KeyStore.getInstance("PKCS12");
    trusted.load(null, null);
    trusted.setCertificateEntry("list-test", certificate);
    TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(trusted);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, trust.getTrustManagers(), null);
    return context;
  }

  // One request over its own connection. The connection goes to 127.0.0.1, and TLS checks the certificate is for "localhost": the name
  // is given, never looked up. contentLength, if not null, is sent in place of the body's own length.
  private static Reply api(SSLContext context, String method, String path, byte[] body) {
    try (Socket raw = new Socket(loopback(), c.list());
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(raw, c.name(), c.list(), true)) {
      SSLParameters parameters = tls.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      tls.setSSLParameters(parameters);
      tls.setSoTimeout(10000);
      tls.startHandshake();

      StringBuilder head = new StringBuilder(method + " " + path + " HTTP/1.1\r\nHost: " + c.name() + "\r\n");

      if (body != null) {
        head.append("Content-Type: application/json\r\nContent-Length: ").append(body.length).append("\r\n");
      }

      head.append("\r\n");
      OutputStream out = tls.getOutputStream();
      out.write(head.toString().getBytes(StandardCharsets.US_ASCII));

      if (body != null) {
        out.write(body);
      }

      out.flush();
      ByteArrayOutputStream got = new ByteArrayOutputStream();
      InputStream in = tls.getInputStream();
      byte[] part = new byte[4096];

      for (int n = in.read(part); n >= 0; n = in.read(part)) {
        got.write(part, 0, n);
      }

      String text = got.toString(StandardCharsets.US_ASCII);
      int end = text.indexOf("\r\n\r\n");

      if (end < 0) {
        return new Reply(0, Map.of(), "", "no HTTP answer");
      }

      String[] lines = text.substring(0, end).split("\r\n");
      String[] first = lines[0].split(" ");
      // The status: its three digits added up by hand, so nothing the server sends can make this throw
      int status = 0;

      if (first.length >= 2 && first[1].matches("[0-9]{3}")) {
        for (int i = 0; i < 3; i++) {
          status = status * 10 + (first[1].charAt(i) - '0');
        }
      }
      Map<String, String> headers = new LinkedHashMap<>();

      for (int i = 1; i < lines.length; i++) {
        int colon = lines[i].indexOf(':');

        if (colon > 0) {
          headers.put(lines[i].substring(0, colon).toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
        }
      }

      return new Reply(status, headers, text.substring(end + 4), "");
    } catch (IOException e) {
      return new Reply(0, Map.of(), "", e.getClass().getSimpleName() + ": " + e.getMessage());
    }
  }

  private static Reply api(SSLContext context, String method, String path, String body) {
    return api(context, method, path, body == null ? null : body.getBytes(StandardCharsets.US_ASCII));
  }

  // A listing's body, written by hand in PROTOCOL.md section 4's order
  private static String listing(String owner, String code, String pass, long passTime, int players) {
    return "{" + (owner == null ? "" : "\"owner\":\"" + owner + "\",") + "\"region\":\"" + c.region() + "\",\"code\":\"" + code + "\",\"pass\":\"" + pass
        + "\",\"passTime\":" + passTime + ",\"name\":\"Smoke test\",\"level\":\"Genshd1\",\"mode\":\"Coop\",\"gameStyle\":3,\"levelNumber\":12,"
        + "\"coopLobby\":0,\"players\":" + players + ",\"maxPlayers\":4,\"version\":" + VERSION + ",\"id\":\"" + HOST_ID
        + "\",\"hostMs\":" + hostMs + "}";
  }

  // How many games a GET /v1/games answer holds, counted from its text
  private static int games(Reply r) {
    if (r.body().equals("{\"games\":[]}")) {
      return 0;
    }

    Matcher m = Pattern.compile("\"code\":\"").matcher(r.body());
    int n = 0;

    while (m.find()) {
      n++;
    }

    return r.body().startsWith("{\"games\":[{") ? n : -1;
  }

  // The word after flag on the command line, or null if flag isn't there (or is last)
  private static String after(List<String> words, String flag) {
    int at = words.indexOf(flag);
    return at < 0 || at + 1 >= words.size() ? null : words.get(at + 1);
  }

  // The access requests of the two identities in file (SmokeIdentities.java), sent to this machine's own list as the game's page sends
  // them (PROTOCOL.md section 4), the host's and then, a minute later, the joiner's: the list takes one a minute from one address, and
  // both come from 127.0.0.1. Each is checked to come back with its own fingerprint, and printed with its access code, for the owner.
  private static void requestAccess(Path file) throws Exception {
    if (c.certificate() == null) {
      check(false, "access requests: this machine runs no list to send them to (a version 2 relay takes its own list's approved players "
          + "only, CRYPTO.md section 6)");
      return;
    }

    Identity[] players = SmokeIdentities.read(file);

    if (players == null) {
      check(false, "the identities file " + file + " holds two identities as --make-identities writes them");
      return;
    }

    SSLContext tls = trustingOnly(c.certificate());
    String[] who = {"host", "joiner"};

    // The list may still be starting: asked until it answers, up to 15 s
    long until = System.nanoTime() + 15_000_000_000L;

    while (api(tls, "GET", "/v1/relays", (String) null).status() != 200 && System.nanoTime() < until) {
      pause(250);
    }

    for (int i = 0; i < 2; i++) {
      if (i > 0) {
        pause(61_000);
      }

      // The fingerprint worked out here, by hand from PROTOCOL.md (the first 16 bytes of SHA-384("AVPX-ID-2" || the 1,665 public bytes)),
      // not with the server's own code: so the list's answer is held to what the protocol says, not to the server's idea of it
      byte[] statics = players[i].statics();
      MessageDigest sha = MessageDigest.getInstance("SHA-384");
      sha.update("AVPX-ID-2".getBytes(StandardCharsets.US_ASCII));
      String fp = HexFormat.of().formatHex(Arrays.copyOf(sha.digest(statics), 16));
      String body = "{\"v\":1,\"name\":\"smoke " + who[i] + "\",\"key\":\"" + Base64.getEncoder().encodeToString(statics) + "\"}";
      Reply r = api(tls, "POST", "/v1/access-requests", body);
      boolean waiting = r.body().equals("{\"v\":1,\"fp\":\"" + fp + "\",\"state\":\"waiting\"}");
      boolean approved = r.body().equals("{\"v\":1,\"fp\":\"" + fp + "\",\"state\":\"approved\"}");
      check(r.status() == 200 && (waiting || approved), "the " + who[i] + "'s access request: 200, with its own fingerprint, waiting or "
          + "approved", r.status() + " " + r.body());
      System.out.println(who[i] + " " + fp + " " + AccessCode.of(fp) + (approved ? " approved" : waiting ? " waiting" : " not asked"));
    }
  }

  // What this machine's own list gives games for its own relay, GET /v1/relay-keys?region= (PROTOCOL.md section 4): it must be exactly
  // the public halves of the static keys the relay's settings hold. Then their id, worked out here by hand from CRYPTO.md section 12.1
  // (SHA-384 of "AVPX relay keys v2", then the P-384 key, then the ML-KEM key), not with the server's own code, is printed: the owner
  // holds it to MakeRelayKeys' ID line and to the RelayKey line in the game's AliensVsPredator.cfg. The game checks that id itself, and
  // refuses keys that don't hash to it, so this is for finding a mistake on deploy day, not what keeps a player safe. Added 2026-11-09
  // by Melanikus for AVPx Dedicated Server, for Secondary's dry run of the self-test.
  private static void relayKeys(Settings settings) throws Exception {
    if (c.certificate() == null) {
      System.out.println("NOT RUN  GET /v1/relay-keys: this machine runs no list (the list's machine has these keys in list.relays)");
      return;
    }

    SSLContext tls = trustingOnly(c.certificate());

    // The list may still be starting: asked until it answers, up to 15 s
    long until = System.nanoTime() + 15_000_000_000L;
    Reply r = api(tls, "GET", "/v1/relay-keys?region=" + c.region(), (String) null);

    while (r.status() != 200 && System.nanoTime() < until) {
      pause(250);
      r = api(tls, "GET", "/v1/relay-keys?region=" + c.region(), (String) null);
    }

    HexFormat hex = HexFormat.of();
    byte[] p384 = settings.staticKeys().p384Public();
    byte[] kem = settings.staticKeys().kemPublic();
    String expected = "{\"region\":\"" + c.region() + "\",\"p384\":\"" + hex.formatHex(p384) + "\",\"mlkem\":\"" + hex.formatHex(kem) + "\"}";
    // What went wrong is said only when something did: a PASS line carries no words of a failure
    boolean theirOwn = r.status() == 200 && r.body().equals(expected);
    check(theirOwn, "GET /v1/relay-keys for " + c.region() + ": 200, and exactly the public keys this relay's settings hold",
        theirOwn ? "" : r.status() == 200 ? "another answer" : r.status() + " " + r.body());

    MessageDigest sha = MessageDigest.getInstance("SHA-384");
    sha.update("AVPX relay keys v2".getBytes(StandardCharsets.US_ASCII));
    sha.update(p384);
    sha.update(kem);
    String id = hex.formatHex(sha.digest());
    System.out.println("relay " + c.region() + " ID " + id);
    System.out.println("  the game finds it in this machine's servers.cfg line: Smoke --installed --servers-line <name> <public IPv4> prints it");
  }

  // ----- The servers.cfg line (#175)

  // The one line a game's servers.cfg takes for this machine (AvP-docs' #175 design, Fifth's reader), and a # line before it naming
  // the server's commit and the day, printed on their own, so the operator shares them as they are and copies nothing by hand:
  //   <name> TAB <public IPv4>:<the list's port> TAB <the list's pin> TAB <public IPv4>:<the relay's control port> TAB <the relay's id>
  // Only the name and the public address are the operator's to give, since nothing on the machine knows them for sure (behind a
  // provider's network, the machine's own addresses aren't the one players reach). Everything else is worked out here, from what this
  // machine runs, and checked against what it serves:
  //   - the list's pin: SHA-256 of the SubjectPublicKeyInfo (the DER of the certificate's public key) in the certificate file the list's
  //     settings name, which must be the very key the list serves over TLS right now, asked on 127.0.0.1;
  //   - the relay's id: CRYPTO.md section 12.1's SHA-384, by hand, of the static keys the settings hold, which must be the keys the
  //     list's GET /v1/relay-keys gives.
  // The game trusts the list by that pin alone (#175's "trust the pin alone"), so the line holds for as long as the list keeps its key:
  // deploy/README.md says how a certificate is made again from the same key. Exit 0 with the two lines, or 1 with the reason on the
  // error stream and nothing on the output.
  private static int serversLine(Settings settings, String name, String address) throws Exception {
    String wrong = settings.protocol() != 2 ? "a servers.cfg line is for a version 2 server (\"protocol\": 2)"
        : c.certificate() == null ? "a servers.cfg line needs this machine's list: its settings have none"
        : !isLineName(name) ? "the name must be 1 to 31 printable ASCII characters, with no space at either end and no # first"
        : !isUsableIpv4(address) ? "the address must be this machine's public IPv4, written plainly, one a server can have (not 0.x, "
            + "224 and up, or a carrier's 100.64/10)"
        : null;

    if (wrong != null) {
      System.err.println("servers line: " + wrong);
      return 1;
    }

    Certificate file;

    try (InputStream in = Files.newInputStream(c.certificate())) {
      file = CertificateFactory.getInstance("X.509").generateCertificate(in);
    }

    byte[] spki = file.getPublicKey().getEncoded();
    SSLContext tls = trustingOnly(c.certificate());
    byte[] served = servedKey(tls);

    if (served == null || !MessageDigest.isEqual(served, spki)) {
      System.err.println("servers line: the list doesn't serve the key its certificate file holds (is it running? was the file changed "
          + "since it started?): a pin from the file would be wrong");
      return 1;
    }

    HexFormat hex = HexFormat.of();
    byte[] p384 = settings.staticKeys().p384Public();
    byte[] kem = settings.staticKeys().kemPublic();
    Reply keys = api(tls, "GET", "/v1/relay-keys?region=" + c.region(), (String) null);
    String expected = "{\"region\":\"" + c.region() + "\",\"p384\":\"" + hex.formatHex(p384) + "\",\"mlkem\":\"" + hex.formatHex(kem) + "\"}";

    if (keys.status() != 200 || !keys.body().equals(expected)) {
      System.err.println("servers line: the list's GET /v1/relay-keys doesn't give the static keys this relay's settings hold");
      return 1;
    }

    MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
    sha384.update("AVPX relay keys v2".getBytes(StandardCharsets.US_ASCII));
    sha384.update(p384);
    sha384.update(kem);
    String id = hex.formatHex(sha384.digest());
    String pin = hex.formatHex(MessageDigest.getInstance("SHA-256").digest(spki));
    System.out.print("# " + name + ": AVPx Dedicated Server " + deployedCommit() + ", made " + LocalDate.now(ZoneOffset.UTC) + " (UTC)\n"
        + name + "\t" + address + ":" + settings.list().port() + "\t" + pin + "\t" + address + ":" + settings.controlPort() + "\t" + id
        + "\n");
    System.out.flush();
    return 0;
  }

  // A servers.cfg name (#175): 1 to 31 characters of printable ASCII, so no tab; and here, also no space at either end (a reader that
  // trims would see another name) and no # first (a line starting with # is a comment, and the game would never read it)
  static boolean isLineName(String name) {
    if (name == null || name.isEmpty() || name.length() > 31 || name.charAt(0) == ' ' || name.charAt(0) == '#'
        || name.charAt(name.length() - 1) == ' ') {
      return false;
    }

    for (int i = 0; i < name.length(); i++) {
      if (name.charAt(i) < 32 || name.charAt(i) > 126) {
        return false;
      }
    }

    return true;
  }

  // One plain IPv4 address a server can have, as the game's IsUsableAddress takes it (relay_list.cpp) and #175's line allows it: four
  // whole numbers 0 to 255 with no 0 in front, and not 0.x.x.x, nor 224 and up (multicast, 240/4, broadcast), nor 100.64/10 (a carrier's
  // NAT: never a player's own network). A private, loopback or link-local address is printed: the game takes one in an added line only.
  static boolean isUsableIpv4(String address) {
    if (address == null || !Pattern.matches("(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}", address)) {
      return false;
    }

    // Each part worked out digit by digit (the pattern has held it to 1 to 3 digits), with no parse that could throw
    String[] parts = address.split("\\.");
    int[] part = new int[parts.length];

    for (int i = 0; i < parts.length; i++) {
      for (char c : parts[i].toCharArray()) {
        part[i] = part[i] * 10 + (c - '0');
      }

      if (part[i] > 255) {
        return false;
      }
    }

    return part[0] != 0 && part[0] < 224 && !(part[0] == 100 && part[1] >= 64 && part[1] <= 127);
  }

  // The public key the list serves now, as the DER of its SubjectPublicKeyInfo, asked over TLS on 127.0.0.1 with the list's own
  // certificate as the only one trusted: null if the list doesn't answer, or serves another
  private static byte[] servedKey(SSLContext context) {
    try (Socket raw = new Socket(loopback(), c.list());
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(raw, c.name(), c.list(), true)) {
      SSLParameters parameters = tls.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      tls.setSSLParameters(parameters);
      tls.setSoTimeout(10000);
      tls.startHandshake();
      return tls.getSession().getPeerCertificates()[0].getPublicKey().getEncoded();
    } catch (IOException e) {
      return null;
    }
  }

  // The commit this machine runs: what /opt/avpx/current points at, a folder named by its commit (deploy/remote-deploy.sh), or "an
  // unknown commit" where it's not that (a server put together by hand)
  private static String deployedCommit() {
    try {
      String folder = Path.of("/opt/avpx/current").toRealPath().getFileName().toString();
      return Pattern.matches("[0-9a-f]{40}", folder) ? folder : "an unknown commit";
    } catch (IOException e) {
      return "an unknown commit";
    }
  }

  public static void main(String[] args) throws Exception {
    List<String> words = Arrays.asList(args);

    // Two identities for a version 2 game (SmokeIdentities.java), and nothing else
    if (words.contains("--make-identities")) {
      String file = after(words, "--make-identities");
      System.exit(file != null && SmokeIdentities.make(Path.of(file)) ? 0 : 1);
    }

    if (words.contains("--installed")) {
      Settings settings = Settings.read(INSTALLED_SETTINGS);

      // This machine's servers.cfg line, and nothing else: --servers-line <name> <public IPv4>
      int lineAt = words.indexOf("--servers-line");

      if (lineAt >= 0) {
        c = installed(settings, words);
        boolean given = lineAt + 2 < words.size();
        System.exit(serversLine(settings, given ? words.get(lineAt + 1) : null, given ? words.get(lineAt + 2) : null));
      }

      // The two identities' access requests, to this machine's own list (SmokeIdentities.java), and nothing else
      String requestFor = after(words, "--request-access");

      if (requestFor != null) {
        c = installed(settings, words);
        requestAccess(Path.of(requestFor));
        finish();
        return;
      }

      // A version 2 relay speaks only version 2, so its checks are SmokeV2's (see the top), after the list's answer for its keys
      if (settings.protocol() == 2) {
        c = installed(settings, words);
        relayKeys(settings);
        String identities = after(words, "--identities");
        SmokeV2.run(settings, identities == null ? null : Path.of(identities));
        finish();
        return;
      }

      c = installed(settings, words);
    }

    boolean withList = c.certificate() != null;
    boolean withLog = c.log() != null && !words.contains("--without-log");
    SSLContext tls = withList ? trustingOnly(c.certificate()) : null;

    if (withList ? !listAnswers(tls) : !relayAnswers()) {
      finish();
      return;
    }

    try (DatagramSocket host = udp(); DatagramSocket joiner = udp(); DatagramSocket stranger = udp()) {
      // Echo: 3 times, 100 ms apart, as the host's game would
      double best = Double.MAX_VALUE;

      for (int i = 1; i <= 3; i++) {
        byte[] mine = random(16);
        long t0 = System.nanoTime();
        Got back = ask(host, c.control(), msg(ECHO, mine, null, 0, i));
        double ms = (System.nanoTime() - t0) / 1e6;
        Read m = back == null ? null : read(back.data());
        check(m != null && m.type() == ECHO_BACK && MessageDigest.isEqual(m.secret(), mine) && m.number() == i && back.data().length == 64
            && back.fromPort() == c.control(), "ECHO " + i + " comes back as ECHO_BACK, the same 64 bytes' worth, from the control port",
            String.format(Locale.ROOT, "%.2f ms", ms));
        best = Math.min(best, ms);
        pause(100);
      }

      hostMs = Math.max(1, Math.round(best));

      // The host opens a room
      Read c1 = readOrNothing(ask(host, c.control(), msg(HOST_OPEN)));
      check(c1.type() == COOKIE, "HOST_OPEN first gets a COOKIE");
      Read opened = readOrNothing(ask(host, c.control(), msg(HOST_OPEN, c1.secret(), null, 0, 0)));
      check(opened.type() == HOST_OPENED && CODE.matcher(opened.code()).matches() && !allZero(opened.pass())
          && Math.abs(opened.passTime() - System.currentTimeMillis() / 1000.0) < 5 && allZero(opened.tail()),
          "HOST_OPENED: a token, a code, a pass and a pass time of now");
      byte[] token = opened.secret();
      String code = opened.code();
      String pass = HexFormat.of().formatHex(opened.pass());
      String owner = "";

      if (withList) {
        // The host lists it
        Reply posted = api(tls, "POST", "/v1/games", listing(null, code, pass, opened.passTime(), 1));
        Matcher ownerFound = OWNER.matcher(posted.body());
        check(posted.status() == 201 && ownerFound.matches(), "POST /v1/games with the pass: 201 and an owner key");
        owner = ownerFound.matches() ? ownerFound.group(1) : "";
        Reply shown = api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null);
        check(games(shown) == 1 && shown.body().contains("\"region\":\"" + c.region() + "\",\"code\":\"" + code + "\",\"name\":\"Smoke test\"")
            && shown.body().contains("\"levelNumber\":12") && shown.body().contains("\"version\":" + VERSION + ",\"id\":\"" + HOST_ID + "\"")
            && !shown.body().contains(owner) && !shown.body().contains(pass),
            "the listing shows, with its host's id and no owner key or pass in it");
      } else {
        // No list here to check the pass, so it's checked by hand: this relay's own, for its region
        check(MessageDigest.isEqual(opened.pass(), passFor(passKey, c.region(), code, opened.passTime())),
            "the pass is this relay's own, for region " + c.region());
      }

      // A joiner joins
      Read c2 = readOrNothing(ask(joiner, c.control(), msg(JOIN, null, code, 0, 0)));
      check(c2.type() == COOKIE, "JOIN first gets a COOKIE");
      Read joined = readOrNothing(ask(joiner, c.control(), msg(JOIN, c2.secret(), code, 0, 0)));
      check(joined.type() == JOIN_PORT && joined.port() >= c.firstRelayPort() && joined.port() <= c.lastRelayPort() && joined.code().equals(code),
          "JOIN_PORT: a ticket and a relay port", "port " + joined.port());
      byte[] ticket = joined.secret();
      int port = joined.port();

      // The joiner's hello claims its port, and only then is the host told (PROTOCOL.md section 2). A relay from before 2026-11-09
      // told the host at the JOIN; its NEW_JOINER is waiting by now, so this passes against both.
      send(joiner, port, msg(JOINER_HELLO, ticket, null, 0, 0));
      Read note = readOrNothing(next(host, 1000));
      check(note.type() == NEW_JOINER && note.port() == joined.port() && MessageDigest.isEqual(note.secret(), token),
          "the joiner's hello claims its port, and the host hears NEW_JOINER with that port and its token");

      send(host, port, msg(HOST_HELLO, token, null, port, 0));
      Got ready = next(joiner, 1000);
      check(ready != null && readOrNothing(ready).type() == READY && ready.fromPort() == port,
          "both hellos, and READY comes to the joiner from its port");

      // 100 game-sized packets each way, byte for byte
      List<DatagramSocket[]> ways = List.of(new DatagramSocket[] {joiner, host}, new DatagramSocket[] {host, joiner});
      List<String> names = List.of("joiner to host", "host to joiner");

      for (int w = 0; w < 2; w++) {
        DatagramSocket from = ways.get(w)[0];
        DatagramSocket to = ways.get(w)[1];
        Map<Integer, byte[]> sent = new HashMap<>();

        for (int i = 0; i < 100; i++) {
          byte[] p = random(20 + RANDOM.nextInt(1380));
          p[0] = (byte) i;
          p[1] = (byte) (i >>> 8);
          p[2] = 0;
          p[3] = 0;
          p[4] = (byte) 0xee;   // never AVPR, so a packet is never taken for a message
          sent.put(i, p);
          send(from, port, p);
        }

        int same = 0;
        int fromRelay = 0;

        for (int k = 0; k < 100; k++) {
          Got got = next(to, 2000);

          if (got == null) {
            break;
          }

          int i = got.data().length >= 4 ? (got.data()[0] & 0xff) | ((got.data()[1] & 0xff) << 8) : -1;

          if (sent.containsKey(i) && MessageDigest.isEqual(sent.get(i), got.data())) {
            same++;
            sent.remove(i);
          }

          if (got.fromPort() == port) {
            fromRelay++;
          }
        }

        check(same == 100 && fromRelay == 100, "100 packets " + names.get(w) + ", every one arrived byte for byte, from the relay's port",
            same + " same, " + fromRelay + " from port " + port);
      }

      // Keep and renew
      Read kept = readOrNothing(ask(host, c.control(), msg(HOST_KEEP, token, null, 0, 0)));
      check(kept.type() == HOST_KEPT && kept.number() == 1 && !allZero(kept.pass()), "HOST_KEPT: 1 joiner, and a fresh pass");
      String freshPass = HexFormat.of().formatHex(kept.pass());

      if (withList) {
        Reply put = api(tls, "PUT", "/v1/games", listing(owner, code, freshPass, kept.passTime(), 2));
        check(put.status() == 204, "PUT with the owner key and the fresh pass: 204");
      }

      // Hostile packets, from a third socket
      byte[] tooLong = new byte[65];
      Arrays.fill(tooLong, (byte) 1);
      send(stranger, c.control(), tooLong);
      byte[] wrongMagic = msg(ECHO, random(16), null, 0, 0);
      wrongMagic[0] = 0x42;
      send(stranger, c.control(), wrongMagic);
      byte[] huge = new byte[1600];
      Arrays.fill(huge, (byte) 2);
      send(stranger, c.control(), huge);
      send(stranger, c.control(), msg(ECHO_BACK, random(16), null, 0, 1));
      byte[] keptForged = msg(HOST_KEPT, random(16), null, 0, 0);
      keptForged[40] = 9;
      send(stranger, c.control(), keptForged);
      send(stranger, c.control(), msg(JOIN, null, code, 5, 0));
      check(next(stranger, 500) == null,
          "six bad control packets (65 bytes, wrong magic, 1,600 bytes, an ECHO_BACK, a HOST_KEPT, a JOIN with a port) get no answer");
      Read refused = readOrNothing(ask(stranger, c.control(), msg(HOST_KEEP, random(16), null, 0, 0)));
      check(refused.type() == REFUSED && refused.number() == 1, "a HOST_KEEP with a wrong token: REFUSED 1");
      send(stranger, port, "a stranger on the joiner's port".getBytes(StandardCharsets.US_ASCII));
      check(next(host, 500) == null && next(joiner, 300) == null, "a stranger's packet on the joiner's port reaches nobody");

      if (withList) {
        // Hostile HTTPS
        check(api(tls, "POST", "/v1/games", listing(null, "ZZZZ2222", HexFormat.of().formatHex(random(16)), opened.passTime(), 1)).status() == 403,
            "POST with a forged pass: 403");
        byte[] spaces = new byte[2048];
        Arrays.fill(spaces, (byte) 0x20);
        check(api(tls, "POST", "/v1/games", spaces).status() == 413, "a 2 KB body: 413");
        check(api(tls, "POST", "/v1/games", "{\"region\":").status() == 400, "a body that isn't JSON: 400");
        check(api(tls, "PUT", "/v1/games", listing("f".repeat(32), code, freshPass, kept.passTime(), 1)).status() == 403,
            "PUT with the wrong owner key: 403");
        pause(1100);
        check(api(tls, "GET", "/v1/games?version=" + VERSION + "?x", (byte[]) null).status() == 400, "a query with a second ?: 400");

        // The end of the game
        pause(1100);
        check(api(tls, "DELETE", "/v1/games", "{\"region\":\"" + c.region() + "\",\"code\":\"" + code + "\",\"owner\":\"" + owner + "\"}").status() == 204,
            "DELETE with the owner key: 204");
        pause(1100);
        check(games(api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null)) == 0, "the listing is gone");
      }

      send(host, c.control(), msg(HOST_CLOSE, token, null, 0, 0));
      pause(100);
      Read c3 = readOrNothing(ask(joiner, c.control(), msg(JOIN, null, code, 0, 0)));
      Read after = readOrNothing(ask(joiner, c.control(), msg(JOIN, c3.secret(), code, 0, 0)));
      check(after.type() == REFUSED && after.number() == 1, "after HOST_CLOSE, a JOIN gets REFUSED 1");
      check(notLoopback == 0, "every packet came from 127.0.0.1");

      if (withLog) {
        checkLog(code, token, ticket, owner, pass);
      }
    }

    if (!withList) {
      System.out.println("NOT RUN  the list's checks over HTTPS, and the log's: this machine's settings have no list (a relay-only machine)."
          + " This is a run of the relay's checks only.");
    }

    finish();
  }

  // Waits for the list, up to 15 s, then its first checks over HTTPS; false if it never answered
  private static boolean listAnswers(SSLContext tls) throws Exception {
    Reply relays = null;

    for (int i = 0; i < 75 && relays == null; i++) {
      Reply r = api(tls, "GET", "/v1/relays", (byte[]) null);

      if (r.status() == 200) {
        relays = r;
      } else {
        pause(200);
      }
    }

    check(relays != null, "the list answers over HTTPS");

    if (relays == null) {
      return false;
    }

    Reply noCa = api(SSLContext.getDefault(), "GET", "/v1/relays", (byte[]) null);
    check(noCa.status() == 0 && noCa.error().matches("(?s).*(SSLHandshake|PKIX|certif).*"),
        "without the test certificate, the client refuses the server", noCa.error());
    check(relays.body().equals(c.relaysText()), "GET /v1/relays", relays.body());
    check(relays.headers().containsKey("strict-transport-security") && "nosniff".equals(relays.headers().get("x-content-type-options")),
        "HSTS and nosniff headers");
    Reply empty = api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null);
    check(empty.status() == 200 && games(empty) == 0, "GET /v1/games, empty at first");
    return true;
  }

  // A relay-only machine: waits for its control port to answer an ECHO, up to 15 s; false if it never did
  private static boolean relayAnswers() throws Exception {
    boolean answered = false;

    try (DatagramSocket probe = udp()) {
      long until = System.nanoTime() + 15_000_000_000L;

      while (!answered && System.nanoTime() < until) {
        byte[] mine = random(16);
        Read m = readOrNothing(ask(probe, c.control(), msg(ECHO, mine, null, 0, 0)));
        answered = m.type() == ECHO_BACK && MessageDigest.isEqual(m.secret(), mine);
      }
    }

    check(answered, "the relay answers on its control port");
    return answered;
  }

  // A pass, made by hand as PROTOCOL.md section 3 says: HMAC-SHA-256, with the relay's pass key, of "AVPX-PASS-1", the region, a 0 byte,
  // the room's code and the pass time (8 bytes, little-endian), cut to 16 bytes
  static byte[] passFor(byte[] key, String region, String code, long passTime) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(key, "HmacSHA256"));
    mac.update("AVPX-PASS-1".getBytes(StandardCharsets.US_ASCII));
    mac.update(region.getBytes(StandardCharsets.US_ASCII));
    mac.update((byte) 0);
    mac.update(code.getBytes(StandardCharsets.US_ASCII));

    for (int i = 0; i < 8; i++) {
      mac.update((byte) (passTime >>> (8 * i)));
    }

    return Arrays.copyOf(mac.doFinal(), 16);
  }

  // The config of the server installed on this machine, from its own settings, read as the server reads them
  private static Config installed(Settings settings, List<String> words) throws Exception {
    Settings.ListSettings list = settings.list();
    int[] ports = settings.relayPorts();

    // A relay-only machine: the relay's checks only (see the top), with its pass key to check its passes by hand
    if (list == null) {
      passKey = settings.passKey();
      return new Config(null, 0, settings.controlPort(), ports[0], ports[ports.length - 1], settings.region(), null, null, null);
    }

    String name = null;
    StringBuilder relays = new StringBuilder("{\"relays\":[");

    for (int i = 0; i < list.relays().size(); i++) {
      Listings.Relay r = list.relays().get(i);
      relays.append(i > 0 ? "," : "").append("{\"region\":\"").append(r.region()).append("\",\"host\":\"").append(r.host())
          .append("\",\"port\":").append(r.port()).append('}');

      if (r.region().equals(settings.region())) {
        name = r.host();
      }
    }

    relays.append("]}");
    int given = words.indexOf("--name");

    if (given >= 0) {
      name = given + 1 < words.size() && DNS_NAME.matcher(words.get(given + 1)).matches() ? words.get(given + 1) : null;

      if (name == null) {
        throw new IllegalArgumentException("--name needs a DNS name after it");
      }
    }

    return new Config(name, list.port(), settings.controlPort(), ports[0], ports[ports.length - 1], settings.region(), relays.toString(),
        Path.of(list.certFile()), null);
  }

  // The log: wait for the once-a-minute lines, up to 75 s, then the six checks of what they say and what they never hold
  private static void checkLog(String code, byte[] token, byte[] ticket, String owner, String pass) throws Exception {
    String text = "";

    for (int i = 0; i < 75; i++) {
      text = Files.exists(c.log()) ? Files.readString(c.log(), StandardCharsets.UTF_8) : "";

      if (text.contains("relay: in the last") && text.contains("list: in the last")) {
        break;
      }

      pause(1000);
    }

    System.out.println("\n----- server.log\n" + text + "----- end of server.log\n");
    String relayLine = lineWith(text, "relay: in the last");
    String listLine = lineWith(text, "list: in the last");
    check(relayLine.matches(".*1 games opened, 1 closed.*"), "the relay line counts 1 game opened and 1 closed");
    check(relayLine.matches(".* 1 joins, 1 joiners ready, 2 refusals, 3 echoes;.*"),
        "and 1 join (the one after the close was refused), 2 refusals, 3 echoes");
    check(relayLine.contains("forwarded 200 packets (100 joiners to hosts, 100 hosts to joiners)"), "and 200 packets forwarded, 100 each way");
    check(relayLine.matches(".*dropped 1 too big, 0 over a limit, 5 not a message, 1 from strangers.*"),
        "and the drops: 1 too big, 5 not a message, 1 stranger");
    check(listLine.matches(".*1 games listed, 1 renewals, 1 taken down, 0 ended unrenewed; 1 passes refused.*"),
        "the list line: 1 listed, 1 renewal, 1 taken down, 1 pass refused (the forged one)");
    List<String> secrets = List.of(HOST, code, HexFormat.of().formatHex(token), HexFormat.of().formatHex(ticket), owner, pass, "Smoke test");
    boolean none = true;

    for (String secret : secrets) {
      none &= !text.contains(secret);
    }

    check(none && !Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+").matcher(text).find(),
        "the log holds no address, code, token, ticket, owner key, pass or name");
  }

  private static String lineWith(String text, String start) {
    for (String line : text.split("\n")) {
      int at = line.indexOf(start);

      if (at >= 0) {
        return line.substring(at);
      }
    }

    return "";
  }

  static void finish() {
    System.out.println("\n" + passed + " passed, " + failed + " failed");
    System.exit(failed == 0 && passed > 0 ? 0 : 1);
  }
}
