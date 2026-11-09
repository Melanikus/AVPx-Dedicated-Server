package avpx.tools;

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
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
// SAFE TO RUN ANYWHERE: it sends only to 127.0.0.1, and binds only there, so it can test only a server on the same machine and can never be
// pointed at anyone else's. HTTPS trusts only list-test.pem, and checks the certificate is for "localhost" (the name the relays' list gives).
//
// INDEPENDENT OF THE SERVER: it uses none of the server's code. Its messages are written by hand from PROTOCOL.md section 2, and the
// list's answers are compared as exact text, so a fault in the server's own encoder or JSON can't hide itself here.
//
// What it expects is the server started with the settings the checks name: region "virginia", the list on 8443, the control port 27500,
// relay ports 27501 to 27564, a relay whose host is "localhost", and the log in server.log.
public final class Smoke {
  private Smoke() {
  }

  private static final String HOST = "127.0.0.1";
  private static final String NAME = "localhost";
  private static final int LIST = 8443;
  private static final int CONTROL = 27500;
  private static final int FIRST_RELAY_PORT = 27501;
  private static final int LAST_RELAY_PORT = 27564;
  private static final int VERSION = 113;
  private static final Path CERTIFICATE = Path.of("list-test.pem");
  private static final Path LOG = Path.of("server.log");

  // The relay's message types, by their numbers (PROTOCOL.md section 2)
  private static final int ECHO = 14;
  private static final int ECHO_BACK = 15;
  private static final int HOST_OPEN = 1;
  private static final int HOST_OPENED = 2;
  private static final int HOST_KEEP = 3;
  private static final int HOST_KEPT = 4;
  private static final int HOST_CLOSE = 5;
  private static final int JOIN = 6;
  private static final int JOIN_PORT = 7;
  private static final int NEW_JOINER = 8;
  private static final int HOST_HELLO = 9;
  private static final int JOINER_HELLO = 10;
  private static final int READY = 11;
  private static final int REFUSED = 12;
  private static final int COOKIE = 13;

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Pattern CODE = Pattern.compile("[2-9A-HJ-NP-Z]{8}");
  private static final Pattern OWNER = Pattern.compile("\\{\"owner\":\"([0-9a-f]{32})\"\\}");

  private static int passed;
  private static int failed;
  private static int notLoopback;

  // The host's round trip to the relay, from its best echo, which its listing says (hostMs)
  private static long hostMs = 1;

  private static void check(boolean ok, String name, String more) {
    if (ok) {
      passed++;
    } else {
      failed++;
    }

    System.out.println((ok ? "PASS" : "FAIL") + "  " + name + (more.isEmpty() ? "" : "  (" + more + ")"));
  }

  private static void check(boolean ok, String name) {
    check(ok, name, "");
  }

  private static void pause(long ms) throws InterruptedException {
    Thread.sleep(ms);
  }

  private static byte[] random(int n) {
    byte[] out = new byte[n];
    RANDOM.nextBytes(out);
    return out;
  }

  // ----- The relay's 64-byte messages, by hand (PROTOCOL.md section 2): little-endian numbers

  private static byte[] msg(int type, byte[] secret, String code, int port, int number) {
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

  private static byte[] msg(int type) {
    return msg(type, null, null, 0, 0);
  }

  // A message's fields, read by hand; null if it isn't one
  private record Read(int type, byte[] secret, String code, int port, int number, byte[] pass, long passTime, byte[] tail) {
  }

  private static Read read(byte[] b) {
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

  private static boolean allZero(byte[] b) {
    for (byte x : b) {
      if (x != 0) {
        return false;
      }
    }

    return true;
  }

  // ----- UDP, on 127.0.0.1 only

  private record Got(byte[] data, int fromPort) {
  }

  private static DatagramSocket udp() throws IOException {
    DatagramSocket s = new DatagramSocket(new InetSocketAddress(loopback(), 0));
    s.setReceiveBufferSize(1 << 20);
    return s;
  }

  private static InetAddress loopback() {
    return Inet4Address.ofLiteral(HOST);
  }

  private static void send(DatagramSocket s, int port, byte[] data) throws IOException {
    s.send(new DatagramPacket(data, data.length, new InetSocketAddress(loopback(), port)));
  }

  // The next packet s gets within ms, or null
  private static Got next(DatagramSocket s, int ms) throws IOException {
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

  private static Got ask(DatagramSocket s, int port, byte[] data) throws IOException {
    send(s, port, data);
    return next(s, 1000);
  }

  // The message in what came back, or an empty one (type 0) if nothing did, so a check fails rather than the run stopping
  private static Read readOrNothing(Got got) {
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
    try (Socket raw = new Socket(loopback(), LIST);
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(raw, NAME, LIST, true)) {
      SSLParameters parameters = tls.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      tls.setSSLParameters(parameters);
      tls.setSoTimeout(10000);
      tls.startHandshake();

      StringBuilder head = new StringBuilder(method + " " + path + " HTTP/1.1\r\nHost: " + NAME + "\r\n");

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
    return "{" + (owner == null ? "" : "\"owner\":\"" + owner + "\",") + "\"region\":\"virginia\",\"code\":\"" + code + "\",\"pass\":\"" + pass
        + "\",\"passTime\":" + passTime + ",\"name\":\"Smoke test\",\"level\":\"Genshd1\",\"mode\":\"Coop\",\"gameStyle\":3,\"levelNumber\":12,"
        + "\"coopLobby\":0,\"players\":" + players + ",\"maxPlayers\":4,\"version\":" + VERSION + ",\"hostMs\":" + hostMs + "}";
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

  public static void main(String[] args) throws Exception {
    boolean withLog = !Arrays.asList(args).contains("--without-log");
    SSLContext tls = trustingOnly(CERTIFICATE);

    // Wait for the server: up to 15 s
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
      finish();
      return;
    }

    Reply noCa = api(SSLContext.getDefault(), "GET", "/v1/relays", (byte[]) null);
    check(noCa.status() == 0 && noCa.error().matches("(?s).*(SSLHandshake|PKIX|certif).*"),
        "without the test certificate, the client refuses the server", noCa.error());
    check(relays.body().equals("{\"relays\":[{\"region\":\"virginia\",\"host\":\"localhost\",\"port\":" + CONTROL + "}]}"), "GET /v1/relays",
        relays.body());
    check(relays.headers().containsKey("strict-transport-security") && "nosniff".equals(relays.headers().get("x-content-type-options")),
        "HSTS and nosniff headers");
    Reply empty = api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null);
    check(empty.status() == 200 && games(empty) == 0, "GET /v1/games, empty at first");

    try (DatagramSocket host = udp(); DatagramSocket joiner = udp(); DatagramSocket stranger = udp()) {
      // Echo: 3 times, 100 ms apart, as the host's game would
      double best = Double.MAX_VALUE;

      for (int i = 1; i <= 3; i++) {
        byte[] mine = random(16);
        long t0 = System.nanoTime();
        Got back = ask(host, CONTROL, msg(ECHO, mine, null, 0, i));
        double ms = (System.nanoTime() - t0) / 1e6;
        Read m = back == null ? null : read(back.data());
        check(m != null && m.type() == ECHO_BACK && Arrays.equals(m.secret(), mine) && m.number() == i && back.data().length == 64
            && back.fromPort() == CONTROL, "ECHO " + i + " comes back as ECHO_BACK, the same 64 bytes' worth, from the control port",
            String.format(Locale.ROOT, "%.2f ms", ms));
        best = Math.min(best, ms);
        pause(100);
      }

      hostMs = Math.max(1, Math.round(best));

      // The host opens a room
      Read c1 = readOrNothing(ask(host, CONTROL, msg(HOST_OPEN)));
      check(c1.type() == COOKIE, "HOST_OPEN first gets a COOKIE");
      Read opened = readOrNothing(ask(host, CONTROL, msg(HOST_OPEN, c1.secret(), null, 0, 0)));
      check(opened.type() == HOST_OPENED && CODE.matcher(opened.code()).matches() && !allZero(opened.pass())
          && Math.abs(opened.passTime() - System.currentTimeMillis() / 1000.0) < 5 && allZero(opened.tail()),
          "HOST_OPENED: a token, a code, a pass and a pass time of now");
      byte[] token = opened.secret();
      String code = opened.code();
      String pass = HexFormat.of().formatHex(opened.pass());

      // The host lists it
      Reply posted = api(tls, "POST", "/v1/games", listing(null, code, pass, opened.passTime(), 1));
      Matcher ownerFound = OWNER.matcher(posted.body());
      check(posted.status() == 201 && ownerFound.matches(), "POST /v1/games with the pass: 201 and an owner key");
      String owner = ownerFound.matches() ? ownerFound.group(1) : "";
      Reply shown = api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null);
      check(games(shown) == 1 && shown.body().contains("\"region\":\"virginia\",\"code\":\"" + code + "\",\"name\":\"Smoke test\"")
          && shown.body().contains("\"levelNumber\":12") && !shown.body().contains(owner) && !shown.body().contains(pass),
          "the listing shows, with no owner key or pass in it");

      // A joiner joins
      Read c2 = readOrNothing(ask(joiner, CONTROL, msg(JOIN, null, code, 0, 0)));
      check(c2.type() == COOKIE, "JOIN first gets a COOKIE");
      Read joined = readOrNothing(ask(joiner, CONTROL, msg(JOIN, c2.secret(), code, 0, 0)));
      check(joined.type() == JOIN_PORT && joined.port() >= FIRST_RELAY_PORT && joined.port() <= LAST_RELAY_PORT && joined.code().equals(code),
          "JOIN_PORT: a ticket and a relay port", "port " + joined.port());
      Read note = readOrNothing(next(host, 1000));
      check(note.type() == NEW_JOINER && note.port() == joined.port() && Arrays.equals(note.secret(), token),
          "the host hears NEW_JOINER with that port and its token");
      byte[] ticket = joined.secret();
      int port = joined.port();

      send(host, port, msg(HOST_HELLO, token, null, port, 0));
      pause(50);
      Got ready = ask(joiner, port, msg(JOINER_HELLO, ticket, null, 0, 0));
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

          if (sent.containsKey(i) && Arrays.equals(sent.get(i), got.data())) {
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
      Read kept = readOrNothing(ask(host, CONTROL, msg(HOST_KEEP, token, null, 0, 0)));
      check(kept.type() == HOST_KEPT && kept.number() == 1 && !allZero(kept.pass()), "HOST_KEPT: 1 joiner, and a fresh pass");
      String freshPass = HexFormat.of().formatHex(kept.pass());
      Reply put = api(tls, "PUT", "/v1/games", listing(owner, code, freshPass, kept.passTime(), 2));
      check(put.status() == 204, "PUT with the owner key and the fresh pass: 204");

      // Hostile packets, from a third socket
      byte[] tooLong = new byte[65];
      Arrays.fill(tooLong, (byte) 1);
      send(stranger, CONTROL, tooLong);
      byte[] wrongMagic = msg(ECHO, random(16), null, 0, 0);
      wrongMagic[0] = 0x42;
      send(stranger, CONTROL, wrongMagic);
      byte[] huge = new byte[1600];
      Arrays.fill(huge, (byte) 2);
      send(stranger, CONTROL, huge);
      send(stranger, CONTROL, msg(ECHO_BACK, random(16), null, 0, 1));
      byte[] keptForged = msg(HOST_KEPT, random(16), null, 0, 0);
      keptForged[40] = 9;
      send(stranger, CONTROL, keptForged);
      send(stranger, CONTROL, msg(JOIN, null, code, 5, 0));
      check(next(stranger, 500) == null,
          "six bad control packets (65 bytes, wrong magic, 1,600 bytes, an ECHO_BACK, a HOST_KEPT, a JOIN with a port) get no answer");
      Read refused = readOrNothing(ask(stranger, CONTROL, msg(HOST_KEEP, random(16), null, 0, 0)));
      check(refused.type() == REFUSED && refused.number() == 1, "a HOST_KEEP with a wrong token: REFUSED 1");
      send(stranger, port, "a stranger on the joiner's port".getBytes(StandardCharsets.US_ASCII));
      check(next(host, 500) == null && next(joiner, 300) == null, "a stranger's packet on the joiner's port reaches nobody");

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
      check(api(tls, "DELETE", "/v1/games", "{\"region\":\"virginia\",\"code\":\"" + code + "\",\"owner\":\"" + owner + "\"}").status() == 204,
          "DELETE with the owner key: 204");
      pause(1100);
      check(games(api(tls, "GET", "/v1/games?version=" + VERSION, (byte[]) null)) == 0, "the listing is gone");
      send(host, CONTROL, msg(HOST_CLOSE, token, null, 0, 0));
      pause(100);
      Read c3 = readOrNothing(ask(joiner, CONTROL, msg(JOIN, null, code, 0, 0)));
      Read after = readOrNothing(ask(joiner, CONTROL, msg(JOIN, c3.secret(), code, 0, 0)));
      check(after.type() == REFUSED && after.number() == 1, "after HOST_CLOSE, a JOIN gets REFUSED 1");
      check(notLoopback == 0, "every packet came from 127.0.0.1");

      if (withLog) {
        checkLog(code, token, ticket, owner, pass);
      }
    }

    finish();
  }

  // The log: wait for the once-a-minute lines, up to 75 s, then the six checks of what they say and what they never hold
  private static void checkLog(String code, byte[] token, byte[] ticket, String owner, String pass) throws Exception {
    String text = "";

    for (int i = 0; i < 75; i++) {
      text = Files.exists(LOG) ? Files.readString(LOG, StandardCharsets.UTF_8) : "";

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

  private static void finish() {
    System.out.println("\n" + passed + " passed, " + failed + " failed");
    System.exit(failed == 0 && passed > 0 ? 0 : 1);
  }
}
