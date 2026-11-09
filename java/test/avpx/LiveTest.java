package avpx;

import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.liveTest;
import static avpx.testing.Tests.matches;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.text;
import static avpx.testing.Tests.throwsWith;

import avpx.list.Json;
import avpx.list.ListServer;
import avpx.list.Listings;
import avpx.relay.Message;
import avpx.relay.Protocol;
import avpx.relay.Protocol.Type;
import avpx.relay.RandomBytes;
import avpx.relay.RelayCore;
import avpx.relay.RelaySockets;
import avpx.testing.Tests;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.stream.Stream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

// The tests with real sockets: the relay's UDP ports and the list's HTTPS server, on the loopback address (127.0.0.1) only, so nothing goes
// to any network. They run only when AVPX_LIVE=1 is set (GitHub's check sets it, and there a live test that doesn't run fails). Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server; the first four ported test for test from test/live.test.js, the rest new.
//
// Unlike the Node tests, the list is tested over real TLS, with a certificate for 127.0.0.1 that build.sh makes fresh with the JDK's own
// keytool (build/test-tls.p12) and throws away with build/. The tests write it out as the two PEM files certbot would, so the server reads
// them just as it reads its real ones. No key is ever kept in the repository.
public final class LiveTest {
  private LiveTest() {
  }

  private static final String LOOPBACK = "127.0.0.1";
  private static final int CONTROL = 37500;
  private static final int[] PORTS = {37501, 37502};
  private static final String REGION = "virginia";
  private static final byte[] KEY = Tests.bytes(32, 0x5a);
  private static final int WAIT_MILLISECONDS = 1000;

  // The certificate build.sh made, and its random password
  private static final Path KEY_STORE = Path.of("build", "test-tls.p12");
  private static final Path KEY_STORE_PASSWORD = Path.of("build", "test-tls.password");

  private static RelayCore core(int[] ports) {
    return new RelayCore(CONTROL, ports, REGION, KEY, RandomBytes.secure(), new RelayCore.Limits(), System.currentTimeMillis());
  }

  private static InetAddress loopback() {
    return Inet4Address.ofLiteral(LOOPBACK);
  }

  private static DatagramSocket socket() throws IOException {
    DatagramSocket s = new DatagramSocket(new InetSocketAddress(loopback(), 0));
    s.setSoTimeout(WAIT_MILLISECONDS);
    return s;
  }

  // The next packet s gets, or null if none comes within a second
  private static byte[] next(DatagramSocket s) throws IOException {
    Got got = nextWithPort(s);
    return got == null ? null : got.data();
  }

  // A packet, and the port it came from
  private record Got(byte[] data, int fromPort) {
  }

  // The next packet s gets, with the port it came from, or null if none comes within a second
  private static Got nextWithPort(DatagramSocket s) throws IOException {
    DatagramPacket packet = new DatagramPacket(new byte[2048], 2048);

    try {
      s.receive(packet);
    } catch (SocketTimeoutException e) {
      return null;
    }

    byte[] out = new byte[packet.getLength()];
    System.arraycopy(packet.getData(), 0, out, 0, packet.getLength());
    return new Got(out, packet.getPort());
  }

  private static void sendTo(DatagramSocket s, int port, byte[] data) throws IOException {
    s.send(new DatagramPacket(data, data.length, new InetSocketAddress(loopback(), port)));
  }

  // Sends from s to a port, and waits for the next packet s gets (or null within a second)
  private static byte[] ask(DatagramSocket s, int port, byte[] data) throws IOException {
    sendTo(s, port, data);
    return next(s);
  }

  // ----- The list, over TLS

  private record Reply(int status, Map<String, String> headers, String body) {
  }

  // The test certificate's key store, its password read from the file build.sh wrote
  private static KeyStore keyStore(char[] password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");

    try (InputStream in = Files.newInputStream(KEY_STORE)) {
      store.load(in, password);
    }

    return store;
  }

  private static char[] password() throws IOException {
    return Files.readString(KEY_STORE_PASSWORD, StandardCharsets.US_ASCII).trim().toCharArray();
  }

  private static String pem(String what, byte[] der) {
    return "-----BEGIN " + what + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END " + what + "-----\n";
  }

  // The list's server on 127.0.0.1, any free port, with the test certificate written out as PEM files in a folder of its own
  private record Running(ListServer server, Path folder, SSLContext client) {
    void stop() throws IOException {
      server.stop();

      try (Stream<Path> files = Files.list(folder)) {
        for (Path f : files.toList()) {
          Files.delete(f);
        }
      }

      Files.delete(folder);
    }
  }

  private static Running listServer() throws Exception {
    return listServer(line -> { }, System::currentTimeMillis, () -> { });
  }

  // The same, with where its lines go, its clock, and what it does if a timer of its own fails, given
  private static Running listServer(Consumer<String> log, LongSupplier now, Runnable whenFailed) throws Exception {
    char[] password = password();
    KeyStore store = keyStore(password);
    PrivateKey key = (PrivateKey) store.getKey("avpx-test", password);
    Certificate certificate = store.getCertificate("avpx-test");
    Path folder = Files.createTempDirectory("avpx-tls-");
    Path certFile = folder.resolve("fullchain.pem");
    Path keyFile = folder.resolve("privkey.pem");
    Files.writeString(certFile, pem("CERTIFICATE", certificate.getEncoded()), StandardCharsets.US_ASCII);
    Files.writeString(keyFile, pem("PRIVATE KEY", key.getEncoded()), StandardCharsets.US_ASCII);

    Listings listings = new Listings(List.of(new Listings.Relay(REGION, "virginia.relay.example.net", CONTROL, KEY)), RandomBytes.secure(),
        System.currentTimeMillis());
    Settings.ListSettings settings = new Settings.ListSettings(LOOPBACK, 0, certFile.toString(), keyFile.toString(), List.of());
    ListServer server = ListServer.start(settings, listings, log, now, whenFailed);

    // The client trusts the test certificate, and only it
    KeyStore trusted = KeyStore.getInstance("PKCS12");
    trusted.load(null, null);
    trusted.setCertificateEntry("avpx-test", certificate);
    TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(trusted);
    SSLContext client = SSLContext.getInstance("TLS");
    client.init(null, trust.getTrustManagers(), null);
    return new Running(server, folder, client);
  }

  // A connection to the list that never says a word. It's a TLS connection, not a plain one, so nothing here reads a plain socket. It's
  // put on TLS's server side (setUseClientMode(false)): a server side waits for the other end to speak first, and so does the list's
  // server, so neither speaks, nothing is sent either way, and the handshake never begins. To the list it looks exactly like a client
  // that connects and then stays silent. Its credentials are the test certificate and key, as TLS's server side must have some, though
  // it never gets as far as using them.
  private static SSLSocket silent(Running list) throws Exception {
    char[] password = password();
    KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keys.init(keyStore(password), password);
    SSLContext waiting = SSLContext.getInstance("TLS");
    waiting.init(keys.getKeyManagers(), null, null);
    SSLSocket s = (SSLSocket) waiting.getSocketFactory().createSocket(LOOPBACK, list.server().port());
    s.setUseClientMode(false);
    return s;
  }

  // How long the list's server takes to close a silent connection, in milliseconds; the test fails if it's still open after "most". As
  // nothing is ever sent, its read can end only with the server's close: the end of the stream, or TLS saying the other end went away
  // before the handshake began.
  private static long closedAfter(SSLSocket s, int most) throws IOException {
    s.setSoTimeout(most);
    long started = System.nanoTime();
    boolean closed;

    try {
      closed = s.getInputStream().read() < 0;
    } catch (SocketTimeoutException e) {
      closed = false;
    } catch (IOException e) {
      closed = true;
    }

    long waited = (System.nanoTime() - started) / 1000000;
    ok(closed, "closed by the server, not still open after " + most + " ms (" + waited + " ms)");
    return waited;
  }

  // One request, over its own TLS connection, as the game sends one: the answer read to its end (the server closes after it)
  private static Reply request(Running list, String method, String path, String body, Map<String, String> extra) throws IOException {
    try (SSLSocket s = (SSLSocket) list.client().getSocketFactory().createSocket(LOOPBACK, list.server().port())) {
      // Like a game, the client checks the certificate is for the address it asked for (127.0.0.1), not only that it trusts it
      SSLParameters parameters = s.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      s.setSSLParameters(parameters);
      s.setSoTimeout(10000);
      StringBuilder head = new StringBuilder(method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n");

      for (Map.Entry<String, String> header : extra.entrySet()) {
        head.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
      }

      byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.US_ASCII);

      if (body != null) {
        head.append("Content-Type: application/json\r\nContent-Length: ").append(bytes.length).append("\r\n");
      }

      head.append("\r\n");
      OutputStream out = s.getOutputStream();
      out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
      out.write(bytes);
      out.flush();

      ByteArrayOutputStream got = new ByteArrayOutputStream();
      InputStream in = s.getInputStream();
      byte[] part = new byte[4096];

      for (int n = in.read(part); n >= 0; n = in.read(part)) {
        got.write(part, 0, n);
      }

      String text = got.toString(StandardCharsets.US_ASCII);
      int end = text.indexOf("\r\n\r\n");
      ok(end >= 0, "an answer with a head");
      String[] lines = text.substring(0, end).split("\r\n");
      String[] first = lines[0].split(" ");
      long status = first.length >= 2 ? Json.digitsValue(first[1], 999) : -1;
      ok(status > 0, "an answer that starts with HTTP/1.1 and a status that is a number");
      Map<String, String> headers = new LinkedHashMap<>();

      for (int i = 1; i < lines.length; i++) {
        int colon = lines[i].indexOf(':');
        headers.put(lines[i].substring(0, colon).toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
      }

      return new Reply((int) status, headers, text.substring(end + 4));
    }
  }

  private static Reply request(Running list, String method, String path) throws IOException {
    return request(list, method, path, null, Map.of());
  }

  private static Map<String, Object> json(String body) throws Json.Bad {
    return Json.readObject(latin1(body), 3);
  }

  public static void register() {
    liveTest("a whole game through the relay's real UDP ports", () -> {
      List<String> lines = new ArrayList<>();
      RelaySockets relay = RelaySockets.start(LOOPBACK, core(PORTS), line -> {
        synchronized (lines) {
          lines.add(line);
        }
      }, System::currentTimeMillis);

      try (DatagramSocket host = socket(); DatagramSocket joiner = socket()) {
        byte[] mine = latin1("sixteen bytes!!!");
        byte[] echo = Protocol.encode(Message.of(Type.ECHO).secret(mine).number(1));
        byte[] echoed = ask(host, CONTROL, echo);
        same(echoed.length, echo.length, "the echo comes back the same size");
        same(Protocol.decode(echoed).type(), Type.ECHO_BACK, "an ECHO_BACK");
        same(Protocol.decode(echoed).secret(), mine, "with the asker's own bytes");

        Message cookie = Protocol.decode(ask(host, CONTROL, Protocol.encode(Message.of(Type.HOST_OPEN))));
        same(cookie.type(), Type.COOKIE, "a cookie");
        Message opened = Protocol.decode(ask(host, CONTROL, Protocol.encode(Message.of(Type.HOST_OPEN).secret(cookie.secret()))));
        same(opened.type(), Type.HOST_OPENED, "the game");
        ok(opened.pass() != null && opened.passTime() > 0, "with a pass for the list");

        Message joinCookie = Protocol.decode(ask(joiner, CONTROL, Protocol.encode(Message.of(Type.JOIN).code(opened.code()))));
        Message joined = Protocol.decode(ask(joiner, CONTROL, Protocol.encode(Message.of(Type.JOIN).secret(joinCookie.secret())
            .code(opened.code()))));
        same(joined.type(), Type.JOIN_PORT, "a port of its own");

        // The joiner's hello claims the port, and only then is the host told which (PROTOCOL.md section 2)
        sendTo(joiner, joined.port(), Protocol.encode(Message.of(Type.JOINER_HELLO).secret(joined.secret())));
        Message newJoiner = Protocol.decode(next(host));
        same(newJoiner.port(), joined.port(), "once the joiner has said hello, the host is told which port");

        sendTo(host, joined.port(), Protocol.encode(Message.of(Type.HOST_HELLO).secret(opened.secret()).port(joined.port())));
        Message ready = Protocol.decode(next(joiner));
        same(ready.type(), Type.READY, "READY, to the joiner, once the host has said hello too");

        sendTo(joiner, joined.port(), latin1("an ENet packet"));
        Got passed = nextWithPort(host);

        // Nothing within a second ends the test here, with its reason, before anything of the packet is read
        if (passed == null) {
          throw new Tests.Failure("the joiner's packet never reached the host");
        }

        same(text(passed.data()), "an ENet packet", "the joiner's packet reaches the host, unchanged");
        same(passed.fromPort(), joined.port(), "from the joiner's own relay port, so the host sees each joiner as a peer of its own");
        same(ask(host, joined.port(), latin1("and its answer")), null, "the host's answer goes to the joiner, not back to the host");
      } finally {
        relay.stop();
      }

      synchronized (lines) {
        ok(lines.stream().anyMatch(l -> l.startsWith("relay: listening")), "it said it was listening");
        // As it stopped, it gave its counts: the echo, the game, the join, and one packet each way
        String last = lines.get(lines.size() - 1);
        matches(last, "^relay: in the last ", "its last line is its counts, given as it stopped");
        matches(last, "1 games opened, 0 closed, 0 ended unkept; 1 joins, 1 joiners ready, 0 refusals, 1 echoes;", "the game, its joiner and the echo");
        matches(last, "forwarded 2 packets \\(1 joiners to hosts, 1 hosts to joiners\\)", "and a packet each way");
      }
    });

    // The review's V1-3: an error nobody expected, in a turn of the relay's loop, stops the relay and says so; before, it ended the
    // relay's thread alone, with nobody told. Here the relay's clock throws from its second reading on, which is inside a turn.
    liveTest("the relay stops, and says so, when a turn of its loop throws something nobody expected", () -> {
      List<String> lines = new ArrayList<>();
      AtomicInteger readings = new AtomicInteger();
      RelaySockets relay = RelaySockets.start(LOOPBACK, core(PORTS), line -> {
        synchronized (lines) {
          lines.add(line);
        }
      }, () -> {
        if (readings.incrementAndGet() >= 2) {
          throw new IllegalStateException("words that must never be written: 198.51.100.10");
        }

        return System.currentTimeMillis();
      });

      for (int i = 0; i < 100 && !relay.failed(); i++) {
        Thread.sleep(50);
      }

      relay.stop();
      ok(relay.failed(), "it says it failed, so Main stops the server with 1, for systemd to start it again");

      synchronized (lines) {
        ok(lines.stream().anyMatch(l -> l.startsWith("relay: stopped by an error nobody expected, java.lang.IllegalStateException at ")),
            "its line names the error's kind and where it came from");
        ok(lines.stream().noneMatch(l -> l.contains("198.51.100.10")), "and never the error's words");
      }

      // Its ports were all closed as it stopped: they open again at once
      RelaySockets again = RelaySockets.start(LOOPBACK, core(PORTS), line -> { }, System::currentTimeMillis);
      again.stop();
    });

    // The same for the list: a timer whose task throws is never run again, and Java tells nobody. Here its clock throws once told to.
    liveTest("the list's timers stop, say so and tell the server, once, when one throws something nobody expected", () -> {
      List<String> lines = new ArrayList<>();
      AtomicBoolean throwing = new AtomicBoolean();
      AtomicInteger told = new AtomicInteger();
      Running list = listServer(line -> {
        synchronized (lines) {
          lines.add(line);
        }
      }, () -> {
        if (throwing.get()) {
          throw new IllegalStateException("words that must never be written: 198.51.100.10");
        }

        return System.currentTimeMillis();
      }, told::incrementAndGet);

      try {
        throwing.set(true);

        // The list ticks once a second; then a second and a half more, to show nothing more is said or done
        for (int i = 0; i < 100 && told.get() == 0; i++) {
          Thread.sleep(50);
        }

        Thread.sleep(1500);
        same(told.get(), 1, "the server is told, once");
        ok(list.server().failed(), "the list says it failed");

        synchronized (lines) {
          same(lines.stream().filter(l -> l.startsWith("list: stopped by an error nobody expected, java.lang.IllegalStateException at ")).count(),
              1L, "one line names the error's kind and where it came from");
          ok(lines.stream().noneMatch(l -> l.contains("198.51.100.10")), "and none has the error's words");
        }
      } finally {
        list.stop();
      }
    });

    liveTest("the relay won't start on a port that's taken, and closes what it opened", () -> {
      try (DatagramSocket blocker = new DatagramSocket(new InetSocketAddress(loopback(), PORTS[1]))) {
        throwsWith(() -> RelaySockets.start(LOOPBACK, core(PORTS), line -> { }, System::currentTimeMillis), "could not be opened",
            "a port taken");
        RelaySockets again = RelaySockets.start(LOOPBACK, core(new int[] {PORTS[0]}), line -> { }, System::currentTimeMillis);
        again.stop();
        ok(!blocker.isClosed(), "the port it couldn't have is still the other socket's");
      }
    });

    liveTest("the list's server answers with JSON and its safety headers, and refuses a body over 1 KB", () -> {
      Running list = listServer();

      try {
        Reply empty = request(list, "GET", "/v1/games?version=1");
        same(empty.status(), 200, "GET /v1/games");
        same(json(empty.body()), Map.of("games", List.of()), "no games");
        matches(empty.headers().get("content-type"), "^application/json", "JSON");
        same(empty.headers().get("x-content-type-options"), "nosniff", "nothing but data");
        matches(empty.headers().get("strict-transport-security"), "max-age=", "HSTS");
        same(empty.headers().get("connection"), "close", "one request a connection");
        // Each of these is 400 for its own reason, not only because there's no good body, so each says which
        Reply chunked = request(list, "POST", "/v1/games", null, Map.of("Transfer-Encoding", "chunked"));
        same(chunked.status(), 400, "a body sent in chunks");
        matches(chunked.body(), "Transfer-Encoding", "refused for its Transfer-Encoding");
        Map<String, String> twoLengths = new LinkedHashMap<>();
        twoLengths.put("Content-Length", "2");
        twoLengths.put("content-length", "2");
        Reply two = request(list, "POST", "/v1/games", null, twoLengths);
        same(two.status(), 400, "two Content-Lengths");
        matches(two.body(), "one Content-Length", "refused for its two Content-Lengths");
        Reply huge = request(list, "POST", "/v1/games", null, Map.of("Content-Length", "99999999999999999999"));
        same(huge.status(), 413, "a Content-Length of 20 digits is too big, and nothing throws");
        Reply notANumber = request(list, "POST", "/v1/games", null, Map.of("Content-Length", "1x"));
        same(notANumber.status(), 400, "a Content-Length that isn't a number");
        matches(notANumber.body(), "whole number", "refused for not being a whole number");
        same(request(list, "POST", "/v1/games", "x".repeat(1025), Map.of()).status(), 413, "a body over 1 KB");
        Reply relays = request(list, "GET", "/v1/relays");
        Map<String, Object> want = new LinkedHashMap<>();
        want.put("region", REGION);
        want.put("host", "virginia.relay.example.net");
        want.put("port", CONTROL);
        same(json(relays.body()), Map.of("relays", List.of(want)), "the relays");
        same(request(list, "GET", "/nothing").status(), 404, "no such path");
      } finally {
        list.stop();
      }
    });

    liveTest("the list's server holds one address to its rate", () -> {
      Running list = listServer();

      try {
        List<Integer> statuses = new ArrayList<>();

        for (int i = 0; i < 8; i++) {
          statuses.add(request(list, "GET", "/v1/games?version=1").status());
        }

        ok(statuses.contains(429), "some of 8 quick list reads are refused: " + statuses);
      } finally {
        list.stop();
      }
    });

    liveTest("a request's head is at most 8 KB: just under, it's answered; over, it's refused with 431 before anything else", () -> {
      Running list = listServer();

      try {
        same(request(list, "GET", "/v1/relays", null, Map.of("X-Pad", "a".repeat(7000))).status(), 200, "a head of about 7 KB");
        same(request(list, "GET", "/v1/relays", null, Map.of("X-Pad", "a".repeat(9000))).status(), 431, "a head of about 9 KB");
      } finally {
        list.stop();
      }
    });

    liveTest("an address has at most 10 connections at once: the 11th is closed before any of it is read", () -> {
      Running list = listServer();
      List<SSLSocket> ten = new ArrayList<>();

      try {
        for (int i = 0; i < 10; i++) {
          ten.add(silent(list));
        }

        // Each of the ten is held open (they say nothing, so the server waits for their TLS); the 11th is closed at once
        try (SSLSocket eleventh = silent(list)) {
          long waited = closedAfter(eleventh, 3000);
          ok(waited < 2000, "the 11th is closed at once, not at a deadline (" + waited + " ms)");
        }
      } finally {
        for (SSLSocket s : ten) {
          s.close();
        }

        list.stop();
      }
    });

    liveTest("a connection that sends nothing is closed at its 5 s deadline, TLS handshake and all", () -> {
      Running list = listServer();

      try (SSLSocket idle = silent(list)) {
        long waited = closedAfter(idle, 10000);
        ok(waited >= 4000 && waited < 8000, "at its deadline (" + waited + " ms)");
      } finally {
        list.stop();
      }
    });

    liveTest("a key that isn't the certificate's is refused, and the server doesn't start", () -> {
      char[] password = password();
      KeyStore store = keyStore(password);
      Certificate certificate = store.getCertificate("avpx-test");
      java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
      generator.initialize(256);
      PrivateKey other = generator.generateKeyPair().getPrivate();
      Path folder = Files.createTempDirectory("avpx-tls-");
      Path certFile = folder.resolve("fullchain.pem");
      Path keyFile = folder.resolve("privkey.pem");

      try {
        Files.writeString(certFile, pem("CERTIFICATE", certificate.getEncoded()), StandardCharsets.US_ASCII);
        Files.writeString(keyFile, pem("PRIVATE KEY", other.getEncoded()), StandardCharsets.US_ASCII);
        Listings listings = new Listings(List.of(), RandomBytes.secure(), System.currentTimeMillis());
        Settings.ListSettings settings = new Settings.ListSettings(LOOPBACK, 0, certFile.toString(), keyFile.toString(), List.of());
        throwsWith(() -> ListServer.start(settings, listings, line -> { }, System::currentTimeMillis, () -> { }), "doesn't belong",
            "another key with this certificate");

        Files.writeString(keyFile, "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", StandardCharsets.US_ASCII);
        throwsWith(() -> ListServer.start(settings, listings, line -> { }, System::currentTimeMillis, () -> { }), "PKCS#8",
            "a key in an older form");
      } finally {
        Files.deleteIfExists(certFile);
        Files.deleteIfExists(keyFile);
        Files.delete(folder);
      }
    });
  }
}
