package avpx.list;

import avpx.Settings;
import avpx.relay.AddressHasher;
import avpx.relay.PerSender;
import avpx.relay.RandomBytes;
import avpx.relay.TokenBucket;
import java.io.BufferedInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

// The list's HTTPS server: Java's own TLS, with every limit in PROTOCOL.md section 5, around Routes.java. Written 2026-11-08 by Melanikus
// for AVPx Dedicated Server, from list/https.js, to the design agreed for the Java version.
//
// HOW A CONNECTION GOES:
//   1. One thread takes each new connection (accept). Before a single byte of it is read, the connection is counted: 200 at once in all,
//      and 10 from one address (known by its hash, as every per-address limit is). One over either is closed there and then.
//   2. The connection gets a thread of its own, a virtual one (Java's cheap kind), at most 200 of them, one for each connection allowed.
//   3. TLS starts on it, 1.3 or 1.2 only, with the strong ciphers only, from the certificate in use now.
//   4. Its head (Http.java) must have come within HEADERS_MILLISECONDS of the connection's start, the TLS handshake included, and its
//      body, and the answer going out, within BODY_MILLISECONDS after that. A timer closes the connection at each deadline, whatever it's
//      doing, so a sender who trickles a byte at a time is cut off.
//   5. The request is held to the per-address limits (5 a second, 20 at once; the two GETs 1 a second, 5 at once) and everyone's (500 a
//      second, 1,000 at once), and then Routes.java answers it, under the one lock that keeps the listings to one thread at a time.
//   6. One request a connection: every answer says Connection: close, and the connection is closed after it.
// Every answer is JSON, with headers that tell a browser to treat it as nothing but data, and HSTS.
//
// A BODY: one Content-Length, at most 1 KB. Transfer-Encoding (a body sent in chunks) is 400, two Content-Lengths 400, more than 1 KB 413.
// An answer sent before the body was read is followed by reading and throwing away what the sender still sends, up to
// MOST_THROWN_AWAY_BYTES, so an honest sender gets its answer and not a broken connection.
//
// THE CERTIFICATE comes from two PEM files (Certificates.java), read at start, and read again every CERTIFICATE_LOOK_MILLISECONDS: if
// they've changed, and the new pair is good, new connections use it, so a renewed certificate is taken up without a restart. A pair that
// isn't good is written in the log and the old one kept.
//
// NO ADDRESS IS WRITTEN ANYWHERE. A connection's address is only used, in memory, to key its limits through a hash (AddressHasher.java).
// Once a second, the listings' tick takes down the ones not renewed in time, and once a minute gives a line of counts for the log.
public final class ListServer {
  static final int MOST_HEAD_BYTES = 8 * 1024;
  static final long HEADERS_MILLISECONDS = 5000;
  static final long BODY_MILLISECONDS = 5000;
  static final int MOST_CONNECTIONS = 200;
  static final int MOST_CONNECTIONS_PER_ADDRESS = 10;
  static final double REQUEST_RATE = 5;
  static final double REQUEST_BURST = 20;
  static final double LIST_RATE = 1;
  static final double LIST_BURST = 5;
  static final double EVERYONE_RATE = 500;
  static final double EVERYONE_BURST = 1000;
  static final int MOST_SENDERS = 10000;
  static final long CERTIFICATE_LOOK_MILLISECONDS = 60L * 60 * 1000;
  static final long TICK_MILLISECONDS = 1000;
  static final int MOST_THROWN_AWAY_BYTES = 64 * 1024;
  private static final int BACKLOG = 200;
  private static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};
  private static final Pattern DIGITS = Pattern.compile("[0-9]+");

  // The headers every answer has, in this order
  private static final Map<String, String> HEADERS = headers();

  private static Map<String, String> headers() {
    Map<String, String> h = new LinkedHashMap<>();
    h.put("Content-Type", "application/json; charset=utf-8");
    h.put("Cache-Control", "no-store");
    h.put("X-Content-Type-Options", "nosniff");
    h.put("Strict-Transport-Security", "max-age=31536000");
    h.put("Content-Security-Policy", "default-src 'none'");
    h.put("Referrer-Policy", "no-referrer");
    h.put("Connection", "close");
    return h;
  }

  // The words for each status the list answers with
  private static final Map<Integer, String> REASONS = Map.ofEntries(Map.entry(200, "OK"), Map.entry(201, "Created"),
      Map.entry(204, "No Content"), Map.entry(400, "Bad Request"), Map.entry(403, "Forbidden"), Map.entry(404, "Not Found"),
      Map.entry(405, "Method Not Allowed"), Map.entry(409, "Conflict"), Map.entry(413, "Content Too Large"),
      Map.entry(429, "Too Many Requests"), Map.entry(431, "Request Header Fields Too Large"), Map.entry(500, "Internal Server Error"),
      Map.entry(503, "Service Unavailable"));

  // Certificate files that can't be used, with the reason, which never holds a key's bytes
  public static final class CertificateProblem extends Exception {
    private static final long serialVersionUID = 1L;

    CertificateProblem(String words) {
      super(words);
    }
  }

  private final Listings listings;
  private final Consumer<String> log;
  private final LongSupplier now;
  private final ServerSocket server;
  private final Path certFile;
  private final Path keyFile;
  private volatile Certificates.Loaded certificate;

  // Everything below is used only under lock: the hasher, the limits, the connections each address has open, and the listings
  private final Object lock = new Object();
  private final AddressHasher hasher = new AddressHasher(RandomBytes.secure());
  private final PerSender perAddress;
  private final PerSender lists;
  private final TokenBucket everyone;
  private final Map<String, Integer> open = new HashMap<>();

  private final Semaphore slots = new Semaphore(MOST_CONNECTIONS);
  private final Set<Socket> live = ConcurrentHashMap.newKeySet();
  private final ScheduledExecutorService timers;
  private Thread acceptor;
  private volatile boolean running = true;

  private ListServer(Listings listings, Consumer<String> log, LongSupplier now, ServerSocket server, Path certFile, Path keyFile,
      Certificates.Loaded certificate) {
    this.listings = listings;
    this.log = log;
    this.now = now;
    this.server = server;
    this.certFile = certFile;
    this.keyFile = keyFile;
    this.certificate = certificate;
    this.perAddress = new PerSender(REQUEST_RATE, REQUEST_BURST, MOST_SENDERS, hasher);
    this.lists = new PerSender(LIST_RATE, LIST_BURST, MOST_SENDERS, hasher);
    this.everyone = new TokenBucket(EVERYONE_RATE, EVERYONE_BURST);
    this.timers = Executors.newSingleThreadScheduledExecutor(task -> new Thread(task, "list-timers"));
  }

  // Reads the certificate, opens the HTTPS port, and starts. settings: the list's settings (its address, port and certificate files).
  // listings: what it serves. log: where its lines go. now: the time in milliseconds since 1970-01-01 UTC.
  public static ListServer start(Settings.ListSettings settings, Listings listings, Consumer<String> log, LongSupplier now)
      throws CertificateProblem, IOException {
    Path certFile = Path.of(settings.certFile());
    Path keyFile = Path.of(settings.keyFile());
    Certificates.Loaded certificate = Certificates.load(certFile, keyFile);

    // A Java that offered none of the strong ciphers would fail every connection's TLS: better not to start, and say why
    if (strongCiphers(certificate.context().getDefaultSSLParameters().getCipherSuites()).length == 0) {
      throw new CertificateProblem("this Java offers none of the strong TLS ciphers the list uses");
    }

    ServerSocket server = new ServerSocket();

    try {
      server.bind(new InetSocketAddress(Inet4Address.ofLiteral(settings.address()), settings.port()), BACKLOG);
    } catch (IOException | RuntimeException e) {
      server.close();
      throw e;
    }

    ListServer list = new ListServer(listings, log, now, server, certFile, keyFile, certificate);
    list.timers.scheduleAtFixedRate(list::tick, TICK_MILLISECONDS, TICK_MILLISECONDS, TimeUnit.MILLISECONDS);
    list.timers.scheduleAtFixedRate(list::lookAtCertificate, CERTIFICATE_LOOK_MILLISECONDS, CERTIFICATE_LOOK_MILLISECONDS,
        TimeUnit.MILLISECONDS);
    list.acceptor = new Thread(list::acceptAll, "list-accept");
    list.acceptor.start();
    log.accept("list: listening on HTTPS " + server.getLocalPort());
    return list;
  }

  // The port it listens on (a test asks for any free one)
  public int port() {
    return server.getLocalPort();
  }

  private static void closeQuietly(Closeable c) {
    try {
      c.close();
    } catch (IOException e) {
      // already closing, or closed: nothing more to do
    }
  }

  // ----- Connections

  private void acceptAll() {
    while (running) {
      Socket raw;

      try {
        raw = server.accept();
      } catch (IOException e) {
        if (server.isClosed()) {
          return;
        }

        continue;
      }

      String key = admit(raw);

      if (key == null) {
        closeQuietly(raw);
        continue;
      }

      live.add(raw);

      try {
        Thread.ofVirtual().name("list-connection").start(() -> serve(raw, key));
      } catch (RuntimeException e) {
        live.remove(raw);
        release(key);
        closeQuietly(raw);
      }
    }
  }

  // Counts a new connection, before any of it is read: the hash of its address, or null if it's one over a limit
  private String admit(Socket raw) {
    if (!slots.tryAcquire()) {
      return null;
    }

    synchronized (lock) {
      String key = hasher.keyOf(raw.getInetAddress().getHostAddress(), now.getAsLong());
      int count = open.getOrDefault(key, 0);

      if (count >= MOST_CONNECTIONS_PER_ADDRESS) {
        slots.release();
        return null;
      }

      open.put(key, count + 1);
      return key;
    }
  }

  // A connection has ended: its count goes, by the hash it was counted under, even if the hasher's secret has changed since
  private void release(String key) {
    synchronized (lock) {
      int left = open.getOrDefault(key, 1) - 1;

      if (left > 0) {
        open.put(key, left);
      } else {
        open.remove(key);
      }
    }

    slots.release();
  }

  private void serve(Socket raw, String key) {
    ScheduledFuture<?> deadline = timers.schedule(() -> closeQuietly(raw), HEADERS_MILLISECONDS, TimeUnit.MILLISECONDS);
    SSLSocket tls = null;

    try {
      tls = (SSLSocket) certificate.context().getSocketFactory().createSocket(raw, null, true);
      // The server's side of the connection. The list asks for no certificate from the other end, so it checks none; if it ever did ask,
      // the identity check below would apply to it, as the client's check applies to the server's certificate.
      tls.setUseClientMode(false);
      SSLParameters parameters = tls.getSSLParameters();
      parameters.setProtocols(PROTOCOLS.clone());
      parameters.setCipherSuites(strongCiphers(tls.getEnabledCipherSuites()));
      parameters.setUseCipherSuitesOrder(true);
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      tls.setSSLParameters(parameters);
      tls.setSoTimeout((int) HEADERS_MILLISECONDS);
      tls.startHandshake();

      try (InputStream in = new BufferedInputStream(tls.getInputStream()); OutputStream out = tls.getOutputStream()) {
        Http.Head head;

        try {
          head = Http.read(in, MOST_HEAD_BYTES);
        } catch (Http.Refused refused) {
          sendEarly(tls, out, in, error(refused.status(), refused.getMessage()));
          return;
        }

        // The head came in time: from here, the body and the answer have their own time
        deadline.cancel(false);
        deadline = timers.schedule(() -> closeQuietly(raw), BODY_MILLISECONDS, TimeUnit.MILLISECONDS);
        answer(head, tls, in, out, raw.getInetAddress().getHostAddress());
      }
    } catch (IOException | RuntimeException e) {
      // The sender went away, was too slow, or its TLS was no good: nothing to answer, and nothing to write about it
    } finally {
      deadline.cancel(false);
      closeQuietly(tls != null ? tls : raw);
      live.remove(raw);
      release(key);
    }
  }

  // TLS 1.3's ciphers, and TLS 1.2's with a fresh key for each connection (ECDHE) and an authenticated cipher (GCM or ChaCha20)
  private static String[] strongCiphers(String[] enabled) {
    List<String> strong = new ArrayList<>();

    for (String name : enabled) {
      boolean tls13 = name.startsWith("TLS_AES_") || name.startsWith("TLS_CHACHA20_");
      boolean tls12 = name.startsWith("TLS_ECDHE_") && (name.contains("_GCM_") || name.contains("_CHACHA20_"));

      if (tls13 || tls12) {
        strong.add(name);
      }
    }

    return strong.toArray(new String[0]);
  }

  private void answer(Http.Head head, SSLSocket tls, InputStream in, OutputStream out, String address) throws IOException {
    long at = now.getAsLong();
    boolean isList = head.method().equals("GET") && (head.path().equals("/v1/games") || head.path().equals("/v1/relays"));
    boolean allowed;

    synchronized (lock) {
      allowed = perAddress.allows(address, at) && (!isList || lists.allows(address, at)) && everyone.take(at);
    }

    if (!allowed) {
      sendEarly(tls, out, in, error(429, "too many requests: wait and try again"));
      return;
    }

    if (!head.values("transfer-encoding").isEmpty()) {
      sendEarly(tls, out, in, error(400, "a body sent in chunks (Transfer-Encoding) isn't taken: send it with one Content-Length"));
      return;
    }

    List<String> lengths = head.values("content-length");
    int length = 0;

    if (lengths.size() > 1) {
      sendEarly(tls, out, in, error(400, "a request has one Content-Length at most"));
      return;
    }

    if (lengths.size() == 1) {
      String declared = lengths.get(0);

      if (!DIGITS.matcher(declared).matches()) {
        sendEarly(tls, out, in, error(400, "Content-Length must be a whole number"));
        return;
      }

      // Digits, but more than a body may be (however many digits: Json.digitsValue never throws)
      long declaredLength = Json.digitsValue(declared, Requests.MOST_BODY_BYTES);

      if (declaredLength < 0) {
        sendEarly(tls, out, in, error(413, "the body is too big"));
        return;
      }

      length = (int) declaredLength;
    }

    byte[] body = in.readNBytes(length);

    if (body.length < length) {
      // The sender went away before its body was all there: no one to answer
      return;
    }

    Routes.Answer answer;

    synchronized (lock) {
      answer = Routes.handle(listings, head.method(), head.path(), head.query(), body, now.getAsLong());
    }

    send(out, answer);
  }

  private static Routes.Answer error(int status, String words) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("error", words);
    return new Routes.Answer(status, body);
  }

  // An answer sent before the request's body was read. The server then ends its side of the connection (TLS's close_notify), so the
  // sender knows the answer is all, and reads and throws away what the sender still sends: closing with it unread would reset the
  // connection, and an honest sender could lose its answer.
  private static void sendEarly(SSLSocket tls, OutputStream out, InputStream in, Routes.Answer answer) throws IOException {
    send(out, answer);

    try {
      tls.shutdownOutput();
    } catch (IOException | UnsupportedOperationException e) {
      // This TLS can't end only its own side: the deadline closes the connection instead
    }

    throwAway(in);
  }

  private static void throwAway(InputStream in) throws IOException {
    byte[] bin = new byte[4096];
    int thrown = 0;

    while (thrown < MOST_THROWN_AWAY_BYTES) {
      int n = in.read(bin);

      if (n < 0) {
        return;
      }

      thrown += n;
    }
  }

  private static void send(OutputStream out, Routes.Answer answer) throws IOException {
    byte[] body = answer.body() == null ? new byte[0] : Json.write(answer.body()).getBytes(StandardCharsets.US_ASCII);
    StringBuilder head = new StringBuilder();
    head.append("HTTP/1.1 ").append(answer.status()).append(' ').append(REASONS.getOrDefault(answer.status(), "Error")).append("\r\n");

    for (Map.Entry<String, String> header : HEADERS.entrySet()) {
      head.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
    }

    if (answer.status() != 204) {
      head.append("Content-Length: ").append(body.length).append("\r\n");
    }

    head.append("\r\n");
    out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
    out.write(body);
    out.flush();
  }

  // ----- Once a second, and once an hour

  private void tick() {
    List<String> lines;

    synchronized (lock) {
      lines = listings.tick(now.getAsLong());
    }

    for (String line : lines) {
      log.accept(line);
    }
  }

  // A renewed certificate is taken up without a restart. Both files are read again each time (they're a few KB, once an hour), and a
  // pair is used only if its bytes differ from the pair in use, and it's good.
  private void lookAtCertificate() {
    try {
      byte[] cert = Certificates.readFile(certFile);
      byte[] key = Certificates.readFile(keyFile);

      if (!certificate.sameFiles(cert, key)) {
        certificate = Certificates.load(cert, key);
        log.accept("list: the certificate files changed, and the new ones are in use");
      }
    } catch (CertificateProblem e) {
      log.accept("list: the certificate files could not be used (" + e.getMessage() + "), so the old ones are kept");
    }
  }

  // Stops: no new connection is taken, the timers stop, and every connection still open is closed
  public void stop() {
    running = false;
    closeQuietly(server);
    timers.shutdownNow();

    for (Socket s : live) {
      closeQuietly(s);
    }

    try {
      acceptor.join();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
