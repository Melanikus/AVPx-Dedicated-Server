package avpx.relay;

import avpx.Fatal;
import java.io.Closeable;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

// The relay's UDP sockets, around a Relay (RelayCore.java for protocol version 1, avpx.v2.SealedRelay for version 2): one for the control
// port and one for each joiner's port, all opened at start. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, from
// relay/sockets.js.
//
// This is all the relay does on the network: a packet that comes to one of its ports goes to the core, and whatever the core says to send
// is sent, from the port it names. Every decision is the core's, so it can be tested without sockets. The sockets are IPv4 only, as the
// game's ENet is.
//
// ONE THREAD does all of it, as Node's one loop did: it waits for any port to have a packet (a Selector watches them all), hands each
// packet to the core, and sends what the core gives back. So the core is only ever used by one thread, and needs no locks. No port can
// keep the others waiting: each is read at most MOST_PACKETS_A_TURN packets before the others get their turn.
//
// A socket's error is counted, with no address, and the relay goes on; the count goes in the log. About once a second, the core's tick
// ends what has run out and may give a line for the log.
//
// ANYTHING ELSE thrown out of a turn of the loop (the review's V1-3) stops it: avpx/Fatal.java writes one line, the relay stops as if
// told to, and failed() says so, so Main stops the server with a failure for systemd to start it again. Before, such an error ended the
// relay's thread alone, and the server looked up while it passed no games.
public final class RelaySockets {
  private static final long TICK_MILLISECONDS = 1000;
  private static final int MOST_PACKETS_A_TURN = 64;

  private final Relay core;
  private final Consumer<String> log;
  private final LongSupplier now;
  private final Selector selector;
  private final Map<Integer, DatagramChannel> channels;
  private final ByteBuffer buffer;
  private Thread thread;
  private volatile boolean running = true;
  private volatile boolean failed;
  private long errors;
  private long tickedAt;

  private RelaySockets(Relay core, Consumer<String> log, LongSupplier now, Selector selector, Map<Integer, DatagramChannel> channels) {
    this.core = core;
    this.log = log;
    this.now = now;
    this.selector = selector;
    this.channels = channels;
    this.buffer = ByteBuffer.allocate(core.mostDatagramBytes() + 1);
  }

  // Opens every port, the core's control port and each of its relay ports, on address ("0.0.0.0" for all of the machine's), and starts.
  // All of them or none: if any can't be opened, the ones that were are closed, and this throws. log: where its lines go. now: the time,
  // in milliseconds since 1970-01-01 UTC (System::currentTimeMillis: a pass carries the real time to another machine).
  public static RelaySockets start(String address, Relay core, Consumer<String> log, LongSupplier now) throws IOException {
    Selector selector = Selector.open();
    Map<Integer, DatagramChannel> channels = new LinkedHashMap<>();
    List<Integer> ports = new ArrayList<>();
    ports.add(core.controlPort());
    ports.addAll(core.relayPorts());

    try {
      Inet4Address listenOn = Inet4Address.ofLiteral(address);

      for (int port : ports) {
        DatagramChannel channel = DatagramChannel.open(StandardProtocolFamily.INET);
        channels.put(port, channel);
        channel.bind(new InetSocketAddress(listenOn, port));
        channel.configureBlocking(false);
        channel.register(selector, SelectionKey.OP_READ, port);
      }
    } catch (IOException | RuntimeException e) {
      for (DatagramChannel channel : channels.values()) {
        closeQuietly(channel);
      }

      closeQuietly(selector);
      throw new IOException("relay: a UDP port could not be opened (" + e.getClass().getSimpleName() + "), so the relay did not start", e);
    }

    RelaySockets relay = new RelaySockets(core, log, now, selector, channels);
    relay.thread = new Thread(relay::run, "relay");
    relay.thread.start();
    log.accept("relay: listening on UDP " + core.controlPort() + " for control, and " + core.relayPorts().size() + " ports for joiners");
    return relay;
  }

  private static void closeQuietly(Closeable c) {
    try {
      c.close();
    } catch (IOException e) {
      // Closing at the end, or after a failure already being reported: nothing more to do
    }
  }

  private void run() {
    // Every turn, the first one's clock reading among them, is one Fatal.turn: anything thrown out of it stops the relay, said and seen
    boolean going = Fatal.turn("relay", () -> tickedAt = now.getAsLong(), log);

    while (going && running && selector.isOpen()) {
      going = Fatal.turn("relay", this::oneTurn, log);
    }

    failed = !going;

    // Stopping: the counts since the last line, so the last part of a minute isn't lost, and then every port closes, whatever happened
    Fatal.turn("relay", () -> log.accept(core.countsLine(now.getAsLong())), log);

    for (DatagramChannel channel : channels.values()) {
      closeQuietly(channel);
    }

    closeQuietly(selector);
  }

  // One turn: wait up to a tick for packets, read them, and tick when it's time
  private void oneTurn() {
    try {
      selector.select(TICK_MILLISECONDS);
    } catch (IOException e) {
      errors++;
    }

    Iterator<SelectionKey> ready = selector.selectedKeys().iterator();

    while (ready.hasNext()) {
      SelectionKey key = ready.next();
      ready.remove();

      if (key.isValid() && key.isReadable() && key.channel() instanceof DatagramChannel channel && key.attachment() instanceof Integer port) {
        readSome(channel, port);
      }
    }

    long at = now.getAsLong();

    if (at - tickedAt >= TICK_MILLISECONDS || at < tickedAt) {
      tickedAt = at;

      for (String line : core.tick(at)) {
        log.accept(line);
      }

      if (errors > 0) {
        log.accept("relay: " + errors + " socket errors in the last moments, and the relay goes on");
        errors = 0;
      }
    }
  }

  // Whether the relay stopped on an error nobody expected (Fatal), rather than because it was told to: then the server must stop too
  public boolean failed() {
    return failed;
  }

  // Up to MOST_PACKETS_A_TURN packets from one port, each handed to the core, and what it says sent
  private void readSome(DatagramChannel channel, int localPort) {
    for (int i = 0; i < MOST_PACKETS_A_TURN; i++) {
      SocketAddress from;
      buffer.clear();

      try {
        from = channel.receive(buffer);
      } catch (IOException e) {
        errors++;
        return;
      }

      if (from == null) {
        return;
      }

      // A packet bigger than the buffer comes in cut to its size, one byte more than the most: the core drops it as too big
      buffer.flip();
      byte[] data = new byte[buffer.remaining()];
      buffer.get(data);

      if (from instanceof InetSocketAddress sender && sender.getAddress() instanceof Inet4Address ipv4) {
        for (RelayCore.Out out : core.receive(localPort, ipv4.getHostAddress(), sender.getPort(), data, now.getAsLong())) {
          send(out);
        }
      }
    }
  }

  private void send(RelayCore.Out out) {
    DatagramChannel channel = channels.get(out.from());

    if (channel == null) {
      return;
    }

    try {
      // ofLiteral reads the address as written, and never asks the network what a name means
      channel.send(ByteBuffer.wrap(out.data()), new InetSocketAddress(Inet4Address.ofLiteral(out.address()), out.port()));
    } catch (IOException | RuntimeException e) {
      errors++;
    }
  }

  // Stops: the thread ends, and every port is closed
  public void stop() {
    stopSoon();
    join();
  }

  // Tells the relay to stop, and doesn't wait: for another thread (the list's, on its own failure), which mustn't wait on the relay's
  public void stopSoon() {
    running = false;
    selector.wakeup();
  }

  // Waits until the relay has stopped
  public void join() {
    try {
      thread.join();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
