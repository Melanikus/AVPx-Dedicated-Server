package avpx.relay;

import avpx.relay.Protocol.Type;
import avpx.relay.Protocol.Why;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

// What the relay does with each packet it's sent, with no network of its own: a packet in, the packets to send out. Written 2026-11-08
// by Melanikus for AVPx Dedicated Server, from relay/core.js.
//
// Keeping the sockets out of here (RelaySockets.java has them) means every rule below can be tested by handing it packets, with no socket
// opened (CoreTest.java). It isn't safe to use from two threads at once, and doesn't need to be: the relay runs on one thread.
//
// HOW A GAME GOES THROUGH THE RELAY (Protocol.java has the messages):
//
//   1. The host asks the relay's CONTROL port for a game (HOST_OPEN). The relay first answers with a COOKIE, a stamp only that sender's
//      address can have seen, and opens the game only when the host asks again with it (see "cookies" below). Its answer, HOST_OPENED,
//      has the host's TOKEN (16 random bytes: proof it's the host, from then on) and the game's CODE (8 letters, for joiners).
//   2. The host says HOST_KEEP with its token every 15 s. A game not kept for gameLifeMilliseconds ends.
//   3. A joiner asks the control port to JOIN a game by its code, with a cookie too. The relay gives it one of its other ports, its own
//      for this joiner (JOIN_PORT, with a TICKET: proof it's that joiner), and tells the host (NEW_JOINER, with that port).
//   4. Both send a hello to that port, from their game's own socket: the host with its token, the joiner with its ticket. That fixes the
//      address and port each one's packets come from, as the relay sees them, through whatever NAT is between.
//   5. Once both are there, the relay tells the joiner READY, and from then on passes every packet from one to the other, from that
//      port, unread and unchanged. The host sees each joiner as a peer of its own, because each comes from a port of its own.
//
// WHAT IT REFUSES, AND THE LIMITS (AVP Tao 3: input is hostile): a packet bigger than mostDatagramBytes; anything on the control port
// that isn't exactly a message, or comes too fast from its sender or from everyone; a hello with the wrong secret; a packet on a joiner's
// port from anyone but its two ends; more than a port's share of packets and bytes a second. The most games, games for one sender,
// joiners for one game and ports there are are all fixed. A port waiting for its two ends is freed after pendingMilliseconds, and one with
// no traffic after idleMilliseconds.
//
// COOKIES: a sender can put any address on its packets. Without cookies, someone could ask for a thousand games or ports in other
// people's names, and fill the relay. So the two asks that make the relay keep something (HOST_OPEN, JOIN) need a cookie: 16 bytes the
// relay makes from the sender's address and port, the time, and a secret of its own, and sends to that address. Only someone who gets
// packets at that address can know it, and the relay keeps nothing to check it: it makes it again. A cookie is good for 10 to 20 s.
//
// PASSES (Pass.java): the list may be on another machine, so it can't look a room up here. The relay puts a fresh pass in every
// HOST_OPENED and HOST_KEPT, made with this relay's own pass key from its region, the room's code and the time; the host shows it to the
// list, which checks it with the same key. So the time this is given (now) is the real time: a pass carries it to another machine.
//
// ECHO: anyone may ask the control port for an ECHO_BACK, to time its round trip and pick the nearest relay. The answer is the question's
// own 16 bytes and count, to the address it came from, no bigger, and kept to the same limits as every control message. Nothing is kept.
//
// NO ADDRESSES ARE WRITTEN ANYWHERE (the user's ruling: no IPs). Addresses live in memory only while a game or a port needs them, and are
// forgotten when it ends; the per-sender limits key by a hash (AddressHasher.java). The relay's lines (tick) are counts and times only.
// Codes, tokens and tickets are never written either: a code would let anyone join.
public final class RelayCore {
  // Every limit of the relay's, with its starting value (PROTOCOL.md section 5). A test changes some, on a Limits of its own.
  public static final class Limits {
    public int mostGames = 500;
    public int mostGamesPerSender = 2;
    public int mostJoinersPerGame = 8;                // the game's own most players is 8, the host among them
    public long gameLifeMilliseconds = 45000;         // a host keeps its game every 15 s
    public long pendingMilliseconds = 15000;          // for both ends of a joiner's port to say hello
    public long idleMilliseconds = 30000;             // a connected game's ENet sends something every second or so
    public int mostDatagramBytes = 1500;              // ENet's packets are at most 1400 bytes as the game sets it up
    public long cookieSlotMilliseconds = 10000;
    public double controlRate = 10;                   // control messages a second from one sender
    public double controlBurst = 20;
    public double everyoneRate = 2000;                // and from everyone
    public double everyoneBurst = 4000;
    public double refusalRate = 1;                    // REFUSED answers a second to one sender: a refusal is an answer anyone can ask for
    public double refusalBurst = 2;
    public double joinRate = 4;                       // joins a second for one game
    public double joinBurst = 8;
    public double helloRate = 20;                     // hellos a second on one joiner's port
    public double helloBurst = 40;
    public double portPacketRate = 400;               // packets a second each way, on one joiner's port
    public double portPacketBurst = 800;
    public double portByteRate = 256 * 1024;          // bytes a second each way, on one joiner's port
    public double portByteBurst = 512 * 1024;
    public int mostSenders = 10000;                   // senders the per-sender limits remember
    public long statsMilliseconds = 60000;            // how often a line of counts goes to the log
  }

  // The cookies' secret is made again this often
  private static final long COOKIE_KEY_LIFE_MILLISECONDS = 24L * 60 * 60 * 1000;
  private static final int COOKIE_KEY_BYTES = 32;

  // How many times a new game's code is made before the relay says it's busy: 8 tries at 40 random bits each, against at most 500 games
  private static final int CODE_TRIES = 8;

  // A packet to send: from one of the relay's own ports, to an address and port
  public record Out(int from, String address, int port, byte[] data) {
  }

  // Where a host's or joiner's packets come from, as the relay sees them through its NAT
  record End(String address, int port) {
    boolean is(String otherAddress, int otherPort) {
      return address.equals(otherAddress) && port == otherPort;
    }
  }

  // A game: its code, its host's token, and where its host is
  static final class Game {
    final byte[] code;
    final String codeText;
    final byte[] token;
    final String tokenHex;
    final String sender;               // the hash of the address that opened it, for the most games one address may have
    final TokenBucket joinLimit;
    final Set<Integer> joiners = new LinkedHashSet<>();
    End host;
    long keptAt;

    Game(byte[] code, byte[] token, End host, String sender, long keptAt, TokenBucket joinLimit) {
      this.code = code;
      this.codeText = new String(code, StandardCharsets.US_ASCII);
      this.token = token;
      this.tokenHex = Crypto.hex(token);
      this.host = host;
      this.sender = sender;
      this.keptAt = keptAt;
      this.joinLimit = joinLimit;
    }
  }

  // A joiner's port's two limits, for one way
  record Way(TokenBucket packets, TokenBucket bytes) {
  }

  // One of the relay's ports for joiners: free, waiting for its two hellos (pending), or passing a game's packets (active)
  static final class Slot {
    enum State { FREE, PENDING, ACTIVE }

    final int port;
    State state = State.FREE;
    Game game;
    byte[] ticket;
    End hostEnd;
    End joinerEnd;
    long madeAt;
    long trafficAt;
    TokenBucket hellos;
    Way up;                            // from the joiner to the host
    Way down;                          // from the host to the joiner

    Slot(int port) {
      this.port = port;
    }
  }

  // What happened since the last line of counts
  static final class Counts {
    long opened;
    long closed;
    long expired;
    long joins;
    long refused;
    long echoes;
    long forwardedPackets;
    long forwardedBytes;
    long tooBig;
    long overLimit;
    long notAMessage;
    long strangers;
    long portsExpired;
  }

  private final String region;
  private final byte[] passKey;
  private final Limits limits;
  private final int controlPort;
  private final RandomBytes random;
  private final AddressHasher hasher;
  private byte[] cookieKey;
  private long cookieKeyMadeAt;

  final Map<String, Game> games = new LinkedHashMap<>();           // by code
  final Map<String, Game> gamesByToken = new HashMap<>();          // by token, as hex
  final Map<String, Integer> gamesPerSender = new HashMap<>();     // by hashed address: how many games it has open
  final Map<Integer, Slot> slots = new LinkedHashMap<>();          // by relay port
  final ArrayDeque<Integer> free = new ArrayDeque<>();             // the ports free, the one freed longest ago first

  private final TokenBucket everyone;
  private final PerSender perSender;
  private final PerSender refusals;
  private long statsAt;
  Counts counts = new Counts();

  // controlPort: the port hosts and joiners ask on. ports: the relay's other ports, one for each joiner while it's connected, all opened
  // by RelaySockets. region: this relay's region name, such as "virginia". passKey: this relay's pass key, 32 bytes, which the list holds
  // too. random: where random bytes come from (RandomBytes.secure() for the server). limits: the limits (new Limits() for the server's
  // own). now: the time, in milliseconds since 1970-01-01 UTC.
  public RelayCore(int controlPort, int[] ports, String region, byte[] passKey, RandomBytes random, Limits limits, long now) {
    if (!Pass.isRegion(region) || passKey == null || passKey.length != Pass.PASS_KEY_BYTES) {
      throw new IllegalArgumentException("RelayCore: a region name, and a pass key of 32 bytes");
    }

    this.region = region;
    this.passKey = passKey.clone();
    this.limits = limits;
    this.controlPort = controlPort;
    this.random = random;
    this.hasher = new AddressHasher(random);
    this.cookieKey = random.next(COOKIE_KEY_BYTES);
    this.cookieKeyMadeAt = now;

    for (int port : ports) {
      if (port < 1 || port > 65535 || port == controlPort || slots.containsKey(port)) {
        throw new IllegalArgumentException("RelayCore: each relay port is a different port from 1 to 65535, and not the control port");
      }

      slots.put(port, new Slot(port));
      free.addLast(port);
    }

    this.everyone = new TokenBucket(limits.everyoneRate, limits.everyoneBurst);
    this.perSender = new PerSender(limits.controlRate, limits.controlBurst, limits.mostSenders, hasher);
    this.refusals = new PerSender(limits.refusalRate, limits.refusalBurst, limits.mostSenders, hasher);
    this.statsAt = now;
  }

  public int controlPort() {
    return controlPort;
  }

  // The relay's ports for joiners, in order
  public List<Integer> relayPorts() {
    return List.copyOf(slots.keySet());
  }

  // ----- A packet in

  // A packet came to localPort from address:port at now (milliseconds). Gives back what to send, each from one of the relay's own ports.
  public List<Out> receive(int localPort, String address, int port, byte[] data, long now) {
    try {
      if (data == null || data.length > limits.mostDatagramBytes) {
        counts.tooBig++;
        return List.of();
      }

      if (localPort == controlPort) {
        return onControl(address, port, data, now);
      }

      Slot slot = slots.get(localPort);
      return slot != null ? onRelayPort(slot, address, port, data, now) : List.of();
    } catch (RuntimeException e) {
      // Nothing a packet holds should get here; if something does, the packet is dropped and the relay goes on
      counts.notAMessage++;
      return List.of();
    }
  }

  // An answer from the control port, to whoever asked
  private Out control(String address, int port, Message m) {
    return new Out(controlPort, address, port, Protocol.encode(m));
  }

  private List<Out> onControl(String address, int port, byte[] data, long now) {
    // The sender's own limit first, so one sender going too fast doesn't use up everyone's
    if (!perSender.allows(address, now) || !everyone.take(now)) {
      counts.overLimit++;
      return List.of();
    }

    Message m = Protocol.decode(data);

    if (m == null) {
      counts.notAMessage++;
      return List.of();
    }

    switch (m.type()) {
      case Type.HOST_OPEN:
        return hostOpen(m, address, port, now);
      case Type.HOST_KEEP:
        return hostKeep(m, address, port, now);
      case Type.HOST_CLOSE:
        return hostClose(m);
      case Type.JOIN:
        return join(m, address, port, now);
      case Type.ECHO:
        // The asker's own bytes and count, straight back: the same size, to the same address, and nothing kept
        counts.echoes++;
        return List.of(control(address, port, Message.of(Type.ECHO_BACK).secret(m.secret()).number(m.number())));
      default:
        // A message the relay sends (an ECHO_BACK among them, so two relays can't answer each other), or a hello, which belongs on a
        // joiner's port
        counts.notAMessage++;
        return List.of();
    }
  }

  private List<Out> hostOpen(Message m, String address, int port, long now) {
    if (!cookieIsGood(m.secret(), address, port, now)) {
      return List.of(control(address, port, Message.of(Type.COOKIE).secret(cookieFor(address, port, now, 0))));
    }

    String sender = hasher.keyOf(address, now);

    if (gamesPerSender.getOrDefault(sender, 0) >= limits.mostGamesPerSender) {
      return refuse(address, port, now, Why.TOO_MANY_GAMES);
    }

    if (games.size() >= limits.mostGames) {
      return refuse(address, port, now, Why.BUSY);
    }

    byte[] code = null;

    for (int tries = 0; tries < CODE_TRIES && code == null; tries++) {
      byte[] made = makeCode(random);
      code = games.containsKey(new String(made, StandardCharsets.US_ASCII)) ? null : made;
    }

    if (code == null) {
      return refuse(address, port, now, Why.BUSY);
    }

    Game game = new Game(code, random.next(Protocol.SECRET_BYTES), new End(address, port), sender, now,
        new TokenBucket(limits.joinRate, limits.joinBurst));
    games.put(game.codeText, game);
    gamesByToken.put(game.tokenHex, game);
    gamesPerSender.merge(sender, 1, Integer::sum);
    counts.opened++;
    return List.of(control(address, port, withPass(Message.of(Type.HOST_OPENED).secret(game.token).code(code), game, now)));
  }

  // The game a token is for, or null: found by the token's hex, then the token itself compared in a time that says nothing
  private Game byToken(byte[] token) {
    Game game = token == null ? null : gamesByToken.get(Crypto.hex(token));
    return game != null && Crypto.same(game.token, token) ? game : null;
  }

  private List<Out> hostKeep(Message m, String address, int port, long now) {
    Game game = byToken(m.secret());

    if (game == null) {
      return refuse(address, port, now, Why.NO_SUCH_GAME);
    }

    // The host's NAT may have given it a new port: the token says it's the host, so this is where it is now
    game.host = new End(address, port);
    game.keptAt = now;
    return List.of(control(address, port, withPass(Message.of(Type.HOST_KEPT).secret(game.token).number(game.joiners.size()), game, now)));
  }

  private List<Out> hostClose(Message m) {
    Game game = byToken(m.secret());

    if (game != null) {
      closeGame(game);
      counts.closed++;
    }

    return List.of();
  }

  private List<Out> join(Message m, String address, int port, long now) {
    if (!cookieIsGood(m.secret(), address, port, now)) {
      return List.of(control(address, port, Message.of(Type.COOKIE).secret(cookieFor(address, port, now, 0))));
    }

    byte[] wanted = m.code();
    Game game = wanted == null ? null : games.get(new String(wanted, StandardCharsets.US_ASCII));

    if (game == null) {
      return refuse(address, port, now, Why.NO_SUCH_GAME);
    }

    if (game.joiners.size() >= limits.mostJoinersPerGame) {
      return refuse(address, port, now, Why.GAME_FULL);
    }

    if (!game.joinLimit.take(now) || free.isEmpty()) {
      return refuse(address, port, now, Why.BUSY);
    }

    int relayPort = free.pollFirst();
    Slot slot = slots.get(relayPort);
    slot.state = Slot.State.PENDING;
    slot.game = game;
    slot.ticket = random.next(Protocol.SECRET_BYTES);
    slot.hostEnd = null;
    slot.joinerEnd = null;
    slot.madeAt = now;
    slot.trafficAt = now;
    slot.hellos = new TokenBucket(limits.helloRate, limits.helloBurst);
    slot.up = new Way(new TokenBucket(limits.portPacketRate, limits.portPacketBurst), new TokenBucket(limits.portByteRate, limits.portByteBurst));
    slot.down = new Way(new TokenBucket(limits.portPacketRate, limits.portPacketBurst), new TokenBucket(limits.portByteRate, limits.portByteBurst));
    game.joiners.add(relayPort);
    counts.joins++;

    return List.of(
        control(address, port, Message.of(Type.JOIN_PORT).secret(slot.ticket).code(game.code).port(relayPort)),
        control(game.host.address(), game.host.port(), Message.of(Type.NEW_JOINER).secret(game.token).port(relayPort)));
  }

  private List<Out> onRelayPort(Slot slot, String address, int port, byte[] data, long now) {
    if (slot.state == Slot.State.FREE) {
      counts.strangers++;
      return List.of();
    }

    boolean fromHost = slot.hostEnd != null && slot.hostEnd.is(address, port);
    boolean fromJoiner = slot.joinerEnd != null && slot.joinerEnd.is(address, port);

    // A hello: only ever exactly a message, so a game's packet is never taken for one unless it is one, secret and all
    if (data.length == Protocol.MESSAGE_BYTES) {
      Message m = Protocol.decode(data);

      if (m != null && (m.type() == Type.HOST_HELLO || m.type() == Type.JOINER_HELLO)) {
        return onHello(slot, m, address, port, now);
      }
    }

    if (slot.state != Slot.State.ACTIVE || !(fromHost || fromJoiner)) {
      counts.strangers++;
      return List.of();
    }

    Way way = fromJoiner ? slot.up : slot.down;

    if (!way.packets().take(now) || !way.bytes().take(now, data.length)) {
      counts.overLimit++;
      return List.of();
    }

    slot.trafficAt = now;
    counts.forwardedPackets++;
    counts.forwardedBytes += data.length;
    End to = fromJoiner ? slot.hostEnd : slot.joinerEnd;
    return List.of(new Out(slot.port, to.address(), to.port(), data));
  }

  private List<Out> onHello(Slot slot, Message m, String address, int port, long now) {
    if (!slot.hellos.take(now)) {
      counts.overLimit++;
      return List.of();
    }

    if (m.type() == Type.HOST_HELLO && Crypto.same(m.secret(), slot.game.token) && m.port() == slot.port) {
      slot.hostEnd = new End(address, port);
    } else if (m.type() == Type.JOINER_HELLO && Crypto.same(m.secret(), slot.ticket)) {
      slot.joinerEnd = new End(address, port);
    } else {
      counts.strangers++;
      return List.of();
    }

    if (slot.hostEnd == null || slot.joinerEnd == null) {
      return List.of();
    }

    slot.state = Slot.State.ACTIVE;
    slot.trafficAt = now;
    byte[] ready = Protocol.encode(Message.of(Type.READY).secret(slot.ticket).port(slot.port));

    // The joiner hears READY each time it says hello once both ends are there, so a READY that was lost is sent again when it asks again
    if (m.type() == Type.JOINER_HELLO) {
      return List.of(new Out(slot.port, address, port, ready));
    }

    return List.of(new Out(slot.port, slot.joinerEnd.address(), slot.joinerEnd.port(), ready));
  }

  private List<Out> refuse(String address, int port, long now, int why) {
    counts.refused++;

    if (!refusals.allows(address, now)) {
      return List.of();
    }

    return List.of(control(address, port, Message.of(Type.REFUSED).number(why)));
  }

  // ----- Cookies

  // The cookie for an address and port in the time slot now is in, or slotsBack slots before it
  private byte[] cookieFor(String address, int port, long now, int slotsBack) {
    if (now - cookieKeyMadeAt >= COOKIE_KEY_LIFE_MILLISECONDS || now < cookieKeyMadeAt) {
      cookieKey = random.next(COOKIE_KEY_BYTES);
      cookieKeyMadeAt = now;
    }

    long timeSlot = Math.floorDiv(now, limits.cookieSlotMilliseconds) - slotsBack;
    byte[] what = (address + "|" + port + "|" + timeSlot).getBytes(StandardCharsets.UTF_8);
    return Arrays.copyOf(Crypto.hmacSha256(cookieKey, what), Protocol.SECRET_BYTES);
  }

  // A cookie made for this address and port in this time slot or the one before: 10 to 20 s old at most
  private boolean cookieIsGood(byte[] secret, String address, int port, long now) {
    return secret != null
        && (Crypto.same(secret, cookieFor(address, port, now, 0)) || Crypto.same(secret, cookieFor(address, port, now, 1)));
  }

  // ----- Passes

  // The message with a fresh pass for its game's host to show the list, the time in whole seconds
  private Message withPass(Message m, Game game, long now) {
    long passTime = Math.floorDiv(now, 1000);
    return m.pass(Pass.make(passKey, region, game.code, passTime), passTime);
  }

  // ----- Endings

  private void freeSlot(Slot slot) {
    if (slot.state == Slot.State.FREE) {
      return;
    }

    slot.game.joiners.remove(slot.port);
    Arrays.fill(slot.ticket, (byte) 0);
    slot.state = Slot.State.FREE;
    slot.game = null;
    slot.ticket = null;
    slot.hostEnd = null;
    slot.joinerEnd = null;
    slot.hellos = null;
    slot.up = null;
    slot.down = null;
    free.addLast(slot.port);
  }

  private void closeGame(Game game) {
    for (int port : new ArrayList<>(game.joiners)) {
      freeSlot(slots.get(port));
    }

    games.remove(game.codeText);
    gamesByToken.remove(game.tokenHex);
    int left = gamesPerSender.getOrDefault(game.sender, 1) - 1;

    if (left > 0) {
      gamesPerSender.put(game.sender, left);
    } else {
      gamesPerSender.remove(game.sender);
    }

    Arrays.fill(game.token, (byte) 0);
  }

  // Called about once a second: ends what has run out, and gives back the lines to write, if any (counts only, never an address or code)
  public List<String> tick(long now) {
    for (Game game : new ArrayList<>(games.values())) {
      if (now - game.keptAt >= limits.gameLifeMilliseconds) {
        closeGame(game);
        counts.expired++;
      }
    }

    for (Slot slot : slots.values()) {
      boolean waitedTooLong = slot.state == Slot.State.PENDING && now - slot.madeAt >= limits.pendingMilliseconds;
      boolean idleTooLong = slot.state == Slot.State.ACTIVE && now - slot.trafficAt >= limits.idleMilliseconds;

      if (waitedTooLong || idleTooLong) {
        freeSlot(slot);
        counts.portsExpired++;
      }
    }

    if (now - statsAt < limits.statsMilliseconds) {
      return List.of();
    }

    Counts c = counts;
    int pending = 0;

    for (Slot slot : slots.values()) {
      if (slot.state == Slot.State.PENDING) {
        pending++;
      }
    }

    String line = "relay: in the last " + Math.round((now - statsAt) / 1000.0) + " s: " + c.opened + " games opened, " + c.closed
        + " closed, " + c.expired + " ended unkept; " + c.joins + " joins, " + c.refused + " refusals, " + c.echoes + " echoes; forwarded "
        + c.forwardedPackets + " packets, " + c.forwardedBytes + " bytes; dropped " + c.tooBig + " too big, " + c.overLimit
        + " over a limit, " + c.notAMessage + " not a message, " + c.strangers + " from strangers; " + c.portsExpired
        + " ports timed out. Now " + games.size() + " games, " + (slots.size() - free.size()) + " of " + slots.size()
        + " ports in use (" + pending + " waiting for both ends)";
    statsAt = now;
    counts = new Counts();
    return List.of(line);
  }

  // A game's code: 5 random bytes (40 bits) as 8 code letters, 5 bits each. Only the bits not yet used are kept between bytes, so the
  // number never grows past 12 bits.
  static byte[] makeCode(RandomBytes random) {
    byte[] bytes = random.next(5);
    int bits = 0;
    int value = 0;
    StringBuilder out = new StringBuilder(Protocol.CODE_BYTES);

    for (byte b : bytes) {
      value = ((value << 8) | (b & 0xff)) & 0xfff;
      bits += 8;

      while (bits >= 5) {
        out.append(Protocol.CODE_LETTERS.charAt((value >>> (bits - 5)) & 31));
        bits -= 5;
        value &= (1 << bits) - 1;
      }
    }

    return out.toString().getBytes(StandardCharsets.US_ASCII);
  }
}
