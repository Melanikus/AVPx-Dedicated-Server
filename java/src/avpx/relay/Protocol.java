package avpx.relay;

import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

// The relay's own messages: what a host, a joiner and the relay say to each other. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server, from relay/protocol.js.
//
// WHY THE RELAY: a game hosted behind carrier-grade NAT (an internet provider sharing one public address between many homes) can't be
// reached from the internet, however the home router is set. So every internet game goes through our own small relay: the host and each
// joiner talk to the relay, which passes the game's packets between them. README.md says how this works.
//
// WHAT A MESSAGE IS: exactly MESSAGE_BYTES bytes, every field in its place, and every number little-endian (its smallest byte first):
//
//     bytes  0-3    'AVPR', so a stray packet is never taken for one
//     byte   4      the version of these messages, VERSION
//     byte   5      the type, one of Type below
//     bytes  6-7    0
//     bytes  8-23   a secret, 16 bytes: a host's token, a joiner's ticket, a cookie (RelayCore.java says what those are), or an echo's
//                   bytes
//     bytes 24-31   a game's code, 8 letters from CODE_LETTERS
//     bytes 32-33   a port
//     bytes 34-35   a number: why the relay refused, how many joiners a game has, or an echo's count
//     bytes 36-51   a pass, 16 bytes (Pass.java says what that is)
//     bytes 52-59   the pass time: when the pass was made, whole seconds since 1970-01-01 UTC
//     bytes 60-63   0
//
// Each type uses only some of the fields (uses(), below), and every field it doesn't use is 0.
//
// Every message is the same size, questions and answers alike, so the relay never answers with more bytes than it was sent: nobody can
// use it to flood someone else by asking in their name (an "amplification" attack). Anything that isn't exactly a message, with its
// zeros zero and its type known, isn't one: decode gives back null, and the relay drops it. Nothing in a message is ever a length or an
// index into anything, so a message can't make the relay read past what it was given (AVP Tao 3: input is hostile).
//
// THE GAME'S OWN PACKETS are never one of these, and the relay never reads or changes them: it only passes them on. See RelayCore.java.
//
// PROTOCOL.md section 2 says all this for any language, with the same numbers.
public final class Protocol {
  private Protocol() {
  }

  public static final int VERSION = 1;
  public static final int MESSAGE_BYTES = 64;
  public static final int SECRET_BYTES = 16;
  public static final int CODE_BYTES = 8;

  // 'AVPR', the first 4 bytes of every message
  private static final byte[] MAGIC = {0x41, 0x56, 0x50, 0x52};

  // The most a pass time can be: the most a JSON number holds exactly (2 to the 53rd, less 1), because the list takes the pass time as a
  // JSON number (PROTOCOL.md section 4)
  public static final long MOST_PASS_TIME = 9007199254740991L;

  // A game's code is what a joiner types or picks, so it has no letters that look alike (no 0, 1, I, O): 32 letters, 5 bits each, 8 of
  // them, 40 bits. Guessing one is slowed by the relay's limits on asking (RelayCore.java).
  public static final String CODE_LETTERS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

  // The types, by their numbers
  public static final class Type {
    private Type() {
    }

    public static final int HOST_OPEN = 1;      // a host asks for a game: a cookie, or nothing the first time
    public static final int HOST_OPENED = 2;    // the relay's answer: the host's token, the game's code, and a pass for the list
    public static final int HOST_KEEP = 3;      // a host says it's still there, every 15 s: its token
    public static final int HOST_KEPT = 4;      // the relay's answer: the token, how many joiners the game has, and a fresh pass
    public static final int HOST_CLOSE = 5;     // a host ends its game: its token. No answer.
    public static final int JOIN = 6;           // a joiner asks to join a game: its code, and a cookie, or nothing the first time
    public static final int JOIN_PORT = 7;      // the relay's answer: a ticket, the code, and the relay's port for this joiner
    public static final int NEW_JOINER = 8;     // the relay tells the host a joiner is coming, on that port: the host's token, the port
    public static final int HOST_HELLO = 9;     // the host, from its game's own socket, to that port: its token, the port
    public static final int JOINER_HELLO = 10;  // the joiner, from its game's own socket, to that port: its ticket
    public static final int READY = 11;         // the relay, from that port, to the joiner: both ends are there, start the game
    public static final int REFUSED = 12;       // the relay's answer when it won't: why, in the number
    public static final int COOKIE = 13;        // the answer to a HOST_OPEN or JOIN with no good cookie: the cookie to ask again with
    public static final int ECHO = 14;          // anyone asks for an answer at once, to time the round trip: 16 bytes, and a count
    public static final int ECHO_BACK = 15;     // the same 16 bytes and count back. A different type, so two relays can't be set
                                                // answering each other for ever
  }

  // Why the relay refused, in a REFUSED's number
  public static final class Why {
    private Why() {
    }

    public static final int NO_SUCH_GAME = 1;    // no game has that code (or it has ended)
    public static final int GAME_FULL = 2;       // the game has as many joiners as it can
    public static final int BUSY = 3;            // the relay has no room: too many games, or no port free
    public static final int TOO_MANY_GAMES = 4;  // this address already has as many games open as one address can
  }

  // A message's fields, as the table of which type uses which names them. PASS is the pass and its pass time together.
  public enum Field {
    SECRET, CODE, PORT, NUMBER, PASS
  }

  // The fields each type uses; every other field of that type is 0. PROTOCOL.md section 2's table, row for row.
  private static final Map<Integer, Set<Field>> USES = makeUses();

  private static Map<Integer, Set<Field>> makeUses() {
    Map<Integer, Set<Field>> uses = new TreeMap<>();
    uses.put(Type.HOST_OPEN, Collections.unmodifiableSet(EnumSet.of(Field.SECRET)));
    uses.put(Type.HOST_OPENED, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.CODE, Field.PASS)));
    uses.put(Type.HOST_KEEP, Collections.unmodifiableSet(EnumSet.of(Field.SECRET)));
    uses.put(Type.HOST_KEPT, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.NUMBER, Field.PASS)));
    uses.put(Type.HOST_CLOSE, Collections.unmodifiableSet(EnumSet.of(Field.SECRET)));
    uses.put(Type.JOIN, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.CODE)));
    uses.put(Type.JOIN_PORT, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.CODE, Field.PORT)));
    uses.put(Type.NEW_JOINER, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.PORT)));
    uses.put(Type.HOST_HELLO, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.PORT)));
    uses.put(Type.JOINER_HELLO, Collections.unmodifiableSet(EnumSet.of(Field.SECRET)));
    uses.put(Type.READY, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.PORT)));
    uses.put(Type.REFUSED, Collections.unmodifiableSet(EnumSet.of(Field.NUMBER)));
    uses.put(Type.COOKIE, Collections.unmodifiableSet(EnumSet.of(Field.SECRET)));
    uses.put(Type.ECHO, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.NUMBER)));
    uses.put(Type.ECHO_BACK, Collections.unmodifiableSet(EnumSet.of(Field.SECRET, Field.NUMBER)));
    return Collections.unmodifiableMap(uses);
  }

  // Every type and the fields it uses, in the order of their numbers
  public static Map<Integer, Set<Field>> uses() {
    return USES;
  }

  // The fields one type uses, or null for a number that's no type
  public static Set<Field> uses(int type) {
    return USES.get(type);
  }

  // Every type's number, smallest first
  public static List<Integer> types() {
    return List.copyOf(USES.keySet());
  }

  // Whether 8 bytes are a game's code: every one of them one of CODE_LETTERS
  public static boolean isCode(byte[] bytes) {
    if (bytes == null || bytes.length != CODE_BYTES) {
      return false;
    }

    for (byte b : bytes) {
      if (CODE_LETTERS.indexOf((char) (b & 0xff)) < 0) {
        return false;
      }
    }

    return true;
  }

  // The fields a message has filled in: a secret, code or pass that's there, a port or number that isn't 0, a pass time that isn't 0
  private static Set<Field> given(byte[] secret, byte[] code, int port, int number, byte[] pass, long passTime) {
    Set<Field> given = EnumSet.noneOf(Field.class);

    if (secret != null) {
      given.add(Field.SECRET);
    }

    if (code != null) {
      given.add(Field.CODE);
    }

    if (port != 0) {
      given.add(Field.PORT);
    }

    if (number != 0) {
      given.add(Field.NUMBER);
    }

    if (pass != null || passTime != 0) {
      given.add(Field.PASS);
    }

    return given;
  }

  // A message's 64 bytes, from its fields. Throws on any field that isn't right for its type: only our own code calls this, so a wrong
  // field is a bug to find at once.
  public static byte[] encode(Message m) {
    Set<Field> uses = USES.get(m.type());

    if (uses == null) {
      throw new IllegalArgumentException("encode: no such type");
    }

    byte[] secret = m.secret();
    byte[] code = m.code();
    byte[] pass = m.pass();

    if (secret != null && secret.length != SECRET_BYTES) {
      throw new IllegalArgumentException("encode: a secret is 16 bytes");
    }

    if (code != null && !isCode(code)) {
      throw new IllegalArgumentException("encode: a code is 8 of the code letters");
    }

    if (m.port() < 0 || m.port() > 0xffff || m.number() < 0 || m.number() > 0xffff) {
      throw new IllegalArgumentException("encode: a port or number fits in 16 bits");
    }

    if (pass != null && pass.length != Pass.PASS_BYTES) {
      throw new IllegalArgumentException("encode: a pass is 16 bytes");
    }

    if (m.passTime() < 0 || m.passTime() > MOST_PASS_TIME) {
      throw new IllegalArgumentException("encode: a pass time is a whole number of seconds, 0 to 2 to the 53rd less 1");
    }

    for (Field field : given(secret, code, m.port(), m.number(), pass, m.passTime())) {
      if (!uses.contains(field)) {
        throw new IllegalArgumentException("encode: this type has no " + field);
      }
    }

    byte[] out = new byte[MESSAGE_BYTES];
    System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
    out[4] = (byte) VERSION;
    out[5] = (byte) m.type();

    if (secret != null) {
      System.arraycopy(secret, 0, out, 8, SECRET_BYTES);
    }

    if (code != null) {
      System.arraycopy(code, 0, out, 24, CODE_BYTES);
    }

    putTwoBytes(out, 32, m.port());
    putTwoBytes(out, 34, m.number());

    if (pass != null) {
      System.arraycopy(pass, 0, out, 36, Pass.PASS_BYTES);
    }

    putEightBytes(out, 52, m.passTime());
    return out;
  }

  // A message's fields from its bytes, or null if the bytes aren't exactly a message. What it gives back holds copies, so nothing kept
  // from a message holds on to the packet it came in.
  public static Message decode(byte[] bytes) {
    if (bytes == null || bytes.length != MESSAGE_BYTES) {
      return null;
    }

    for (int i = 0; i < MAGIC.length; i++) {
      if (bytes[i] != MAGIC[i]) {
        return null;
      }
    }

    int type = bytes[5] & 0xff;
    Set<Field> uses = USES.get(type);

    if (bytes[4] != VERSION || uses == null) {
      return null;
    }

    // The bytes that are always 0
    if (bytes[6] != 0 || bytes[7] != 0) {
      return null;
    }

    for (int i = 60; i < MESSAGE_BYTES; i++) {
      if (bytes[i] != 0) {
        return null;
      }
    }

    byte[] secret = Arrays.copyOfRange(bytes, 8, 24);
    byte[] code = Arrays.copyOfRange(bytes, 24, 32);
    byte[] pass = Arrays.copyOfRange(bytes, 36, 52);
    int port = twoBytes(bytes, 32);
    int number = twoBytes(bytes, 34);
    long passTime = eightBytes(bytes, 52);
    boolean codeIsZero = allZero(code);

    // A code is all code letters, or all zeros; anything in between isn't a message
    if (!codeIsZero && !isCode(code)) {
      return null;
    }

    // A pass time past the most a JSON number holds exactly isn't one any relay made. One with its top bit set reads as below 0 here.
    if (passTime < 0 || passTime > MOST_PASS_TIME) {
      return null;
    }

    byte[] secretGiven = allZero(secret) ? null : secret;
    byte[] codeGiven = codeIsZero ? null : code;
    byte[] passGiven = allZero(pass) ? null : pass;

    // A field this type doesn't use must be 0
    if (!uses.containsAll(given(secretGiven, codeGiven, port, number, passGiven, passTime))) {
      return null;
    }

    return Message.of(type).secret(secretGiven).code(codeGiven).port(port).number(number).pass(passGiven, passTime);
  }

  private static boolean allZero(byte[] bytes) {
    for (byte b : bytes) {
      if (b != 0) {
        return false;
      }
    }

    return true;
  }

  // ----- Numbers in bytes, the smallest byte first (little-endian)

  private static void putTwoBytes(byte[] out, int at, int value) {
    out[at] = (byte) value;
    out[at + 1] = (byte) (value >>> 8);
  }

  private static int twoBytes(byte[] bytes, int at) {
    return (bytes[at] & 0xff) | ((bytes[at + 1] & 0xff) << 8);
  }

  static void putEightBytes(byte[] out, int at, long value) {
    for (int i = 0; i < 8; i++) {
      out[at + i] = (byte) (value >>> (8 * i));
    }
  }

  static long eightBytes(byte[] bytes, int at) {
    long value = 0;

    for (int i = 7; i >= 0; i--) {
      value = (value << 8) | (bytes[at + i] & 0xff);
    }

    return value;
  }
}
