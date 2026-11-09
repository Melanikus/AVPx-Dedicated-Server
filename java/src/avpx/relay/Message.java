package avpx.relay;

// One of the relay's own messages, as its fields (Protocol.java says what each is, and turns one into its 64 bytes and back). Written
// 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// A message is made with Message.of(type), and each field the type uses is filled in after it, one at a time:
//
//     Message.of(Type.HOST_OPENED).secret(token).code(code).pass(pass, passTime)
//
// A field left out is nothing: no bytes (secret, code, pass), or 0 (port, number, passTime). Nothing is checked here; Protocol.encode
// checks every field before it writes one, and Protocol.decode before it gives one back.
//
// What's put in is copied, and what's given back is a copy, so a message never shares its bytes with anything else: changing the bytes it
// was made from, or the ones it gave back, changes nothing in it.
public final class Message {
  private final int type;
  private byte[] secret;
  private byte[] code;
  private int port;
  private int number;
  private byte[] pass;
  private long passTime;

  private Message(int type) {
    this.type = type;
  }

  public static Message of(int type) {
    return new Message(type);
  }

  private static byte[] copy(byte[] bytes) {
    return bytes == null ? null : bytes.clone();
  }

  // ----- Filling it in

  // A token, a ticket, a cookie, or an echo's 16 bytes
  public Message secret(byte[] value) {
    secret = copy(value);
    return this;
  }

  // A game's code: its 8 code letters, as bytes
  public Message code(byte[] value) {
    code = copy(value);
    return this;
  }

  // A relay port
  public Message port(int value) {
    port = value;
    return this;
  }

  // A reason, or a count
  public Message number(int value) {
    number = value;
    return this;
  }

  // A pass, and its pass time (whole seconds since 1970-01-01 UTC): they always go together
  public Message pass(byte[] value, long time) {
    pass = copy(value);
    passTime = time;
    return this;
  }

  // ----- Reading it

  public int type() {
    return type;
  }

  public byte[] secret() {
    return copy(secret);
  }

  public byte[] code() {
    return copy(code);
  }

  public int port() {
    return port;
  }

  public int number() {
    return number;
  }

  public byte[] pass() {
    return copy(pass);
  }

  public long passTime() {
    return passTime;
  }
}
