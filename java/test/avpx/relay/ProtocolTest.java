package avpx.relay;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.text;
import static avpx.testing.Tests.throwsAny;

import avpx.relay.Protocol.Field;
import avpx.relay.Protocol.Type;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

// The tests of Protocol.java and Pass.java: every message reads back as it was written, anything that isn't exactly a message is refused,
// and a pass is the HMAC PROTOCOL.md section 3 writes. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, ported test for test
// from test/protocol.test.js. Where Java can't even hold what a Node test tried (a port of 1.5, a pass time of 1.5 s, text where bytes go),
// the test says so and tries the nearest thing Java can hold.
public final class ProtocolTest {
  private ProtocolTest() {
  }

  private static final byte[] SECRET = latin1("0123456789abcdef");
  private static final byte[] CODE = latin1("ABCD2345");
  private static final byte[] PASS = latin1("fedcba9876543210");
  private static final long PASS_TIME = 1794268800L;   // 2026-11-11, as whole seconds

  // Every field a type uses, filled in; the rest left out
  private static Message full(int type) {
    Set<Field> uses = Protocol.uses(type);
    Message m = Message.of(type);

    if (uses.contains(Field.SECRET)) {
      m.secret(SECRET);
    }

    if (uses.contains(Field.CODE)) {
      m.code(CODE);
    }

    if (uses.contains(Field.PORT)) {
      m.port(27501);
    }

    if (uses.contains(Field.NUMBER)) {
      m.number(3);
    }

    if (uses.contains(Field.PASS)) {
      m.pass(PASS, PASS_TIME);
    }

    return m;
  }

  // A copy of bytes with one byte changed, read as a message
  private static Message change(byte[] from, int at, int value) {
    byte[] b = from.clone();
    b[at] = (byte) value;
    return Protocol.decode(b);
  }

  public static void register() {
    test("every type reads back as it was written, each with the fields it uses", () -> {
      same(Protocol.types().size(), 15, "the 15 types of PROTOCOL.md section 2");

      for (int type : Protocol.types()) {
        Message fields = full(type);
        byte[] bytes = Protocol.encode(fields);
        same(bytes.length, Protocol.MESSAGE_BYTES, "type " + type + "'s size");
        Message m = Protocol.decode(bytes);
        ok(m != null, "type " + type + " reads back");
        same(m.type(), type, "its type");
        same(m.secret(), fields.secret(), "its secret");
        same(m.code(), fields.code(), "its code");
        same(m.port(), fields.port(), "its port");
        same(m.number(), fields.number(), "its number");
        same(m.pass(), fields.pass(), "its pass");
        same(m.passTime(), fields.passTime(), "its pass time");
      }
    });

    test("which fields each type uses is PROTOCOL.md section 2's table, row for row", () -> {
      Map<Integer, Set<Field>> want = new TreeMap<>();
      want.put(Type.HOST_OPEN, EnumSet.of(Field.SECRET));
      want.put(Type.HOST_OPENED, EnumSet.of(Field.SECRET, Field.CODE, Field.PASS));
      want.put(Type.HOST_KEEP, EnumSet.of(Field.SECRET));
      want.put(Type.HOST_KEPT, EnumSet.of(Field.SECRET, Field.NUMBER, Field.PASS));
      want.put(Type.HOST_CLOSE, EnumSet.of(Field.SECRET));
      want.put(Type.JOIN, EnumSet.of(Field.SECRET, Field.CODE));
      want.put(Type.JOIN_PORT, EnumSet.of(Field.SECRET, Field.CODE, Field.PORT));
      want.put(Type.NEW_JOINER, EnumSet.of(Field.SECRET, Field.PORT));
      want.put(Type.HOST_HELLO, EnumSet.of(Field.SECRET, Field.PORT));
      want.put(Type.JOINER_HELLO, EnumSet.of(Field.SECRET));
      want.put(Type.READY, EnumSet.of(Field.SECRET, Field.PORT));
      want.put(Type.REFUSED, EnumSet.of(Field.NUMBER));
      want.put(Type.COOKIE, EnumSet.of(Field.SECRET));
      want.put(Type.ECHO, EnumSet.of(Field.SECRET, Field.NUMBER));
      want.put(Type.ECHO_BACK, EnumSet.of(Field.SECRET, Field.NUMBER));
      same(Protocol.uses(), want, "the table");
      same(List.of(Type.ECHO, Type.ECHO_BACK), List.of(14, 15), "the echo's two numbers");
    });

    test("the fields sit where PROTOCOL.md says, little-endian", () -> {
      byte[] b = Protocol.encode(Message.of(Type.HOST_KEPT).secret(SECRET).number(0x0102).pass(PASS, 0x0102030405L));
      same(text(Arrays.copyOfRange(b, 0, 4)), "AVPR", "the magic");
      same(new int[] {b[4], b[5], b[6], b[7]}, new int[] {1, Type.HOST_KEPT, 0, 0}, "the version, the type and the reserved bytes");
      same(Arrays.copyOfRange(b, 8, 24), SECRET, "the secret");
      same(new int[] {b[34], b[35]}, new int[] {0x02, 0x01}, "the number, its smallest byte first");
      same(Arrays.copyOfRange(b, 36, 52), PASS, "the pass");
      same(Arrays.copyOfRange(b, 52, 60), new byte[] {5, 4, 3, 2, 1, 0, 0, 0}, "the pass time, its smallest byte first");
      same(Arrays.copyOfRange(b, 60, 64), new byte[4], "the padding");
    });

    test("a message with no secret or code reads them back as null", () -> {
      Message m = Protocol.decode(Protocol.encode(Message.of(Type.HOST_OPEN)));
      same(m.secret(), null, "no secret");
      same(m.code(), null, "no code");
      same(m.port(), 0, "no port");
      same(m.pass(), null, "no pass");
    });

    test("a message is the same size whatever its type, so no answer is bigger than its question", () -> {
      for (int type : Protocol.types()) {
        same(Protocol.encode(full(type)).length, Protocol.MESSAGE_BYTES, "type " + type);
      }
    });

    test("anything that is not exactly a message is not one", () -> {
      byte[] good = Protocol.encode(Message.of(Type.JOIN).code(CODE));
      ok(Protocol.decode(good) != null, "the good one is");

      same(Protocol.decode(Arrays.copyOf(good, 63)), null, "one byte short");
      same(Protocol.decode(Arrays.copyOf(good, 65)), null, "one byte over");
      same(Protocol.decode(new byte[0]), null, "nothing");
      // Node's test gave it text; in Java a message can only be given bytes, so the nearest thing is no bytes at all
      same(Protocol.decode(null), null, "not bytes at all");

      same(change(good, 0, 0x41 + 1), null, "the wrong magic");
      same(change(good, 4, 2), null, "another version");
      same(change(good, 5, 0), null, "no type");
      same(change(good, 5, 16), null, "the type after the last");
      same(change(good, 5, 99), null, "an unknown type");
      same(change(good, 5, 0xff), null, "a type with its top bit set, which Java's bytes read as below 0");
      same(change(good, 6, 1), null, "a reserved byte not 0 (6)");
      same(change(good, 7, 1), null, "a reserved byte not 0 (7)");
      same(change(good, 60, 1), null, "the padding not 0 (60)");
      same(change(good, 63, 1), null, "the padding not 0 (63)");
      same(change(good, 24, 0x30), null, "a code with a 0 in it, which no code has");
      same(change(good, 31, 0), null, "a code with a 0 byte at its end");

      byte[] big = Protocol.encode(Message.of(Type.HOST_KEPT).secret(SECRET).pass(PASS, 1));
      Protocol.putEightBytes(big, 52, Protocol.MOST_PASS_TIME + 1);
      same(Protocol.decode(big), null, "a pass time past the most a JSON number holds exactly");
      Protocol.putEightBytes(big, 52, -1L);
      same(Protocol.decode(big), null, "a pass time with every bit set, which a Java long reads as below 0");
      Protocol.putEightBytes(big, 52, Protocol.MOST_PASS_TIME);
      ok(Protocol.decode(big) != null, "and the most it holds is a message");
    });

    test("a field its type doesn't use, not 0, makes it no message", () -> {
      // One byte of each field, in turn, on every type that doesn't use that field
      Map<String, Integer> at = new LinkedHashMap<>();
      at.put("secret", 8);
      at.put("code", 24);
      at.put("port", 32);
      at.put("number", 34);
      at.put("pass", 36);
      at.put("passTime", 52);
      Map<String, Field> usedBy = Map.of("secret", Field.SECRET, "code", Field.CODE, "port", Field.PORT, "number", Field.NUMBER,
          "pass", Field.PASS, "passTime", Field.PASS);
      int tried = 0;

      for (int type : Protocol.types()) {
        byte[] bytes = Protocol.encode(full(type));

        for (Map.Entry<String, Integer> field : at.entrySet()) {
          if (!Protocol.uses(type).contains(usedBy.get(field.getKey()))) {
            byte[] b = bytes.clone();

            if (field.getKey().equals("code")) {
              System.arraycopy(latin1("ABCD2345"), 0, b, field.getValue(), 8);
            } else {
              b[field.getValue()] = 1;
            }

            same(Protocol.decode(b), null, "type " + type + " with a " + field.getKey());
            tried++;
          }
        }
      }

      ok(tried > 40, tried + " tried");
    });

    test("a code is only ever 8 of the code letters", () -> {
      ok(Protocol.isCode(latin1("23456789")), "23456789");
      ok(!Protocol.isCode(latin1("ABCDEFGI")), "I is not a code letter");
      ok(!Protocol.isCode(latin1("abcdefgh")), "small letters are not");
      ok(!Protocol.isCode(latin1("ABCDEFG")), "7 letters are not a code");
      // Node's test gave it text; Java's isCode only takes bytes, so the nearest thing is no bytes at all
      ok(!Protocol.isCode(null), "nothing is not a code");
      same(Protocol.CODE_LETTERS.length(), 32, "32 letters");
      ok(!Pattern.compile("[01IO]").matcher(Protocol.CODE_LETTERS).find(), "no letters that look like another");
    });

    test("the relay's own code cannot write a wrong message", () -> {
      throwsAny(() -> Protocol.encode(Message.of(99)), "type 99");
      throwsAny(() -> Protocol.encode(Message.of(Type.JOIN).secret(new byte[15])), "a secret of 15");
      throwsAny(() -> Protocol.encode(Message.of(Type.JOIN).code(latin1("ABCDEFGI"))), "a code with an I");
      throwsAny(() -> Protocol.encode(Message.of(Type.JOIN_PORT).port(65536)), "a port of 65536");
      throwsAny(() -> Protocol.encode(Message.of(Type.REFUSED).number(-1)), "a number below 0");
      // Node's test tried a port of 1.5; a Java int can't hold one, so the nearest thing is a port below 0
      throwsAny(() -> Protocol.encode(Message.of(Type.JOIN_PORT).port(-1)), "a port below 0");
      throwsAny(() -> Protocol.encode(Message.of(Type.HOST_KEPT).pass(new byte[15], 1)), "a pass of 15");
      throwsAny(() -> Protocol.encode(Message.of(Type.HOST_KEPT).pass(null, -1)), "a pass time below 0");
      throwsAny(() -> Protocol.encode(Message.of(Type.HOST_KEPT).pass(null, Protocol.MOST_PASS_TIME + 1)), "a pass time past the most");
      throwsAny(() -> Protocol.encode(Message.of(Type.JOIN).port(1)), "a field JOIN doesn't use");
      throwsAny(() -> Protocol.encode(Message.of(Type.HOST_KEEP).pass(PASS, 0)), "a pass on a HOST_KEEP");
      throwsAny(() -> Protocol.encode(Message.of(Type.ECHO_BACK).code(CODE)), "a code on an ECHO_BACK");
    });

    test("what decode gives back holds copies, not the packet it came in", () -> {
      byte[] bytes = Protocol.encode(Message.of(Type.HOST_KEPT).secret(SECRET).pass(PASS, PASS_TIME));
      Message m = Protocol.decode(bytes);
      Arrays.fill(bytes, (byte) 0);
      same(m.secret(), SECRET, "the secret is still there");
      same(m.pass(), PASS, "and the pass");

      // And Java's own: what a message gives back is a copy too, so changing it changes nothing in the message
      m.secret()[0] = 0;
      same(m.secret(), SECRET, "a secret given back and changed leaves the message's own alone");
    });

    test("a pass is the HMAC PROTOCOL.md section 3 writes, byte for byte", () -> {
      byte[] key = bytes(32, 7);
      byte[] time = new byte[8];
      Protocol.putEightBytes(time, 0, PASS_TIME);
      ByteArrayOutputStream what = new ByteArrayOutputStream();
      what.writeBytes(latin1("AVPX-PASS-1"));
      what.writeBytes(latin1("virginia"));
      what.write(0);
      what.writeBytes(CODE);
      what.writeBytes(time);
      byte[] want = Arrays.copyOf(Crypto.hmacSha256(key, what.toByteArray()), 16);
      same(Pass.make(key, "virginia", CODE, PASS_TIME), want, "the pass");

      notSame(Pass.make(key, "paris", CODE, PASS_TIME), want, "another region, another pass");
      notSame(Pass.make(key, "virginia", latin1("ABCD2346"), PASS_TIME), want, "another code");
      notSame(Pass.make(key, "virginia", CODE, PASS_TIME + 1), want, "another second");
      notSame(Pass.make(bytes(32, 8), "virginia", CODE, PASS_TIME), want, "another key");

      throwsAny(() -> Pass.make(new byte[31], "virginia", CODE, PASS_TIME), "a key that isn't 32 bytes");
      throwsAny(() -> Pass.make(key, "Virginia", CODE, PASS_TIME), "a region with a capital");
      // Node's test tried a fraction of a second; a Java long can't hold one, so the nearest thing is a time below 0
      throwsAny(() -> Pass.make(key, "virginia", CODE, -1), "a time below 0");
    });

    test("a region is 1 to 16 small letters, digits and -", () -> {
      for (String good : List.of("virginia", "saopaulo", "paris", "a", "us-east-1", "x".repeat(16))) {
        ok(Pass.isRegion(good), good);
      }

      // Node's test also tried a number (7); a Java region can only be text, so null stands in for anything that isn't
      for (String bad : Arrays.asList("", "x".repeat(17), "Paris", "sao paulo", "sao_paulo", "paris\n", "vir.ginia", null)) {
        ok(!Pass.isRegion(bad), String.valueOf(bad));
      }
    });
  }
}
