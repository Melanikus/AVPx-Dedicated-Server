package avpx.relay;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.text;

import avpx.relay.Protocol.Field;
import avpx.testing.SeededRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

// The same bytes as the Node version, byte for byte. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// The server was first written in Node (at commit f37b495), and games already speak to it. So this one must write exactly the same
// messages and passes from the same fields, and the tests' seeded random must give exactly the same bytes, or a test that passes here
// could mean something else than the Node test it was ported from. Each value below was made by the Node version's own code (its
// relay/protocol.js, relay/pass.js, relay/core.js, relay/limits.js and support/seeded-random.js, at f37b495), and is written here as it
// came out. Nothing here is from the network; these are the reference, and a change to any of them is a change to PROTOCOL.md.
public final class VectorsTest {
  private VectorsTest() {
  }

  // Each type, with every field it uses filled in as test/protocol.test.js fills them (full()): secret '0123456789abcdef', code
  // 'ABCD2345', port 27501, number 3, pass 'fedcba9876543210' with pass time 1794268800
  private static final String[] MESSAGES = {
    "41565052010100003031323334353637383961626364656600000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "41565052010200003031323334353637383961626364656641424344323334350000000066656463626139383736353433323130805ef26a0000000000000000",
    "41565052010300003031323334353637383961626364656600000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "41565052010400003031323334353637383961626364656600000000000000000000030066656463626139383736353433323130805ef26a0000000000000000",
    "41565052010500003031323334353637383961626364656600000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "41565052010600003031323334353637383961626364656641424344323334350000000000000000000000000000000000000000000000000000000000000000",
    "41565052010700003031323334353637383961626364656641424344323334356d6b000000000000000000000000000000000000000000000000000000000000",
    "41565052010800003031323334353637383961626364656600000000000000006d6b000000000000000000000000000000000000000000000000000000000000",
    "41565052010900003031323334353637383961626364656600000000000000006d6b000000000000000000000000000000000000000000000000000000000000",
    "41565052010a00003031323334353637383961626364656600000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "41565052010b00003031323334353637383961626364656600000000000000006d6b000000000000000000000000000000000000000000000000000000000000",
    "41565052010c00000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000",
    "41565052010d00003031323334353637383961626364656600000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "41565052010e00003031323334353637383961626364656600000000000000000000030000000000000000000000000000000000000000000000000000000000",
    "41565052010f00003031323334353637383961626364656600000000000000000000030000000000000000000000000000000000000000000000000000000000",
  };

  public static void register() {
    test("every type's message is the Node version's, byte for byte", () -> {
      same(Protocol.types().size(), MESSAGES.length, "one for each type");

      for (int type : Protocol.types()) {
        Set<Field> uses = Protocol.uses(type);
        Message m = Message.of(type);

        if (uses.contains(Field.SECRET)) {
          m.secret(latin1("0123456789abcdef"));
        }

        if (uses.contains(Field.CODE)) {
          m.code(latin1("ABCD2345"));
        }

        if (uses.contains(Field.PORT)) {
          m.port(27501);
        }

        if (uses.contains(Field.NUMBER)) {
          m.number(3);
        }

        if (uses.contains(Field.PASS)) {
          m.pass(latin1("fedcba9876543210"), 1794268800L);
        }

        same(hex(Protocol.encode(m)), MESSAGES[type - 1], "type " + type);
      }
    });

    test("a pass is the Node version's, byte for byte", () -> {
      same(hex(Pass.make(bytes(32, 7), "virginia", latin1("ABCD2345"), 1794268800L)), "da4328405a74a021fcf7c40db8d768ae", "the pass");
    });

    test("the tests' seeded random, the codes it makes, and an address's hash are the Node version's", () -> {
      same(hex(SeededRandom.of(3).next(8)), "3c8cdfc762dda363", "seed 3's first 8 bytes");

      SeededRandom random = SeededRandom.of(11);
      List<String> codes = new ArrayList<>();

      for (int i = 0; i < 4; i++) {
        codes.add(text(RelayCore.makeCode(random)));
      }

      same(codes, List.of("9P57L6XR", "V2CVG8KQ", "T74PQQN6", "NKL9PCV8"), "seed 11's first 4 codes");
      same(new AddressHasher(SeededRandom.of(7)).keyOf("203.0.113.7", 0), "a90f9e29b26d810d49ab8c6a07eca276", "an address's hash");
    });
  }
}
