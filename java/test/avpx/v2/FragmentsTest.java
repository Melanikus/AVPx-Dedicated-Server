package avpx.v2;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsAny;

import avpx.testing.SeededRandom;
import java.util.List;

// The tests of Fragments.java (CRYPTO.md section 5, "Big messages over UDP", and 5.1's strict rules): every handshake message comes out
// as 1,200-byte datagrams and back in again, in any order, and a datagram that could be read more than one way is refused. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class FragmentsTest {
  private FragmentsTest() {
  }

  private static final byte[] ID = bytes(8, 0x11);
  private static final byte[] COOKIE = bytes(16, 0x22);

  // A message of n bytes, none of them 0, so a byte that moves or goes missing is seen
  private static byte[] message(int n) {
    byte[] m = SeededRandom.of(n).next(n);

    for (int i = 0; i < n; i++) {
      m[i] |= 1;
    }

    return m;
  }

  // The message put back together from its datagrams, read in the order given
  private static byte[] back(List<byte[]> datagrams, int... order) {
    Fragments.Fragment first = Fragments.read(Fragments.toRelay(), datagrams.get(order[0]));
    Fragments.Assembly assembly = new Fragments.Assembly(first);

    for (int i : order) {
      ok(assembly.add(Fragments.read(Fragments.toRelay(), datagrams.get(i))), "fragment " + i + " is taken");
    }

    ok(assembly.complete(), "every fragment is in");
    return assembly.message();
  }

  private static byte[] changed(byte[] d, int at, int to) {
    byte[] c = d.clone();
    c[at] = (byte) to;
    return c;
  }

  public static void register() {
    test("how many fragments a message takes: the length over 1,164, rounded up, and 1 for a message of no bytes", () -> {
      same(Fragments.count(0), 1, "no bytes");
      same(Fragments.count(1), 1, "1 byte");
      same(Fragments.count(1164), 1, "1,164 bytes");
      same(Fragments.count(1165), 2, "1,165 bytes");
      same(Fragments.count(HandshakeA.A2_BYTES), 2, "A2, 1,689 bytes");
      same(Fragments.count(HandshakeA.A1_BYTES), 3, "A1, 3,249 bytes");
      same(Fragments.count(4656), 4, "4,656 bytes, the most");
    });

    test("A1, A2, A3, an empty message and the biggest: each as 1,200-byte datagrams, and back, in order and out of it", () -> {
      for (int n : new int[] {HandshakeA.A1_BYTES, HandshakeA.A2_BYTES, HandshakeA.A3_BYTES, 0, 1164, 1165, Fragments.MOST_MESSAGE_BYTES}) {
        byte[] m = message(n);
        List<byte[]> datagrams = Fragments.cut(Fragments.toRelay(), 7, ID, COOKIE, m);
        same(datagrams.size(), Fragments.count(n), n + " bytes: its count");

        for (byte[] d : datagrams) {
          same(d.length, 1200, n + " bytes: every datagram is 1,200 bytes");
        }

        int[] forwards = new int[datagrams.size()];
        int[] backwards = new int[datagrams.size()];

        for (int i = 0; i < forwards.length; i++) {
          forwards[i] = i;
          backwards[i] = forwards.length - 1 - i;
        }

        same(back(datagrams, forwards), m, n + " bytes, in order");
        same(back(datagrams, backwards), m, n + " bytes, last first");
      }
    });

    test("a fragment says its kind, number, count, id, cookie and length, as cut", () -> {
      List<byte[]> datagrams = Fragments.cut(Fragments.toRelay(), 7, ID, COOKIE, message(HandshakeA.A1_BYTES));
      Fragments.Fragment f = Fragments.read(Fragments.toRelay(), datagrams.get(2));
      same(f.kind(), 7, "the kind");
      same(f.index(), 2, "its number");
      same(f.count(), 3, "the count");
      same(f.id(), ID, "the id");
      same(f.cookie(), COOKIE, "the cookie");
      same(f.length(), HandshakeA.A1_BYTES, "the length");
      same(f.part().length, HandshakeA.A1_BYTES - 2 * 1164, "the last part: what's left");
      same((datagrams.get(2)[34] & 0xff) | ((datagrams.get(2)[35] & 0xff) << 8), 2 * 1164, "it starts at 2 times 1,164, little-endian");
    });

    test("cut refuses what can't be sent: more than 4,656 bytes, an id that isn't 8 bytes, a cookie that isn't 16, a magic not 4", () -> {
      throwsAny(() -> Fragments.cut(Fragments.toRelay(), 7, ID, COOKIE, new byte[4657]), "4,657 bytes");
      throwsAny(() -> Fragments.cut(Fragments.toRelay(), 7, new byte[7], COOKIE, new byte[10]), "a 7-byte id");
      throwsAny(() -> Fragments.cut(Fragments.toRelay(), 7, ID, new byte[15], new byte[10]), "a 15-byte cookie");
      throwsAny(() -> Fragments.cut(new byte[3], 7, ID, COOKIE, new byte[10]), "a 3-byte magic");
    });

    test("STRICT: a datagram that isn't exactly one fragment, read only one way, is refused (refusal 6)", () -> {
      List<byte[]> a1 = Fragments.cut(Fragments.toRelay(), 7, ID, COOKIE, message(HandshakeA.A1_BYTES));
      byte[] first = a1.get(0);
      byte[] last = a1.get(2);
      byte[] magic = Fragments.toRelay();
      ok(Fragments.read(magic, first) != null && Fragments.read(magic, last) != null, "as cut, both read");

      same(Fragments.read(magic, null), null, "nothing");
      same(Fragments.read(magic, java.util.Arrays.copyOf(first, 1199)), null, "1,199 bytes");
      same(Fragments.read(magic, java.util.Arrays.copyOf(first, 1201)), null, "1,201 bytes");
      same(Fragments.read(Fragments.hostToJoiner(), first), null, "another magic: AVPE where AVPR is wanted");
      same(Fragments.read(magic, changed(first, 3, 'X')), null, "a magic with a byte changed");
      same(Fragments.read(magic, changed(first, 4, 1)), null, "version 1");
      same(Fragments.read(magic, changed(first, 4, 3)), null, "version 3");
      same(Fragments.read(magic, changed(first, 7, 0)), null, "a count of 0");
      same(Fragments.read(magic, changed(first, 7, 5)), null, "a count of 5");
      same(Fragments.read(magic, changed(first, 7, 4)), null, "a count of 4, for a length that takes 3");
      same(Fragments.read(magic, changed(first, 7, 2)), null, "a count of 2, for a length that takes 3");
      same(Fragments.read(magic, changed(last, 6, 3)), null, "fragment number 3 of 3");
      same(Fragments.read(magic, changed(changed(first, 32, 0x31), 33, 0x12)), null, "a length of 4,657, past the most");
      same(Fragments.read(magic, changed(last, 34, (2 * 1164 + 1) & 0xff)), null, "the last fragment, starting a byte late");
      same(Fragments.read(magic, changed(first, 34, 1)), null, "the first, starting at 1, not 0");
      same(Fragments.read(magic, changed(last, 1199, 1)), null, "a byte after the last part that isn't 0");
      same(Fragments.read(magic, changed(last, 36 + HandshakeA.A1_BYTES - 2 * 1164, 1)), null, "the byte just after the last part");

      // A fragment that says it starts at fragment 1's place, but is numbered 0: two ways to read it, so it's refused
      same(Fragments.read(magic, changed(changed(first, 34, 1164 & 0xff), 35, 1164 >>> 8)), null, "fragment 0 starting at 1,164");
    });

    test("an assembly takes a fragment again only if it's the very same, and nothing of another message", () -> {
      byte[] magic = Fragments.toRelay();
      List<byte[]> a1 = Fragments.cut(magic, 7, ID, COOKIE, message(HandshakeA.A1_BYTES));
      Fragments.Assembly assembly = new Fragments.Assembly(Fragments.read(magic, a1.get(0)));
      ok(assembly.add(Fragments.read(magic, a1.get(0))), "fragment 0");
      ok(assembly.add(Fragments.read(magic, a1.get(0))), "fragment 0 again, the same bytes: taken (a datagram can come twice)");
      ok(!assembly.complete(), "but it counts once: 1 of 3");
      same(assembly.bytesHeld(), 1164, "it holds 1,164 bytes");

      // The first bytes to come for a place are the ones kept: a changed fragment that comes first is taken, as nothing here can tell it
      // from the true one, and then the true one is refused. Only the whole message's tag can tell, and it fails, so the handshake does.
      byte[] changedPart = a1.get(1).clone();
      changedPart[100] ^= 1;
      ok(assembly.add(Fragments.read(magic, changedPart)), "a changed fragment 1 that comes first is taken");
      ok(!assembly.add(Fragments.read(magic, a1.get(1))), "and the true one after it is refused, as other bytes for the same place");
    });

    test("an assembly refuses another kind, count or length, and the same fragment with other bytes", () -> {
      byte[] magic = Fragments.toRelay();
      byte[] m = message(HandshakeA.A1_BYTES);
      List<byte[]> a1 = Fragments.cut(magic, 7, ID, COOKIE, m);
      Fragments.Assembly assembly = new Fragments.Assembly(Fragments.read(magic, a1.get(0)));
      ok(assembly.add(Fragments.read(magic, a1.get(0))), "fragment 0");

      byte[] otherBytes = a1.get(0).clone();
      otherBytes[100] ^= 1;
      ok(!assembly.add(Fragments.read(magic, otherBytes)), "fragment 0 again, with a byte changed");
      ok(!assembly.add(Fragments.read(magic, Fragments.cut(magic, 8, ID, COOKIE, m).get(1))), "fragment 1 of another kind");
      ok(!assembly.add(Fragments.read(magic, Fragments.cut(magic, 7, ID, COOKIE, message(HandshakeA.A1_BYTES - 1)).get(1))),
          "fragment 1 of a message a byte shorter");
      ok(!assembly.add(Fragments.read(magic, Fragments.cut(magic, 7, ID, COOKIE, message(HandshakeA.A2_BYTES)).get(1))),
          "fragment 1 of a message of 2 fragments");
      throwsAny(assembly::message, "the message before every fragment is in");

      ok(assembly.add(Fragments.read(magic, a1.get(2))), "fragment 2");
      ok(assembly.add(Fragments.read(magic, a1.get(1))), "fragment 1");
      same(assembly.bytesHeld(), HandshakeA.A1_BYTES, "it holds the whole message");
      same(assembly.message(), m, "and gives it back");
    });

    test("the magics handed out are copies: changing one changes nothing here", () -> {
      byte[] magic = Fragments.toRelay();
      magic[0] = 'X';
      same(Fragments.toRelay(), "AVPR".getBytes(java.nio.charset.StandardCharsets.US_ASCII), "AVPR, still");
      same(Fragments.hostToJoiner(), "AVPE".getBytes(java.nio.charset.StandardCharsets.US_ASCII), "and AVPE");
    });
  }
}
