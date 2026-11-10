package avpx.list;

import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import java.util.HexFormat;

// The tests of ServersLine.java: the fingerprint against a known answer made apart from this code, and the line's shape. Written
// 2026-11-10 by Melanikus for AVPx Dedicated Server.
//
// Two known answers, each made apart from this code:
// - CRYPTO.md section 12.2's, from nyc3's real keys on 2026-11-10 (its list's P-256 SubjectPublicKeyInfo and its relay's id), made by
//   Secondary with Node's own crypto and again with Windows' certutil over the same 163 bytes. This is the third implementation;
// - one from made-up bytes, the same every time, made with Node's crypto (AvP-docs' tools/primary/servers-line-vector.js, outside the
//   repository): a 120-byte SubjectPublicKeyInfo (the size of a P-384 one) whose byte i is (7i + 3) mod 256, and a 48-byte relay id
//   whose byte i is (13i + 5) mod 256.
public final class ServersLineTest {
  private ServersLineTest() {
  }

  private static byte[] madeUp(int length, int times, int plus) {
    byte[] b = new byte[length];

    for (int i = 0; i < length; i++) {
      b[i] = (byte) ((times * i + plus) % 256);
    }

    return b;
  }

  private static final byte[] SPKI = madeUp(120, 7, 3);
  private static final byte[] RELAY_ID = madeUp(48, 13, 5);
  private static final String FINGERPRINT = "83ae7c68eb28a4437f459cd86be1abc96b7f0dd806d7bef9301197be00f5f73b";
  // The same sum with the zero byte after the words left out: a fingerprint without it must differ
  private static final String WITHOUT_THE_ZERO = "441b8c0bf860e6372bc542f66a7bbfd31db90a65c977bab7e2d43c5e84f93798";

  // CRYPTO.md 12.2's known answer: nyc3, 2026-11-10
  private static final String NYC3_SPKI = "3059301306072a8648ce3d020106082a8648ce3d030107034200046860ab37215b80bc818041605b4dc15b0f553ff8e0294ef67e"
      + "0145059ab4fe9fb670e3b138d4fbef7c9a82ae095b32dc647e20fc0840c56c1edf1402f51515f8";
  private static final String NYC3_RELAY_ID = "d4afea79e806fa341d350643a54b6964e532c591c0544be9ce93db4c752b9d89f668f026ffeb75a64f5049082499e445";
  private static final String NYC3_FINGERPRINT = "bb0e2958dade79033a90f34811c84837b404708cc004c5b1d37d9a26f28d663e";

  public static void register() {
    test("CRYPTO.md 12.2's known answer: nyc3's list key and relay id give its fingerprint", () -> {
      HexFormat hex = HexFormat.of();
      byte[] spki = hex.parseHex(NYC3_SPKI);
      same(spki.length, 91, "nyc3's SubjectPublicKeyInfo is 91 bytes, as a P-256 key's is");
      same(hex.formatHex(ServersLine.fingerprint(spki, hex.parseHex(NYC3_RELAY_ID))), NYC3_FINGERPRINT, "nyc3's fingerprint");
    });

    test("the fingerprint is SHA-256 of the words, a zero byte, the SubjectPublicKeyInfo and the relay id: Node's known answer", () -> {
      String got = HexFormat.of().formatHex(ServersLine.fingerprint(SPKI, RELAY_ID));
      same(got, FINGERPRINT, "the fingerprint");
      notSame(got, WITHOUT_THE_ZERO, "and the zero byte after the words is in the sum");
    });

    test("one changed byte of either key gives another fingerprint", () -> {
      byte[] spki = SPKI.clone();
      spki[60] ^= 1;
      byte[] id = RELAY_ID.clone();
      id[47] ^= 1;
      notSame(HexFormat.of().formatHex(ServersLine.fingerprint(spki, RELAY_ID)), FINGERPRINT, "a changed SubjectPublicKeyInfo");
      notSame(HexFormat.of().formatHex(ServersLine.fingerprint(SPKI, id)), FINGERPRINT, "a changed relay id");
    });

    test("a fingerprint needs a SubjectPublicKeyInfo and a relay id of exactly 48 bytes", () -> {
      throwsWith(() -> ServersLine.fingerprint(new byte[0], RELAY_ID), "48-byte id", "no SubjectPublicKeyInfo");
      throwsWith(() -> ServersLine.fingerprint(null, RELAY_ID), "48-byte id", "a missing SubjectPublicKeyInfo");
      throwsWith(() -> ServersLine.fingerprint(SPKI, new byte[47]), "48-byte id", "a relay id of 47 bytes");
      throwsWith(() -> ServersLine.fingerprint(SPKI, new byte[49]), "48-byte id", "of 49");
    });

    test("the line: the address, the fingerprint and the name, two spaces between, the name last", () -> {
      byte[] fp = HexFormat.of().parseHex(FINGERPRINT);
      same(ServersLine.line("104.131.35.41", 443, 27500, fp, "New York"), "104.131.35.41  " + FINGERPRINT + "  New York",
          "on the usual ports, the address alone");
      same(ServersLine.line("203.0.113.9", 8443, 27500, fp, "Home"), "203.0.113.9:8443:27500  " + FINGERPRINT + "  Home",
          "another list port: both ports written");
      same(ServersLine.line("203.0.113.9", 443, 27600, fp, "Home"), "203.0.113.9:443:27600  " + FINGERPRINT + "  Home",
          "another relay port: both ports written");
      throwsWith(() -> ServersLine.line("203.0.113.9", 443, 27500, new byte[31], "Home"), "32 bytes", "a fingerprint of 31 bytes");
    });
  }
}
