package avpx.crypto;

import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.testing.Kat;
import avpx.testing.ScriptedRandom;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

// ECDH on P-384 (P384.java) against every published case in test-vectors/crypto-kat: NIST's and Wycheproof's. Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server. (ECDSA's cases went with Signatures.java, 2026-11-09: nothing in the server signs or checks a
// signature until the signed relays directory, CRYPTO.md section 12, and they come back with it. git keeps both.)
//
// The other side's point always goes through P384.decode, the one way a point from outside gets in, so these cases are its check too:
// a point off the curve, of the wrong length, or compressed (which version 2 never sends) must be refused there, and never reach Java's
// ECDH, which would throw on it.
public final class P384KatTest {
  private P384KatTest() {
  }

  // P-384's curve, as Java has it
  private static final ECParameterSpec CURVE = ((ECPublicKey) P384.generate(ScriptedRandom.seeded(1)).getPublic()).getParams();

  // Our private key, from its number as the case gives it
  private static PrivateKey ours(byte[] scalar) throws Exception {
    return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1, scalar), CURVE));
  }

  private static String unless(boolean right, String what) {
    return right ? null : what;
  }

  // An ECDH case. "valid": the point is taken, and agrees to exactly the shared secret. "invalid": the point is refused. "acceptable"
  // (either is allowed): mayTake says whether taking it is right here; if it's taken, it must still agree exactly.
  private static String ecdh(Kat.Case c, byte[] point, boolean mayTake) throws Exception {
    ECPublicKey theirs = P384.decode(point);
    boolean acceptable = "acceptable".equals(c.result());

    if (theirs == null) {
      return c.valid() ? "the point was refused" : null;
    }

    if (!c.valid() && !(acceptable && mayTake)) {
      return "the point was taken";
    }

    return unless(Arrays.equals(P384.agree(ours(c.bytes("private")), theirs), c.bytes("shared")), "another shared secret");
  }

  // The point a DER key names, as the 97 bytes the wire carries it in (0x04, then x, then y, 48 bytes each, big-endian), or null if
  // either number needs more than 48 bytes (a key on a bigger curve)
  private static byte[] wire(ECPublicKey key) {
    byte[] out = new byte[97];
    out[0] = 0x04;
    return fits(key.getW().getAffineX(), out, 1) && fits(key.getW().getAffineY(), out, 49) ? out : null;
  }

  // Writes a number into 48 bytes at "at", big-endian, with 0s in front; false if it needs more. Java's own bytes for a number may
  // have one 0 in front (its sign), which isn't part of the number.
  private static boolean fits(BigInteger n, byte[] out, int at) {
    byte[] b = n.toByteArray();
    int skip = b.length > 1 && b[0] == 0 ? 1 : 0;
    int length = b.length - skip;

    if (n.signum() < 0 || length > 48) {
      return false;
    }

    System.arraycopy(b, skip, out, at + 48 - length, length);
    return true;
  }

  public static void register() {
    test("ECDH P-384, NIST CAVP's 25: each point is taken, and agrees to exactly the shared secret", () -> {
      String file = "ecdh-p384/nist-cavp.json";
      same(Kat.each(file, Kat.read(file), c -> ecdh(c, c.bytes("public"), false)), 25, "all 25");
    });

    test("P-384 points, NIST's 12 to accept or refuse (FIPS 186-4 PKV): P384.decode decides each as NIST does", () -> {
      String file = "ecdh-p384/nist-cavp-pkv.json";
      same(Kat.each(file, Kat.read(file), c -> {
        boolean taken = P384.decode(c.bytes("public")) != null;
        return c.valid() ? unless(taken, "refused: " + c.text("reason")) : unless(!taken, "taken: " + c.text("reason"));
      }), 12, "all 12");
    });

    test("ECDH P-384, Wycheproof's 790 points as sent: every good one agrees exactly, every bad one is refused at decode, none throws", () -> {
      String file = "ecdh-p384/wycheproof-ecpoint.json";
      same(Kat.each(file, Kat.read(file), c -> ecdh(c, c.bytes("public"), false)), 790, "all 790");
    });

    // Version 2 never takes a DER key. These cases are here for the points they name: whatever the DER said (another curve, odd
    // parameters, a point off the curve), the point is put in the 97 bytes the wire carries and goes through P384.decode, as anything
    // from outside does. Java's refusing the DER itself counts as a refusal.
    test("ECDH P-384, Wycheproof's 1,047 DER keys: every good one agrees exactly through the wire's own check, every bad one is refused", () -> {
      String file = "ecdh-p384/wycheproof-der.json";
      same(Kat.each(file, Kat.read(file), c -> {
        PublicKey key;

        try {
          key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(c.bytes("publicDer")));
        } catch (java.security.GeneralSecurityException e) {
          return c.valid() ? "Java refused the DER of a good key" : null;
        }

        byte[] point = key instanceof ECPublicKey ec ? wire(ec) : null;

        // A good case's key must be P-384's, so its point fits the wire; a bad or odd one may not, which refuses it
        if (point == null) {
          return c.valid() ? "a good key whose point doesn't fit 97 bytes" : null;
        }

        return ecdh(c, point, true);
      }), 1047, "all 1,047");
    });

  }
}
