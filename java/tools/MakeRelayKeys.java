package avpx.tools;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HexFormat;

// Makes a version 2 relay's static keys (CRYPTO.md section 4): a P-384 key and an ML-KEM-1024 key, from Java's own SecureRandom. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   java -cp java/build/tools:java/build/server avpx.tools.MakeRelayKeys       (after build.sh; on Windows, ; in place of :)
//
// It prints two things:
// - "staticKeys", SECRET: it goes in that relay's /etc/avpx/settings.json and nowhere else, a file only root and the server's user can
//   read (deploy/README.md). Anyone who has it can be that relay.
// - the public keys, which go in the signed directory, so a game knows the relay before it says anything.
// It takes nothing from its command line and writes no file, so the secret is only where it's put. Each run makes new keys.
public final class MakeRelayKeys {
  private MakeRelayKeys() {
  }

  // A P-384 private key's number, as 48 bytes, big-endian
  private static byte[] number(KeyPair pair) {
    byte[] b = ((ECPrivateKey) pair.getPrivate()).getS().toByteArray();
    byte[] out = new byte[P384.SECRET_BYTES];
    int skip = b.length > out.length ? b.length - out.length : 0;
    System.arraycopy(b, skip, out, out.length - (b.length - skip), b.length - skip);
    return out;
  }

  public static void main(String[] args) {
    SecureRandom random = new SecureRandom();
    KeyPair p384 = P384.generate(random);
    byte[] number = number(p384);
    byte[] point = P384.encode((ECPublicKey) p384.getPublic());
    byte[] seed = new byte[MlKem.SEED_BYTES];
    random.nextBytes(seed);
    KeyPair kem = MlKem.fromSeed(seed);

    // What the relay will read must load as one pair, exactly as Settings.java loads it, or nothing is printed
    if (kem == null || P384.pair(number, point) == null) {
      System.err.println("MakeRelayKeys: the keys made don't load as a relay's settings would load them; nothing was printed");
      System.exit(1);
    }

    HexFormat hex = HexFormat.of();
    System.out.println("SECRET: for this relay's /etc/avpx/settings.json only, beside \"protocol\": 2");
    System.out.println("\"staticKeys\": {");
    System.out.println("  \"p384Private\": \"" + hex.formatHex(number) + "\",");
    System.out.println("  \"p384Public\": \"" + hex.formatHex(point) + "\",");
    System.out.println("  \"mlkemSeed\": \"" + hex.formatHex(seed) + "\"");
    System.out.println("}");
    System.out.println();
    System.out.println("PUBLIC: for the signed directory");
    System.out.println("p384Public  " + hex.formatHex(point));
    System.out.println("mlkemPublic " + hex.formatHex(MlKem.encode(kem.getPublic())));
  }
}
