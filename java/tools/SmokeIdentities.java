package avpx.tools;

import avpx.access.AccessCode;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.v2.Identity;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

// The two players Smoke plays a version 2 game with: a host and a joiner, each an identity (CRYPTO.md section 4). Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server.
//
// A version 2 relay takes approved players only (section 6), and only the owner approves, with tools of their own that never go in this
// repository. So Smoke never approves anyone. It goes the way a player goes:
//   java -jar avpx-smoke.jar --make-identities <file>                 makes the two, writes them to file, and prints each one's
//                                                                     fingerprint and access code
//   java -jar avpx-smoke.jar --installed --request-access <file>     sends their two access requests to this machine's own list
//   (the owner approves the two codes with their own tools)
//   java -jar avpx-smoke.jar --installed --identities <file>         plays a whole game with them
// CI goes the same way, but approves with a decisions file of its own, the way the owner's tools do (java.yml).
//
// The file holds the two private keys, so it's made readable by its owner only (0600 where the file system has that) from its first
// moment, and never over a file that's there; shred it after the run. Smoke reads it as hostile input like anything else: exactly the
// lines below, each checked, and the keys held to each other.
//
// The file: the line "AVPX smoke identities 1", a line saying it holds private keys, then for the host and then the joiner, three lines
// each: its P-384 private number (96 hex digits), its P-384 public key (194), its ML-KEM key's seed (128: FIPS 203's d then z).
final class SmokeIdentities {
  private SmokeIdentities() {
  }

  private static final String FIRST_LINE = "AVPX smoke identities 1";
  private static final String SECOND_LINE = "# PRIVATE KEYS of two test players: never copy this file anywhere, and shred it after the run";
  private static final int MOST_FILE_BYTES = 4096;
  private static final Pattern NUMBER = Pattern.compile("[0-9a-f]{96}");
  private static final Pattern POINT = Pattern.compile("04[0-9a-f]{192}");
  private static final Pattern SEED = Pattern.compile("[0-9a-f]{128}");
  private static final HexFormat HEX = HexFormat.of();

  // A fresh identity nobody has approved, from Java's own SecureRandom
  static Identity fresh() {
    SecureRandom random = new SecureRandom();
    return Identity.of(P384.generate(random), MlKem.generate(random));
  }

  // Two fresh identities, written to file (which mustn't be there yet), and their fingerprints and access codes printed for the owner.
  // False if the file couldn't be written.
  static boolean make(Path file) {
    SecureRandom random = new SecureRandom();
    StringBuilder out = new StringBuilder(FIRST_LINE).append('\n').append(SECOND_LINE).append('\n');
    String[] fingerprints = new String[2];

    for (int i = 0; i < 2; i++) {
      KeyPair p384 = P384.generate(random);
      byte[] seed = new byte[MlKem.SEED_BYTES];
      random.nextBytes(seed);
      KeyPair kem = MlKem.fromSeed(seed);

      if (kem == null) {
        return false;
      }

      Identity id = Identity.of(p384, kem);
      out.append(String.format("%096x", ((ECPrivateKey) p384.getPrivate()).getS())).append('\n');
      out.append(HEX.formatHex(P384.encode((ECPublicKey) p384.getPublic()))).append('\n');
      out.append(HEX.formatHex(seed)).append('\n');
      fingerprints[i] = HEX.formatHex(id.fingerprint());
    }

    // Made with rights for its owner only (0600) from its first moment, where the file system has them: never readable by others, even
    // for an instant between making it and setting its rights
    FileAttribute<?>[] ownerOnly = FileSystems.getDefault().supportedFileAttributeViews().contains("posix")
        ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))}
        : new FileAttribute<?>[0];

    try (SeekableByteChannel channel = Files.newByteChannel(file, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
        ownerOnly)) {
      ByteBuffer bytes = ByteBuffer.wrap(out.toString().getBytes(StandardCharsets.US_ASCII));

      while (bytes.hasRemaining()) {
        channel.write(bytes);
      }
    } catch (IOException | UnsupportedOperationException e) {
      System.out.println("FAIL  the identities file couldn't be written, or is there already (" + e.getClass().getSimpleName() + ")");
      return false;
    }

    System.out.println("host " + fingerprints[0] + " " + AccessCode.of(fingerprints[0]));
    System.out.println("joiner " + fingerprints[1] + " " + AccessCode.of(fingerprints[1]));
    return true;
  }

  // The host's and the joiner's identities from the file, or null if it isn't exactly what make writes, or the keys don't hold together
  static Identity[] read(Path file) {
    List<String> lines;

    try {
      if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || Files.size(file) > MOST_FILE_BYTES) {
        return null;
      }

      lines = Files.readAllLines(file, StandardCharsets.US_ASCII);
    } catch (IOException | RuntimeException e) {
      return null;
    }

    if (lines.size() != 8 || !lines.get(0).equals(FIRST_LINE) || !lines.get(1).equals(SECOND_LINE)) {
      return null;
    }

    Identity[] out = new Identity[2];

    for (int i = 0; i < 2; i++) {
      String number = lines.get(2 + 3 * i);
      String point = lines.get(3 + 3 * i);
      String seed = lines.get(4 + 3 * i);

      if (!NUMBER.matcher(number).matches() || !POINT.matcher(point).matches() || !SEED.matcher(seed).matches()) {
        return null;
      }

      KeyPair p384 = P384.pair(HEX.parseHex(number), HEX.parseHex(point));
      KeyPair kem = MlKem.fromSeed(HEX.parseHex(seed));

      if (p384 == null || kem == null) {
        return null;
      }

      out[i] = Identity.of(p384, kem);
    }

    return out;
  }
}
