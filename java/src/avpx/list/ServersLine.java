package avpx.list;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

// A server's line in the game's servers.cfg, and the fingerprint in it: the owner's short line, 2026-11-10 (the game's issue #175).
// Written 2026-11-10 by Melanikus for AVPx Dedicated Server.
//
// THE LINE is what a player puts in servers.cfg, beside the game's bin folder, to play on this server:
//   <address>  <fingerprint>  <name>
// - the address is the machine's public IPv4, written plainly. The list is at port 443 and the relay's control port is 27500; a server
//   on other ports is written <address>:<list port>:<relay port>, both given;
// - the fingerprint is 64 hex digits, small letters (below);
// - the name is the rest of the line: 1 to 31 printable ASCII characters, single spaces inside it allowed, but never two in a row (the
//   game's reader takes a run of spaces as one, so it would show another name), none at either end, not starting with # (a line starting
//   with # is a comment). Smoke's isLineName checks it before a line is printed.
// The game reads the fields apart at any run of spaces or tabs (a chat app turns tabs into spaces), so two spaces are written here.
//
// THE FINGERPRINT is one number for both of the server's keys: SHA-256 over
//   the 23 ASCII characters "AVPx servers.cfg line 1", one zero byte, the list certificate's SubjectPublicKeyInfo (its public key, in DER),
//   and the relay's 48-byte id (CRYPTO.md section 12.1, the SHA-384 of the relay's static keys).
// The game asks the list at the line's address for its certificate (TLS) and the relay's keys (GET /v1/relay-keys, over that same TLS),
// works the same sum out from what it was given, and talks to that address no further unless it's the line's fingerprint. "line 1" is the
// format's version: another format would be "line 2", and a game that doesn't know it refuses it.
//
// Smoke --installed --servers-line prints this machine's line with these two methods, from the key the list is serving and the relay's
// keys, each checked against the other (tools/Smoke.java).
public final class ServersLine {
  private ServersLine() {
  }

  public static final int DEFAULT_LIST_PORT = 443;
  public static final int DEFAULT_RELAY_PORT = 27500;
  public static final int RELAY_ID_BYTES = 48;
  public static final int FINGERPRINT_BYTES = 32;

  private static final byte[] WORDS = "AVPx servers.cfg line 1".getBytes(StandardCharsets.US_ASCII);

  // The fingerprint of a server whose list serves spki (DER) and whose relay's id is relayId (48 bytes)
  public static byte[] fingerprint(byte[] spki, byte[] relayId) {
    if (spki == null || spki.length == 0 || relayId == null || relayId.length != RELAY_ID_BYTES) {
      throw new IllegalArgumentException("a fingerprint needs the list's SubjectPublicKeyInfo and the relay's 48-byte id");
    }

    MessageDigest sha256;

    try {
      sha256 = MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      // Every Java has SHA-256 (the standard requires it), so this would be a broken Java: stop rather than print a wrong line
      throw new IllegalStateException("SHA-256 isn't in this Java", e);
    }

    sha256.update(WORDS);
    sha256.update((byte) 0);
    sha256.update(spki);
    sha256.update(relayId);
    return sha256.digest();
  }

  // The line itself, with no line break: the address alone when both ports are the usual ones, else with both ports after it
  public static String line(String address, int listPort, int relayPort, byte[] fingerprint, String name) {
    if (fingerprint == null || fingerprint.length != FINGERPRINT_BYTES) {
      throw new IllegalArgumentException("a line's fingerprint is 32 bytes");
    }

    String where = listPort == DEFAULT_LIST_PORT && relayPort == DEFAULT_RELAY_PORT ? address : address + ":" + listPort + ":" + relayPort;
    return where + "  " + HexFormat.of().formatHex(fingerprint) + "  " + name;
  }
}
