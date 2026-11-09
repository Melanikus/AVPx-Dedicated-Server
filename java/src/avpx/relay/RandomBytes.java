package avpx.relay;

import java.security.SecureRandom;

// Where the server's random bytes come from. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// Every secret the server makes (a host's token, a joiner's ticket, a game's code, an owner key, the keys its cookies and address hashes
// are made with) comes from here. The server uses secure(): the operating system's own random source, through Java's SecureRandom, which
// nobody can guess. The tests use a seeded one of their own instead, so a test run is the same every time.
@FunctionalInterface
public interface RandomBytes {
  // n random bytes
  byte[] next(int n);

  // The server's: unguessable. SecureRandom may be used by many threads at once.
  static RandomBytes secure() {
    SecureRandom random = new SecureRandom();
    return n -> {
      byte[] out = new byte[n];
      random.nextBytes(out);
      return out;
    };
  }
}
