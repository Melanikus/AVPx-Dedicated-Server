package avpx.testing;

import avpx.relay.RandomBytes;

// Random bytes the tests can repeat. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, from support/seeded-random.js.
//
// Random bytes that are the same on every run, so a test can say exactly what it expects: a simple generator started from a seed. The
// same seed gives the same bytes as the Node version's, byte for byte. Not for the server itself, which uses RandomBytes.secure().
public final class SeededRandom implements RandomBytes {
  // The generator's state: a whole number of 32 bits, which Java's int arithmetic keeps to 32 bits by itself, as Node's Math.imul and
  // >>> 0 did
  private int state;

  private SeededRandom(int seed) {
    state = seed;
  }

  public static SeededRandom of(int seed) {
    return new SeededRandom(seed);
  }

  @Override
  public byte[] next(int n) {
    byte[] out = new byte[n];

    for (int i = 0; i < n; i++) {
      state = state * 1664525 + 1013904223;
      // The top 8 bits of the state are the byte
      out[i] = (byte) (state >>> 24);
    }

    return out;
  }
}
