package avpx.testing;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.ArrayList;
import java.util.List;

// A "random" source that gives exactly the bytes it was given, in order, then refuses: for known-answer tests and test vectors only.
// Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// Java's key generation and ML-KEM's encapsulation take the randomness they use from a SecureRandom their caller gives them. Given this
// one, they're fixed: FIPS 203's key generation from its seeds d and z, an encapsulation from its m, a P-384 key from its bytes. So a
// test can check them against NIST's answers, and a whole handshake can be written down byte for byte for every other implementation.
// Never for the server: it uses RandomBytes.secure() and SecureRandom.
public final class ScriptedRandom extends SecureRandom {
  private static final long serialVersionUID = 1L;
  private final Script script;

  private ScriptedRandom(Script script) {
    super(script, null);
    this.script = script;
  }

  // Every draw so far, in order, each as the bytes it gave: so the test vectors can write down what each key was made from (FIPS 203's
  // d and z, an encapsulation's m), as the bytes every other implementation takes, not as how Java happened to ask for them
  public List<byte[]> draws() {
    List<byte[]> out = new ArrayList<>();

    for (byte[] d : script.draws) {
      out.add(d.clone());
    }

    return out;
  }

  // The bytes to give, one after another
  public static ScriptedRandom of(byte[]... parts) {
    int total = 0;

    for (byte[] p : parts) {
      total += p.length;
    }

    byte[] all = new byte[total];
    int at = 0;

    for (byte[] p : parts) {
      System.arraycopy(p, 0, all, at, p.length);
      at += p.length;
    }

    return new ScriptedRandom(new Script(all));
  }

  // Endless bytes from a seed, the same every run, for where a test needs randomness it doesn't check byte by byte
  public static ScriptedRandom seeded(int seed) {
    return new ScriptedRandom(new Script(SeededRandom.of(seed)));
  }

  private static final class Script extends SecureRandomSpi {
    private static final long serialVersionUID = 1L;
    private final byte[] bytes;
    // Not kept if this were ever written out (SecureRandomSpi can be serialized; SeededRandom can't): nothing here ever is
    private final transient SeededRandom more;
    private final ArrayList<byte[]> draws = new ArrayList<>();
    private int at;

    Script(byte[] bytes) {
      this.bytes = bytes;
      this.more = null;
    }

    Script(SeededRandom more) {
      this.bytes = new byte[0];
      this.more = more;
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
      // Seeding changes nothing: the bytes are the script's
    }

    @Override
    protected void engineNextBytes(byte[] out) {
      if (more != null) {
        System.arraycopy(more.next(out.length), 0, out, 0, out.length);
      } else if (at + out.length > bytes.length) {
        throw new IllegalStateException("ScriptedRandom: asked for more bytes than it was given");
      } else {
        System.arraycopy(bytes, at, out, 0, out.length);
        at += out.length;
      }

      draws.add(out.clone());
    }

    @Override
    protected byte[] engineGenerateSeed(int n) {
      byte[] out = new byte[n];
      engineNextBytes(out);
      return out;
    }
  }
}
