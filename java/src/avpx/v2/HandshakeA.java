package avpx.v2;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

// Handshake A (CRYPTO.md section 6): a game and its relay agree on keys, and the relay is proved to the game. Noise's pattern NK, made
// post-quantum as PQNoise does (a KEM stands in for a Diffie-Hellman where a static key is proved), and hybrid (every ECDH result and
// every ML-KEM secret goes into one chain). Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   <- s                    the game knows the relay's static P-384 and ML-KEM keys beforehand, from the signed directory
//   ...
//   -> e, es, skem          A1, game to relay: 3,249 bytes
//   <- e, ee, ekem          A2, relay to game: 1,689 bytes, sealing the relay's 8-byte session id
//   -> (confirmation)       A3, game to relay: 16 bytes, the game's key confirmation
//
// The start (settled with Third, 2026-11-09): h = SHA-384(the protocol name), ck = h; MixHash(the region in ASCII, then one 0 byte); then,
// as Noise does for a pre-message, MixHash(the relay's static P-384 key, 97 bytes) and MixHash(its static ML-KEM key, 1,568 bytes).
//
// The tokens:
//   e     send an ephemeral P-384 key, MixHash it; the game (the initiator) also sends an ephemeral ML-KEM key, and MixHashes that
//   es    MixKey(ECDH(the game's ephemeral key, the relay's static key))
//   skem  the game encapsulates to the relay's static ML-KEM key, sends the ciphertext, MixHashes it, and MixKeys the secret
//   ee    MixKey(ECDH(the two ephemeral keys))
//   ekem  the relay encapsulates to the game's ephemeral ML-KEM key, sends the ciphertext, MixHashes it, and MixKeys the secret
// es and skem prove the relay: only the holder of both its static keys can make an A2 that opens. ee and ekem give forward secrecy.
//
// The game's side is here too, for the tests and the test vectors: the game itself is Fifth's, and must match this byte for byte.
//
// Wiping (CRYPTO.md section 9): every array of ours that held a secret is zeroed as soon as it's used (each ECDH and ML-KEM result after
// its MixKey, the state when the handshake ends). Java's own EC and ML-KEM private key objects keep their bytes inside and give no way to
// clear them, which is CRYPTO.md's known limit for a managed language: a memory dump of a running server can still hold an ephemeral key.
public final class HandshakeA {
  private HandshakeA() {
  }

  public static final String PROTOCOL = "AVPX_pqNK_P384+MLKEM1024_AESGCM_SHA384_v2";
  public static final int A1_BYTES = P384.PUBLIC_BYTES + MlKem.ENCAPSULATION_KEY_BYTES + MlKem.CIPHERTEXT_BYTES + 16;
  public static final int SESSION_ID_BYTES = 8;
  public static final int A2_BYTES = P384.PUBLIC_BYTES + MlKem.CIPHERTEXT_BYTES + SESSION_ID_BYTES + 16;
  public static final int A3_BYTES = 16;
  private static final byte[] NOTHING = new byte[0];

  // The start, for both sides
  static Noise start(String region, byte[] relayStaticP384, byte[] relayStaticKem) {
    Noise noise = new Noise(PROTOCOL);
    byte[] name = region.getBytes(StandardCharsets.US_ASCII);
    noise.mixHash(Arrays.copyOf(name, name.length + 1));
    noise.mixHash(relayStaticP384);
    noise.mixHash(relayStaticKem);
    return noise;
  }

  // What both sides have once the handshake is done: the keys each way, and the relay's session id
  public record Keys(Noise.Split split, byte[] sessionId, byte[] transcript) {
  }

  // ----- The relay's side

  // The relay's static keys, as its settings hold them, with their public halves as they go in the directory
  public record RelayKeys(KeyPair p384, KeyPair kem, byte[] p384Public, byte[] kemPublic) {
    public static RelayKeys of(KeyPair p384, KeyPair kem) {
      return new RelayKeys(p384, kem, P384.encode((ECPublicKey) p384.getPublic()), MlKem.encode(kem.getPublic()));
    }
  }

  // The relay's half-way state, once A1 is read and A2 made: what it needs to check A3
  public static final class Responder {
    private final Noise noise;
    private final byte[] a2;
    private final byte[] sessionId;

    private Responder(Noise noise, byte[] a2, byte[] sessionId) {
      this.noise = noise;
      this.a2 = a2;
      this.sessionId = sessionId;
    }

    // A2's bytes, kept to be sent again, byte for byte, if A1 comes again (CRYPTO.md section 6, "Losses")
    public byte[] a2() {
      return a2.clone();
    }

    // A3: the game's key confirmation. The keys, or null if its tag fails. Either way, this state's secrets are wiped.
    public Keys readA3(byte[] a3) {
      try {
        if (a3 == null || a3.length != A3_BYTES || noise.decryptAndHash(a3) == null) {
          return null;
        }

        return new Keys(noise.split(), sessionId.clone(), noise.h());
      } finally {
        noise.wipe();
      }
    }

    // The game's first sealed message, when A3 was lost, counts as its confirmation: the keys, without A3's tag (CRYPTO.md section 6)
    public Keys keysWithoutA3() {
      return expect().keys();
    }

    // What the game's A3 must be, and the keys it would confirm: both known at once, as nothing in them waits for A3. A3 is an empty
    // EncryptAndHash, so its 16 bytes are fixed by what came before; the game sends them to prove it has the keys. So the relay (SealedRelay)
    // works them out as soon as A2 is made, and takes the keys only once A3 comes and is exactly a3, or, if A3 was lost, once the game's
    // first sealed message opens under them. Either way the transcript is h after A3 (CRYPTO.md 5.1, point 15). This state's secrets are
    // wiped.
    public record Expected(byte[] a3, Keys keys) {
    }

    public Expected expect() {
      try {
        byte[] a3 = noise.encryptAndHash(NOTHING);
        return new Expected(a3, new Keys(noise.split(), sessionId.clone(), noise.h()));
      } finally {
        noise.wipe();
      }
    }
  }

  // A1 read, and A2 made: the relay's state, or null if A1 is no good (a key off the curve or not ML-KEM's, or its tag fails). random
  // gives the relay's ephemeral key, its encapsulation, and its session id.
  public static Responder readA1(RelayKeys relay, String region, byte[] a1, SecureRandom random) {
    if (a1 == null || a1.length != A1_BYTES) {
      return null;
    }

    int at = 0;
    byte[] gameP384 = Arrays.copyOfRange(a1, at, at += P384.PUBLIC_BYTES);
    byte[] gameKem = Arrays.copyOfRange(a1, at, at += MlKem.ENCAPSULATION_KEY_BYTES);
    byte[] ciphertext = Arrays.copyOfRange(a1, at, at += MlKem.CIPHERTEXT_BYTES);
    byte[] tag = Arrays.copyOfRange(a1, at, A1_BYTES);

    ECPublicKey gameEphemeral = P384.decode(gameP384);
    PublicKey gameEphemeralKem = MlKem.decode(gameKem);

    if (gameEphemeral == null || gameEphemeralKem == null) {
      return null;
    }

    Noise noise = start(region, relay.p384Public(), relay.kemPublic());
    boolean good = false;

    try {
      // e
      noise.mixHash(gameP384);
      noise.mixHash(gameKem);
      // es
      mix(noise, P384.agree(relay.p384().getPrivate(), gameEphemeral));
      // skem
      noise.mixHash(ciphertext);
      byte[] secret = MlKem.decapsulate(relay.kem().getPrivate(), ciphertext);

      if (secret == null) {
        return null;
      }

      mix(noise, secret);

      if (noise.decryptAndHash(tag) == null) {
        return null;
      }

      // A2: e, ee, ekem, then the session id sealed
      KeyPair ephemeral = P384.generate(random);
      byte[] relayP384 = P384.encode((ECPublicKey) ephemeral.getPublic());
      noise.mixHash(relayP384);
      mix(noise, P384.agree(ephemeral.getPrivate(), gameEphemeral));
      MlKem.Encapsulated toGame = MlKem.encapsulate(gameEphemeralKem, random);
      noise.mixHash(toGame.ciphertext());
      mix(noise, toGame.secret());
      byte[] sessionId = new byte[SESSION_ID_BYTES];
      random.nextBytes(sessionId);
      byte[] sealed = noise.encryptAndHash(sessionId);

      byte[] a2 = new byte[A2_BYTES];
      int out = 0;
      System.arraycopy(relayP384, 0, a2, out, P384.PUBLIC_BYTES);
      out += P384.PUBLIC_BYTES;
      System.arraycopy(toGame.ciphertext(), 0, a2, out, MlKem.CIPHERTEXT_BYTES);
      out += MlKem.CIPHERTEXT_BYTES;
      System.arraycopy(sealed, 0, a2, out, sealed.length);
      good = true;
      return new Responder(noise, a2, sessionId);
    } finally {
      if (!good) {
        noise.wipe();
      }
    }
  }

  // MixKey of a secret, and the secret wiped
  private static void mix(Noise noise, byte[] secret) {
    noise.mixKey(secret);
    Noise.wipe(secret);
  }

  // ----- The game's side (for the tests and the vectors; the game's own is Fifth's)

  // The game's half-way state, once A1 is made: what it needs to read A2
  public static final class Initiator {
    private final Noise noise;
    private final KeyPair ephemeral;
    private final KeyPair ephemeralKem;
    private final byte[] a1;

    private Initiator(Noise noise, KeyPair ephemeral, KeyPair ephemeralKem, byte[] a1) {
      this.noise = noise;
      this.ephemeral = ephemeral;
      this.ephemeralKem = ephemeralKem;
      this.a1 = a1;
    }

    public byte[] a1() {
      return a1.clone();
    }

    // The game's transcript and chaining key now, for the test vectors
    byte[] h() {
      return noise.h();
    }

    byte[] ck() {
      return noise.ck();
    }

    // What reading A2 gives the game: A3 to send, and the keys
    public record Done(byte[] a3, Keys keys) {
    }

    // A2 read and A3 made, or null if A2 is no good. Either way, this state's secrets are wiped.
    public Done readA2(byte[] a2) {
      try {
        if (a2 == null || a2.length != A2_BYTES) {
          return null;
        }

        int at = 0;
        byte[] relayP384 = Arrays.copyOfRange(a2, at, at += P384.PUBLIC_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(a2, at, at += MlKem.CIPHERTEXT_BYTES);
        byte[] sealed = Arrays.copyOfRange(a2, at, A2_BYTES);
        ECPublicKey relayEphemeral = P384.decode(relayP384);

        if (relayEphemeral == null) {
          return null;
        }

        noise.mixHash(relayP384);
        mix(noise, P384.agree(ephemeral.getPrivate(), relayEphemeral));
        noise.mixHash(ciphertext);
        byte[] secret = MlKem.decapsulate(ephemeralKem.getPrivate(), ciphertext);

        if (secret == null) {
          return null;
        }

        mix(noise, secret);
        byte[] sessionId = noise.decryptAndHash(sealed);

        if (sessionId == null || sessionId.length != SESSION_ID_BYTES) {
          return null;
        }

        byte[] a3 = noise.encryptAndHash(NOTHING);
        return new Done(a3, new Keys(noise.split(), sessionId, noise.h()));
      } finally {
        noise.wipe();
      }
    }
  }

  // A1, from the game to a relay whose static keys the game knows: random gives the game's ephemeral keys and its encapsulation
  public static Initiator writeA1(String region, byte[] relayStaticP384, byte[] relayStaticKem, SecureRandom random) {
    ECPublicKey relayStatic = P384.decode(relayStaticP384);
    PublicKey relayStaticKemKey = MlKem.decode(relayStaticKem);

    if (relayStatic == null || relayStaticKemKey == null) {
      throw new IllegalArgumentException("the relay's static keys aren't a P-384 key and an ML-KEM-1024 key");
    }

    Noise noise = start(region, relayStaticP384, relayStaticKem);
    KeyPair ephemeral = P384.generate(random);
    KeyPair ephemeralKem = MlKem.generate(random);
    byte[] gameP384 = P384.encode((ECPublicKey) ephemeral.getPublic());
    byte[] gameKem = MlKem.encode(ephemeralKem.getPublic());
    noise.mixHash(gameP384);
    noise.mixHash(gameKem);
    mix(noise, P384.agree(ephemeral.getPrivate(), relayStatic));
    MlKem.Encapsulated toRelay = MlKem.encapsulate(relayStaticKemKey, random);
    noise.mixHash(toRelay.ciphertext());
    mix(noise, toRelay.secret());
    byte[] tag = noise.encryptAndHash(NOTHING);

    byte[] a1 = new byte[A1_BYTES];
    int at = 0;
    System.arraycopy(gameP384, 0, a1, at, P384.PUBLIC_BYTES);
    at += P384.PUBLIC_BYTES;
    System.arraycopy(gameKem, 0, a1, at, MlKem.ENCAPSULATION_KEY_BYTES);
    at += MlKem.ENCAPSULATION_KEY_BYTES;
    System.arraycopy(toRelay.ciphertext(), 0, a1, at, MlKem.CIPHERTEXT_BYTES);
    at += MlKem.CIPHERTEXT_BYTES;
    System.arraycopy(tag, 0, a1, at, tag.length);
    return new Initiator(noise, ephemeral, ephemeralKem, a1);
  }
}
