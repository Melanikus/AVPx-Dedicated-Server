package avpx.v2;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.function.Function;
import java.util.function.Predicate;

// Handshake A (CRYPTO.md section 6): a game and its relay agree on keys, the relay is proved to the game, and the game proves to the
// relay that it's an approved player. Noise's pattern IK, made post-quantum as PQNoise does (a KEM stands in for a Diffie-Hellman where a
// static key is proved), and hybrid (every ECDH result and every ML-KEM secret goes into one chain): pqIK. Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server; made pqIK the same day, from pqNK (server #24).
//
//   <- s                              the game knows the relay's static P-384 and ML-KEM keys beforehand (section 12, or 12.1 for now)
//   ...
//   -> e, es, skem, s, ss             A1, game to relay: 4,930 bytes, the player's static keys sealed inside
//   <- e, ee, se, ekem, skem          A2, relay to game: 3,257 bytes, sealing the relay's 8-byte session id
//   -> (confirmation)                 A3, game to relay: 16 bytes, the game's key confirmation
//
// The start (settled with Third, 2026-11-09): h = SHA-384(the protocol name), ck = h; MixHash(the region in ASCII, then one 0 byte); then,
// as Noise does for a pre-message, MixHash(the relay's static P-384 key, 97 bytes) and MixHash(its static ML-KEM key, 1,568 bytes).
//
// The tokens:
//   e     send an ephemeral P-384 key, MixHash it; the game (the initiator) also sends an ephemeral ML-KEM key, and MixHashes that
//   es    MixKey(ECDH(the game's ephemeral key, the relay's static key))
//   skem  in A1: the game encapsulates to the relay's static ML-KEM key; in A2: the relay encapsulates to the PLAYER's static ML-KEM key.
//         Either way the ciphertext is sent and MixHashed, then its secret MixKeyed
//   s     the player's two static public keys (Identity.statics(), 1,665 bytes), sealed: EncryptAndHash under the key skem made
//   ss    MixKey(ECDH(the player's static key, the relay's static key))
//   ee    MixKey(ECDH(the two ephemeral keys))
//   se    MixKey(ECDH(the relay's ephemeral key, the player's static key))
//   ekem  the relay encapsulates to the game's ephemeral ML-KEM key, sends the ciphertext, MixHashes it, and MixKeys the secret
//
// WHAT PROVES WHAT (section 6): es and A1's skem prove the relay, as before: only the holder of both its static keys can make an A2 that
// opens. ss and se prove the player classically: only the holder of the player's static P-384 key makes A1's last tag. A2's skem proves
// the player post-quantum: only the holder of the player's static ML-KEM key can open it, so only they can make A3's tag. So the relay
// takes a game as the player A1 named only at A3 (SealedRelay), never at A1. ee and ekem give forward secrecy.
//
// APPROVAL (section 6): right after A1's s opens, its two keys must be keys (refusal 23), and their id (Identity.idHex: the whole SHA-384) must be an approved
// player's (refusal 22), before ss, before any session is kept and before A2's work. A refusal is answered with nothing (SealedRelay).
//
// The game's side is here too, for the tests and the test vectors: the game itself is Primary's C++ (net_handshake_a.h), and must match
// this byte for byte.
//
// Wiping (CRYPTO.md section 9): every array of ours that held a secret is zeroed as soon as it's used (each ECDH and ML-KEM result after
// its MixKey, the state when the handshake ends). Java's own EC and ML-KEM private key objects keep their bytes inside and give no way to
// clear them, which is CRYPTO.md's known limit for a managed language: a memory dump of a running server can still hold an ephemeral key.
public final class HandshakeA {
  private HandshakeA() {
  }

  public static final String PROTOCOL = "AVPX_pqIK_P384+MLKEM1024_AESGCM_SHA384_v2";
  public static final int TAG_BYTES = 16;
  public static final int SESSION_ID_BYTES = 8;
  // e (both keys), skem's ciphertext, s sealed, and the last tag: 1,665 + 1,568 + 1,681 + 16
  public static final int A1_BYTES = P384.PUBLIC_BYTES + MlKem.ENCAPSULATION_KEY_BYTES + MlKem.CIPHERTEXT_BYTES + Identity.STATIC_BYTES
      + TAG_BYTES + TAG_BYTES;
  // e (P-384 only), ekem's ciphertext, skem's ciphertext, and the session id sealed: 97 + 1,568 + 1,568 + 24
  public static final int A2_BYTES = P384.PUBLIC_BYTES + MlKem.CIPHERTEXT_BYTES + MlKem.CIPHERTEXT_BYTES + SESSION_ID_BYTES + TAG_BYTES;
  public static final int A3_BYTES = TAG_BYTES;

  // CRYPTO.md section 16's numbers for why an A1 was refused
  public static final int REFUSED_TAG = 8;              // a tag that fails, or an ephemeral key that isn't one
  public static final int REFUSED_NOT_APPROVED = 22;    // the id of s's keys isn't an approved player's
  public static final int REFUSED_NOT_KEYS = 23;        // s isn't a P-384 key and an ML-KEM key

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

  // The relay's static keys, as its settings hold them, with their public halves as the list gives them (GET /v1/relay-keys)
  public record RelayKeys(KeyPair p384, KeyPair kem, byte[] p384Public, byte[] kemPublic) {
    public static RelayKeys of(KeyPair p384, KeyPair kem) {
      return new RelayKeys(p384, kem, P384.encode((ECPublicKey) p384.getPublic()), MlKem.encode(kem.getPublic()));
    }
  }

  // The relay's half-way state, once A1 is read and A2 made: what it needs to check A3, and which player A1 named
  public static final class Responder {
    private final Noise noise;
    private final byte[] a2;
    private final byte[] sessionId;
    private final String player;

    private Responder(Noise noise, byte[] a2, byte[] sessionId, String player) {
      this.noise = noise;
      this.a2 = a2;
      this.sessionId = sessionId;
      this.player = player;
    }

    // A2's bytes, kept to be sent again, byte for byte, if A1 comes again (CRYPTO.md section 6, "Losses")
    public byte[] a2() {
      return a2.clone();
    }

    // The id of the player A1 named, as 96 hex digits (Identity.idHex). Not proved until A3 (or the first sealed message for a lost A3).
    public String player() {
      return player;
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
    // EncryptAndHash, so its 16 bytes are fixed by what came before; the game sends them to prove it has the keys (with pqIK, that it holds
    // its static ML-KEM key too, which A2's skem was sealed to). So the relay (SealedRelay) works them out as soon as A2 is made, and takes
    // the keys only once A3 comes and is exactly a3, or, if A3 was lost, once the game's first sealed message opens under them. Either way
    // the transcript is h after A3 (CRYPTO.md 5.1, point 15). This state's secrets are wiped.
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

  // What reading A1 gives: the relay's state, or why A1 was refused (section 16's number), never both
  public record Read(Responder responder, int refusal) {
    static Read refused(int number) {
      return new Read(null, number);
    }
  }

  // A1 read, and A2 made. approved says whether a player's id (96 hex digits) is an approved player's, as the last decision left the
  // approved set (CRYPTO.md section 6). random gives, in this order, the relay's ephemeral key, its encapsulation to the game's ephemeral
  // ML-KEM key, its encapsulation to the player's static ML-KEM key, and its session id.
  public static Read readA1(RelayKeys relay, String region, byte[] a1, Predicate<String> approved, SecureRandom random) {
    if (a1 == null || a1.length != A1_BYTES) {
      return Read.refused(REFUSED_TAG);
    }

    int at = 0;
    byte[] gameP384 = Arrays.copyOfRange(a1, at, at += P384.PUBLIC_BYTES);
    byte[] gameKem = Arrays.copyOfRange(a1, at, at += MlKem.ENCAPSULATION_KEY_BYTES);
    byte[] ciphertext = Arrays.copyOfRange(a1, at, at += MlKem.CIPHERTEXT_BYTES);
    byte[] sealedStatics = Arrays.copyOfRange(a1, at, at += Identity.STATIC_BYTES + TAG_BYTES);
    byte[] tag = Arrays.copyOfRange(a1, at, A1_BYTES);

    ECPublicKey gameEphemeral = P384.decode(gameP384);
    PublicKey gameEphemeralKem = MlKem.decode(gameKem);

    if (gameEphemeral == null || gameEphemeralKem == null) {
      return Read.refused(REFUSED_TAG);
    }

    Noise noise = start(region, relay.p384Public(), relay.kemPublic());
    boolean good = false;

    try {
      // e
      noise.mixHash(gameP384);
      noise.mixHash(gameKem);
      // es
      mix(noise, P384.agree(relay.p384().getPrivate(), gameEphemeral));
      // skem, to the relay's static ML-KEM key
      noise.mixHash(ciphertext);
      byte[] secret = MlKem.decapsulate(relay.kem().getPrivate(), ciphertext);

      if (secret == null) {
        return Read.refused(REFUSED_TAG);
      }

      mix(noise, secret);
      // s: the player's two static public keys
      byte[] statics = noise.decryptAndHash(sealedStatics);

      if (statics == null || statics.length != Identity.STATIC_BYTES) {
        return Read.refused(REFUSED_TAG);
      }

      // The checks, in section 6's order, before ss and before anything is kept: two keys (23), then an approved player's (22)
      byte[] playerP384 = Arrays.copyOf(statics, P384.PUBLIC_BYTES);
      byte[] playerKemBytes = Arrays.copyOfRange(statics, P384.PUBLIC_BYTES, Identity.STATIC_BYTES);
      ECPublicKey playerStatic = P384.decode(playerP384);
      PublicKey playerStaticKem = MlKem.decode(playerKemBytes);

      if (playerStatic == null || playerStaticKem == null) {
        return Read.refused(REFUSED_NOT_KEYS);
      }

      String player = Identity.idHex(playerP384, playerKemBytes);

      if (!approved.test(player)) {
        return Read.refused(REFUSED_NOT_APPROVED);
      }

      // ss, then A1's last tag: only the holder of the player's static P-384 key could have made it
      mix(noise, P384.agree(relay.p384().getPrivate(), playerStatic));

      if (noise.decryptAndHash(tag) == null) {
        return Read.refused(REFUSED_TAG);
      }

      // A2: e, ee, se, ekem, skem (to the player's static ML-KEM key), then the session id sealed
      KeyPair ephemeral = P384.generate(random);
      byte[] relayP384 = P384.encode((ECPublicKey) ephemeral.getPublic());
      noise.mixHash(relayP384);
      mix(noise, P384.agree(ephemeral.getPrivate(), gameEphemeral));
      mix(noise, P384.agree(ephemeral.getPrivate(), playerStatic));
      MlKem.Encapsulated toGame = MlKem.encapsulate(gameEphemeralKem, random);
      noise.mixHash(toGame.ciphertext());
      mix(noise, toGame.secret());
      MlKem.Encapsulated toPlayer = MlKem.encapsulate(playerStaticKem, random);
      noise.mixHash(toPlayer.ciphertext());
      mix(noise, toPlayer.secret());
      byte[] sessionId = new byte[SESSION_ID_BYTES];
      random.nextBytes(sessionId);
      byte[] sealed = noise.encryptAndHash(sessionId);

      byte[] a2 = new byte[A2_BYTES];
      int out = 0;
      System.arraycopy(relayP384, 0, a2, out, P384.PUBLIC_BYTES);
      out += P384.PUBLIC_BYTES;
      System.arraycopy(toGame.ciphertext(), 0, a2, out, MlKem.CIPHERTEXT_BYTES);
      out += MlKem.CIPHERTEXT_BYTES;
      System.arraycopy(toPlayer.ciphertext(), 0, a2, out, MlKem.CIPHERTEXT_BYTES);
      out += MlKem.CIPHERTEXT_BYTES;
      System.arraycopy(sealed, 0, a2, out, sealed.length);
      good = true;
      return new Read(new Responder(noise, a2, sessionId, player), 0);
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

  // ----- The game's side (for the tests and the vectors; the game's own is net_handshake_a.h)

  // The game's half-way state, once A1 is made: what it needs to read A2
  public static final class Initiator {
    private final Noise noise;
    private final Identity player;
    private final KeyPair ephemeral;
    private final KeyPair ephemeralKem;
    private final byte[] a1;

    private Initiator(Noise noise, Identity player, KeyPair ephemeral, KeyPair ephemeralKem, byte[] a1) {
      this.noise = noise;
      this.player = player;
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
        byte[] toEphemeral = Arrays.copyOfRange(a2, at, at += MlKem.CIPHERTEXT_BYTES);
        byte[] toStatic = Arrays.copyOfRange(a2, at, at += MlKem.CIPHERTEXT_BYTES);
        byte[] sealed = Arrays.copyOfRange(a2, at, A2_BYTES);
        ECPublicKey relayEphemeral = P384.decode(relayP384);

        if (relayEphemeral == null) {
          return null;
        }

        // e, ee, se
        noise.mixHash(relayP384);
        mix(noise, P384.agree(ephemeral.getPrivate(), relayEphemeral));
        mix(noise, P384.agree(player.p384().getPrivate(), relayEphemeral));
        // ekem, to the game's ephemeral ML-KEM key
        noise.mixHash(toEphemeral);
        byte[] secret = MlKem.decapsulate(ephemeralKem.getPrivate(), toEphemeral);

        if (secret == null) {
          return null;
        }

        mix(noise, secret);
        // skem, to the player's static ML-KEM key
        noise.mixHash(toStatic);
        byte[] staticSecret = MlKem.decapsulate(player.kem().getPrivate(), toStatic);

        if (staticSecret == null) {
          return null;
        }

        mix(noise, staticSecret);
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

  // A1, from the game, as player, to a relay whose static keys the game knows: random gives the game's ephemeral keys and its
  // encapsulation, in that order (the order they first appear in A1)
  public static Initiator writeA1(String region, byte[] relayStaticP384, byte[] relayStaticKem, Identity player, SecureRandom random) {
    KeyPair ephemeral = P384.generate(random);
    KeyPair ephemeralKem = MlKem.generate(random);
    return writeA1(region, relayStaticP384, relayStaticKem, player, ephemeral, ephemeralKem, key -> MlKem.encapsulate(key, random));
  }

  // The same A1 from given ephemeral keys and a given m, as test-vectors/crypto-v2.json writes them down: so a copy of this code can be
  // held to those known answers before it's trusted (Smoke's pin). Never for a real handshake, whose keys and m must be fresh.
  public static Initiator writeA1(String region, byte[] relayStaticP384, byte[] relayStaticKem, Identity player, KeyPair ephemeral,
      KeyPair ephemeralKem, byte[] m) {
    return writeA1(region, relayStaticP384, relayStaticKem, player, ephemeral, ephemeralKem, key -> MlKem.encapsulate(key, m));
  }

  private static Initiator writeA1(String region, byte[] relayStaticP384, byte[] relayStaticKem, Identity player, KeyPair ephemeral,
      KeyPair ephemeralKem, Function<PublicKey, MlKem.Encapsulated> encapsulate) {
    ECPublicKey relayStatic = P384.decode(relayStaticP384);
    PublicKey relayStaticKemKey = MlKem.decode(relayStaticKem);

    if (relayStatic == null || relayStaticKemKey == null) {
      throw new IllegalArgumentException("the relay's static keys aren't a P-384 key and an ML-KEM-1024 key");
    }

    Noise noise = start(region, relayStaticP384, relayStaticKem);
    byte[] gameP384 = P384.encode((ECPublicKey) ephemeral.getPublic());
    byte[] gameKem = MlKem.encode(ephemeralKem.getPublic());
    // e, es, skem
    noise.mixHash(gameP384);
    noise.mixHash(gameKem);
    mix(noise, P384.agree(ephemeral.getPrivate(), relayStatic));
    MlKem.Encapsulated toRelay = encapsulate.apply(relayStaticKemKey);
    noise.mixHash(toRelay.ciphertext());
    mix(noise, toRelay.secret());
    // s, ss, then the last tag
    byte[] sealedStatics = noise.encryptAndHash(player.statics());
    mix(noise, P384.agree(player.p384().getPrivate(), relayStatic));
    byte[] tag = noise.encryptAndHash(NOTHING);

    byte[] a1 = new byte[A1_BYTES];
    int at = 0;
    System.arraycopy(gameP384, 0, a1, at, P384.PUBLIC_BYTES);
    at += P384.PUBLIC_BYTES;
    System.arraycopy(gameKem, 0, a1, at, MlKem.ENCAPSULATION_KEY_BYTES);
    at += MlKem.ENCAPSULATION_KEY_BYTES;
    System.arraycopy(toRelay.ciphertext(), 0, a1, at, MlKem.CIPHERTEXT_BYTES);
    at += MlKem.CIPHERTEXT_BYTES;
    System.arraycopy(sealedStatics, 0, a1, at, sealedStatics.length);
    at += sealedStatics.length;
    System.arraycopy(tag, 0, a1, at, tag.length);
    return new Initiator(noise, player, ephemeral, ephemeralKem, a1);
  }
}
