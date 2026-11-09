package avpx.v2;

import avpx.crypto.Hkdf;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Locale;

// Handshake B (CRYPTO.md section 8, and 5.1 points 17 to 20; pattern pqXX, hybrid): a joiner and its host, end to end, through the
// relay, which only forwards it. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// THE SERVER NEVER RUNS THIS: B is from game to game. It's here, beside the tests, as the reference that crypto-v2.json's handshake B
// is made with, so the game, which runs both sides, can check itself against an implementation written apart from its own. Every step
// is the one proofs/pqxx.pv models, in its order:
//
//   start   h = SHA-384(PROTOCOL), ck = h; then the prologue (start)
//   B1  ->  e, commitment         the joiner's ephemeral P-384 key, then its ephemeral ML-KEM key (two MixHashes), then SHA-384(nJ), the
//                                 joiner's promise of the 32 bytes it puts into the check code (a third MixHash), all sent as they are
//   B2  <-  e, ee, ekem, s, es    the host's ephemeral P-384 key; ECDH of the two; an encapsulation to the joiner's ephemeral ML-KEM key;
//                                 the host's static keys, sealed; ECDH of the joiner's ephemeral with the host's static; then a tag
//   B3  ->  skem, s, se           an encapsulation to the host's static ML-KEM key; the joiner's static keys, sealed; ECDH of the
//                                 joiner's static with the host's ephemeral; then a tag
//   B4  <-  skem, nH              an encapsulation to the joiner's static ML-KEM key; then nH, the host's 32 bytes for the check code,
//                                 sealed: its tag is the host's key confirmation
//   B5  ->  nJ                    nJ, sealed: its tag is the joiner's key confirmation, and the host holds nJ to the commitment in B1
//
// Each side draws its random values in the order they first appear in its own messages (Third, for 5.1 point 14), so a given seed makes
// the same handshake in any implementation. Each ML-KEM ciphertext goes as it is, with a MixHash, then its secret is mixed in (as
// handshake A's). Every secret is wiped once mixed.
final class HandshakeB {
  private HandshakeB() {
  }

  static final String PROTOCOL = "AVPX_pqXX_P384+MLKEM1024_AESGCM_SHA384_v2";
  static final int STATIC_BYTES = P384.PUBLIC_BYTES + MlKem.ENCAPSULATION_KEY_BYTES;
  static final int NONCE_BYTES = 32;
  static final int COMMITMENT_BYTES = 48;
  static final int B1_BYTES = STATIC_BYTES + COMMITMENT_BYTES;
  static final int B2_BYTES = P384.PUBLIC_BYTES + MlKem.CIPHERTEXT_BYTES + STATIC_BYTES + 16 + 16;
  static final int B3_BYTES = MlKem.CIPHERTEXT_BYTES + STATIC_BYTES + 16 + 16;
  static final int B4_BYTES = MlKem.CIPHERTEXT_BYTES + NONCE_BYTES + 16;
  static final int B5_BYTES = NONCE_BYTES + 16;
  static final int FINGERPRINT_BYTES = 16;

  // The kinds of B's datagrams (CRYPTO.md section 8's table)
  static final int B1 = 16;
  static final int B2 = 17;
  static final int B3 = 18;
  static final int B4 = 19;
  static final int B5 = 20;

  private static final byte[] NOTHING = new byte[0];
  private static final byte[] CHECK_CODE_WORDS = "AVPX check code v2".getBytes(StandardCharsets.US_ASCII);

  // A player's whole id, 48 bytes (CRYPTO.md section 8): Identity.java's, the one the server itself uses (handshake A's approval, the list's
  // access requests), so there's one way it's made
  static byte[] id(byte[] p384Public, byte[] kemPublic) {
    return Identity.idOf(p384Public, kemPublic);
  }

  // The start, for both sides: h = SHA-384(the protocol's name), ck = h; then the prologue, three MixHashes (5.1, point 17): the region's
  // name and a 0 byte (as A's); the joiner's relay port, 2 bytes little-endian; the host's whole id, 48 bytes, as the listing gives it. No
  // pre-message: pattern XX has none.
  static Noise start(String region, int relayPort, byte[] hostId) {
    Noise noise = new Noise(PROTOCOL);
    byte[] name = region.getBytes(StandardCharsets.US_ASCII);
    noise.mixHash(Arrays.copyOf(name, name.length + 1));
    noise.mixHash(new byte[] {(byte) relayPort, (byte) (relayPort >>> 8)});
    noise.mixHash(hostId);
    return noise;
  }

  // The 6 digits both screens show (5.1, point 19): HKDF-SHA-384(salt = the transcript, h after B5; no input; info "AVPX check code
  // v2"), 8 bytes, read as an unsigned 64-bit number, little-endian, mod 1,000,000, with 0s in front
  static String checkCode(byte[] transcript) {
    byte[] b = Hkdf.derive(transcript, NOTHING, CHECK_CODE_WORDS, 8);
    long n = 0;

    for (int i = 7; i >= 0; i--) {
      n = (n << 8) | (b[i] & 0xffL);
    }

    return String.format(Locale.ROOT, "%06d", Long.remainderUnsigned(n, 1_000_000));
  }

  // What both sides have when B is done: the keys each way, the transcript (h after B5), and the other side's whole id
  record Keys(Noise.Split split, byte[] transcript, byte[] theirId) {
  }

  private static void mix(Noise noise, byte[] secret) {
    noise.mixKey(secret);
    Noise.wipe(secret);
  }

  private static byte[] join(byte[]... parts) {
    int n = 0;

    for (byte[] p : parts) {
      n += p.length;
    }

    byte[] out = new byte[n];
    int at = 0;

    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, at, p.length);
      at += p.length;
    }

    return out;
  }

  // ----- The joiner (Noise's initiator)

  static final class Joiner {
    private final Noise noise;
    private final Identity me;
    private final byte[] hostId;
    private final SecureRandom random;
    private final KeyPair e;
    private final KeyPair ek;
    private final byte[] nJ;
    private final byte[] b1;
    private ECPublicKey hostEphemeral;

    private Joiner(Noise noise, Identity me, byte[] hostId, SecureRandom random, KeyPair e, KeyPair ek, byte[] nJ, byte[] b1) {
      this.noise = noise;
      this.me = me;
      this.hostId = hostId.clone();
      this.random = random;
      this.e = e;
      this.ek = ek;
      this.nJ = nJ;
      this.b1 = b1;
    }

    byte[] b1() {
      return b1.clone();
    }

    // B2 read and B3 made; null if B2 is no good, or its host isn't the one the listing named (refusal 10). Null wipes this state.
    byte[] readB2(byte[] b2) {
      byte[] b3 = null;

      try {
        if (b2 == null || b2.length != B2_BYTES) {
          return null;
        }

        int at = 0;
        byte[] reP384 = Arrays.copyOfRange(b2, at, at += P384.PUBLIC_BYTES);
        byte[] ct2 = Arrays.copyOfRange(b2, at, at += MlKem.CIPHERTEXT_BYTES);
        byte[] sealedS = Arrays.copyOfRange(b2, at, at += STATIC_BYTES + 16);
        byte[] tag = Arrays.copyOfRange(b2, at, B2_BYTES);
        hostEphemeral = P384.decode(reP384);

        if (hostEphemeral == null) {
          return null;
        }

        // e, ee, ekem
        noise.mixHash(reP384);
        mix(noise, P384.agree(e.getPrivate(), hostEphemeral));
        noise.mixHash(ct2);
        byte[] ss2 = MlKem.decapsulate(ek.getPrivate(), ct2);

        if (ss2 == null) {
          return null;
        }

        mix(noise, ss2);

        // s: the host's static keys, which must be the ones whose id the listing gave
        byte[] statics = noise.decryptAndHash(sealedS);

        if (statics == null) {
          return null;
        }

        byte[] hostP384 = Arrays.copyOf(statics, P384.PUBLIC_BYTES);
        byte[] hostKem = Arrays.copyOfRange(statics, P384.PUBLIC_BYTES, STATIC_BYTES);
        ECPublicKey hostStatic = P384.decode(hostP384);
        PublicKey hostStaticKem = MlKem.decode(hostKem);

        if (hostStatic == null || hostStaticKem == null || !MessageDigest.isEqual(id(hostP384, hostKem), hostId)) {
          return null;
        }

        // es, and B2's tag
        mix(noise, P384.agree(e.getPrivate(), hostStatic));

        if (noise.decryptAndHash(tag) == null) {
          return null;
        }

        // B3: skem, s, se, and a tag
        MlKem.Encapsulated toHost = MlKem.encapsulate(hostStaticKem, random);
        noise.mixHash(toHost.ciphertext());
        mix(noise, toHost.secret());
        byte[] sealedJ = noise.encryptAndHash(me.statics());
        mix(noise, P384.agree(me.p384().getPrivate(), hostEphemeral));
        byte[] tag3 = noise.encryptAndHash(NOTHING);
        b3 = join(toHost.ciphertext(), sealedJ, tag3);
        return b3;
      } finally {
        if (b3 == null) {
          noise.wipe();
        }
      }
    }

    // B4 read (the host's key confirmation, and nH) and B5 made: B5 to send, and the keys. Null if B4 is no good. Either way, the state
    // is wiped.
    Done readB4(byte[] b4) {
      return readB4(b4, nJ.clone());
    }

    // The same, but with B5 revealing `reveal`: the joiner's own nJ, or, only in the test that the host refuses it (refusal 21), another
    Done readB4(byte[] b4, byte[] reveal) {
      try {
        if (b4 == null || b4.length != B4_BYTES) {
          return null;
        }

        byte[] ct4 = Arrays.copyOf(b4, MlKem.CIPHERTEXT_BYTES);
        byte[] sealedNH = Arrays.copyOfRange(b4, MlKem.CIPHERTEXT_BYTES, B4_BYTES);
        noise.mixHash(ct4);
        byte[] ss4 = MlKem.decapsulate(me.kem().getPrivate(), ct4);

        if (ss4 == null) {
          return null;
        }

        mix(noise, ss4);
        byte[] nH = noise.decryptAndHash(sealedNH);

        if (nH == null) {
          return null;
        }

        Noise.wipe(nH);
        byte[] b5 = noise.encryptAndHash(reveal);
        return new Done(b5, new Keys(noise.split(), noise.h(), hostId.clone()));
      } finally {
        noise.wipe();
        Noise.wipe(nJ);
        Noise.wipe(reveal);
      }
    }

    record Done(byte[] b5, Keys keys) {
    }
  }

  // B1, from a joiner to the host the listing named (by its id), on its joiner's port of that region's relay. random gives, in
  // order: the joiner's ephemeral P-384 key, its ephemeral ML-KEM key, nJ, then (in B3) its encapsulation to the host's static key.
  static Joiner writeB1(String region, int relayPort, byte[] hostId, Identity me, SecureRandom random) {
    Noise noise = start(region, relayPort, hostId);
    KeyPair e = P384.generate(random);
    KeyPair ek = MlKem.generate(random);
    byte[] nJ = new byte[NONCE_BYTES];
    random.nextBytes(nJ);
    byte[] eP384 = P384.encode((ECPublicKey) e.getPublic());
    byte[] ekPublic = MlKem.encode(ek.getPublic());
    byte[] commitment = Noise.sha384(nJ);
    noise.mixHash(eP384);
    noise.mixHash(ekPublic);
    noise.mixHash(commitment);
    return new Joiner(noise, me, hostId, random, e, ek, nJ, join(eP384, ekPublic, commitment));
  }

  // ----- The host (Noise's responder)

  static final class Host {
    private final Noise noise;
    private final Identity me;
    private final SecureRandom random;
    private final KeyPair re;
    private final byte[] commitment;
    private final byte[] b2;
    private byte[] joinerId;

    private Host(Noise noise, Identity me, SecureRandom random, KeyPair re, byte[] commitment, byte[] b2) {
      this.noise = noise;
      this.me = me;
      this.random = random;
      this.re = re;
      this.commitment = commitment;
      this.b2 = b2;
    }

    // B2's bytes, kept to be sent again, byte for byte, if B1 comes again (section 8, "Losses")
    byte[] b2() {
      return b2.clone();
    }

    // B3 read and B4 made; null if B3 is no good. Null wipes this state.
    byte[] readB3(byte[] b3) {
      byte[] b4 = null;

      try {
        if (b3 == null || b3.length != B3_BYTES) {
          return null;
        }

        int at = 0;
        byte[] ct3 = Arrays.copyOfRange(b3, at, at += MlKem.CIPHERTEXT_BYTES);
        byte[] sealedJ = Arrays.copyOfRange(b3, at, at += STATIC_BYTES + 16);
        byte[] tag = Arrays.copyOfRange(b3, at, B3_BYTES);

        // skem
        noise.mixHash(ct3);
        byte[] ss3 = MlKem.decapsulate(me.kem().getPrivate(), ct3);

        if (ss3 == null) {
          return null;
        }

        mix(noise, ss3);

        // s: the joiner's static keys
        byte[] statics = noise.decryptAndHash(sealedJ);

        if (statics == null) {
          return null;
        }

        byte[] joinerP384 = Arrays.copyOf(statics, P384.PUBLIC_BYTES);
        byte[] joinerKem = Arrays.copyOfRange(statics, P384.PUBLIC_BYTES, STATIC_BYTES);
        ECPublicKey joinerStatic = P384.decode(joinerP384);
        PublicKey joinerStaticKem = MlKem.decode(joinerKem);

        if (joinerStatic == null || joinerStaticKem == null) {
          return null;
        }

        // se, and B3's tag
        mix(noise, P384.agree(re.getPrivate(), joinerStatic));

        if (noise.decryptAndHash(tag) == null) {
          return null;
        }

        joinerId = id(joinerP384, joinerKem);

        // B4: skem to the joiner's static key, then nH, sealed (its tag is the host's key confirmation)
        MlKem.Encapsulated toJoiner = MlKem.encapsulate(joinerStaticKem, random);
        noise.mixHash(toJoiner.ciphertext());
        mix(noise, toJoiner.secret());
        byte[] nH = new byte[NONCE_BYTES];
        random.nextBytes(nH);
        byte[] sealedNH = noise.encryptAndHash(nH);
        Noise.wipe(nH);
        b4 = join(toJoiner.ciphertext(), sealedNH);
        return b4;
      } finally {
        if (b4 == null) {
          noise.wipe();
        }
      }
    }

    // B5 read: the joiner's key confirmation, and nJ, which must be what B1's commitment promised (refusal 21). The keys, or null. B5
    // can't be stood in for (it holds nJ, which the check code needs), so the joiner sends it again until the host's first sealed datagram
    // comes. Either way, the state is wiped.
    Keys readB5(byte[] b5) {
      try {
        if (b5 == null || b5.length != B5_BYTES) {
          return null;
        }

        byte[] nJ = noise.decryptAndHash(b5);

        if (nJ == null || !MessageDigest.isEqual(Noise.sha384(nJ), commitment)) {
          return null;
        }

        Noise.wipe(nJ);
        return new Keys(noise.split(), noise.h(), joinerId.clone());
      } finally {
        noise.wipe();
      }
    }
  }

  // B1 read and B2 made by the host, on the joiner's relay port; null if B1 is no good. random gives, in order: the host's ephemeral
  // P-384 key, its encapsulation to the joiner's ephemeral key, then (in B4) its encapsulation to the joiner's static key, then nH.
  static Host readB1(String region, int relayPort, Identity me, byte[] b1, SecureRandom random) {
    if (b1 == null || b1.length != B1_BYTES) {
      return null;
    }

    byte[] jeP384 = Arrays.copyOf(b1, P384.PUBLIC_BYTES);
    byte[] jeKem = Arrays.copyOfRange(b1, P384.PUBLIC_BYTES, STATIC_BYTES);
    byte[] commitment = Arrays.copyOfRange(b1, STATIC_BYTES, B1_BYTES);
    ECPublicKey joinerEphemeral = P384.decode(jeP384);
    PublicKey joinerEphemeralKem = MlKem.decode(jeKem);

    if (joinerEphemeral == null || joinerEphemeralKem == null) {
      return null;
    }

    Noise noise = start(region, relayPort, me.id());
    noise.mixHash(jeP384);
    noise.mixHash(jeKem);
    noise.mixHash(commitment);

    // B2: e, ee, ekem, s, es, and a tag
    KeyPair re = P384.generate(random);
    byte[] reP384 = P384.encode((ECPublicKey) re.getPublic());
    noise.mixHash(reP384);
    mix(noise, P384.agree(re.getPrivate(), joinerEphemeral));
    MlKem.Encapsulated toJoiner = MlKem.encapsulate(joinerEphemeralKem, random);
    noise.mixHash(toJoiner.ciphertext());
    mix(noise, toJoiner.secret());
    byte[] sealedS = noise.encryptAndHash(me.statics());
    mix(noise, P384.agree(me.p384().getPrivate(), joinerEphemeral));
    byte[] tag = noise.encryptAndHash(NOTHING);
    return new Host(noise, me, random, re, commitment, join(reP384, toJoiner.ciphertext(), sealedS, tag));
  }
}
