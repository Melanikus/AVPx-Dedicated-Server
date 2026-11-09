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

// Handshake B (CRYPTO.md section 8; pattern pqXX, hybrid): a joiner and its host, end to end, through the relay, which only forwards it.
// Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// THE SERVER NEVER RUNS THIS: B is from game to game. It's here, beside the tests, as the reference that crypto-v2.json's handshake B
// is made with, so the game, which runs both sides, can check itself against an implementation written apart from its own. Every step
// is the one proofs/pqxx.pv models, in its order (each marked below):
//
//   start   h = SHA-384(PROTOCOL), ck = h; then the prologue (see start)
//   B1  ->  e                     the joiner's ephemeral P-384 key, then its ephemeral ML-KEM key (two MixHashes), sent as they are
//   B2  <-  e, ee, ekem, s, es    the host's ephemeral P-384 key; ECDH of the two; an encapsulation to the joiner's ephemeral ML-KEM key;
//                                 the host's static keys, sealed; ECDH of the joiner's ephemeral with the host's static; then a tag
//   B3  ->  skem, s, se           an encapsulation to the host's static ML-KEM key; the joiner's static keys, sealed; ECDH of the
//                                 joiner's static with the host's ephemeral; then a tag
//   B4  <-  skem                  an encapsulation to the joiner's static ML-KEM key; then the host's tag, its key confirmation
//   B5  ->                        the joiner's tag, its key confirmation, made after B4's skem
//
// Each ML-KEM ciphertext goes as it is, with a MixHash, then its secret is mixed in (as handshake A's). Every secret is wiped once mixed.
final class HandshakeB {
  private HandshakeB() {
  }

  static final String PROTOCOL = "AVPX_pqXX_P384+MLKEM1024_AESGCM_SHA384_v2";
  static final int STATIC_BYTES = P384.PUBLIC_BYTES + MlKem.ENCAPSULATION_KEY_BYTES;
  static final int B1_BYTES = STATIC_BYTES;
  static final int B2_BYTES = P384.PUBLIC_BYTES + MlKem.CIPHERTEXT_BYTES + STATIC_BYTES + 16 + 16;
  static final int B3_BYTES = MlKem.CIPHERTEXT_BYTES + STATIC_BYTES + 16 + 16;
  static final int B4_BYTES = MlKem.CIPHERTEXT_BYTES + 16;
  static final int B5_BYTES = 16;
  static final int FINGERPRINT_BYTES = 16;

  // The kinds of B's datagrams (CRYPTO.md section 8's table)
  static final int B1 = 16;
  static final int B2 = 17;
  static final int B3 = 18;
  static final int B4 = 19;
  static final int B5 = 20;

  private static final byte[] NOTHING = new byte[0];
  private static final byte[] FINGERPRINT_WORDS = "AVPX-ID-2".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] CHECK_CODE_WORDS = "AVPX check code v2".getBytes(StandardCharsets.US_ASCII);

  // A player's identity (CRYPTO.md section 4): its static P-384 and ML-KEM keys, with their public halves as the wire carries them
  record Identity(KeyPair p384, KeyPair kem, byte[] p384Public, byte[] kemPublic) {
    static Identity of(KeyPair p384, KeyPair kem) {
      return new Identity(p384, kem, P384.encode((ECPublicKey) p384.getPublic()), MlKem.encode(kem.getPublic()));
    }

    // Both public halves, as `s` sends them: the P-384 key, then the ML-KEM key
    byte[] statics() {
      byte[] out = Arrays.copyOf(p384Public, STATIC_BYTES);
      System.arraycopy(kemPublic, 0, out, P384.PUBLIC_BYTES, MlKem.ENCAPSULATION_KEY_BYTES);
      return out;
    }

    byte[] fingerprint() {
      return HandshakeB.fingerprint(p384Public, kemPublic);
    }
  }

  // A fingerprint: the first 16 bytes of SHA-384("AVPX-ID-2" || the P-384 key || the ML-KEM key), the keys as the wire carries them
  static byte[] fingerprint(byte[] p384Public, byte[] kemPublic) {
    return Arrays.copyOf(Noise.sha384(FINGERPRINT_WORDS, p384Public, kemPublic), FINGERPRINT_BYTES);
  }

  // The start, for both sides: h = SHA-384(the protocol's name), ck = h; then the prologue, as proofs/pqxx.pv has it: MixHash(the
  // joiner's relay port, 2 bytes little-endian), then MixHash(the host's fingerprint as the listing gives it). Pattern XX has no
  // pre-message. (The prologue's bytes are a proposal to Third, waiting for CRYPTO.md 5.1.)
  static Noise start(int relayPort, byte[] hostFingerprint) {
    Noise noise = new Noise(PROTOCOL);
    noise.mixHash(new byte[] {(byte) relayPort, (byte) (relayPort >>> 8)});
    noise.mixHash(hostFingerprint);
    return noise;
  }

  // The 6 digits both screens show (section 8): HKDF-SHA-384(salt = the transcript, no input, info "AVPX check code v2", 4 bytes), read
  // as a number little-endian, mod 1,000,000, with 0s in front. The same on both screens only if no one is in the middle. (Its exact form
  // is a proposal to Third, waiting for CRYPTO.md 5.1.)
  static String checkCode(byte[] transcript) {
    byte[] b = Hkdf.derive(transcript, NOTHING, CHECK_CODE_WORDS, 4);
    long n = (b[0] & 0xffL) | ((b[1] & 0xffL) << 8) | ((b[2] & 0xffL) << 16) | ((b[3] & 0xffL) << 24);
    return String.format(Locale.ROOT, "%06d", n % 1_000_000);
  }

  // What both sides have when B is done: the keys each way, the transcript (h after B5), and the other side's fingerprint
  record Keys(Noise.Split split, byte[] transcript, byte[] theirFingerprint) {
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
    private final byte[] hostFingerprint;
    private final SecureRandom random;
    private final KeyPair e;
    private final KeyPair ek;
    private final byte[] b1;
    private ECPublicKey hostEphemeral;

    private Joiner(Noise noise, Identity me, byte[] hostFingerprint, SecureRandom random, KeyPair e, KeyPair ek, byte[] b1) {
      this.noise = noise;
      this.me = me;
      this.hostFingerprint = hostFingerprint.clone();
      this.random = random;
      this.e = e;
      this.ek = ek;
      this.b1 = b1;
    }

    byte[] b1() {
      return b1.clone();
    }

    byte[] h() {
      return noise.h();
    }

    byte[] ck() {
      return noise.ck();
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

        // s: the host's static keys, which must be the ones whose fingerprint the listing gave
        byte[] statics = noise.decryptAndHash(sealedS);

        if (statics == null) {
          return null;
        }

        byte[] hostP384 = Arrays.copyOf(statics, P384.PUBLIC_BYTES);
        byte[] hostKem = Arrays.copyOfRange(statics, P384.PUBLIC_BYTES, STATIC_BYTES);
        ECPublicKey hostStatic = P384.decode(hostP384);
        PublicKey hostStaticKem = MlKem.decode(hostKem);

        if (hostStatic == null || hostStaticKem == null || !MessageDigest.isEqual(fingerprint(hostP384, hostKem), hostFingerprint)) {
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

    // B4 read (the host's key confirmation) and B5 made: B5 to send, and the keys. Null if B4 is no good. Either way, the state is wiped.
    Done readB4(byte[] b4) {
      try {
        if (b4 == null || b4.length != B4_BYTES) {
          return null;
        }

        byte[] ct4 = Arrays.copyOf(b4, MlKem.CIPHERTEXT_BYTES);
        byte[] tag = Arrays.copyOfRange(b4, MlKem.CIPHERTEXT_BYTES, B4_BYTES);
        noise.mixHash(ct4);
        byte[] ss4 = MlKem.decapsulate(me.kem().getPrivate(), ct4);

        if (ss4 == null) {
          return null;
        }

        mix(noise, ss4);

        if (noise.decryptAndHash(tag) == null) {
          return null;
        }

        byte[] b5 = noise.encryptAndHash(NOTHING);
        return new Done(b5, new Keys(noise.split(), noise.h(), hostFingerprint.clone()));
      } finally {
        noise.wipe();
      }
    }

    record Done(byte[] b5, Keys keys) {
    }
  }

  // B1, from a joiner to the host the listing named (by its fingerprint), on the joiner's relay port
  static Joiner writeB1(int relayPort, byte[] hostFingerprint, Identity me, SecureRandom random) {
    Noise noise = start(relayPort, hostFingerprint);
    KeyPair e = P384.generate(random);
    KeyPair ek = MlKem.generate(random);
    byte[] eP384 = P384.encode((ECPublicKey) e.getPublic());
    byte[] ekPublic = MlKem.encode(ek.getPublic());
    noise.mixHash(eP384);
    noise.mixHash(ekPublic);
    return new Joiner(noise, me, hostFingerprint, random, e, ek, join(eP384, ekPublic));
  }

  // ----- The host (Noise's responder)

  static final class Host {
    private final Noise noise;
    private final Identity me;
    private final SecureRandom random;
    private final KeyPair re;
    private final byte[] b2;
    private byte[] joinerFingerprint;

    private Host(Noise noise, Identity me, SecureRandom random, KeyPair re, byte[] b2) {
      this.noise = noise;
      this.me = me;
      this.random = random;
      this.re = re;
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

        joinerFingerprint = fingerprint(joinerP384, joinerKem);

        // B4: skem to the joiner's static key, and the host's tag
        MlKem.Encapsulated toJoiner = MlKem.encapsulate(joinerStaticKem, random);
        noise.mixHash(toJoiner.ciphertext());
        mix(noise, toJoiner.secret());
        byte[] tag4 = noise.encryptAndHash(NOTHING);
        b4 = join(toJoiner.ciphertext(), tag4);
        return b4;
      } finally {
        if (b4 == null) {
          noise.wipe();
        }
      }
    }

    // What the joiner's B5 must be, and the keys it confirms: known at once, as nothing in them waits for B5 (as HandshakeA.expect). The
    // host takes them when B5 comes and is exactly b5, or, if B5 was lost, when the joiner's first sealed datagram opens under them.
    record Expected(byte[] b5, Keys keys) {
    }

    Expected expect() {
      try {
        byte[] b5 = noise.encryptAndHash(NOTHING);
        return new Expected(b5, new Keys(noise.split(), noise.h(), joinerFingerprint.clone()));
      } finally {
        noise.wipe();
      }
    }
  }

  // B1 read and B2 made by the host, on the joiner's relay port; null if B1 is no good
  static Host readB1(int relayPort, Identity me, byte[] b1, SecureRandom random) {
    if (b1 == null || b1.length != B1_BYTES) {
      return null;
    }

    byte[] jeP384 = Arrays.copyOf(b1, P384.PUBLIC_BYTES);
    byte[] jeKem = Arrays.copyOfRange(b1, P384.PUBLIC_BYTES, B1_BYTES);
    ECPublicKey joinerEphemeral = P384.decode(jeP384);
    PublicKey joinerEphemeralKem = MlKem.decode(jeKem);

    if (joinerEphemeral == null || joinerEphemeralKem == null) {
      return null;
    }

    Noise noise = start(relayPort, me.fingerprint());
    noise.mixHash(jeP384);
    noise.mixHash(jeKem);

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
    return new Host(noise, me, random, re, join(reP384, toJoiner.ciphertext(), sealedS, tag));
  }
}
