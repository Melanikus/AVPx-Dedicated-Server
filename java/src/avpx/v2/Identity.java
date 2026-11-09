package avpx.v2;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HexFormat;

// A player's identity (CRYPTO.md section 4): a static P-384 key and a static ML-KEM-1024 key, with their public halves as the wire carries
// them, and the fingerprint that names it. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// The game keeps one from run to run (the game's net_identity.h). The server only ever sees the public halves: in handshake A's `s`
// (section 6), and in an access request (PROTOCOL.md, POST /v1/access-requests). The private halves are here only for the tests and the
// test vectors, which play the game's side.
//
// The FINGERPRINT is the first 16 bytes of SHA-384 of the 9 ASCII letters "AVPX-ID-2" (with nothing after them), then the P-384 key (97
// bytes: 04, then x and y) and the ML-KEM key (1,568 bytes), raw, as they travel (section 8). It's shown as 32 hex digits, small letters,
// and it's for people. The ID is the whole of that SHA-384, 96 hex digits, and it's what a machine compares (idHex, below).
// A relay's id starts with other words (RelayId.java), so the one can never be taken for the other.
public record Identity(KeyPair p384, KeyPair kem, byte[] p384Public, byte[] kemPublic) {
  public static final int STATIC_BYTES = P384.PUBLIC_BYTES + MlKem.ENCAPSULATION_KEY_BYTES;
  public static final int FINGERPRINT_BYTES = 16;
  private static final byte[] FINGERPRINT_WORDS = "AVPX-ID-2".getBytes(StandardCharsets.US_ASCII);

  public static Identity of(KeyPair p384, KeyPair kem) {
    return new Identity(p384, kem, P384.encode((ECPublicKey) p384.getPublic()), MlKem.encode(kem.getPublic()));
  }

  // Both public halves, one after the other, as `s` sends them and an access request carries them: the P-384 key, then the ML-KEM key
  public byte[] statics() {
    byte[] out = Arrays.copyOf(p384Public, STATIC_BYTES);
    System.arraycopy(kemPublic, 0, out, P384.PUBLIC_BYTES, MlKem.ENCAPSULATION_KEY_BYTES);
    return out;
  }

  public byte[] fingerprint() {
    return fingerprintOf(p384Public, kemPublic);
  }

  // The fingerprint of two public halves, as 16 bytes
  public static byte[] fingerprintOf(byte[] p384Public, byte[] kemPublic) {
    return Arrays.copyOf(Noise.sha384(FINGERPRINT_WORDS, p384Public, kemPublic), FINGERPRINT_BYTES);
  }

  // The same, as 32 hex digits, small letters: how people and the owner's tools see it (the access code is made from it, the list's
  // answer and the owner's decisions name it)
  public static String fingerprintHex(byte[] p384Public, byte[] kemPublic) {
    return HexFormat.of().formatHex(fingerprintOf(p384Public, kemPublic));
  }

  // The player's ID: the whole SHA-384 the fingerprint is the first 16 bytes of, as 96 hex digits, small letters. Whatever a MACHINE
  // compares is this, never the fingerprint (PO's ruling, 2026-11-09; CRYPTO.md section 8): the relay's approved check (handshake A,
  // refusal 22) and the access store. Someone who made keys of their own with an approved player's 16-byte fingerprint would be taken as
  // them, and finding such keys is a search of 2 to the 128th, which a quantum computer could cut to about 2 to the 64th. Matching all 48
  // bytes is beyond reach either way.
  public static String idHex(byte[] p384Public, byte[] kemPublic) {
    return HexFormat.of().formatHex(Noise.sha384(FINGERPRINT_WORDS, p384Public, kemPublic));
  }
}
