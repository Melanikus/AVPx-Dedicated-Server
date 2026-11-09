package avpx.v2;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.crypto.Signatures;
import avpx.list.Json;
import avpx.testing.ScriptedRandom;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// Makes test-vectors/crypto-v2.json, version 2's test vectors (CRYPTO.md section 15, and 5.1 points 14 and 15): the bytes every other
// implementation (the game's) checks itself against. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   cd java; java -cp build/test avpx.v2.CryptoV2Vectors      after build.sh: writes the file again (it takes nothing from its command line)
//
// CryptoV2VectorsTest makes the file again on every test run, and fails if one byte differs: so the file is always exactly what the
// server's code makes.
//
// HOW IT'S MADE:
// - Every random choice comes from a fixed seed (ScriptedRandom.seeded), so it's the same on every run.
// - The file gives each key as what the primitive itself takes, never as our seed: a P-384 private key as its 48-byte number, an
//   ML-KEM key pair as FIPS 203's d then z (64 bytes), an encapsulation as its m (32 bytes). An implementation needs nothing of Java's to
//   make them again.
// - Handshake A is walked here step by step on the Noise state, writing h and ck down after every step. Then the real HandshakeA, given
//   the same randomness, must give exactly the same A1, A2, A3, keys and transcript, or this stops: so the steps in the file are the
//   very ones the server takes.
public final class CryptoV2Vectors {
  private CryptoV2Vectors() {
  }

  static final Path FILE = Path.of("..", "test-vectors", "crypto-v2.json");

  private static final String REGION = "virginia";
  private static final byte[] NOTHING = new byte[0];

  public static void main(String[] args) throws IOException {
    Files.writeString(FILE, make(), StandardCharsets.US_ASCII);
  }

  // ----- Small helpers

  private static String hex(byte[] b) {
    return HexFormat.of().formatHex(b);
  }

  // An object of fields in the order given: name, value, name, value, ...
  private static Map<String, Object> fields(Object... nameValue) {
    Map<String, Object> out = new LinkedHashMap<>();

    for (int i = 0; i < nameValue.length; i += 2) {
      out.put((String) nameValue[i], nameValue[i + 1]);
    }

    return out;
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

  // Stops the making if something isn't as it must be: then the file would be wrong, so there must be no file
  private static void must(boolean right, String what) {
    if (!right) {
      throw new IllegalStateException("crypto-v2.json can't be made: " + what);
    }
  }

  // A P-384 private key's number, as 48 bytes, big-endian
  private static byte[] scalar(KeyPair pair) {
    BigInteger s = ((ECPrivateKey) pair.getPrivate()).getS();
    byte[] b = s.toByteArray();
    byte[] out = new byte[48];
    int skip = b.length > 48 ? b.length - 48 : 0;
    System.arraycopy(b, skip, out, 48 - (b.length - skip), b.length - skip);
    return out;
  }

  // The last draws a random source gave, checked to be the sizes given: so a key generation (64 bytes, d then z) or an encapsulation (32
  // bytes, m) is written down as the bytes it was made from
  private static List<byte[]> lastDraws(ScriptedRandom random, int... sizes) {
    List<byte[]> all = random.draws();
    must(all.size() >= sizes.length, "fewer draws than expected");
    List<byte[]> last = all.subList(all.size() - sizes.length, all.size());

    for (int i = 0; i < sizes.length; i++) {
      must(last.get(i).length == sizes[i], "a draw of " + last.get(i).length + " bytes where " + sizes[i] + " were expected");
    }

    return last;
  }

  // A 64-byte control message, its bytes counting up from where "start" says
  private static byte[] message(int start) {
    byte[] m = new byte[Channel.MESSAGE_BYTES];

    for (int i = 0; i < m.length; i++) {
      m[i] = (byte) (start + i);
    }

    return m;
  }

  // A step of the handshake, with h and ck as they are after it
  private static Map<String, Object> step(String what, Noise noise, Object... more) {
    Map<String, Object> s = fields("step", what);
    s.putAll(fields(more));
    s.put("h", hex(noise.h()));
    s.put("ck", hex(noise.ck()));
    return s;
  }

  // MixKey, done on the state and written down with its secret and the k it makes (HKDF-SHA-384(ck, secret, no info, 80): ck then k)
  private static Map<String, Object> mixKey(String what, Noise noise, byte[] secret) {
    byte[] k = Arrays.copyOfRange(Hkdf.derive(noise.ck(), secret, NOTHING, 80), 48, 80);
    noise.mixKey(secret.clone());
    return step(what, noise, "secret", hex(secret), "k", hex(k));
  }

  // ----- The file

  static String make() {
    Map<String, Object> top = new LinkedHashMap<>();
    top.put("about", "Version 2's test vectors (CRYPTO.md section 15), made by java/test/avpx/v2/CryptoV2Vectors.java from fixed seeds, and"
        + " checked on every test run to be exactly what the server's code makes. Bytes are hex. Keys are given as the primitives take them:"
        + " a P-384 private key as its 48-byte number; an ML-KEM-1024 key pair as FIPS 203's d then z (mlkemSeed, 64 bytes); an encapsulation"
        + " as its m. handshakeA's steps give h and ck after every step (MixKey steps give the secret mixed and the k made), and its"
        + " transcript is h after A3 (5.1, point 15). Its datagrams carry a stand-in cookie: a real one is the relay's own HMAC, and only it"
        + " can check one. result is \"valid\" or \"invalid\".");
    top.put("protocol", HandshakeA.PROTOCOL);
    Map<String, Object> handshake = new LinkedHashMap<>();
    HandshakeA.Keys keys = handshakeA(handshake);
    top.put("handshakeA", handshake);
    Map<String, Object> datagrams = datagrams(handshake);
    top.put("handshakeDatagrams", datagrams);
    List<Object> sealed = sealed(keys);
    top.put("sealed", sealed);
    top.put("nonces", nonces(keys));
    top.put("epochKeys", epochKeys(keys));
    top.put("aesGcm", aesGcm());
    top.put("mlkem", mlkem());
    top.put("signatures", signatures());
    top.put("refusals", refusals(datagrams, sealed));
    StringBuilder out = new StringBuilder();
    write(out, top, "");
    out.append('\n');
    return out.toString();
  }

  // Handshake A, walked step by step, then held to the real HandshakeA: fills "into", and gives back the keys both sides got
  private static HandshakeA.Keys handshakeA(Map<String, Object> into) {
    // The relay's static keys
    KeyPair relayP384 = P384.generate(ScriptedRandom.seeded(101));
    ScriptedRandom relayKemRandom = ScriptedRandom.seeded(102);
    KeyPair relayKem = MlKem.generate(relayKemRandom);
    byte[] relayKemSeed = lastDraws(relayKemRandom, 64).get(0);
    HandshakeA.RelayKeys relay = HandshakeA.RelayKeys.of(relayP384, relayKem);

    List<Object> steps = new ArrayList<>();
    Noise noise = new Noise(HandshakeA.PROTOCOL);
    steps.add(step("start: h = SHA-384(the protocol's name), and ck = h", noise));
    byte[] prologue = Arrays.copyOf(REGION.getBytes(StandardCharsets.US_ASCII), REGION.length() + 1);
    noise.mixHash(prologue);
    steps.add(step("MixHash(the region, then a 0 byte)", noise, "data", hex(prologue)));
    noise.mixHash(relay.p384Public());
    steps.add(step("<- s: MixHash(the relay's static P-384 key)", noise));
    noise.mixHash(relay.kemPublic());
    steps.add(step("<- s: MixHash(the relay's static ML-KEM key)", noise));

    // A1, the game's: e, es, skem, and an empty EncryptAndHash
    ScriptedRandom gameRandom = ScriptedRandom.seeded(201);
    KeyPair gameP384 = P384.generate(gameRandom);
    KeyPair gameKem = MlKem.generate(gameRandom);
    byte[] gameP384Public = P384.encode((ECPublicKey) gameP384.getPublic());
    byte[] gameKemPublic = MlKem.encode(gameKem.getPublic());
    noise.mixHash(gameP384Public);
    steps.add(step("A1, e: MixHash(the game's ephemeral P-384 key)", noise));
    noise.mixHash(gameKemPublic);
    steps.add(step("A1, e: MixHash(the game's ephemeral ML-KEM key)", noise));
    steps.add(mixKey("A1, es: MixKey(ECDH(the game's ephemeral key, the relay's static key))", noise,
        P384.agree(gameP384.getPrivate(), (ECPublicKey) relayP384.getPublic())));
    MlKem.Encapsulated skem = MlKem.encapsulate(relayKem.getPublic(), gameRandom);
    List<byte[]> gameDraws = lastDraws(gameRandom, 64, 32);
    noise.mixHash(skem.ciphertext());
    steps.add(step("A1, skem: MixHash(the ciphertext to the relay's static ML-KEM key)", noise));
    steps.add(mixKey("A1, skem: MixKey(its secret)", noise, skem.secret()));
    byte[] a1Tag = noise.encryptAndHash(NOTHING);
    steps.add(step("A1: EncryptAndHash(nothing), its tag (k at n = 0)", noise, "sent", hex(a1Tag)));
    byte[] a1 = join(gameP384Public, gameKemPublic, skem.ciphertext(), a1Tag);

    // A2, the relay's: e, ee, ekem, and its session id sealed
    ScriptedRandom relayRandom = ScriptedRandom.seeded(301);
    KeyPair relayEphemeral = P384.generate(relayRandom);
    byte[] relayEphemeralPublic = P384.encode((ECPublicKey) relayEphemeral.getPublic());
    noise.mixHash(relayEphemeralPublic);
    steps.add(step("A2, e: MixHash(the relay's ephemeral P-384 key)", noise));
    steps.add(mixKey("A2, ee: MixKey(ECDH(the relay's ephemeral key, the game's ephemeral key))", noise,
        P384.agree(relayEphemeral.getPrivate(), (ECPublicKey) gameP384.getPublic())));
    MlKem.Encapsulated ekem = MlKem.encapsulate(gameKem.getPublic(), relayRandom);
    byte[] ekemM = lastDraws(relayRandom, 32).get(0);
    noise.mixHash(ekem.ciphertext());
    steps.add(step("A2, ekem: MixHash(the ciphertext to the game's ephemeral ML-KEM key)", noise));
    steps.add(mixKey("A2, ekem: MixKey(its secret)", noise, ekem.secret()));
    byte[] sessionId = new byte[HandshakeA.SESSION_ID_BYTES];
    relayRandom.nextBytes(sessionId);
    byte[] sealedId = noise.encryptAndHash(sessionId);
    steps.add(step("A2: EncryptAndHash(the relay's session id) (k at n = 0)", noise, "sent", hex(sealedId)));
    byte[] a2 = join(relayEphemeralPublic, ekem.ciphertext(), sealedId);

    // A3, the game's key confirmation; then Split
    byte[] a3 = noise.encryptAndHash(NOTHING);
    steps.add(step("A3: EncryptAndHash(nothing), the game's key confirmation (k at n = 1); h is now the transcript", noise,
        "sent", hex(a3)));
    Noise.Split split = noise.split();
    byte[] transcript = noise.h();

    // The real handshake, given the same randomness, must be these very steps
    HandshakeA.Initiator game = HandshakeA.writeA1(REGION, relay.p384Public(), relay.kemPublic(), ScriptedRandom.seeded(201));
    must(Arrays.equals(game.a1(), a1), "HandshakeA's A1 isn't the steps'");
    HandshakeA.Responder responder = HandshakeA.readA1(relay, REGION, a1, ScriptedRandom.seeded(301));
    must(responder != null && Arrays.equals(responder.a2(), a2), "HandshakeA's A2 isn't the steps'");
    HandshakeA.Initiator.Done done = game.readA2(a2);
    must(done != null && Arrays.equals(done.a3(), a3), "HandshakeA's A3 isn't the steps'");
    HandshakeA.Keys relayKeys = responder.readA3(a3);
    must(relayKeys != null, "the relay refused A3");

    for (HandshakeA.Keys k : List.of(done.keys(), relayKeys)) {
      must(Arrays.equals(k.split().initiatorKey(), split.initiatorKey()) && Arrays.equals(k.split().responderKey(), split.responderKey())
          && Arrays.equals(k.split().initiatorIv(), split.initiatorIv()) && Arrays.equals(k.split().responderIv(), split.responderIv()),
          "HandshakeA's keys aren't the steps'");
      must(Arrays.equals(k.transcript(), transcript) && Arrays.equals(k.sessionId(), sessionId), "HandshakeA's transcript or id isn't");
    }

    into.put("region", REGION);
    into.put("relayStatic", fields("p384Private", hex(scalar(relayP384)), "p384Public", hex(relay.p384Public()), "mlkemSeed",
        hex(relayKemSeed), "mlkemPublic", hex(relay.kemPublic())));
    into.put("gameEphemeral", fields("p384Private", hex(scalar(gameP384)), "p384Public", hex(gameP384Public), "mlkemSeed",
        hex(gameDraws.get(0)), "mlkemPublic", hex(gameKemPublic)));
    into.put("skem", fields("m", hex(gameDraws.get(1)), "ciphertext", hex(skem.ciphertext()), "secret", hex(skem.secret())));
    into.put("relayEphemeral", fields("p384Private", hex(scalar(relayEphemeral)), "p384Public", hex(relayEphemeralPublic)));
    into.put("ekem", fields("m", hex(ekemM), "ciphertext", hex(ekem.ciphertext()), "secret", hex(ekem.secret())));
    into.put("sessionId", hex(sessionId));
    into.put("a1", hex(a1));
    into.put("a2", hex(a2));
    into.put("a3", hex(a3));
    into.put("steps", steps);
    into.put("split", fields("keyGameToRelay", hex(split.initiatorKey()), "keyRelayToGame", hex(split.responderKey()), "ivGameToRelay",
        hex(split.initiatorIv()), "ivRelayToGame", hex(split.responderIv())));
    into.put("transcript", hex(transcript));
    return done.keys();
  }

  // A1, A2 and A3 as the 1,200-byte datagrams that carry them (CRYPTO.md section 5; 5.1 points 9 and 10)
  private static Map<String, Object> datagrams(Map<String, Object> handshake) {
    byte[] id = new byte[Fragments.ID_BYTES];
    ScriptedRandom.seeded(401).nextBytes(id);
    byte[] cookie = new byte[Fragments.COOKIE_BYTES];
    ScriptedRandom.seeded(402).nextBytes(cookie);
    HexFormat h = HexFormat.of();
    List<Object> a1 = new ArrayList<>();
    List<Object> a2 = new ArrayList<>();
    List<Object> a3 = new ArrayList<>();

    for (byte[] d : Fragments.cut(Fragments.toRelay(), 3, id, cookie, h.parseHex((String) handshake.get("a1")))) {
      a1.add(hex(d));
    }

    for (byte[] d : Fragments.cut(Fragments.toRelay(), 4, id, new byte[Fragments.COOKIE_BYTES], h.parseHex((String) handshake.get("a2")))) {
      a2.add(hex(d));
    }

    for (byte[] d : Fragments.cut(Fragments.toRelay(), 5, id, cookie, h.parseHex((String) handshake.get("a3")))) {
      a3.add(hex(d));
    }

    return fields("id", hex(id), "cookie", hex(cookie), "a1", a1, "a2", a2, "a3", a3);
  }

  // The first sealed control messages each way, and the first of epoch 1 (counter 2^20), from handshake A's keys (CRYPTO.md section 7)
  private static List<Object> sealed(HandshakeA.Keys keys) {
    Channel game = Channel.gameSide(keys, 0);
    Channel relay = Channel.relaySide(keys, 0);
    List<Object> out = new ArrayList<>();
    out.add(fields("from", "game", "counter", 0L, "message", hex(message(0)), "sealed", hex(game.seal(message(0), 0))));
    out.add(fields("from", "relay", "counter", 0L, "message", hex(message(64)), "sealed", hex(relay.seal(message(64), 0))));
    out.add(fields("from", "game", "counter", 1L, "message", hex(message(128)), "sealed", hex(game.seal(message(128), 0))));

    Channel later = Channel.gameSide(keys, 0);
    long edge = 1L << Channel.EPOCH_SHIFT;

    for (long i = 0; i < edge; i++) {
      later.seal(message(0), 0);
    }

    out.add(fields("from", "game", "counter", edge, "message", hex(message(192)), "sealed", hex(later.seal(message(192), 0))));
    return out;
  }

  // nonce(n) = the IV XOR (4 zero bytes, then n as 8 bytes little-endian), with the game-to-relay IV
  private static List<Object> nonces(HandshakeA.Keys keys) {
    List<Object> out = new ArrayList<>();
    byte[] iv = keys.split().initiatorIv();

    for (long n : new long[] {0, 1, 255, 256, 1L << 20, (1L << 32) - 1}) {
      out.add(fields("iv", hex(iv), "n", n, "nonce", hex(Noise.nonce(iv, n))));
    }

    return out;
  }

  // Epoch e's key: HKDF-Expand(the direction's key from Split, "AVPX epoch v2" || e as 4 bytes little-endian, 32) (5.1, point 8)
  private static List<Object> epochKeys(HandshakeA.Keys keys) {
    List<Object> out = new ArrayList<>();
    byte[] key = keys.split().initiatorKey();

    for (long e : new long[] {1, 2, 4095}) {
      byte[] info = Channel.epochInfo(e);
      out.add(fields("key", hex(key), "epoch", e, "info", hex(info), "epochKey", hex(Hkdf.expand(key, info, 32))));
    }

    return out;
  }

  private static List<Object> aesGcm() {
    List<Object> out = new ArrayList<>();
    ScriptedRandom r = ScriptedRandom.seeded(501);

    for (int size : new int[] {0, 64}) {
      byte[] key = new byte[32];
      byte[] nonce = new byte[12];
      byte[] aad = new byte[24];
      byte[] message = new byte[size];
      r.nextBytes(key);
      r.nextBytes(nonce);
      r.nextBytes(aad);
      r.nextBytes(message);
      out.add(fields("key", hex(key), "nonce", hex(nonce), "aad", hex(aad), "message", hex(message), "sealed",
          hex(Gcm.seal(key, nonce, aad, message))));
    }

    return out;
  }

  // An ML-KEM-1024 key pair from d and z, an encapsulation from m, and the same ciphertext changed, which gives FIPS 203's implicit
  // rejection secret: decapsulating it gives exactly that, never an error
  private static Map<String, Object> mlkem() {
    ScriptedRandom r = ScriptedRandom.seeded(601);
    KeyPair pair = MlKem.generate(r);
    MlKem.Encapsulated made = MlKem.encapsulate(pair.getPublic(), r);
    List<byte[]> draws = lastDraws(r, 64, 32);
    byte[] changed = made.ciphertext().clone();
    changed[0] ^= 1;
    byte[] rejection = MlKem.decapsulate(pair.getPrivate(), changed);
    must(Arrays.equals(MlKem.decapsulate(pair.getPrivate(), made.ciphertext()), made.secret()), "ML-KEM doesn't decapsulate its own");
    must(rejection != null && !Arrays.equals(rejection, made.secret()), "a changed ciphertext gave no implicit rejection");
    return fields("mlkemSeed", hex(draws.get(0)), "mlkemPublic", hex(MlKem.encode(pair.getPublic())), "m", hex(draws.get(1)), "ciphertext",
        hex(made.ciphertext()), "secret", hex(made.secret()), "changedCiphertext", hex(changed), "implicitRejectionSecret", hex(rejection));
  }

  // Signatures to check, not to make again (ML-DSA may be randomised, CRYPTO.md section 15): each good one, and the same with a bit
  // changed. The message is a D as section 12 makes one: SHA-384 of the words, then the bytes.
  private static List<Object> signatures() {
    byte[] d;

    try {
      d = MessageDigest.getInstance("SHA-384").digest(join("AVPX test vectors v2".getBytes(StandardCharsets.US_ASCII), message(0)));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("this Java has no SHA-384", e);
    }

    KeyPair ec = Signatures.ecdsaKeys(ScriptedRandom.seeded(701));
    byte[] ecSig = Signatures.ecdsaSign(ec.getPrivate(), d, ScriptedRandom.seeded(702));
    KeyPair ml = Signatures.mlDsaKeys(ScriptedRandom.seeded(703));
    byte[] mlSig = Signatures.mlDsaSign(ml.getPrivate(), d, ScriptedRandom.seeded(704));
    must(Signatures.ecdsaVerify(ec.getPublic(), d, ecSig) && Signatures.mlDsaVerify(ml.getPublic(), d, mlSig), "a signature doesn't check");
    byte[] ecBad = ecSig.clone();
    ecBad[10] ^= 1;
    byte[] mlBad = mlSig.clone();
    mlBad[10] ^= 1;
    byte[] ecPublic = P384.encode((ECPublicKey) ec.getPublic());
    byte[] mlPublic = Signatures.mlDsaEncode(ml.getPublic());
    List<Object> out = new ArrayList<>();
    out.add(fields("scheme", "ECDSA P-384 SHA-384, r then s", "public", hex(ecPublic), "message", hex(d), "signature", hex(ecSig), "result",
        "valid"));
    out.add(fields("scheme", "ECDSA P-384 SHA-384, r then s", "public", hex(ecPublic), "message", hex(d), "signature", hex(ecBad), "result",
        "invalid"));
    out.add(fields("scheme", "ML-DSA-87, pure, the empty context", "public", hex(mlPublic), "message", hex(d), "signature", hex(mlSig),
        "result", "valid"));
    out.add(fields("scheme", "ML-DSA-87, pure, the empty context", "public", hex(mlPublic), "message", hex(d), "signature", hex(mlBad),
        "result", "invalid"));
    return out;
  }

  // Section 16's refusals, as bytes, each changed from a good datagram above in one way. 5 (a bad cookie) comes with the relay's cookie.
  private static List<Object> refusals(Map<String, Object> datagrams, List<Object> sealed) {
    HexFormat h = HexFormat.of();
    byte[] a1First = h.parseHex((String) ((List<?>) datagrams.get("a1")).get(0));
    byte[] a1Last = h.parseHex((String) ((List<?>) datagrams.get("a1")).get(2));
    byte[] gameSealed = h.parseHex((String) ((Map<?, ?>) sealed.get(0)).get("sealed"));
    List<Object> out = new ArrayList<>();
    out.add(refusal(1, "a handshake datagram of 1,199 bytes (A1's first, cut short)", Arrays.copyOf(a1First, 1199)));
    out.add(refusal(1, "a sealed control message of 103 bytes (the game's first, cut short)", Arrays.copyOf(gameSealed, 103)));
    out.add(refusal(2, "another magic: AVPQ", changed(a1First, 3, 'Q')));
    out.add(refusal(3, "another version: 3", changed(a1First, 4, 3)));
    out.add(refusal(4, "an unknown kind: 9", changed(a1First, 5, 9)));
    out.add(refusal(6, "a count of 0", changed(a1First, 7, 0)));
    out.add(refusal(6, "a count of 4, for a length that takes 3", changed(a1First, 7, 4)));
    out.add(refusal(6, "fragment 0 starting at 1, not 0", changed(a1First, 34, 1)));
    out.add(refusal(6, "a byte after the last fragment's part that isn't 0", changed(a1Last, 1199, 1)));
    out.add(refusal(8, "the game's first sealed message with a bit of its tag changed", changed(gameSealed, 103, gameSealed[103] ^ 1)));
    out.add(refusal(8, "the game's first sealed message with a bit of its message changed", changed(gameSealed, 30, gameSealed[30] ^ 1)));
    out.add(refusal(9, "the game's first sealed message again, after it was taken", gameSealed));
    return out;
  }

  private static byte[] changed(byte[] d, int at, int to) {
    byte[] c = d.clone();
    c[at] = (byte) to;
    return c;
  }

  private static Map<String, Object> refusal(long number, String what, byte[] bytes) {
    return fields("refusal", number, "what", what, "bytes", hex(bytes));
  }

  // ----- Writing it out: JSON as the strict reader takes it (no true, false or null; texts of printable ASCII), one field to a line

  private static void write(StringBuilder out, Object value, String indent) {
    if (value instanceof Map<?, ?> object) {
      out.append("{\n");
      int i = 0;

      for (Map.Entry<?, ?> field : object.entrySet()) {
        out.append(indent).append("  ").append(Json.write(field.getKey())).append(": ");
        write(out, field.getValue(), indent + "  ");
        out.append(++i < object.size() ? ",\n" : "\n");
      }

      out.append(indent).append('}');
    } else if (value instanceof List<?> list) {
      out.append("[\n");

      for (int i = 0; i < list.size(); i++) {
        out.append(indent).append("  ");
        write(out, list.get(i), indent + "  ");
        out.append(i + 1 < list.size() ? ",\n" : "\n");
      }

      out.append(indent).append(']');
    } else {
      // A text or a whole number: the server's own writer, which refuses anything else
      out.append(Json.write(value));
    }
  }
}
