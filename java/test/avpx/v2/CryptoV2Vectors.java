package avpx.v2;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import avpx.testing.ScriptedRandom;
import avpx.testing.SeededRandom;
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

  // An object of fields in the order given: name, value, name, value, ... A name left without its value is a mistake here, so it stops.
  private static Map<String, Object> fields(Object... nameValue) {
    if (nameValue.length % 2 != 0) {
      throw new IllegalArgumentException("fields: a name without its value");
    }

    Map<String, Object> out = new LinkedHashMap<>();

    // i + 1 < length, not i < length: each step reads a name and the value after it, so both must be there
    for (int i = 0; i + 1 < nameValue.length; i += 2) {
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
        + " as its m. handshakeA is pqIK (section 6): its player is the game's static keys, which A1's s sends sealed, and skemToPlayer is"
        + " A2's encapsulation to the player's static ML-KEM key. handshakeA's steps give h and ck after every step (MixKey steps give the"
        + " secret mixed and the k made), and its transcript is h after A3 (5.1, point 15). Its datagrams carry a stand-in cookie: a real one is the relay's own HMAC, and only it"
        + " can check one. handshakeB is handshake B (section 8, and 5.1 points 17 to 20) the same way, joiner and host, with both"
        + " identities, fingerprints and ids, nJ and its commitment, nH, the transcript (h after B5) and the check code. Each side draws its"
        + " random values in the order they first appear in its own messages. B's datagrams are end to end (AVPE), with a cookie of 0."
        + " handshakeB.refusals are whole B messages a side must refuse, by refusal number (section 16). sealedGame is section 9's sealed"
        + " game datagrams (AVPG), sealed under handshakeB's split: the joiner's with keys made from secretJoinerToHost, the host's from"
        + " secretHostToJoiner, each epoch's key HKDF-Expand(that secret, \"AVPX epoch v2\" || the epoch, 32), epoch 0's too (5.1 point 8)."
        + " result is \"valid\" or \"invalid\".");
    top.put("protocol", HandshakeA.PROTOCOL);
    Map<String, Object> handshake = new LinkedHashMap<>();
    HandshakeA.Keys keys = handshakeA(handshake);
    top.put("handshakeA", handshake);
    Map<String, Object> datagrams = datagrams(handshake);
    top.put("handshakeDatagrams", datagrams);
    List<Object> sealed = sealed(keys);
    top.put("sealed", sealed);
    List<Object> sealedGame = new ArrayList<>();
    top.put("handshakeB", handshakeB(sealedGame));
    top.put("nonces", nonces(keys));
    top.put("epochKeys", epochKeys(keys));
    top.put("aesGcm", aesGcm());
    top.put("mlkem", mlkem());
    top.put("sealedGame", sealedGame);
    top.put("refusals", refusals(datagrams, sealed));
    StringBuilder out = new StringBuilder();
    write(out, top, "");
    out.append('\n');
    return out.toString();
  }

  // A player's identity, made from seeds, and written down as the primitives take it
  private static Map<String, Object> identityFields(KeyPair p384, byte[] kemSeed, Identity id) {
    return fields("p384Private", hex(scalar(p384)), "p384Public", hex(id.p384Public()), "mlkemSeed", hex(kemSeed), "mlkemPublic",
        hex(id.kemPublic()), "fingerprint", hex(id.fingerprint()), "id", hex(id.id()));
  }

  // Handshake B, walked step by step, then held to the real HandshakeB (java/test/avpx/v2/HandshakeB.java), as handshake A is
  // Handshake B, walked step by step, then held to HandshakeB. Its split also seals the sealed game datagrams, which go into sealedGame.
  private static Map<String, Object> handshakeB(List<Object> sealedGame) {
    int relayPort = 27507;
    KeyPair hostP384 = P384.generate(ScriptedRandom.seeded(801));
    ScriptedRandom hostKemRandom = ScriptedRandom.seeded(802);
    KeyPair hostKem = MlKem.generate(hostKemRandom);
    Identity host = Identity.of(hostP384, hostKem);
    KeyPair joinerP384 = P384.generate(ScriptedRandom.seeded(803));
    ScriptedRandom joinerKemRandom = ScriptedRandom.seeded(804);
    KeyPair joinerKem = MlKem.generate(joinerKemRandom);
    Identity joiner = Identity.of(joinerP384, joinerKem);

    List<Object> steps = new ArrayList<>();
    Noise noise = new Noise(HandshakeB.PROTOCOL);
    steps.add(step("start: h = SHA-384(the protocol's name), and ck = h", noise));
    byte[] prologue = Arrays.copyOf(REGION.getBytes(StandardCharsets.US_ASCII), REGION.length() + 1);
    noise.mixHash(prologue);
    steps.add(step("prologue: MixHash(the region, then a 0 byte)", noise, "data", hex(prologue)));
    byte[] port = {(byte) relayPort, (byte) (relayPort >>> 8)};
    noise.mixHash(port);
    steps.add(step("prologue: MixHash(the joiner's relay port, 2 bytes little-endian)", noise, "data", hex(port)));
    noise.mixHash(host.id());
    steps.add(step("prologue: MixHash(the host's whole id, 48 bytes, as the listing gives it)", noise, "data", hex(host.id())));

    // B1, the joiner's: e, then its commitment to nJ. Its draws, in the order they first appear in its messages: e's two keys, nJ.
    ScriptedRandom joinerRandom = ScriptedRandom.seeded(805);
    KeyPair e = P384.generate(joinerRandom);
    KeyPair ek = MlKem.generate(joinerRandom);
    byte[] nJ = new byte[HandshakeB.NONCE_BYTES];
    joinerRandom.nextBytes(nJ);
    byte[] ekSeed = lastDraws(joinerRandom, 64, 32).get(0);
    byte[] commitment = Noise.sha384(nJ);
    byte[] eP384 = P384.encode((ECPublicKey) e.getPublic());
    byte[] ekPublic = MlKem.encode(ek.getPublic());
    noise.mixHash(eP384);
    steps.add(step("B1, e: MixHash(the joiner's ephemeral P-384 key)", noise));
    noise.mixHash(ekPublic);
    steps.add(step("B1, e: MixHash(the joiner's ephemeral ML-KEM key)", noise));
    noise.mixHash(commitment);
    steps.add(step("B1: MixHash(the joiner's commitment, SHA-384(nJ))", noise, "data", hex(commitment)));
    byte[] b1 = join(eP384, ekPublic, commitment);

    // B2, the host's: e, ee, ekem, s, es, and a tag
    ScriptedRandom hostRandom = ScriptedRandom.seeded(806);
    KeyPair re = P384.generate(hostRandom);
    byte[] reP384 = P384.encode((ECPublicKey) re.getPublic());
    noise.mixHash(reP384);
    steps.add(step("B2, e: MixHash(the host's ephemeral P-384 key)", noise));
    steps.add(mixKey("B2, ee: MixKey(ECDH(the host's ephemeral key, the joiner's ephemeral key))", noise,
        P384.agree(re.getPrivate(), (ECPublicKey) e.getPublic())));
    MlKem.Encapsulated ekem = MlKem.encapsulate(ek.getPublic(), hostRandom);
    byte[] ekemM = lastDraws(hostRandom, 32).get(0);
    noise.mixHash(ekem.ciphertext());
    steps.add(step("B2, ekem: MixHash(the ciphertext to the joiner's ephemeral ML-KEM key)", noise));
    steps.add(mixKey("B2, ekem: MixKey(its secret)", noise, ekem.secret()));
    byte[] sealedHost = noise.encryptAndHash(host.statics());
    steps.add(step("B2, s: EncryptAndHash(the host's static P-384 key, then its static ML-KEM key) (k at n = 0)", noise));
    steps.add(mixKey("B2, es: MixKey(ECDH(the host's static key, the joiner's ephemeral key))", noise,
        P384.agree(hostP384.getPrivate(), (ECPublicKey) e.getPublic())));
    byte[] tag2 = noise.encryptAndHash(NOTHING);
    steps.add(step("B2: EncryptAndHash(nothing), its tag (k at n = 0)", noise, "sent", hex(tag2)));
    byte[] b2 = join(reP384, ekem.ciphertext(), sealedHost, tag2);

    // B3, the joiner's: skem, s, se, and a tag
    MlKem.Encapsulated toHost = MlKem.encapsulate(hostKem.getPublic(), joinerRandom);
    byte[] toHostM = lastDraws(joinerRandom, 32).get(0);
    noise.mixHash(toHost.ciphertext());
    steps.add(step("B3, skem: MixHash(the ciphertext to the host's static ML-KEM key)", noise));
    steps.add(mixKey("B3, skem: MixKey(its secret)", noise, toHost.secret()));
    byte[] sealedJoiner = noise.encryptAndHash(joiner.statics());
    steps.add(step("B3, s: EncryptAndHash(the joiner's static P-384 key, then its static ML-KEM key) (k at n = 0)", noise));
    steps.add(mixKey("B3, se: MixKey(ECDH(the joiner's static key, the host's ephemeral key))", noise,
        P384.agree(joinerP384.getPrivate(), (ECPublicKey) re.getPublic())));
    byte[] tag3 = noise.encryptAndHash(NOTHING);
    steps.add(step("B3: EncryptAndHash(nothing), its tag (k at n = 0)", noise, "sent", hex(tag3)));
    byte[] b3 = join(toHost.ciphertext(), sealedJoiner, tag3);

    // B4, the host's: skem, then nH sealed (its tag is the host's key confirmation); B5, the joiner's: nJ sealed
    MlKem.Encapsulated toJoiner = MlKem.encapsulate(joinerKem.getPublic(), hostRandom);
    byte[] nH = new byte[HandshakeB.NONCE_BYTES];
    hostRandom.nextBytes(nH);
    byte[] toJoinerM = lastDraws(hostRandom, 32, 32).get(0);
    noise.mixHash(toJoiner.ciphertext());
    steps.add(step("B4, skem: MixHash(the ciphertext to the joiner's static ML-KEM key)", noise));
    steps.add(mixKey("B4, skem: MixKey(its secret)", noise, toJoiner.secret()));
    byte[] sealedNH = noise.encryptAndHash(nH);
    steps.add(step("B4: EncryptAndHash(nH), the host's key confirmation (k at n = 0)", noise, "sent", hex(sealedNH)));
    byte[] b4 = join(toJoiner.ciphertext(), sealedNH);
    byte[] b5 = noise.encryptAndHash(nJ);
    steps.add(step("B5: EncryptAndHash(nJ), the joiner's key confirmation (k at n = 1); h is now the transcript", noise,
        "sent", hex(b5)));
    Noise.Split split = noise.split();
    byte[] transcript = noise.h();

    // The real handshake, given the same randomness, must be these very steps
    HandshakeB.Joiner realJoiner = HandshakeB.writeB1(REGION, relayPort, host.id(), joiner, ScriptedRandom.seeded(805));
    must(Arrays.equals(realJoiner.b1(), b1), "HandshakeB's B1 isn't the steps'");
    HandshakeB.Host realHost = HandshakeB.readB1(REGION, relayPort, host, b1, ScriptedRandom.seeded(806));
    must(realHost != null && Arrays.equals(realHost.b2(), b2), "HandshakeB's B2 isn't the steps'");
    must(Arrays.equals(realJoiner.readB2(b2), b3), "HandshakeB's B3 isn't the steps'");
    must(Arrays.equals(realHost.readB3(b3), b4), "HandshakeB's B4 isn't the steps'");
    HandshakeB.Joiner.Done done = realJoiner.readB4(b4);
    must(done != null && Arrays.equals(done.b5(), b5), "HandshakeB's B5 isn't the steps'");
    HandshakeB.Keys hostKeys = realHost.readB5(b5);
    must(hostKeys != null, "the host refused B5's nJ");

    for (HandshakeB.Keys k : List.of(done.keys(), hostKeys)) {
      must(Arrays.equals(k.split().initiatorSecret(), split.initiatorSecret()) && Arrays.equals(k.split().responderSecret(), split.responderSecret())
          && Arrays.equals(k.split().initiatorIv(), split.initiatorIv()) && Arrays.equals(k.split().responderIv(), split.responderIv())
          && Arrays.equals(k.transcript(), transcript), "HandshakeB's keys or transcript aren't the steps'");
    }

    // B's datagrams: end to end (AVPE), a fixed id the joiner chose, no cookie
    byte[] id = new byte[Fragments.ID_BYTES];
    ScriptedRandom.seeded(807).nextBytes(id);
    Map<String, Object> datagrams = fields("id", hex(id));
    byte[][] messages = {b1, b2, b3, b4, b5};

    for (int i = 0; i < messages.length; i++) {
      List<Object> list = new ArrayList<>();

      for (byte[] d : Fragments.cut(Fragments.hostToJoiner(), HandshakeB.B1 + i, id, new byte[Fragments.COOKIE_BYTES], messages[i])) {
        list.add(hex(d));
      }

      datagrams.put("b" + (i + 1), list);
    }

    // Refusal 10's bytes: a B2 from a host with other static keys, sealed under the id the listing names. Every tag checks, because the
    // prologue is the one the joiner expects; only the id of the statics inside is wrong, and the joiner refuses it.
    Identity other = Identity.of(P384.generate(ScriptedRandom.seeded(808)), MlKem.generate(ScriptedRandom.seeded(809)));
    byte[] otherB2 = b2From(relayPort, host.id(), other, e, ek, b1);
    HandshakeB.Joiner refuses = HandshakeB.writeB1(REGION, relayPort, host.id(), joiner, ScriptedRandom.seeded(805));
    must(Arrays.equals(refuses.b1(), b1) && refuses.readB2(otherB2) == null, "the joiner took a B2 from a host the listing didn't name");

    // Refusal 21's bytes: B5 revealing another nJ, with a good tag (the joiner holds the keys). SHA-384 of it isn't B1's commitment, so
    // the host refuses it. The same handshake again, from the same randomness, up to B4.
    HandshakeB.Joiner liar = HandshakeB.writeB1(REGION, relayPort, host.id(), joiner, ScriptedRandom.seeded(805));
    HandshakeB.Host fooled = HandshakeB.readB1(REGION, relayPort, host, liar.b1(), ScriptedRandom.seeded(806));
    byte[] otherNJ = SeededRandom.of(810).next(HandshakeB.NONCE_BYTES);
    HandshakeB.Joiner.Done lied = liar.readB4(fooled.readB3(liar.readB2(fooled.b2())), otherNJ);
    must(lied != null && !Arrays.equals(lied.b5(), b5) && fooled.readB5(lied.b5()) == null, "the host took a B5 whose nJ isn't B1's");
    List<Object> refusals = List.of(
        refusal(10, "B2 from a host with other static keys, sealed under the id the listing names: every tag checks, the id of the"
            + " statics doesn't (the joiner refuses it)", otherB2),
        refusal(21, "B5 revealing another nJ, with a good tag: SHA-384 of it isn't B1's commitment (the host refuses it)", lied.b5()));

    sealedGame.addAll(sealedGame(split));

    return fields("protocol", HandshakeB.PROTOCOL, "region", REGION, "relayPort", (long) relayPort,
        "host", identityFields(hostP384, lastDraws(hostKemRandom, 64).get(0), host),
        "joiner", identityFields(joinerP384, lastDraws(joinerKemRandom, 64).get(0), joiner),
        "joinerEphemeral", fields("p384Private", hex(scalar(e)), "p384Public", hex(eP384), "mlkemSeed", hex(ekSeed), "mlkemPublic",
            hex(ekPublic)),
        "hostEphemeral", fields("p384Private", hex(scalar(re)), "p384Public", hex(reP384)),
        "ekem", fields("m", hex(ekemM), "ciphertext", hex(ekem.ciphertext()), "secret", hex(ekem.secret())),
        "skemToHost", fields("m", hex(toHostM), "ciphertext", hex(toHost.ciphertext()), "secret", hex(toHost.secret())),
        "skemToJoiner", fields("m", hex(toJoinerM), "ciphertext", hex(toJoiner.ciphertext()), "secret", hex(toJoiner.secret())),
        "nJ", hex(nJ), "commitment", hex(commitment), "nH", hex(nH),
        "b1", hex(b1), "b2", hex(b2), "b3", hex(b3), "b4", hex(b4), "b5", hex(b5), "steps", steps,
        "split", fields("secretJoinerToHost", hex(split.initiatorSecret()), "secretHostToJoiner", hex(split.responderSecret()), "ivJoinerToHost",
            hex(split.initiatorIv()), "ivHostToJoiner", hex(split.responderIv())),
        "transcript", hex(transcript), "checkCode", HandshakeB.checkCode(transcript), "datagrams", datagrams, "refusals", refusals);
  }

  // B2 as a host with the identity `as` would make it for B1, but with the prologue naming `hostId`. The host's draws are the same
  // as the real B2's (seed 806), so only the statics and es differ. For a test vector only: it's the case refusal 10 is for, a host
  // that knows the listing's id but not its keys.
  private static byte[] b2From(int relayPort, byte[] hostId, Identity as, KeyPair e, KeyPair ek, byte[] b1) {
    Noise noise = new Noise(HandshakeB.PROTOCOL);
    noise.mixHash(Arrays.copyOf(REGION.getBytes(StandardCharsets.US_ASCII), REGION.length() + 1));
    noise.mixHash(new byte[] {(byte) relayPort, (byte) (relayPort >>> 8)});
    noise.mixHash(hostId);
    int eBytes = P384.encode((ECPublicKey) e.getPublic()).length;
    int ekBytes = MlKem.encode(ek.getPublic()).length;
    noise.mixHash(Arrays.copyOfRange(b1, 0, eBytes));
    noise.mixHash(Arrays.copyOfRange(b1, eBytes, eBytes + ekBytes));
    noise.mixHash(Arrays.copyOfRange(b1, eBytes + ekBytes, b1.length));
    ScriptedRandom hostRandom = ScriptedRandom.seeded(806);
    KeyPair re = P384.generate(hostRandom);
    byte[] reP384 = P384.encode((ECPublicKey) re.getPublic());
    noise.mixHash(reP384);
    noise.mixKey(P384.agree(re.getPrivate(), (ECPublicKey) e.getPublic()));
    MlKem.Encapsulated ekem = MlKem.encapsulate(ek.getPublic(), hostRandom);
    noise.mixHash(ekem.ciphertext());
    noise.mixKey(ekem.secret());
    byte[] sealedStatics = noise.encryptAndHash(as.statics());
    noise.mixKey(P384.agree(as.p384().getPrivate(), (ECPublicKey) e.getPublic()));
    byte[] tag = noise.encryptAndHash(NOTHING);
    return join(reP384, ekem.ciphertext(), sealedStatics, tag);
  }

  // Section 9's sealed game datagrams (AVPG), sealed here by the rule from the primitives the known answers hold (Gcm, Hkdf, Noise.nonce).
  // The relay never seals one, so this is the one place the server's side writes them down, and the game's own code must make and open
  // the same bytes. Both edges of a datagram's size, and the last counter of epoch 0 and the first of epoch 1.
  //   bytes 0-3 "AVPG"; 4-11 the counter, 8 bytes little-endian; then the ENet datagram sealed; then the 16-byte tag. The AAD is bytes 0-11.
  private static List<Object> sealedGame(Noise.Split split) {
    List<Object> out = new ArrayList<>();
    Object[][] cases = {
        {"joiner", 0L, 1392}, {"joiner", 1L, 20}, {"joiner", (1L << 20) - 1, 20}, {"joiner", 1L << 20, 20},
        {"host", 0L, 0}, {"host", 1L, 1472},
    };
    SeededRandom r = SeededRandom.of(811);

    for (Object[] c : cases) {
      boolean fromJoiner = c[0].equals("joiner");
      long counter = (Long) c[1];
      byte[] message = r.next((Integer) c[2]);
      byte[] secret = fromJoiner ? split.initiatorSecret() : split.responderSecret();
      byte[] iv = fromJoiner ? split.initiatorIv() : split.responderIv();
      long epoch = counter >>> Channel.EPOCH_SHIFT;
      byte[] epochKey = Channel.epochKey(secret, epoch);
      byte[] aad = new byte[12];
      aad[0] = 'A';
      aad[1] = 'V';
      aad[2] = 'P';
      aad[3] = 'G';

      for (int i = 0; i < 8; i++) {
        aad[4 + i] = (byte) (counter >>> (8 * i));
      }

      byte[] sealed = join(aad, Gcm.seal(epochKey, Noise.nonce(iv, counter), aad, message));
      must(sealed.length == message.length + 28 && sealed.length <= 1500, "a sealed game datagram of the wrong size");
      must(Arrays.equals(Gcm.open(epochKey, Noise.nonce(iv, counter), aad, Arrays.copyOfRange(sealed, 12, sealed.length)), message),
          "a sealed game datagram that doesn't open");
      out.add(fields("from", c[0], "counter", counter, "epoch", epoch, "message", hex(message), "sealed", hex(sealed)));
    }

    return out;
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

    // The player's static keys (their identity, section 4): what A1's s sends sealed, and what ss, se and A2's skem prove
    KeyPair playerP384 = P384.generate(ScriptedRandom.seeded(901));
    ScriptedRandom playerKemRandom = ScriptedRandom.seeded(902);
    KeyPair playerKem = MlKem.generate(playerKemRandom);
    byte[] playerKemSeed = lastDraws(playerKemRandom, 64).get(0);
    Identity player = Identity.of(playerP384, playerKem);

    // A1, the game's: e, es, skem, s, ss, and an empty EncryptAndHash
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
    byte[] sealedStatics = noise.encryptAndHash(player.statics());
    steps.add(step("A1, s: EncryptAndHash(the player's static P-384 key, then static ML-KEM key, 1,665 bytes) (k at n = 0)", noise,
        "sent", hex(sealedStatics)));
    steps.add(mixKey("A1, ss: MixKey(ECDH(the player's static key, the relay's static key))", noise,
        P384.agree(playerP384.getPrivate(), (ECPublicKey) relayP384.getPublic())));
    byte[] a1Tag = noise.encryptAndHash(NOTHING);
    steps.add(step("A1: EncryptAndHash(nothing), its tag (k at n = 0)", noise, "sent", hex(a1Tag)));
    byte[] a1 = join(gameP384Public, gameKemPublic, skem.ciphertext(), sealedStatics, a1Tag);

    // A2, the relay's: e, ee, se, ekem, skem (to the player's static ML-KEM key), and its session id sealed. The relay draws in that order:
    // its ephemeral key, ekem's m, skem's m, the session id.
    ScriptedRandom relayRandom = ScriptedRandom.seeded(301);
    KeyPair relayEphemeral = P384.generate(relayRandom);
    byte[] relayEphemeralPublic = P384.encode((ECPublicKey) relayEphemeral.getPublic());
    noise.mixHash(relayEphemeralPublic);
    steps.add(step("A2, e: MixHash(the relay's ephemeral P-384 key)", noise));
    steps.add(mixKey("A2, ee: MixKey(ECDH(the relay's ephemeral key, the game's ephemeral key))", noise,
        P384.agree(relayEphemeral.getPrivate(), (ECPublicKey) gameP384.getPublic())));
    steps.add(mixKey("A2, se: MixKey(ECDH(the relay's ephemeral key, the player's static key))", noise,
        P384.agree(relayEphemeral.getPrivate(), (ECPublicKey) playerP384.getPublic())));
    MlKem.Encapsulated ekem = MlKem.encapsulate(gameKem.getPublic(), relayRandom);
    byte[] ekemM = lastDraws(relayRandom, 32).get(0);
    noise.mixHash(ekem.ciphertext());
    steps.add(step("A2, ekem: MixHash(the ciphertext to the game's ephemeral ML-KEM key)", noise));
    steps.add(mixKey("A2, ekem: MixKey(its secret)", noise, ekem.secret()));
    MlKem.Encapsulated toPlayer = MlKem.encapsulate(playerKem.getPublic(), relayRandom);
    byte[] toPlayerM = lastDraws(relayRandom, 32).get(0);
    noise.mixHash(toPlayer.ciphertext());
    steps.add(step("A2, skem: MixHash(the ciphertext to the player's static ML-KEM key)", noise));
    steps.add(mixKey("A2, skem: MixKey(its secret)", noise, toPlayer.secret()));
    byte[] sessionId = new byte[HandshakeA.SESSION_ID_BYTES];
    relayRandom.nextBytes(sessionId);
    byte[] sealedId = noise.encryptAndHash(sessionId);
    steps.add(step("A2: EncryptAndHash(the relay's session id) (k at n = 0)", noise, "sent", hex(sealedId)));
    byte[] a2 = join(relayEphemeralPublic, ekem.ciphertext(), toPlayer.ciphertext(), sealedId);

    // A3, the game's key confirmation; then Split
    byte[] a3 = noise.encryptAndHash(NOTHING);
    steps.add(step("A3: EncryptAndHash(nothing), the game's key confirmation (k at n = 1); h is now the transcript", noise,
        "sent", hex(a3)));
    Noise.Split split = noise.split();
    byte[] transcript = noise.h();

    // The real handshake, given the same randomness, must be these very steps
    HandshakeA.Initiator game = HandshakeA.writeA1(REGION, relay.p384Public(), relay.kemPublic(), player, ScriptedRandom.seeded(201));
    must(Arrays.equals(game.a1(), a1), "HandshakeA's A1 isn't the steps'");
    String playerId = Identity.idHex(player.p384Public(), player.kemPublic());
    HandshakeA.Responder responder = HandshakeA.readA1(relay, REGION, a1, playerId::equals, ScriptedRandom.seeded(301))
        .responder();
    must(responder != null && Arrays.equals(responder.a2(), a2), "HandshakeA's A2 isn't the steps'");
    must(responder.player().equals(playerId), "HandshakeA's player isn't the steps'");
    HandshakeA.Initiator.Done done = game.readA2(a2);
    must(done != null && Arrays.equals(done.a3(), a3), "HandshakeA's A3 isn't the steps'");
    HandshakeA.Keys relayKeys = responder.readA3(a3);
    must(relayKeys != null, "the relay refused A3");

    for (HandshakeA.Keys k : List.of(done.keys(), relayKeys)) {
      must(Arrays.equals(k.split().initiatorSecret(), split.initiatorSecret()) && Arrays.equals(k.split().responderSecret(), split.responderSecret())
          && Arrays.equals(k.split().initiatorIv(), split.initiatorIv()) && Arrays.equals(k.split().responderIv(), split.responderIv()),
          "HandshakeA's keys aren't the steps'");
      must(Arrays.equals(k.transcript(), transcript) && Arrays.equals(k.sessionId(), sessionId), "HandshakeA's transcript or id isn't");
    }

    into.put("region", REGION);
    into.put("relayStatic", fields("p384Private", hex(scalar(relayP384)), "p384Public", hex(relay.p384Public()), "mlkemSeed",
        hex(relayKemSeed), "mlkemPublic", hex(relay.kemPublic())));
    into.put("player", identityFields(playerP384, playerKemSeed, player));
    into.put("gameEphemeral", fields("p384Private", hex(scalar(gameP384)), "p384Public", hex(gameP384Public), "mlkemSeed",
        hex(gameDraws.get(0)), "mlkemPublic", hex(gameKemPublic)));
    into.put("skem", fields("m", hex(gameDraws.get(1)), "ciphertext", hex(skem.ciphertext()), "secret", hex(skem.secret())));
    into.put("relayEphemeral", fields("p384Private", hex(scalar(relayEphemeral)), "p384Public", hex(relayEphemeralPublic)));
    into.put("ekem", fields("m", hex(ekemM), "ciphertext", hex(ekem.ciphertext()), "secret", hex(ekem.secret())));
    into.put("skemToPlayer", fields("m", hex(toPlayerM), "ciphertext", hex(toPlayer.ciphertext()), "secret", hex(toPlayer.secret())));
    into.put("sessionId", hex(sessionId));
    into.put("a1", hex(a1));
    into.put("a2", hex(a2));
    into.put("a3", hex(a3));
    into.put("steps", steps);
    into.put("split", fields("secretGameToRelay", hex(split.initiatorSecret()), "secretRelayToGame", hex(split.responderSecret()), "ivGameToRelay",
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

  // Epoch e's key, epoch 0's too: HKDF-Expand(the direction's 48-byte secret from Split, "AVPX epoch v2" || e as 4 bytes little-endian,
  // 32) (5.1, point 8). Written out here with Hkdf itself, so Channel's own epoch keys are held to the rule, not to themselves.
  private static List<Object> epochKeys(HandshakeA.Keys keys) {
    List<Object> out = new ArrayList<>();
    byte[] secret = keys.split().initiatorSecret();

    for (long e : new long[] {0, 1, 2, 4095}) {
      byte[] info = Channel.epochInfo(e);
      out.add(fields("secret", hex(secret), "epoch", e, "info", hex(info), "epochKey", hex(Hkdf.expand(secret, info, 32))));
    }

    return out;
  }

  // The bytes here go straight into Gcm.seal, and nothing of Java's draws on them, so they come from SeededRandom itself: plain bytes the
  // tests can repeat. (ScriptedRandom is for where Java's own code must be handed a SecureRandom, and a SecureRandom that repeats is,
  // rightly, what CodeQL calls a weak source of keys.) These are the very bytes ScriptedRandom.seeded(501) gave, draw for draw, when the
  // file was first made, so the file is the same; CryptoV2VectorsTest would fail if it weren't.
  private static List<Object> aesGcm() {
    List<Object> out = new ArrayList<>();
    SeededRandom r = SeededRandom.of(501);

    for (int size : new int[] {0, 64}) {
      byte[] key = r.next(32);
      byte[] nonce = r.next(12);
      byte[] aad = r.next(24);
      byte[] message = r.next(size);
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

  // Section 16's refusals, as bytes, each changed from a good datagram above in one way. 5 (a bad cookie) comes with the relay's cookie.
  private static List<Object> refusals(Map<String, Object> datagrams, List<Object> sealed) {
    HexFormat h = HexFormat.of();
    byte[] a1First = h.parseHex((String) ((List<?>) datagrams.get("a1")).get(0));
    List<?> a1Datagrams = (List<?>) datagrams.get("a1");
    byte[] a1Last = h.parseHex((String) a1Datagrams.get(a1Datagrams.size() - 1));
    byte[] gameSealed = h.parseHex((String) ((Map<?, ?>) sealed.get(0)).get("sealed"));
    List<Object> out = new ArrayList<>();
    out.add(refusal(1, "a handshake datagram of 1,199 bytes (A1's first, cut short)", Arrays.copyOf(a1First, 1199)));
    out.add(refusal(1, "a sealed control message of 103 bytes (the game's first, cut short)", Arrays.copyOf(gameSealed, 103)));
    out.add(refusal(2, "another magic: AVPQ", changed(a1First, 3, 'Q')));
    out.add(refusal(3, "another version: 3", changed(a1First, 4, 3)));
    out.add(refusal(4, "an unknown kind: 9", changed(a1First, 5, 9)));
    out.add(refusal(6, "a count of 0", changed(a1First, 7, 0)));
    out.add(refusal(6, "a count of 4, for a length that takes 5", changed(a1First, 7, 4)));
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
