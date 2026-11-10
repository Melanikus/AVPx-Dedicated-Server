package avpx.v2;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

// The tests of test-vectors/crypto-v2.json (CRYPTO.md section 15; 5.1, point 14): that it's exactly what the server's code makes now,
// and that what it holds works the way a reader of it (the game's tests) will use it. Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server.
public final class CryptoV2VectorsTest {
  private CryptoV2VectorsTest() {
  }

  // The top object (1), its sections (2), their cases (3), a case's fields that are lists or objects (4), and their entries (5)
  private static final int DEPTH = 5;

  // The vectors' player's id, made with OpenSSL (the test below says how): the whole SHA-384, which a machine compares
  private static final String PLAYER_ID = "85bb99fe0a831ed599a1062c95c414a17aaa0dd182177bffc7e631c0c9fdd866de2bb4b45084132a6183347245c5a430";

  private static byte[] bytes(Object hex) {
    return HexFormat.of().parseHex((String) hex);
  }

  private static Map<String, Object> object(Object value) {
    return Json.object(value);
  }

  public static void register() {
    // What Smoke's pin (java/tools/SmokeV2.java) does on an installed machine, here on every test run: the game side, given the file's
    // own inputs (keys as numbers and seeds, m), makes the file's handshake A, and its keys seal and open the file's first messages
    test("from crypto-v2.json's own inputs, the game side makes its A1, A3, transcript and first sealed messages (Smoke's pin)", () -> {
      Map<String, Object> top = Json.readObject(Files.readAllBytes(CryptoV2Vectors.FILE), DEPTH);
      Map<String, Object> a = object(top.get("handshakeA"));
      Map<String, Object> game = object(a.get("gameEphemeral"));
      Map<String, Object> relay = object(a.get("relayStatic"));
      Map<String, Object> playerFields = object(a.get("player"));
      Identity player = Identity.of(P384.pair(bytes(playerFields.get("p384Private")), bytes(playerFields.get("p384Public"))),
          MlKem.fromSeed(bytes(playerFields.get("mlkemSeed"))));
      same(player.fingerprint(), bytes(playerFields.get("fingerprint")), "the player's fingerprint, from their two public keys");
      HandshakeA.Initiator initiator = HandshakeA.writeA1((String) a.get("region"), bytes(relay.get("p384Public")),
          bytes(relay.get("mlkemPublic")), player, P384.pair(bytes(game.get("p384Private")), bytes(game.get("p384Public"))),
          MlKem.fromSeed(bytes(game.get("mlkemSeed"))), bytes(object(a.get("skem")).get("m")));
      same(initiator.a1(), bytes(a.get("a1")), "A1, byte for byte");
      HandshakeA.Initiator.Done done = initiator.readA2(bytes(a.get("a2")));
      same(done.a3(), bytes(a.get("a3")), "A3");
      same(done.keys().transcript(), bytes(a.get("transcript")), "the transcript");
      Channel channel = Channel.gameSide(done.keys(), 0);
      Map<String, Object> fromGame = object(Json.list(top.get("sealed")).get(0));
      Map<String, Object> fromRelay = object(Json.list(top.get("sealed")).get(1));
      same(channel.seal(bytes(fromGame.get("message")), 0), bytes(fromGame.get("sealed")), "the game's first sealed message");
      same(channel.open(bytes(fromRelay.get("sealed")), 0), bytes(fromRelay.get("message")), "and the relay's, opened");
    });

    test("test-vectors/crypto-v2.json is exactly what the server's code makes now, byte for byte (5.1, point 14)", () -> {
      String made = CryptoV2Vectors.make();
      String file = Files.readString(CryptoV2Vectors.FILE, StandardCharsets.US_ASCII);

      if (!file.equals(made)) {
        String[] want = made.split("\n", -1);
        String[] have = file.split("\n", -1);
        int line = 0;

        while (line < want.length && line < have.length && want[line].equals(have[line])) {
          line++;
        }

        ok(false, "the file differs from what the code makes, first at line " + (line + 1) + "; if the change is meant, make it again:"
            + " cd java; java -cp build/test avpx.v2.CryptoV2Vectors");
      }
    });

    test("crypto-v2.json, read as the game will read it: its datagrams make A1, its keys open its sealed messages, its refusals are refused", () -> {
      Map<String, Object> top = Json.readObject(Files.readAllBytes(CryptoV2Vectors.FILE), DEPTH);
      Map<String, Object> handshake = object(top.get("handshakeA"));
      Map<String, Object> datagrams = object(top.get("handshakeDatagrams"));

      // A1's five datagrams, read and put together, are A1
      List<Object> a1 = Json.list(datagrams.get("a1"));
      same(a1.size(), 5, "A1 is 5 datagrams");
      Fragments.Assembly assembly = new Fragments.Assembly(Fragments.read(Fragments.toRelay(), bytes(a1.get(0))));

      for (Object d : a1) {
        ok(assembly.add(Fragments.read(Fragments.toRelay(), bytes(d))), "an A1 datagram is taken");
      }

      same(assembly.message(), bytes(handshake.get("a1")), "A1's datagrams make A1");

      // The keys, as the file gives them, open the sealed messages it gives, each way
      Map<String, Object> split = object(handshake.get("split"));
      HandshakeA.Keys keys = new HandshakeA.Keys(new Noise.Split(bytes(split.get("secretGameToRelay")), bytes(split.get("secretRelayToGame")),
          bytes(split.get("ivGameToRelay")), bytes(split.get("ivRelayToGame"))), bytes(handshake.get("sessionId")),
          bytes(handshake.get("transcript")));
      Channel relay = Channel.relaySide(keys, 0);
      Channel game = Channel.gameSide(keys, 0);

      for (Object item : Json.list(top.get("sealed"))) {
        Map<String, Object> s = object(item);
        Channel opener = s.get("from").equals("game") ? relay : game;
        same(opener.open(bytes(s.get("sealed")), 0), bytes(s.get("message")), "the sealed message from the " + s.get("from") + " at counter "
            + s.get("counter"));
      }

      // Every refusal is refused: a handshake datagram by Fragments.read (or, for an unknown kind, by its kind), a sealed message by Channel
      Channel fresh = Channel.relaySide(keys, 0);
      int refused = 0;

      for (Object item : Json.list(top.get("refusals"))) {
        Map<String, Object> r = object(item);
        byte[] b = bytes(r.get("bytes"));
        long number = (Long) r.get("refusal");
        String what = "refusal " + number + ", " + r.get("what");

        if (b.length == Channel.SEALED_BYTES || b.length == Channel.SEALED_BYTES - 1) {
          if (number == 9) {
            ok(fresh.open(b, 0) != null, what + ": the first time, it's taken");
          }

          same(fresh.open(b, 0), null, what);
        } else if (number == 4) {
          Fragments.Fragment f = Fragments.read(Fragments.toRelay(), b);
          ok(f != null && (f.kind() < 1 || f.kind() > 5) && f.kind() != Channel.KIND, what + ": a fragment of a kind no step has");
        } else {
          same(Fragments.read(Fragments.toRelay(), b), null, what);
        }

        refused++;
      }

      same(refused, 12, "12 refusals, every one checked");

      // Handshake B: its datagrams make B1 to B5 again, and its check code is the one its transcript gives
      Map<String, Object> b = object(top.get("handshakeB"));
      Map<String, Object> bDatagrams = object(b.get("datagrams"));

      for (int i = 1; i <= 5; i++) {
        List<Object> parts = Json.list(bDatagrams.get("b" + i));
        Fragments.Assembly message = new Fragments.Assembly(Fragments.read(Fragments.hostToJoiner(), bytes(parts.get(0))));

        for (Object d : parts) {
          ok(message.add(Fragments.read(Fragments.hostToJoiner(), bytes(d))), "a B" + i + " datagram is taken");
        }

        same(message.message(), bytes(b.get("b" + i)), "B" + i + "'s datagrams make B" + i);
      }

      same(HandshakeB.checkCode(bytes(b.get("transcript"))), b.get("checkCode"), "B's check code, from its transcript");
      same(HandshakeB.fingerprint(bytes(object(b.get("host")).get("p384Public")), bytes(object(b.get("host")).get("mlkemPublic"))),
          bytes(object(b.get("host")).get("fingerprint")), "the host's fingerprint, from its two public keys");
    });

    test("a relay's id (CRYPTO.md 12.1) is the one hashes made outside Java give, the game's among them, and only from keys of the right "
        + "sizes", () -> {
      Map<String, Object> top = Json.readObject(Files.readAllBytes(CryptoV2Vectors.FILE), DEPTH);
      Map<String, Object> relay = object(object(top.get("handshakeA")).get("relayStatic"));
      byte[] p384 = bytes(relay.get("p384Public"));
      byte[] kem = bytes(relay.get("mlkemPublic"));
      // Made with OpenSSL, from the bytes "AVPX relay keys v2" then the two keys from the file (2026-11-09):
      //   { printf 'AVPX relay keys v2'; printf '%s%s' "$p384Public" "$mlkemPublic" | xxd -r -p; } | openssl dgst -sha384
      // and the very same by Fifth, with node's crypto, for the game's own test of its relaykey setting (relay-v2-step7 c2aaf06f)
      same(RelayId.of(p384, kem), "fc352802066e547c261e37fe63f114863debbc76b5b29575ab69af80c72eeb91dd9a9dddd8b38218b21df00b4bea5a54",
          "the vectors' relay's id: all 48 bytes");
      byte[] other = p384.clone();
      other[96] ^= 1;
      ok(!RelayId.of(other, kem).equals(RelayId.of(p384, kem)), "a key with one bit changed has another id");
      ok(!RelayId.of(p384, kem).equals(Identity.idHex(p384, kem)),
          "and it isn't a player's id of the same keys: the words in front keep the two apart");
      throwsWith(() -> RelayId.of(Arrays.copyOf(p384, 96), kem), "97 and 1,568 bytes", "a P-384 key of 96 bytes");
      throwsWith(() -> RelayId.of(p384, Arrays.copyOf(kem, 1569)), "97 and 1,568 bytes", "an ML-KEM key of 1,569 bytes");
      throwsWith(() -> RelayId.of(null, kem), "97 and 1,568 bytes", "no P-384 key");
    });

    test("a player's id is the whole SHA-384 its fingerprint is the first 16 bytes of, as hashed outside Java", () -> {
      Map<String, Object> top = Json.readObject(Files.readAllBytes(CryptoV2Vectors.FILE), DEPTH);
      Map<String, Object> player = object(object(top.get("handshakeA")).get("player"));
      byte[] p384 = bytes(player.get("p384Public"));
      byte[] kem = bytes(player.get("mlkemPublic"));
      String id = Identity.idHex(p384, kem);
      same(id.length(), 96, "96 hex digits");
      same(id.substring(0, 32), player.get("fingerprint"), "its first 32 are the fingerprint the file gives");
      // Made with OpenSSL, from "AVPX-ID-2" then the player's two keys from the file (2026-11-09):
      //   { printf 'AVPX-ID-2'; printf '%s%s' "$p384Public" "$mlkemPublic" | xxd -r -p; } | openssl dgst -sha384
      same(id, PLAYER_ID, "the whole of it, as OpenSSL makes it");
    });
  }
}
