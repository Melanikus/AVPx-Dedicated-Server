package avpx.v2;

import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
      HandshakeA.Initiator initiator = HandshakeA.writeA1((String) a.get("region"), bytes(relay.get("p384Public")),
          bytes(relay.get("mlkemPublic")), P384.pair(bytes(game.get("p384Private")), bytes(game.get("p384Public"))),
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

      // A1's three datagrams, read and put together, are A1
      List<Object> a1 = Json.list(datagrams.get("a1"));
      Fragments.Assembly assembly = new Fragments.Assembly(Fragments.read(Fragments.toRelay(), bytes(a1.get(0))));

      for (Object d : a1) {
        ok(assembly.add(Fragments.read(Fragments.toRelay(), bytes(d))), "an A1 datagram is taken");
      }

      same(assembly.message(), bytes(handshake.get("a1")), "A1's datagrams make A1");

      // The keys, as the file gives them, open the sealed messages it gives, each way
      Map<String, Object> split = object(handshake.get("split"));
      HandshakeA.Keys keys = new HandshakeA.Keys(new Noise.Split(bytes(split.get("keyGameToRelay")), bytes(split.get("keyRelayToGame")),
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
  }
}
