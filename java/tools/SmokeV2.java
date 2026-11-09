package avpx.tools;

import avpx.Settings;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.list.Json;
import avpx.v2.Channel;
import avpx.v2.Fragments;
import avpx.v2.HandshakeA;
import avpx.v2.Identity;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

// The smoke test of an installed version 2 relay (CRYPTO.md), from outside its process, the way the game talks to it. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server. Smoke.java runs it, with --installed, when the machine's settings say "protocol": 2.
//
// WHAT IT CHECKS: the relay's control port answers A0; handshake A proves the relay (its static keys are the ones the settings hold); a
// whole game goes through it sealed (HOST_OPEN with no cookie round, JOIN, NEW_JOINER under the host's own session, both hellos, READY);
// 100 of the games' own sealed packets (AVPG) each way, and handshake B's datagrams (AVPE), pass through the joiner's port byte for byte;
// HOST_KEEP; and what must get no answer: version 1's messages, an A0 with a cookie, an A1 with a cookie that isn't the relay's, a sealed
// message sent twice, plaintext on a joiner's port. Version 2's list isn't built yet, so there are no list or log checks, and the
// output says so at its end.
//
// WHAT IT USES OF THE SERVER'S CODE: avpx.v2's game side (HandshakeA's writeA1 and readA2, Channel, Fragments), so as not to keep a
// third copy of the same steps. The 64-byte messages inside the seal are still written by hand (Smoke.msg), as in Smoke.java. And
// BEFORE ANY OF IT IS TRUSTED IT'S PINNED: run on test-vectors/crypto-v2.json's own inputs (built into this jar), it must make that
// file's handshake A byte for byte. That file is the one the game's own code is checked against, so a mistake the server's Java and
// this copy shared would show here. If the pin fails, nothing else runs.
final class SmokeV2 {
  private SmokeV2() {
  }

  private static final HexFormat HEX = HexFormat.of();

  // The two sides of a game, as the relay sees them: a socket, and its sealed channel once handshake A is done
  private record Player(DatagramSocket socket, Channel channel) {
  }

  // identities: the file --identities named (two players the owner approved), or null for none
  static void run(Settings settings, Path identities) throws Exception {
    String why = pin();
    Smoke.check(why == null, "the pin: this copy of version 2's game side makes crypto-v2.json's handshake A, byte for byte",
        why == null ? "" : why);

    if (why != null) {
      System.out.println("NOT RUN  the relay's checks: this copy of version 2's code doesn't give the known answers, so it can't"
          + " be trusted");
      return;
    }

    int control = settings.controlPort();
    int[] ports = settings.relayPorts();
    String region = settings.region();
    byte[] p384 = settings.staticKeys().p384Public();
    byte[] kem = settings.staticKeys().kemPublic();
    Identity[] players = identities == null ? null : SmokeIdentities.read(identities);

    if (identities != null && players == null) {
      Smoke.check(false, "the identities file " + identities + " holds two identities as --make-identities writes them");
      return;
    }

    try (DatagramSocket host = Smoke.udp(); DatagramSocket joiner = Smoke.udp(); DatagramSocket stranger = Smoke.udp()) {
      if (!relayAnswers(host, control)) {
        return;
      }

      // A player nobody approved, made here and now: the relay must give it nothing
      handshake(stranger, control, region, p384, kem, SmokeIdentities.fresh(), false, "a player nobody approved");

      if (players == null) {
        System.out.println("NOT RUN  the whole game through the relay: version 2 takes approved players only. Make two identities with"
            + " --make-identities <file>, send their requests with --installed --request-access <file>, have the owner approve the two"
            + " codes, then run with --installed --identities <file>.");
        return;
      }

      Player h = handshake(host, control, region, p384, kem, players[0], true, "the host");
      Player j = handshake(joiner, control, region, p384, kem, players[1], true, "the joiner");

      if (h == null || j == null) {
        return;
      }

      // The host opens a game: at once, with no cookie round inside the seal
      Smoke.Read opened = hear(h, say(h, control, Smoke.msg(Smoke.HOST_OPEN)));
      Smoke.check(opened.type() == Smoke.HOST_OPENED && !Smoke.allZero(opened.pass())
          && Arrays.equals(opened.pass(), Smoke.passFor(settings.passKey(), region, opened.code(), opened.passTime())),
          "a sealed HOST_OPEN gets a sealed HOST_OPENED at once, with this relay's own pass for region " + region);
      byte[] token = opened.secret();
      String code = opened.code();

      // A joiner joins
      Smoke.Read joined = hear(j, say(j, control, Smoke.msg(Smoke.JOIN, null, code, 0, 0)));
      Smoke.check(joined.type() == Smoke.JOIN_PORT && joined.port() >= ports[0] && joined.port() <= ports[ports.length - 1],
          "a sealed JOIN gets a sealed JOIN_PORT, with a ticket and a relay port", "port " + joined.port());
      int port = joined.port();

      // The joiner's sealed hello claims its port, and only then does the host hear of it, under its own session (PROTOCOL.md section 2)
      Smoke.send(j.socket(), port, j.channel().seal(Smoke.msg(Smoke.JOINER_HELLO, joined.secret(), null, 0, 0), System.currentTimeMillis()));
      Smoke.Read note = hear(h, Smoke.next(host, 1000));
      Smoke.check(note.type() == Smoke.NEW_JOINER && note.port() == joined.port() && Arrays.equals(note.secret(), token),
          "the joiner's hello claims its port, and the host hears NEW_JOINER, sealed under its own session");

      // The host's hello, sealed, on the joiner's port: READY goes to the joiner
      Smoke.send(host, port, h.channel().seal(Smoke.msg(Smoke.HOST_HELLO, token, null, port, 0), System.currentTimeMillis()));
      Smoke.Got ready = Smoke.next(j.socket(), 1000);
      Smoke.check(ready != null && ready.fromPort() == port && hear(j, ready).type() == Smoke.READY,
          "both hellos, sealed, and a sealed READY comes to the joiner from its port");

      gamePackets(joiner, host, port, "joiner to host");
      gamePackets(host, joiner, port, "host to joiner");

      byte[] b = Fragments.cut(Fragments.hostToJoiner(), 16, Smoke.random(8), new byte[16], Smoke.random(1713)).get(0);
      Smoke.send(joiner, port, b);
      Smoke.Got passed = Smoke.next(host, 1000);
      Smoke.check(passed != null && Arrays.equals(passed.data(), b) && passed.fromPort() == port,
          "a handshake B datagram (AVPE, 1,200 bytes) goes through the joiner's port byte for byte");

      // Keep, and a keep sent twice
      byte[] keep = h.channel().seal(Smoke.msg(Smoke.HOST_KEEP, token, null, 0, 0), System.currentTimeMillis());
      Smoke.Read kept = hear(h, Smoke.ask(host, control, keep));
      Smoke.check(kept.type() == Smoke.HOST_KEPT && kept.number() == 1 && !Smoke.allZero(kept.pass()),
          "a sealed HOST_KEEP: HOST_KEPT, 1 joiner");
      Smoke.send(host, control, keep);
      Smoke.check(Smoke.next(host, 500) == null, "the same sealed HOST_KEEP again gets no answer: a sealed message is taken once");

      hostile(stranger, joiner, host, control, port);

      // The end of the game
      say(h, control, Smoke.msg(Smoke.HOST_CLOSE, token, null, 0, 0));
      Smoke.pause(100);
      Smoke.Read after = hear(j, say(j, control, Smoke.msg(Smoke.JOIN, null, code, 0, 0)));
      Smoke.check(after.type() == Smoke.REFUSED && after.number() == 1, "after HOST_CLOSE, a sealed JOIN gets a sealed REFUSED 1");
      Smoke.check(Smoke.notLoopback == 0, "every packet came from 127.0.0.1");
    }

    System.out.println("NOT RUN  the list's games checks and the log's: on a version 2 machine Smoke reaches the list only through"
        + " --request-access. This is a run of the relay's version 2 checks.");
  }

  // ----- The pin

  private static byte[] hex(Object field) {
    return HEX.parseHex((String) field);
  }

  // Null if this copy of the game side makes crypto-v2.json's handshake A from that file's own inputs, byte for byte; else why not
  private static String pin() {
    try (InputStream in = SmokeV2.class.getResourceAsStream("crypto-v2.json")) {
      if (in == null) {
        return "crypto-v2.json isn't in this jar";
      }

      Map<String, Object> top = Json.readObject(in.readAllBytes(), 5);
      Map<String, Object> a = Json.object(top.get("handshakeA"));
      Map<String, Object> relay = Json.object(a.get("relayStatic"));
      Map<String, Object> game = Json.object(a.get("gameEphemeral"));
      Map<String, Object> playerFields = Json.object(a.get("player"));
      KeyPair e = P384.pair(hex(game.get("p384Private")), hex(game.get("p384Public")));
      KeyPair ek = MlKem.fromSeed(hex(game.get("mlkemSeed")));
      KeyPair s = P384.pair(hex(playerFields.get("p384Private")), hex(playerFields.get("p384Public")));
      KeyPair sk = MlKem.fromSeed(hex(playerFields.get("mlkemSeed")));

      if (e == null || ek == null || s == null || sk == null) {
        return "the file's game keys don't load";
      }

      HandshakeA.Initiator initiator = HandshakeA.writeA1((String) a.get("region"), hex(relay.get("p384Public")),
          hex(relay.get("mlkemPublic")), Identity.of(s, sk), e, ek, hex(Json.object(a.get("skem")).get("m")));

      if (!Arrays.equals(initiator.a1(), hex(a.get("a1")))) {
        return "A1 differs from the file's";
      }

      HandshakeA.Initiator.Done done = initiator.readA2(hex(a.get("a2")));

      if (done == null || !Arrays.equals(done.a3(), hex(a.get("a3")))) {
        return "A3 differs from the file's";
      }

      HandshakeA.Keys keys = done.keys();

      if (!Arrays.equals(keys.transcript(), hex(a.get("transcript"))) || !Arrays.equals(keys.sessionId(), hex(a.get("sessionId")))) {
        return "the transcript or the session id differs from the file's";
      }

      // The keys and IVs each way, held by what they do: the game's first sealed message must seal to the file's, byte for byte, and the
      // relay's first must open to the file's message (so Channel is pinned too)
      Channel channel = Channel.gameSide(keys, 0);
      Map<String, Object> fromGame = Json.object(Json.list(top.get("sealed")).get(0));
      Map<String, Object> fromRelay = Json.object(Json.list(top.get("sealed")).get(1));
      boolean seals = Arrays.equals(channel.seal(hex(fromGame.get("message")), 0), hex(fromGame.get("sealed")));
      boolean opens = Arrays.equals(channel.open(hex(fromRelay.get("sealed")), 0), hex(fromRelay.get("message")));
      return seals && opens ? null : "the sealed channel's keys differ from the file's";
    } catch (IOException | Json.Bad | RuntimeException e) {
      return "the pin couldn't be run: " + e.getClass().getSimpleName();
    }
  }

  // ----- The relay

  // A0 asked until it's answered, up to 15 s, so a relay that's still starting gets its time
  private static boolean relayAnswers(DatagramSocket s, int control) throws IOException {
    long until = System.nanoTime() + 15_000_000_000L;
    boolean answered = false;

    while (!answered && System.nanoTime() < until) {
      byte[] id = Smoke.random(8);
      Smoke.Got back = Smoke.ask(s, control, a0(id));
      answered = back != null && back.data().length == 64 && back.fromPort() == control && Arrays.equals(Arrays.copyOfRange(back.data(), 8,
          16), id);
    }

    Smoke.check(answered, "the relay answers A0 with a COOKIE of 64 bytes, for 1,200, from its control port");
    return answered;
  }

  private static byte[] a0(byte[] id) {
    return Fragments.cut(Fragments.toRelay(), 1, id, new byte[16], new byte[0]).get(0);
  }

  // Handshake A, datagram by datagram, as player. approved says whether the relay should take this player (CRYPTO.md section 6). If it
  // should: the player's side, once the relay has proved itself, or null. If not: the check is that nothing at all comes back (refusal
  // 22 is answered with nothing), and it gives null.
  private static Player handshake(DatagramSocket s, int control, String region, byte[] p384, byte[] kem, Identity player, boolean approved,
      String who) throws IOException {
    byte[] id = Smoke.random(8);
    Smoke.Got cookieAnswer = Smoke.ask(s, control, a0(id));

    if (cookieAnswer == null || cookieAnswer.data().length != 64) {
      Smoke.check(false, "handshake A for " + who, "no COOKIE");
      return null;
    }

    byte[] cookie = Arrays.copyOfRange(cookieAnswer.data(), 16, 32);
    HandshakeA.Initiator game = HandshakeA.writeA1(region, p384, kem, player, new SecureRandom());

    for (byte[] d : Fragments.cut(Fragments.toRelay(), 3, id, cookie, game.a1())) {
      Smoke.send(s, control, d);
    }

    List<Smoke.Got> got = new ArrayList<>();

    for (int i = 0; i < 3; i++) {
      Smoke.Got g = Smoke.next(s, 2000);

      if (g == null) {
        break;
      }

      got.add(g);
    }

    if (!approved) {
      Smoke.check(got.isEmpty(), "handshake A for " + who + ": no A2, and no answer at all (refusal 22, answered with nothing)");
      return null;
    }

    HandshakeA.Initiator.Done done = null;
    Fragments.Assembly a2 = null;

    for (Smoke.Got g : got) {
      Fragments.Fragment f = g.data().length == 1200 ? Fragments.read(Fragments.toRelay(), g.data()) : null;

      if (f == null || (a2 == null ? !(a2 = new Fragments.Assembly(f)).add(f) : !a2.add(f))) {
        a2 = null;
        break;
      }
    }

    if (got.size() == 3 && a2 != null && a2.complete()) {
      done = game.readA2(a2.message());
    }

    Smoke.check(done != null, "handshake A for " + who
        + ": A2 in 3 datagrams of 1,200, for A1's 5, and the relay proves its static keys are the installed ones");

    if (done == null) {
      return null;
    }

    Smoke.send(s, control, Fragments.cut(Fragments.toRelay(), 5, id, cookie, done.a3()).get(0));
    return new Player(s, Channel.gameSide(done.keys(), System.currentTimeMillis()));
  }

  private static Smoke.Got say(Player p, int port, byte[] message) throws IOException {
    return Smoke.ask(p.socket(), port, p.channel().seal(message, System.currentTimeMillis()));
  }

  // The message in a sealed answer, opened by the player it's for, or an empty one (type 0) if nothing came or it doesn't open
  private static Smoke.Read hear(Player p, Smoke.Got got) {
    boolean sealed = got != null && got.data().length == Channel.SEALED_BYTES;
    byte[] message = sealed ? p.channel().open(got.data(), System.currentTimeMillis()) : null;
    return Smoke.readOrNothing(message == null ? null : new Smoke.Got(message, got.fromPort()));
  }

  // 100 of the games' own sealed packets (AVPG), of many sizes, through the joiner's port, each to arrive byte for byte from it
  private static void gamePackets(DatagramSocket from, DatagramSocket to, int port, String way) throws IOException {
    Set<String> sent = new HashSet<>();

    for (int i = 0; i < 100; i++) {
      byte[] p = Smoke.random(28 + (i * 13) % 1372);
      System.arraycopy("AVPG".getBytes(StandardCharsets.US_ASCII), 0, p, 0, 4);
      p[4] = (byte) i;
      sent.add(HEX.formatHex(p));
      Smoke.send(from, port, p);
    }

    int same = 0;
    int fromPort = 0;

    for (int k = 0; k < 100; k++) {
      Smoke.Got got = Smoke.next(to, 2000);

      if (got == null) {
        break;
      }

      same += sent.remove(HEX.formatHex(got.data())) ? 1 : 0;
      fromPort += got.fromPort() == port ? 1 : 0;
    }

    Smoke.check(same == 100 && fromPort == 100, "100 sealed game packets " + way + ", every one byte for byte, from the joiner's port",
        same + " same, " + fromPort + " from port " + port);
  }

  // What must get no answer, and reach nobody
  private static void hostile(DatagramSocket stranger, DatagramSocket joiner, DatagramSocket host, int control, int port)
      throws IOException {
    Smoke.send(stranger, control, Smoke.msg(Smoke.HOST_OPEN));
    Smoke.send(stranger, control, Smoke.msg(Smoke.ECHO, Smoke.random(16), null, 0, 1));
    byte[] withCookie = a0(Smoke.random(8));
    withCookie[20] = 1;
    Smoke.send(stranger, control, withCookie);
    // An A1 datagram with a cookie the relay didn't make: refused before anything in it is read, so what it holds doesn't matter
    byte[] badCookie = Fragments.cut(Fragments.toRelay(), 3, Smoke.random(8), Smoke.random(16), new byte[HandshakeA.A1_BYTES]).get(0);
    Smoke.send(stranger, control, badCookie);
    Smoke.check(Smoke.next(stranger, 500) == null,
        "version 1's HOST_OPEN and ECHO, an A0 with a cookie, and an A1 with a cookie that isn't the relay's: no answer to any");
    Smoke.send(stranger, port, "plaintext on the joiner's port".getBytes(StandardCharsets.US_ASCII));
    Smoke.send(joiner, port, "plaintext from the joiner itself".getBytes(StandardCharsets.US_ASCII));
    Smoke.check(Smoke.next(host, 500) == null && Smoke.next(joiner, 300) == null,
        "plaintext on the joiner's port, even from the joiner itself, reaches nobody");
  }
}
