package avpx.relay;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.hex;
import static avpx.testing.Tests.latin1;
import static avpx.testing.Tests.matches;
import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.text;
import static avpx.testing.Tests.throwsWith;

import avpx.relay.Protocol.Type;
import avpx.relay.Protocol.Why;
import avpx.relay.RelayCore.Out;
import avpx.relay.RelayCore.Slot;
import avpx.testing.SeededRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

// The tests of RelayCore.java: a game's whole life through the relay, and every refusal and limit in PROTOCOL.md, by handing it packets.
// No socket is opened. Written 2026-11-08 by Melanikus for AVPx Dedicated Server, ported test for test from test/core.test.js.
public final class CoreTest {
  private CoreTest() {
  }

  // Someone sending to the relay: an address and a port
  private record Who(String address, int port) {
  }

  // A packet the relay sent, with the message it holds read back (null if it isn't one)
  private record Got(int from, String address, int port, byte[] data, Message m) {
  }

  private record Opened(byte[] token, byte[] code, byte[] pass, long passTime) {
  }

  private record Connected(Opened game, int port, byte[] ticket) {
  }

  private static final int CONTROL = 27500;
  private static final int[] PORTS = {27501, 27502, 27503};
  private static final Who HOST = new Who("198.51.100.10", 40000);
  private static final Who JOINER = new Who("203.0.113.20", 50000);
  private static final Who STRANGER = new Who("192.0.2.30", 60000);
  private static final String REGION = "virginia";
  private static final byte[] KEY = bytes(32, 0x5a);

  private static RelayCore relay() {
    return relay(limits -> { });
  }

  private static RelayCore relay(Consumer<RelayCore.Limits> change) {
    RelayCore.Limits limits = new RelayCore.Limits();
    change.accept(limits);
    return new RelayCore(CONTROL, PORTS, REGION, KEY, SeededRandom.of(3), limits, 0);
  }

  // A relay with as many joiner ports as a test needs (27501 on), and the starting limits
  private static RelayCore relayWithPorts(int count) {
    int[] ports = new int[count];

    for (int i = 0; i < count; i++) {
      ports[i] = 27501 + i;
    }

    return new RelayCore(CONTROL, ports, REGION, KEY, SeededRandom.of(3), new RelayCore.Limits(), 0);
  }

  private static List<Out> send(RelayCore r, int to, Who from, Message msg, long now) {
    return r.receive(to, from.address(), from.port(), Protocol.encode(msg), now);
  }

  private static List<Out> send(RelayCore r, int to, Who from, Message msg) {
    return send(r, to, from, msg, 0);
  }

  // A packet that isn't one of the relay's messages, such as a game's own
  private static List<Out> sendRaw(RelayCore r, int to, Who from, byte[] data, long now) {
    return r.receive(to, from.address(), from.port(), data, now);
  }

  private static List<Out> sendRaw(RelayCore r, int to, Who from, byte[] data) {
    return sendRaw(r, to, from, data, 0);
  }

  private static Got got(Out o) {
    return new Got(o.from(), o.address(), o.port(), o.data(), Protocol.decode(o.data()));
  }

  private static Got only(List<Out> out) {
    same(out.size(), 1, "one packet out, not " + out.size());
    return got(out.get(0));
  }

  private static List<Object> where(Got g) {
    return List.of(g.address(), g.port());
  }

  private static List<Object> where(Who w) {
    return List.of(w.address(), w.port());
  }

  private static boolean has(int[] ports, int port) {
    for (int p : ports) {
      if (p == port) {
        return true;
      }
    }

    return false;
  }

  private static Who who(String address, int port) {
    return new Who(address, port);
  }

  // Opens a game the whole way, cookie and all: gives back its token and code
  private static Opened openGame(RelayCore r, Who from, long now) {
    Got cookie = only(send(r, CONTROL, from, Message.of(Type.HOST_OPEN), now));
    same(cookie.m().type(), Type.COOKIE, "a cookie first");
    Got opened = only(send(r, CONTROL, from, Message.of(Type.HOST_OPEN).secret(cookie.m().secret()), now));
    same(opened.m().type(), Type.HOST_OPENED, "then the game");
    return new Opened(opened.m().secret(), opened.m().code(), opened.m().pass(), opened.m().passTime());
  }

  private static Opened openGame(RelayCore r) {
    return openGame(r, HOST, 0);
  }

  // A joiner asks to join, cookie and all: gives back what the relay sent (the answer to the joiner, and the note to the host)
  private static List<Got> join(RelayCore r, byte[] code, Who from, long now) {
    Got cookie = only(send(r, CONTROL, from, Message.of(Type.JOIN).code(code), now));
    same(cookie.m().type(), Type.COOKIE, "a cookie first");
    List<Got> out = new ArrayList<>();

    for (Out o : send(r, CONTROL, from, Message.of(Type.JOIN).secret(cookie.m().secret()).code(code), now)) {
      out.add(got(o));
    }

    return out;
  }

  private static List<Got> join(RelayCore r, byte[] code, Who from) {
    return join(r, code, from, 0);
  }

  private static List<Got> join(RelayCore r, byte[] code) {
    return join(r, code, JOINER, 0);
  }

  // A game with one joiner connected, both hellos said: gives back the game, the joiner's port and its ticket
  private static Connected connected(RelayCore r, long now) {
    Opened game = openGame(r, HOST, now);
    Got toJoiner = join(r, game.code(), JOINER, now).get(0);
    int port = toJoiner.m().port();
    send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port), now);
    Got ready = only(send(r, port, JOINER, Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret()), now));
    same(ready.m().type(), Type.READY, "READY once both have said hello");
    return new Connected(game, port, toJoiner.m().secret());
  }

  private static Connected connected(RelayCore r) {
    return connected(r, 0);
  }

  private static Message keep(byte[] token) {
    return Message.of(Type.HOST_KEEP).secret(token);
  }

  public static void register() {
    test("a game's whole life: open, join, the joiner's hello, NEW_JOINER, the host's hello, READY, packets both ways", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      ok(Protocol.isCode(game.code()) && game.token().length == 16, "a code and a token");

      List<Got> out = join(r, game.code());
      same(out.size(), 1, "one packet out: the host isn't told of a JOIN alone");
      Got toJoiner = out.get(0);
      same(toJoiner.m().type(), Type.JOIN_PORT, "JOIN_PORT");
      ok(has(PORTS, toJoiner.m().port()), "one of the relay's ports");
      same(toJoiner.m().code(), game.code(), "the game's code");
      same(where(toJoiner), where(JOINER), "to the joiner");

      // The joiner's hello claims its port, and only then is the host told
      int port = toJoiner.m().port();
      Got toHost = only(send(r, port, JOINER, Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret())));
      same(toHost.m().type(), Type.NEW_JOINER, "NEW_JOINER");
      same(toHost.from(), CONTROL, "from the control port, where the host hears the relay");
      same(where(toHost), where(HOST), "to the host");
      same(toHost.m().port(), port, "the same port");
      same(toHost.m().secret(), game.token(), "the note to the host carries its token, so the host knows it came from the relay");

      Got ready = only(send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port)));
      same(ready.m().type(), Type.READY, "READY, once the host has said hello too");
      same(where(ready), where(JOINER), "to the joiner");
      same(ready.from(), port, "READY comes from the joiner's own port");

      byte[] up = latin1("a game packet from the joiner");
      Got forwardedUp = only(sendRaw(r, port, JOINER, up));
      same(List.of(forwardedUp.from(), forwardedUp.address(), forwardedUp.port()), List.of(port, HOST.address(), HOST.port()), "to the host");
      same(forwardedUp.data(), up, "passed on unchanged");
      byte[] down = latin1("and one from the host");
      Got forwardedDown = only(sendRaw(r, port, HOST, down));
      same(List.of(forwardedDown.from(), forwardedDown.address(), forwardedDown.port()), List.of(port, JOINER.address(), JOINER.port()),
          "to the joiner");
      same(forwardedDown.data(), down, "passed on unchanged");
    });

    test("the host's hello can come first, and the joiner's then gets READY, with no NEW_JOINER", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      Got toJoiner = join(r, game.code()).get(0);
      int port = toJoiner.m().port();
      same(send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port)).size(), 0, "the host's hello alone: nothing");
      Got ready = only(send(r, port, JOINER, Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret())));
      same(ready.m().type(), Type.READY, "READY, and nothing to the host, which is there already");
      same(where(ready), where(JOINER), "to the joiner");
    });

    test("NEW_JOINER goes again, at most once a second, while the claimed port waits for its host", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      Got toJoiner = join(r, game.code()).get(0);
      int port = toJoiner.m().port();
      Message hello = Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret());
      same(only(send(r, port, JOINER, hello, 0)).m().type(), Type.NEW_JOINER, "the first hello: the host is told");
      same(send(r, port, JOINER, hello, 500).size(), 0, "half a second on: not again yet");
      same(only(send(r, port, JOINER, hello, 1000)).m().type(), Type.NEW_JOINER, "a second on: again, in case the first was lost");
      send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port), 1200);
      same(only(send(r, port, JOINER, hello, 2500)).m().type(), Type.READY, "once the host is there: READY, never NEW_JOINER");
    });

    test("the same JOIN again, from the same address and port, gets the same port and ticket, and never a second port", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      Got first = join(r, game.code(), JOINER, 0).get(0);
      List<Got> again = join(r, game.code(), JOINER, 1000);
      same(again.size(), 1, "one answer");
      same(List.of(again.get(0).m().type(), again.get(0).m().port()), List.of(Type.JOIN_PORT, first.m().port()), "JOIN_PORT, the same port");
      same(again.get(0).m().secret(), first.m().secret(), "and the same ticket");
      same(r.free.size(), PORTS.length - 1, "one port taken, not two");

      Got other = join(r, game.code(), who(JOINER.address(), JOINER.port() + 1), 1000).get(0);
      notSame(other.m().port(), first.m().port(), "from another port of the same address, it's another joiner: another port");
    });

    test("a sender waits on at most 2 unclaimed ports; a third JOIN gets no answer, and the game's joins aren't spent", () -> {
      RelayCore r = relayWithPorts(8);
      Opened game = openGame(r);
      Who sender = who("192.0.2.66", 7000);
      same(join(r, game.code(), sender, 0).get(0).m().type(), Type.JOIN_PORT, "the first");
      same(join(r, game.code(), who(sender.address(), 7001), 0).get(0).m().type(), Type.JOIN_PORT, "the second");
      Got cookie = only(send(r, CONTROL, who(sender.address(), 7002), Message.of(Type.JOIN).code(game.code()), 0));
      same(send(r, CONTROL, who(sender.address(), 7002), Message.of(Type.JOIN).secret(cookie.m().secret()).code(game.code()), 0).size(), 0,
          "the third: dropped, unanswered, so the joiner's game asks again");
      same(r.games.get(new String(game.code(), java.nio.charset.StandardCharsets.US_ASCII)).joinLimit.take(0), true,
          "the game's join rate still has room");

      r.tick(5000);
      same(join(r, game.code(), who(sender.address(), 7002), 5000).get(0).m().type(), Type.JOIN_PORT, "once those two are freed, it gets in");
    });

    test("a sender holds at most 8 ports in all, claimed or not", () -> {
      RelayCore r = relayWithPorts(12);
      Opened one = openGame(r, HOST, 0);
      Opened two = openGame(r, who("198.51.100.11", 40000), 0);
      Who sender = who("192.0.2.66", 7000);

      for (int i = 0; i < 8; i++) {
        Got port = join(r, (i % 2 == 0 ? one : two).code(), who(sender.address(), 7000 + i), i * 1000L).get(0);
        send(r, port.m().port(), who(sender.address(), 7000 + i), Message.of(Type.JOINER_HELLO).secret(port.m().secret()), i * 1000L);
      }

      Got ninth = join(r, one.code(), who(sender.address(), 7100), 9000).get(0);
      same(List.of(ninth.m().type(), ninth.m().number()), List.of(Type.REFUSED, Why.BUSY), "the ninth is refused: busy");
      same(join(r, one.code(), JOINER, 9000).get(0).m().type(), Type.JOIN_PORT, "another address still gets in");
    });

    test("a lost READY is sent again when the joiner says hello again", () -> {
      RelayCore r = relay();
      Connected c = connected(r);
      Got again = only(send(r, c.port(), JOINER, Message.of(Type.JOINER_HELLO).secret(c.ticket())));
      same(again.m().type(), Type.READY, "READY again");
    });

    test("opening and joining need a cookie, and only the asker's own address gets it", () -> {
      RelayCore r = relay();
      Got first = only(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN)));
      same(first.m().type(), Type.COOKIE, "a cookie");
      same(where(first), where(HOST), "to the asker");
      same(r.games.size(), 0, "nothing is kept for a first ask");

      Got someoneElses = only(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN).secret(first.m().secret())));
      same(someoneElses.m().type(), Type.COOKIE, "one address's cookie is no good from another");
      same(r.games.size(), 0, "nothing kept");

      Got wrongPort = only(send(r, CONTROL, who(HOST.address(), HOST.port() + 1), Message.of(Type.HOST_OPEN).secret(first.m().secret())));
      same(wrongPort.m().type(), Type.COOKIE, "nor from another port of the same address");
    });

    test("a cookie is good for 10 to 20 s", () -> {
      RelayCore r = relay();
      byte[] cookie = only(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN), 5000)).m().secret();
      same(only(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN).secret(cookie), 19999)).m().type(), Type.HOST_OPENED,
          "made at 5 s, good at 19.999 s");
      byte[] later = only(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN), 5000)).m().secret();
      same(only(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN).secret(later), 20000)).m().type(), Type.COOKIE, "and no good at 20 s");
    });

    test("every answer to an address not yet proven is no bigger than its question", () -> {
      RelayCore r = relay();
      List<Message> questions = List.of(Message.of(Type.HOST_OPEN), Message.of(Type.JOIN).code(latin1("ABCD2345")), keep(bytes(16, 7)),
          Message.of(Type.ECHO).secret(bytes(16, 3)).number(1));

      for (Message msg : questions) {
        byte[] question = Protocol.encode(msg);

        for (Out answer : r.receive(CONTROL, STRANGER.address(), STRANGER.port(), question, 0)) {
          ok(answer.data().length <= question.length, "the answer to type " + msg.type());
        }
      }
    });

    test("a host can open 2 games, not 3; and the relay holds at most its most", () -> {
      RelayCore r = relay();
      openGame(r);
      openGame(r);
      byte[] cookie = only(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN))).m().secret();
      Got third = only(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN).secret(cookie)));
      same(List.of(third.m().type(), third.m().number()), List.of(Type.REFUSED, Why.TOO_MANY_GAMES), "the third is refused");

      RelayCore small = relay(l -> l.mostGames = 1);
      openGame(small);
      byte[] cookie2 = only(send(small, CONTROL, STRANGER, Message.of(Type.HOST_OPEN))).m().secret();
      Got busy = only(send(small, CONTROL, STRANGER, Message.of(Type.HOST_OPEN).secret(cookie2)));
      same(List.of(busy.m().type(), busy.m().number()), List.of(Type.REFUSED, Why.BUSY), "a relay at its most is busy");
    });

    test("joining a code that is no game is refused", () -> {
      RelayCore r = relay();
      List<Got> out = join(r, latin1("ZZZZZZZZ"));
      same(out.size(), 1, "one answer");
      same(List.of(out.get(0).m().type(), out.get(0).m().number()), List.of(Type.REFUSED, Why.NO_SUCH_GAME), "no such game");
    });

    test("a game takes at most its most joiners, counting the claimed only, and the relay at most its ports", () -> {
      RelayCore r = relay(l -> l.mostJoinersPerGame = 2);
      Opened game = openGame(r);

      for (int i = 1; i <= 2; i++) {
        Who joiner = who("203.0.113." + i, 1);
        Got port = join(r, game.code(), joiner).get(0);
        same(port.m().type(), Type.JOIN_PORT, "joiner " + i);
        send(r, port.m().port(), joiner, Message.of(Type.JOINER_HELLO).secret(port.m().secret()));
      }

      Got full = join(r, game.code(), who("203.0.113.3", 1)).get(0);
      same(List.of(full.m().type(), full.m().number()), List.of(Type.REFUSED, Why.GAME_FULL), "the third, once both have claimed: the game is full");

      // Two given ports for one last place: the first to claim it has it, and the other's hello claims nothing
      RelayCore race = relay(l -> l.mostJoinersPerGame = 1);
      Opened g = openGame(race);
      Who a = who("203.0.113.40", 1);
      Who b = who("203.0.113.41", 1);
      Got portA = join(race, g.code(), a).get(0);
      Got portB = join(race, g.code(), b).get(0);
      same(List.of(portA.m().type(), portB.m().type()), List.of(Type.JOIN_PORT, Type.JOIN_PORT), "both get a port while neither has claimed");
      same(only(send(race, portA.m().port(), a, Message.of(Type.JOINER_HELLO).secret(portA.m().secret()))).m().type(), Type.NEW_JOINER,
          "the first claims the place");
      same(send(race, portB.m().port(), b, Message.of(Type.JOINER_HELLO).secret(portB.m().secret())).size(), 0,
          "the second's hello claims nothing: the game is full");
      same(race.slots.get(portB.m().port()).claimed, false, "its port stays unclaimed, to be freed");

      RelayCore r2 = relay();
      Opened g2 = openGame(r2);

      for (int i = 0; i < PORTS.length; i++) {
        same(join(r2, g2.code(), who("203.0.113." + (10 + i), 1)).get(0).m().type(), Type.JOIN_PORT, "joiner " + i);
      }

      Got noPort = join(r2, g2.code(), who("203.0.113.99", 1)).get(0);
      same(List.of(noPort.m().type(), noPort.m().number()), List.of(Type.REFUSED, Why.BUSY), "every port is taken");
    });

    test("a hello with the wrong secret binds nothing", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      Got toJoiner = join(r, game.code()).get(0);
      int port = toJoiner.m().port();
      same(send(r, port, STRANGER, Message.of(Type.HOST_HELLO).secret(bytes(16, 1)).port(port)).size(), 0, "a host hello, the wrong token");
      same(send(r, port, STRANGER, Message.of(Type.JOINER_HELLO).secret(bytes(16, 1))).size(), 0, "a joiner hello, the wrong ticket");
      int another = port == 27501 ? 27502 : 27501;
      same(send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(another)).size(), 0, "a host hello naming another port");
      same(r.slots.get(port).hostEnd, null, "no host bound");
      same(r.slots.get(port).joinerEnd, null, "no joiner bound");
    });

    test("on a joiner's port, only its two ends are heard", () -> {
      RelayCore r = relay();
      int port = connected(r).port();
      same(sendRaw(r, port, STRANGER, latin1("anything")).size(), 0, "a stranger");
      same(sendRaw(r, port, who(JOINER.address(), JOINER.port() + 1), latin1("x")).size(), 0, "the joiner's address, from another port");
      int another = port == PORTS[0] ? PORTS[1] : PORTS[0];
      same(sendRaw(r, another, JOINER, latin1("x")).size(), 0, "the joiner, on a port that isn't its");
    });

    test("a host or joiner whose NAT moved it is heard again after a hello with its secret", () -> {
      RelayCore r = relay();
      Connected c = connected(r);
      Who moved = who(JOINER.address(), JOINER.port() + 7);
      same(only(send(r, c.port(), moved, Message.of(Type.JOINER_HELLO).secret(c.ticket()))).m().type(), Type.READY, "READY where it is now");
      Got out = only(sendRaw(r, c.port(), HOST, latin1("to the joiner, where it is now")));
      same(where(out), where(moved), "to the joiner where it is now");

      Who hostMoved = who(HOST.address(), HOST.port() + 9);
      send(r, c.port(), hostMoved, Message.of(Type.HOST_HELLO).secret(c.game().token()).port(c.port()));
      Got up = only(sendRaw(r, c.port(), moved, latin1("to the host, where it is now")));
      same(where(up), where(hostMoved), "to the host where it is now");
    });

    test("nothing on a joiner's port is passed on before both hellos", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      int port = join(r, game.code()).get(0).m().port();
      send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port));
      same(sendRaw(r, port, HOST, latin1("too early")).size(), 0, "too early");
    });

    test("a packet over 1,500 bytes is dropped, and 1,500 is passed on", () -> {
      RelayCore r = relay();
      int port = connected(r).port();
      same(sendRaw(r, port, JOINER, new byte[1501]).size(), 0, "1,501 bytes");
      same(sendRaw(r, port, JOINER, new byte[1500]).size(), 1, "1,500 bytes");
      same(sendRaw(r, CONTROL, JOINER, new byte[1501]).size(), 0, "on the control port too");
    });

    test("a port passes on at most its packets and bytes a second, each way", () -> {
      RelayCore r = relay(l -> {
        l.portPacketRate = 2;
        l.portPacketBurst = 3;
        l.portByteRate = 1000000;
        l.portByteBurst = 1000000;
      });
      int port = connected(r).port();

      for (int i = 0; i < 3; i++) {
        same(sendRaw(r, port, JOINER, latin1("x"), 1).size(), 1, "packet " + i);
      }

      same(sendRaw(r, port, JOINER, latin1("x"), 1).size(), 0, "the 4th at once is over the limit");
      same(sendRaw(r, port, HOST, latin1("x"), 1).size(), 1, "the other way has its own");
      same(sendRaw(r, port, JOINER, latin1("x"), 501).size(), 1, "half a second later, one more");

      RelayCore byteLimited = relay(l -> {
        l.portByteRate = 100;
        l.portByteBurst = 1000;
      });
      int b = connected(byteLimited).port();
      same(sendRaw(byteLimited, b, JOINER, new byte[1000], 1).size(), 1, "1,000 bytes");
      same(sendRaw(byteLimited, b, JOINER, new byte[1], 1).size(), 0, "its bytes are used up");
    });

    test("one address asking too fast is held back, and others are not", () -> {
      RelayCore r = relay(l -> {
        l.controlRate = 1;
        l.controlBurst = 2;
      });
      same(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN)).size(), 1, "the 1st");
      same(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN)).size(), 1, "the 2nd");
      same(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPEN)).size(), 0, "the 3rd at once");
      same(send(r, CONTROL, HOST, Message.of(Type.HOST_OPEN)).size(), 1, "another address is not held back");
    });

    test("refusals to one address are kept to their own limit", () -> {
      RelayCore r = relay(l -> {
        l.refusalRate = 1;
        l.refusalBurst = 1;
      });
      same(only(send(r, CONTROL, STRANGER, keep(bytes(16, 9)))).m().type(), Type.REFUSED, "the first is refused");
      same(send(r, CONTROL, STRANGER, keep(bytes(16, 9))).size(), 0, "the second refusal at once isn't sent");
    });

    test("anything on the control port that isn't a message is dropped, as are messages that belong elsewhere", () -> {
      RelayCore r = relay();
      same(sendRaw(r, CONTROL, STRANGER, latin1("hello")).size(), 0, "not a message");
      same(send(r, CONTROL, STRANGER, Message.of(Type.HOST_OPENED).secret(bytes(16, 1)).code(latin1("ABCD2345"))).size(), 0, "a HOST_OPENED");
      same(send(r, CONTROL, STRANGER, Message.of(Type.JOINER_HELLO).secret(bytes(16, 1))).size(), 0, "a hello");
      same(send(r, CONTROL, STRANGER, Message.of(Type.ECHO_BACK).secret(bytes(16, 1)).number(1)).size(), 0,
          "an ECHO_BACK, so two relays can't answer each other");
      same(send(r, CONTROL, STRANGER, Message.of(Type.COOKIE).secret(bytes(16, 1))).size(), 0, "a COOKIE");
      same(send(r, CONTROL, STRANGER, Message.of(Type.REFUSED).number(1)).size(), 0, "a REFUSED");
      same(sendRaw(r, 1234, STRANGER, latin1("a port the relay doesn't have")).size(), 0, "a port the relay doesn't have");
    });

    test("an echo comes straight back to its sender, the same size, with its own bytes and count, and nothing is kept", () -> {
      RelayCore r = relay();
      byte[] mine = latin1("sixteen bytes!!!");
      byte[] question = Protocol.encode(Message.of(Type.ECHO).secret(mine).number(3));
      Got back = only(r.receive(CONTROL, STRANGER.address(), STRANGER.port(), question, 0));
      same(back.m().type(), Type.ECHO_BACK, "an ECHO_BACK");
      same(back.m().secret(), mine, "the asker's own 16 bytes");
      same(back.m().number(), 3, "and its count");
      same(List.of(back.from(), back.address(), back.port()), List.of(CONTROL, STRANGER.address(), STRANGER.port()),
          "from the control port, to the sender only");
      same(back.data().length, question.length, "no bigger than the question");
      same(List.of(r.games.size(), r.free.size()), List.of(0, PORTS.length), "nothing kept");

      Got empty = only(send(r, CONTROL, STRANGER, Message.of(Type.ECHO)));
      same(empty.m().type(), Type.ECHO_BACK, "an echo of nothing is answered");
      same(empty.m().secret(), null, "with nothing");
      same(empty.m().number(), 0, "and no count");
      same(send(r, PORTS[0], STRANGER, Message.of(Type.ECHO).secret(mine)).size(), 0, "only the control port answers echoes");
    });

    test("echoes are held to the control limits, and one over gets no answer at all", () -> {
      RelayCore r = relay(l -> {
        l.controlRate = 1;
        l.controlBurst = 3;
      });
      Message echo = Message.of(Type.ECHO).secret(bytes(16, 4)).number(1);

      for (int i = 0; i < 3; i++) {
        same(only(send(r, CONTROL, STRANGER, echo)).m().type(), Type.ECHO_BACK, "echo " + i);
      }

      same(send(r, CONTROL, STRANGER, echo).size(), 0, "the 4th at once: nothing, not a REFUSED");
      same(only(send(r, CONTROL, HOST, echo)).m().type(), Type.ECHO_BACK, "another address has its own");

      RelayCore all = relay(l -> {
        l.everyoneRate = 1;
        l.everyoneBurst = 2;
      });
      same(send(all, CONTROL, STRANGER, echo).size(), 1, "one");
      same(send(all, CONTROL, HOST, echo).size(), 1, "two");
      same(send(all, CONTROL, JOINER, echo).size(), 0, "and everyone's together");
    });

    test("HOST_OPENED and every HOST_KEPT carry a fresh pass the list can check with this relay's key", () -> {
      RelayCore r = relay();
      long now = 1794268800123L;
      Opened game = openGame(r, HOST, now);
      same(game.passTime(), 1794268800L, "the pass time is now, in whole seconds");
      same(game.pass(), Pass.make(KEY, REGION, game.code(), game.passTime()), "made from this relay's key, region and the game's code");

      Got kept = only(send(r, CONTROL, HOST, keep(game.token()), now + 15000));
      same(kept.m().passTime(), 1794268815L, "a HOST_KEPT has a fresh one");
      same(kept.m().pass(), Pass.make(KEY, REGION, game.code(), 1794268815L), "made the same way");
      notSame(kept.m().pass(), game.pass(), "and not the old one");

      RelayCore other = new RelayCore(CONTROL, PORTS, "paris", KEY, SeededRandom.of(3), new RelayCore.Limits(), 0);
      notSame(openGame(other, HOST, now).pass(), game.pass(), "the same key in another region makes another pass");
    });

    test("a kept game lives; an unkept one ends, with its ports and its code", () -> {
      RelayCore r = relay();
      Connected c = connected(r);
      same(only(send(r, CONTROL, HOST, keep(c.game().token()), 30000)).m().type(), Type.HOST_KEPT, "kept at 30 s");
      sendRaw(r, c.port(), JOINER, latin1("x"), 30000);
      r.tick(70000);
      same(r.games.size(), 1, "kept at 30 s, so alive at 70 s");
      r.tick(75000);
      same(r.games.size(), 0, "not kept for 45 s: it ends");
      same(r.slots.get(c.port()).state, Slot.State.FREE, "its port is free");
      same(join(r, c.game().code(), JOINER, 75000).get(0).m().number(), Why.NO_SUCH_GAME, "and its code is no game");
    });

    test("HOST_KEPT says how many joiners the game has", () -> {
      RelayCore r = relay();
      Connected c = connected(r);
      same(only(send(r, CONTROL, HOST, keep(c.game().token()))).m().number(), 1, "one joiner");
    });

    test("a host that closes its game ends it at once; a wrong token closes nothing", () -> {
      RelayCore r = relay();
      Connected c = connected(r);
      send(r, CONTROL, STRANGER, Message.of(Type.HOST_CLOSE).secret(bytes(16, 5)));
      same(r.games.size(), 1, "the wrong token closes nothing");
      same(send(r, CONTROL, HOST, Message.of(Type.HOST_CLOSE).secret(c.game().token())).size(), 0, "no answer");
      same(r.games.size(), 0, "the game is gone");
      same(r.slots.get(c.port()).state, Slot.State.FREE, "and its port is free");
      same(only(send(r, CONTROL, HOST, keep(c.game().token()))).m().number(), Why.NO_SUCH_GAME, "its token is no good now");
    });

    test("a port not claimed is freed after 5 s, one waiting for its host after 15 s, and an idle one after 30 s", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      int port = join(r, game.code()).get(0).m().port();
      r.tick(4999);
      same(r.slots.get(port).state, Slot.State.PENDING, "not claimed, still there at 4.999 s");
      r.tick(5000);
      same(r.slots.get(port).state, Slot.State.FREE, "freed at 5 s");

      RelayCore claimed = relay();
      Opened g = openGame(claimed);
      Got toJoiner = join(claimed, g.code()).get(0);
      send(claimed, toJoiner.m().port(), JOINER, Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret()), 100);
      claimed.tick(14999);
      same(claimed.slots.get(toJoiner.m().port()).state, Slot.State.PENDING, "claimed, waiting for the host, still there at 14.999 s");
      claimed.tick(15000);
      same(claimed.slots.get(toJoiner.m().port()).state, Slot.State.FREE, "freed 15 s after the JOIN");
      same(claimed.portsPerSender.size() + claimed.unclaimedPerSender.size(), 0, "and the sender's counts with it");

      RelayCore r2 = relay();
      Connected c = connected(r2);
      send(r2, CONTROL, HOST, keep(c.game().token()), 20000);
      r2.tick(29999);
      same(r2.slots.get(c.port()).state, Slot.State.ACTIVE, "still passing packets at 29.999 s");
      r2.tick(30000);
      same(r2.slots.get(c.port()).state, Slot.State.FREE, "freed after 30 s with none");
      same(r2.games.size(), 1, "the game lives on without that joiner");
    });

    test("a freed port goes back to be used again", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);

      for (int i = 0; i < PORTS.length; i++) {
        join(r, game.code(), who("203.0.113." + i, 1));
      }

      r.tick(15000);
      send(r, CONTROL, HOST, keep(game.token()), 15000);
      ok(has(PORTS, join(r, game.code(), JOINER, 15000).get(0).m().port()), "a port again");
    });

    test("the log lines are counts and times only: no address, code, token or ticket", () -> {
      RelayCore r = relay();
      Connected c = connected(r, 0);
      sendRaw(r, c.port(), JOINER, latin1("x"), 1);
      sendRaw(r, c.port(), HOST, latin1("y"), 1);
      sendRaw(r, c.port(), HOST, latin1("z"), 1);
      sendRaw(r, c.port(), STRANGER, latin1("x"), 1);
      // The game and its joiner are still alive when the line is made, so anything of theirs could get into it
      send(r, CONTROL, HOST, keep(c.game().token()), 50000);
      send(r, c.port(), HOST, Message.of(Type.HOST_HELLO).secret(c.game().token()).port(c.port()), 50000);
      send(r, c.port(), JOINER, Message.of(Type.JOINER_HELLO).secret(c.ticket()), 50000);
      List<String> lines = r.tick(60000);
      same(r.games.size(), 1, "the game is alive as the line is made");
      same(r.slots.get(c.port()).state, Slot.State.ACTIVE, "and so is its joiner");
      same(lines.size(), 1, "one line");
      String line = lines.get(0);
      matches(line, "forwarded 3 packets \\(1 joiners to hosts, 2 hosts to joiners\\)", "the packets passed on, each way");
      matches(line, "1 joins, 1 joiners ready,", "one joiner, ready once, though its READY went twice");

      for (String secret : List.of(HOST.address(), JOINER.address(), STRANGER.address(), text(c.game().code()), hex(c.game().token()),
          hex(c.ticket()))) {
        ok(!line.contains(secret), "the line has no " + secret);
      }

      ok(!Pattern.compile("\\d+\\.\\d+\\.\\d+\\.\\d+").matcher(line).find(), "nothing that looks like an address");
      same(r.tick(60001).size(), 0, "and the next line only a minute later");
    });

    test("as the relay stops, its counts so far are a line at once, and the next minute counts from there", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      send(r, CONTROL, HOST, Message.of(Type.HOST_CLOSE).secret(game.token()), 1000);
      String line = r.countsLine(1000);
      matches(line, "^relay: in the last 1 s: 1 games opened, 1 closed,", "a second's counts, made now");
      ok(!line.contains(HOST.address()) && !line.contains(text(game.code())), "with no address or code");
      same(r.tick(60000).size(), 0, "and the next line comes a minute after this one, not after the start");
      matches(r.tick(61000).get(0), "^relay: in the last 60 s: 0 games opened, 0 closed,", "counting only what came after");
    });

    test("a game's code is 8 code letters made from 40 random bits", () -> {
      Set<String> seen = new HashSet<>();
      SeededRandom random = SeededRandom.of(11);

      for (int i = 0; i < 500; i++) {
        byte[] code = RelayCore.makeCode(random);
        ok(Protocol.isCode(code), text(code));
        seen.add(text(code));
      }

      ok(seen.size() > 490, "they differ");
      same(text(RelayCore.makeCode(n -> new byte[5])), "22222222", "all 0 bits is the first letter each time");
      same(text(RelayCore.makeCode(n -> bytes(5, 0xff))), "ZZZZZZZZ", "all 1 bits is the last");
    });

    test("nothing a packet holds can throw out of the relay", () -> {
      RelayCore r = relay();
      int port = connected(r).port();
      SeededRandom random = SeededRandom.of(99);

      for (int i = 0; i < 2000; i++) {
        int size = (random.next(1)[0] & 0xff) % 80;
        byte[] junk = random.next(size);

        if (size >= 6) {
          System.arraycopy(latin1("AVPR"), 0, junk, 0, 4);
          junk[4] = 1;
        }

        for (int at : new int[] {CONTROL, port}) {
          ok(r.receive(at, STRANGER.address(), STRANGER.port(), junk, i) != null, "packet " + i + " gives back a list");
        }
      }

      // Node's test also gave it text where bytes go; in Java a packet can only be bytes, so the nearest thing is none at all
      ok(r.receive(CONTROL, STRANGER.address(), STRANGER.port(), null, 0) != null, "no bytes at all");
    });

    test("the relay refuses ports it could not keep apart, and needs its region and pass key", () -> {
      RelayCore.Limits limits = new RelayCore.Limits();
      doesNotThrow(() -> new RelayCore(27500, new int[] {27501}, REGION, KEY, SeededRandom.of(1), limits, 0), "a good one");
      throwsWith(() -> new RelayCore(27500, new int[] {27500}, REGION, KEY, SeededRandom.of(1), limits, 0), "each relay port",
          "the control port as a relay port");
      throwsWith(() -> new RelayCore(27500, new int[] {27501, 27501}, REGION, KEY, SeededRandom.of(1), limits, 0), "each relay port",
          "one port twice");
      throwsWith(() -> new RelayCore(27500, new int[] {0}, REGION, KEY, SeededRandom.of(1), limits, 0), "each relay port", "port 0");
      throwsWith(() -> new RelayCore(27500, new int[] {27501}, null, KEY, SeededRandom.of(1), limits, 0), "region", "no region");
      throwsWith(() -> new RelayCore(27500, new int[] {27501}, "Virginia", KEY, SeededRandom.of(1), limits, 0), "region",
          "a region with a capital");
      throwsWith(() -> new RelayCore(27500, new int[] {27501}, REGION, null, SeededRandom.of(1), limits, 0), "pass key", "no pass key");
      throwsWith(() -> new RelayCore(27500, new int[] {27501}, REGION, bytes(16, 1), SeededRandom.of(1), limits, 0), "pass key",
          "a pass key of 16 bytes");
    });

    // The independent review's V1-1 (2026-11-09, AvP-docs/engine/review-server-Reviewer.md): anyone can read a game's code from the
    // list and JOIN it, and a JOIN that never says hello must not hold a real player's place
    test("joins that never say hello can't keep a real joiner out of a game", () -> {
      RelayCore r = relayWithPorts(20);
      Opened game = openGame(r);
      Who flooder = who("192.0.2.66", 7000);

      // 8 joins, one every half second, each from a port of its own: inside the game's join rate (4 a second, 8 at once) and the
      // sender's (10 a second, 20 at once)
      for (int i = 0; i < 8; i++) {
        join(r, game.code(), who(flooder.address(), flooder.port() + i), i * 500L);
      }

      Got real = join(r, game.code(), JOINER, 4000).get(0);
      same(real.m().type(), Type.JOIN_PORT, "the real joiner still gets a port, though the flooder asked for all 8 of the game's");
    });

    test("joins that never say hello can't take the relay's ports from everyone else", () -> {
      RelayCore r = relayWithPorts(16);
      Opened one = openGame(r, HOST, 0);
      Opened two = openGame(r, who("198.51.100.11", 40000), 0);
      Who flooder = who("192.0.2.66", 7000);

      // 16 joins, the two games in turn, one every 0.3 s, each from a port of its own: inside every rate there is
      for (int i = 0; i < 16; i++) {
        join(r, (i % 2 == 0 ? one : two).code(), who(flooder.address(), flooder.port() + i), i * 300L);
      }

      Got real = join(r, one.code(), JOINER, 5000).get(0);
      same(real.m().type(), Type.JOIN_PORT, "a real joiner still gets one of the relay's 16 ports");
    });

    // The review's V1-2: a stranger who knows a joiner's port sends hellos with wrong secrets, to use up the port's hellos
    test("a stranger's flood of hellos with wrong secrets can't keep the real hellos out", () -> {
      RelayCore r = relay();
      Opened game = openGame(r);
      Got toJoiner = join(r, game.code()).get(0);
      int port = toJoiner.m().port();

      for (int i = 0; i < 100; i++) {
        send(r, port, STRANGER, Message.of(Type.HOST_HELLO).secret(bytes(16, i)).port(port), 0);
        send(r, port, STRANGER, Message.of(Type.JOINER_HELLO).secret(bytes(16, i + 100)), 0);
      }

      send(r, port, HOST, Message.of(Type.HOST_HELLO).secret(game.token()).port(port), 0);
      List<Out> answer = send(r, port, JOINER, Message.of(Type.JOINER_HELLO).secret(toJoiner.m().secret()), 0);
      same(answer.size(), 1, "the joiner's hello is answered, though 200 wrong ones came first");
      same(only(answer).m().type(), Type.READY, "with READY");
    });
  }
}
