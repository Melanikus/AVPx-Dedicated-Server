package avpx.v2;

import static avpx.testing.Tests.bytes;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsAny;

import avpx.crypto.Gcm;
import avpx.crypto.Hkdf;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

// The tests of Channel.java (CRYPTO.md sections 7 and 9, and 5.1's points on nonces and epochs): what one side seals only the other opens,
// once, exactly as sealed; the keys change by themselves every 2^20 messages; and a session ends at its limits. Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server.
//
// The datagrams the channel should make are also made here BY HAND, straight from CRYPTO.md's layout, with code of this file's own (the
// header, the nonce, the epoch keys), so the channel is held to the written layout, not only to itself.
public final class ChannelTest {
  private ChannelTest() {
  }

  private static final byte[] ID = bytes(8, 0x5a);
  private static final byte[] GAME_KEY = bytes(48, 0x01);
  private static final byte[] GAME_IV = bytes(12, 0x02);
  private static final byte[] RELAY_KEY = bytes(48, 0x03);
  private static final byte[] RELAY_IV = bytes(12, 0x04);
  private static final long DAY = 24L * 60 * 60 * 1000;

  private static Channel game(long now) {
    return new Channel(ID, GAME_KEY, GAME_IV, RELAY_KEY, RELAY_IV, now);
  }

  private static Channel relay(long now) {
    return new Channel(ID, RELAY_KEY, RELAY_IV, GAME_KEY, GAME_IV, now);
  }

  private static byte[] message(int n) {
    byte[] m = new byte[64];
    m[0] = (byte) n;
    m[63] = (byte) (n >>> 8);
    return m;
  }

  // ----- The channel's datagrams, by hand from CRYPTO.md section 7 and 5.1

  // Every epoch's key, epoch 0's too, is HKDF-Expand(the 48-byte secret, "AVPX epoch v2" || e as 4 bytes little-endian, 32): the secret
  // itself never seals anything (CRYPTO.md 5.1 point 8)
  private static byte[] epochKey(byte[] key, long epoch) {
    byte[] words = "AVPX epoch v2".getBytes(StandardCharsets.US_ASCII);
    byte[] info = Arrays.copyOf(words, words.length + 4);

    for (int i = 0; i < 4; i++) {
      info[words.length + i] = (byte) (epoch >>> (8 * i));
    }

    return Hkdf.expand(key, info, 32);
  }

  // 'AVPR', 2, 32, 0, 0, the session id, the counter as 8 bytes little-endian; then the message sealed under the epoch's key, with the
  // nonce the IV XOR (4 zero bytes || the counter little-endian), and those first 24 bytes as the AAD
  private static byte[] byHand(byte[] key, byte[] iv, long counter, byte[] message) {
    byte[] aad = new byte[24];
    aad[0] = 'A';
    aad[1] = 'V';
    aad[2] = 'P';
    aad[3] = 'R';
    aad[4] = 2;
    aad[5] = 32;
    System.arraycopy(ID, 0, aad, 8, 8);
    byte[] nonce = iv.clone();

    for (int i = 0; i < 8; i++) {
      aad[16 + i] = (byte) (counter >>> (8 * i));
      nonce[4 + i] ^= (byte) (counter >>> (8 * i));
    }

    byte[] sealed = Gcm.seal(epochKey(key, counter >>> 20), nonce, aad, message);
    byte[] d = Arrays.copyOf(aad, 104);
    System.arraycopy(sealed, 0, d, 24, sealed.length);
    return d;
  }

  public static void register() {
    test("the game's first two seals are byte for byte the datagrams CRYPTO.md describes, and the relay opens them", () -> {
      Channel game = game(0);
      Channel relay = relay(0);
      byte[] first = game.seal(message(1), 0);
      same(first.length, 104, "104 bytes");
      same(first, byHand(GAME_KEY, GAME_IV, 0, message(1)), "counter 0, as made by hand");
      byte[] second = game.seal(message(2), 0);
      same(second, byHand(GAME_KEY, GAME_IV, 1, message(2)), "counter 1, as made by hand");
      same(relay.open(first, 0), message(1), "the relay opens the first");
      same(relay.open(second, 0), message(2), "and the second");
      same(relay.lastRefusal(), Channel.Refusal.NONE, "with no refusal");
      same(game.open(relay.seal(message(3), 0), 0), message(3), "the relay's way, with the relay's key: the game opens it");
      same(relay.seal(message(3), 0), byHand(RELAY_KEY, RELAY_IV, 1, message(3)), "the relay's counter is its own, now at 1");
    });

    test("a side can't open what it sealed itself: each way has its own key and IV", () -> {
      Channel game = game(0);
      same(game.open(game.seal(message(1), 0), 0), null, "the game, its own datagram");
      same(game.lastRefusal(), Channel.Refusal.TAG, "its tag fails");
    });

    test("every byte of a sealed datagram changed, one at a time: refused, by its shape, its counter or its tag; then the true one opens", () -> {
      Channel relay = relay(0);
      byte[] d = game(0).seal(message(1), 0);

      for (int i = 0; i < 104; i++) {
        byte[] c = d.clone();
        c[i] ^= (byte) (1 << (i % 8));
        same(relay.open(c, 0), null, "byte " + i);
        Channel.Refusal why = relay.lastRefusal();

        if (i < 16) {
          same(why, Channel.Refusal.SHAPE, "byte " + i + ", in the header or the session id: not this session's shape");
        } else if (i < 20) {
          same(why, Channel.Refusal.TAG, "byte " + i + ", a counter still below 2^32: its tag fails");
        } else if (i < 24) {
          same(why, Channel.Refusal.REPLAYED, "byte " + i + ", a counter of 2^32 or more: past what a session may use");
        } else {
          same(why, Channel.Refusal.TAG, "byte " + i + ", in the sealed message or its tag: its tag fails");
        }
      }

      same(relay.open(d, 0), message(1), "none of those used up counter 0: the true datagram still opens (a forgery can't block it)");
      same(relay.open(Arrays.copyOf(d, 103), 0), null, "103 bytes");
      same(relay.lastRefusal(), Channel.Refusal.SHAPE, "the wrong size");
      same(relay.open(null, 0), null, "nothing");
    });

    test("a datagram opens once: again, it's refused; out of order is fine while it's new", () -> {
      Channel game = game(0);
      Channel relay = relay(0);
      List<byte[]> sent = new ArrayList<>();

      for (int i = 0; i < 4; i++) {
        sent.add(game.seal(message(i), 0));
      }

      for (int i : new int[] {3, 0, 2, 1}) {
        same(relay.open(sent.get(i), 0), message(i), "counter " + i + ", out of order");
      }

      for (int i = 0; i < 4; i++) {
        same(relay.open(sent.get(i), 0), null, "counter " + i + " again");
        same(relay.lastRefusal(), Channel.Refusal.REPLAYED, "refused as replayed");
      }
    });

    test("a datagram from more than 1,023 behind the newest is refused, however true", () -> {
      Channel game = game(0);
      Channel relay = relay(0);
      List<byte[]> sent = new ArrayList<>();

      for (int i = 0; i < 1026; i++) {
        sent.add(game.seal(message(i), 0));
      }

      same(relay.open(sent.get(1025), 0), message(1025), "counter 1,025");
      same(relay.open(sent.get(1), 0), null, "counter 1, 1,024 behind");
      same(relay.lastRefusal(), Channel.Refusal.REPLAYED, "refused, as too old");
      same(relay.open(sent.get(2), 0), message(2), "counter 2, 1,023 behind: still in the window");
    });

    test("another session's datagram is refused by its id, and sessionIdOf reads only the sealed shape", () -> {
      byte[] d = game(0).seal(message(1), 0);
      Channel other = new Channel(bytes(8, 0x5b), RELAY_KEY, RELAY_IV, GAME_KEY, GAME_IV, 0);
      same(other.open(d, 0), null, "another session id");
      same(other.lastRefusal(), Channel.Refusal.SHAPE, "refused by its shape");
      same(Channel.sessionIdOf(d), ID, "the id, from bytes 8 to 15");
      same(Channel.sessionIdOf(Arrays.copyOf(d, 105)), null, "105 bytes");
      byte[] kind = d.clone();
      kind[5] = 33;
      same(Channel.sessionIdOf(kind), null, "another kind");
      byte[] zeros = d.clone();
      zeros[7] = 1;
      same(Channel.sessionIdOf(zeros), null, "bytes 6 and 7 not 0");
    });

    test("THE KEYS CHANGE BY THEMSELVES every 2^20 messages: the last of epoch 0 and the first of epoch 1, as made by hand", () -> {
      Channel relay = relay(0);
      long edge = 1L << 20;
      same(relay.open(byHand(GAME_KEY, GAME_IV, edge - 1, message(1)), 0), message(1), "counter 2^20 - 1, under epoch 0's key");
      same(relay.open(byHand(GAME_KEY, GAME_IV, edge, message(2)), 0), message(2), "counter 2^20, under epoch 1's key");

      // Counter 2^20 + 1 sealed under the old key: refused, so both sides must change at the very same counter
      byte[] old = byHand(GAME_KEY, GAME_IV, edge + 1, message(3));
      byte[] aad = Arrays.copyOf(old, 24);
      byte[] nonce = GAME_IV.clone();

      for (int i = 0; i < 8; i++) {
        nonce[4 + i] ^= (byte) ((edge + 1) >>> (8 * i));
      }

      byte[] underOldKey = Arrays.copyOf(aad, 104);
      System.arraycopy(Gcm.seal(epochKey(GAME_KEY, 0), nonce, aad, message(3)), 0, underOldKey, 24, 80);
      same(relay.open(underOldKey, 0), null, "counter 2^20 + 1 under epoch 0's key");
      same(relay.lastRefusal(), Channel.Refusal.TAG, "its tag fails");
      same(relay.open(old, 0), message(3), "and under epoch 1's, it opens");

      ok(!Arrays.equals(epochKey(GAME_KEY, 0), Arrays.copyOf(GAME_KEY, 32)), "epoch 0's key isn't the secret, nor its first 32 bytes");
      ok(!Arrays.equals(epochKey(GAME_KEY, 1), epochKey(GAME_KEY, 0)), "epoch 1's key isn't epoch 0's");
      ok(!Arrays.equals(epochKey(GAME_KEY, 1), epochKey(GAME_KEY, 2)), "nor epoch 2's");
      byte[] info = Arrays.copyOf("AVPX epoch v2".getBytes(StandardCharsets.US_ASCII), 17);
      info[13] = 1;
      same(Channel.epochInfo(1), info, "epoch 1's info: the words, then 1 as 4 bytes little-endian");
      same(relay.open(byHand(GAME_KEY, GAME_IV, (1L << 32) - 1, message(4)), 0), message(4), "the last counter a session may use, 2^32 - 1");
    });

    test("the sealing side changes key at 2^20 by itself too: a game's message 2^20 is sealed under epoch 1's key", () -> {
      Channel game = game(0);
      long edge = 1L << 20;

      for (long i = 0; i < edge - 1; i++) {
        game.seal(message(0), 0);
      }

      same(game.seal(message(1), 0), byHand(GAME_KEY, GAME_IV, edge - 1, message(1)), "message 2^20 - 1, under the key itself");
      same(game.seal(message(2), 0), byHand(GAME_KEY, GAME_IV, edge, message(2)), "message 2^20, under epoch 1's key");
    });

    test("a session ends: at counter 2^32, at 24 hours, with its clock gone back, or after 65,536 failed tags", () -> {
      Channel relay = relay(1000);
      byte[] beyond = byHand(GAME_KEY, GAME_IV, 1L << 32, message(1));
      same(relay.open(beyond, 1000), null, "counter 2^32");
      same(relay.lastRefusal(), Channel.Refusal.REPLAYED, "past what a session may use");

      Channel day = relay(1000);
      byte[] d = game(1000).seal(message(1), 1000);
      same(day.open(d, 1000 + DAY), null, "24 hours on");
      same(day.lastRefusal(), Channel.Refusal.OVER, "the session is over");
      same(relay(1000).open(d, 999), null, "a clock gone back");
      same(relay(1000).open(d, 1000 + DAY - 1), message(1), "a millisecond short of 24 hours: it opens");
      same(game(1000).seal(message(1), 1000 + DAY), null, "and the sealing side seals nothing at 24 hours");

      Channel tags = relay(0);
      byte[] good = game(0).seal(message(1), 0);
      byte[] bad = good.clone();
      bad[50] ^= 1;

      for (int i = 0; i < 65535; i++) {
        tags.open(bad, 0);
      }

      ok(!tags.over(0), "65,535 failed tags: not over yet");
      tags.open(bad, 0);
      ok(tags.over(0), "the 65,536th: over");
      same(tags.open(good, 0), null, "and then a true datagram is refused too: only a new handshake goes on");
      same(tags.lastRefusal(), Channel.Refusal.OVER, "as the session is over");
    });

    test("wiped, a channel seals and opens nothing", () -> {
      Channel game = game(0);
      Channel relay = relay(0);
      byte[] d = game.seal(message(1), 0);
      relay.wipe();
      same(relay.open(d, 0), null, "it opens nothing");
      same(relay.lastRefusal(), Channel.Refusal.OVER, "it's over");
      game.wipe();
      same(game.seal(message(1), 0), null, "and seals nothing");
      throwsAny(() -> game(0).seal(new byte[63], 0), "a control message is 64 bytes, never 63");
    });
  }
}
