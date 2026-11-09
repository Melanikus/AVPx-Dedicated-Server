package avpx.list;

import static avpx.testing.Tests.notSame;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;

import avpx.relay.AddressHasher;
import avpx.testing.SeededRandom;
import java.net.InetAddress;

// The tests of AccessLimits.java: every try held to 1 a minute and 10 an hour from one address; a new request to 5 a day from one address
// and 10 a day from one network; and a crowd of senders that can't start any of them afresh. Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server, for Secondary's review of the access store, 1.1.
public final class AccessLimitsTest {
  private AccessLimitsTest() {
  }

  private static final long NOW = 1794268800000L;
  private static final long MINUTE = 60_000;

  // An address written as digits (InetAddress.ofLiteral never asks a name server)
  private static InetAddress at(String literal) {
    return InetAddress.ofLiteral(literal);
  }

  private static AccessLimits limits(int most) {
    return new AccessLimits(most, new AddressHasher(SeededRandom.of(3)));
  }

  public static void register() {
    test("every try: 1 a minute from one address, and 10 an hour", () -> {
      AccessLimits l = limits(100);
      ok(l.allowsTry(at("203.0.113.7"), NOW), "the first");
      ok(!l.allowsTry(at("203.0.113.7"), NOW + 1000), "not another a second later");
      ok(l.allowsTry(at("203.0.113.8"), NOW + 1000), "another address has its own");

      // The hour's limit holds 10, and fills by one every 6 minutes: so at one a minute, tries 1 to 11 go through, and the 12th doesn't
      for (int i = 1; i <= 10; i++) {
        ok(l.allowsTry(at("203.0.113.7"), NOW + i * MINUTE), "one a minute: try " + (i + 1));
      }

      ok(!l.allowsTry(at("203.0.113.7"), NOW + 11 * MINUTE), "but the 12th, 11 minutes in, is refused by the hour's limit");
      ok(l.allowsTry(at("203.0.113.7"), NOW + 17 * MINUTE), "and the hour's limit lets one more through 6 minutes on");
    });

    test("a new request: 5 a day from one address, and 10 a day from one network (an IPv4 address's first 24 bits)", () -> {
      AccessLimits l = limits(100);

      for (int i = 0; i < 5; i++) {
        ok(l.allowsNew(at("198.51.100.1"), NOW), "new request " + (i + 1) + " from one address");
      }

      ok(!l.allowsNew(at("198.51.100.1"), NOW), "the 6th from that address in a day: refused");

      for (int i = 0; i < 5; i++) {
        ok(l.allowsNew(at("198.51.100.2"), NOW), "another address in the same network: its own 5, the network's 6th to 10th");
      }

      ok(!l.allowsNew(at("198.51.100.3"), NOW), "a third address in that network, with all its own 5: refused, the network's 10 are used");
      ok(l.allowsNew(at("198.51.101.3"), NOW), "an address in the next network along: allowed");
      ok(l.allowsNew(at("198.51.100.1"), NOW + 24L * 60 * 60 * 1000), "and a day on, the hasher's new secret starts every bucket again");
    });

    test("an IPv6 sender, for its own limits, is its first 64 bits: one host's /64 is one sender (Secondary's re-check, N-1)", () -> {
      AccessLimits l = limits(100);
      ok(l.allowsTry(at("2001:db8:1:2::1"), NOW), "the first try from a /64");
      ok(!l.allowsTry(at("2001:db8:1:2::ffff"), NOW + 1000), "another address in the same /64, a second later: the same sender, refused");
      ok(l.allowsTry(at("2001:db8:1:3::1"), NOW + 1000), "the next /64 along: another sender");
      same(AccessLimits.senderOf(at("198.51.100.7")), "198.51.100.7", "an IPv4 address is itself");
      same(AccessLimits.senderOf(at("2001:db8:1:2:aaaa::1")), "v6 20010db800010002", "an IPv6 one is its first 8 bytes");
    });

    test("a network is the first 24 bits of an IPv4 address, or the first 48 of an IPv6 one", () -> {
      same(AccessLimits.networkOf(at("198.51.100.250")), "v4 c63364", "198.51.100.x");
      same(AccessLimits.networkOf(at("198.51.100.1")), AccessLimits.networkOf(at("198.51.100.250")), "one /24, one network");
      notSame(AccessLimits.networkOf(at("198.51.101.1")), AccessLimits.networkOf(at("198.51.100.1")), "the next /24, another");
      same(AccessLimits.networkOf(at("2001:db8:1:2::1")), "v6 20010db80001", "2001:db8:1:...");
      same(AccessLimits.networkOf(at("2001:db8:1:ffff::9")), AccessLimits.networkOf(at("2001:db8:1:2::1")), "one /48, one network");
      notSame(AccessLimits.networkOf(at("2001:db8:2::1")), AccessLimits.networkOf(at("2001:db8:1::1")), "the next /48, another");
      same(AccessLimits.networkOf(at("::ffff:198.51.100.7")), "v4 c63364", "an IPv4 address written as IPv6 is the IPv4 one");
    });

    test("a crowd of more senders than the limits remember can't start any of them afresh: a new sender is refused instead", () -> {
      AccessLimits l = limits(3);
      ok(l.allowsTry(at("192.0.2.1"), NOW) && l.allowsTry(at("192.0.2.2"), NOW) && l.allowsTry(at("192.0.2.3"), NOW), "three senders");
      ok(!l.allowsTry(at("192.0.2.4"), NOW), "a fourth, while the oldest still holds part of its limit: refused");
      ok(!l.allowsTry(at("192.0.2.1"), NOW + 1000), "and the first is still held to its minute, not started again");
      ok(l.allowsTry(at("192.0.2.4"), NOW + 60L * 60 * 1000), "an hour on, every bucket is full again, so the oldest may go: allowed");
    });
  }
}
