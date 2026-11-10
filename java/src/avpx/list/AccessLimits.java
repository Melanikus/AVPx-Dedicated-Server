package avpx.list;

import avpx.relay.AddressHasher;
import avpx.relay.PerSender;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.HexFormat;

// The limits on POST /v1/access-requests (PROTOCOL.md section 4, "The limits"). Written 2026-11-09 by Melanikus for AVPx Dedicated Server,
// for Secondary's review of the access store, finding 1.1.
//
// WHY THERE ARE TWO KINDS. A key costs nothing to make, so a stranger can send any number of new requests, each a key the list has never
// seen, and fill the 1,000 places for waiting requests, so that honest players get "busy" for a month. So:
//   - EVERY TRY, before its body is even read: 1 a minute and 10 an hour from one address. Asking again (how a player sees their state)
//     costs only these.
//   - A NEW REQUEST, a key the store doesn't have yet, once its body has been checked and the store would keep it: 5 a day from one
//     address, and 10 a day from one network. AccessStore.request asks this only then, so a malformed try or a player asking again
//     never uses up anyone's day.
// Every bucket starts full again each day (below), so one address can add at most 10 a day (5 at once, then 5 more as its bucket fills),
// and one network 20: in the 30 days a waiting request stays, at most 300 from one address and 600 from one network, so neither can
// fill the 1,000 places alone. Filling them takes 100 networks at once, or 50 over a day. A real crowd of machines can still do it,
// since free keys can't be told from real ones: that's SERVER-BLOCKERS.md's line before the list is announced, and the owner's
// "forgotten" decision (AccessStore.java) clears what came in.
//
// A NETWORK is an IPv4 address's first 24 bits, or an IPv6 address's first 48: about what one home, or one hosting customer, is given
// (the list listens on IPv4 only for now). Its key is made with the same hasher as an address's, so no network is kept either.
//
// A CROWD OF SENDERS can't reset these: each limit remembers at most `most` senders, and forgets one only once its bucket is full again
// (PerSender.keepingDrained). These are TCP connections, so an address can't be made up.
//
// THE DAY is the hasher's: its secret changes every 24 hours, and every bucket starts again with it.
//
// Not safe from two threads at once, like the hasher it shares: ListServer keeps it under its one lock.
final class AccessLimits {
  static final double PER_MINUTE_RATE = 1.0 / 60;
  static final double PER_MINUTE_BURST = 1;
  static final double PER_HOUR_RATE = 10.0 / 3600;
  static final double PER_HOUR_BURST = 10;
  static final double NEW_PER_DAY_RATE = 5.0 / (24 * 60 * 60);
  static final double NEW_PER_DAY_BURST = 5;
  static final double NEW_PER_NETWORK_RATE = 10.0 / (24 * 60 * 60);
  static final double NEW_PER_NETWORK_BURST = 10;
  static final int IPV4_NETWORK_BYTES = 3;
  static final int IPV6_NETWORK_BYTES = 6;
  static final int IPV6_SENDER_BYTES = 8;

  private final PerSender perMinute;
  private final PerSender perHour;
  private final PerSender newPerDay;
  private final PerSender newPerNetwork;

  AccessLimits(int mostSenders, AddressHasher hasher) {
    perMinute = PerSender.keepingDrained(PER_MINUTE_RATE, PER_MINUTE_BURST, mostSenders, hasher);
    perHour = PerSender.keepingDrained(PER_HOUR_RATE, PER_HOUR_BURST, mostSenders, hasher);
    newPerDay = PerSender.keepingDrained(NEW_PER_DAY_RATE, NEW_PER_DAY_BURST, mostSenders, hasher);
    newPerNetwork = PerSender.keepingDrained(NEW_PER_NETWORK_RATE, NEW_PER_NETWORK_BURST, mostSenders, hasher);
  }

  // A try from this address, at now: both limits are asked (and spent from) only while the one before allows it
  boolean allowsTry(InetAddress from, long now) {
    String address = senderOf(from);
    return perMinute.allows(address, now) && perHour.allows(address, now);
  }

  // A new request from this address, at now: its address's day first, then its network's
  boolean allowsNew(InetAddress from, long now) {
    return newPerDay.allows(senderOf(from), now) && newPerNetwork.allows(networkOf(from), now);
  }

  // Who a sender is, for its own limits: an IPv4 address itself, or an IPv6 address's first 64 bits (Secondary's re-check, N-1). A
  // machine on IPv6 is usually given a whole /64, so keyed by the full address, one host could hold every one of a limit's buckets short
  // of full, with one try from each of many of its addresses, and keepingDrained would then refuse every new sender. The list listens on
  // IPv4 only for now: this is for the day it doesn't. Never written anywhere: it's only hashed.
  static String senderOf(InetAddress from) {
    return from instanceof Inet4Address ? from.getHostAddress() : "v6 " + HexFormat.of().formatHex(from.getAddress(), 0, IPV6_SENDER_BYTES);
  }

  // The network an address is in, as text: "v4 " and the first 3 bytes in hex, or "v6 " and the first 6. Never written anywhere: it's only
  // hashed, as an address is.
  static String networkOf(InetAddress from) {
    byte[] bytes = from.getAddress();
    boolean v4 = from instanceof Inet4Address;
    int keep = v4 ? IPV4_NETWORK_BYTES : IPV6_NETWORK_BYTES;
    return (v4 ? "v4 " : "v6 ") + HexFormat.of().formatHex(bytes, 0, keep);
  }
}
