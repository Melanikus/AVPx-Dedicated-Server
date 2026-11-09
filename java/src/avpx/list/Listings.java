package avpx.list;

import avpx.list.Requests.Listing;
import avpx.list.Requests.Refusal;
import avpx.relay.Crypto;
import avpx.relay.Pass;
import avpx.relay.RandomBytes;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// What the list holds: the games hosts have listed, each checked with its relay's pass. Written 2026-11-08 by Melanikus for AVPx Dedicated
// Server, from list/listings.js.
//
// The list may be on another machine than a game's relay, and never asks the relay anything. A host shows the list the pass its relay
// gave it (Pass.java), and the list makes the pass again with that relay's key: if it matches and is less than a minute old, the room is
// real. The host then gets an OWNER key, 16 random bytes that travel only over HTTPS, and only it can change or take down its listing with
// that. The host renews its listing with a fresh pass every 15 s; one not renewed for LISTING_LIFE_MILLISECONDS goes.
//
// A game is known here by its region and code together: two relays could, rarely, make the same code.
//
// Nothing here is an address, and nothing here is written anywhere but the counts in tick's line. It isn't safe to use from two threads at
// once: the list's server holds one lock around it (ListServer.java). PROTOCOL.md sections 3 and 4.
public final class Listings {
  public static final int MOST_LISTINGS = 2000;
  static final long LISTING_LIFE_MILLISECONDS = 45000;       // a host renews every 15 s
  static final long PASS_LIFE_MILLISECONDS = 60000;          // a pass is good for a minute after its pass time
  static final long MOST_PASS_AHEAD_MILLISECONDS = 5000;     // and not at all if its time is ahead of the list's own clock by more than this
  static final long STATS_MILLISECONDS = 60000;
  private static final int OWNER_BYTES = 16;

  // A relay the list knows: its region, where games find it, and its pass key, which never leaves the list
  public record Relay(String region, String host, int port, byte[] passKey) {
  }

  // A game on the list
  static final class Entry {
    Listing shown;
    final byte[] owner;
    final long listedAt;
    long renewedAt;

    Entry(Listing shown, byte[] owner, long listedAt, long renewedAt) {
      this.shown = shown;
      this.owner = owner;
      this.listedAt = listedAt;
      this.renewedAt = renewedAt;
    }
  }

  // What happened since the last line of counts
  static final class Counts {
    long listed;
    long renewed;
    long ended;
    long expired;
    long passesRefused;
    long full;
  }

  private final Map<String, Relay> relays = new LinkedHashMap<>();
  private final RandomBytes random;
  final Map<String, Entry> byGame = new LinkedHashMap<>();   // by "region code", the first listed first
  private long statsAt;
  private Counts counts = new Counts();

  // relays: every relay the list knows, already checked (Settings.java). random: where owner keys come from. now: the time.
  public Listings(List<Relay> relays, RandomBytes random, long now) {
    for (Relay r : relays) {
      this.relays.put(r.region(), new Relay(r.region(), r.host(), r.port(), r.passKey().clone()));
    }

    this.random = random;
    this.statsAt = now;
  }

  private static String key(String region, String code) {
    return region + " " + code;
  }

  // The relays, as GET /v1/relays gives them: never a key
  public List<Map<String, Object>> relayList() {
    List<Map<String, Object>> out = new ArrayList<>();

    for (Relay r : relays.values()) {
      Map<String, Object> shown = new LinkedHashMap<>();
      shown.put("region", r.region());
      shown.put("host", r.host());
      shown.put("port", r.port());
      out.add(shown);
    }

    return out;
  }

  // Whether a pass is good for this region and code, at now: made with that relay's key, and less than a minute old
  boolean passIsGood(String region, String code, byte[] pass, long passTime, long now) throws Refusal {
    Relay relay = relays.get(region);

    if (relay == null) {
      throw new Refusal(400, "region must be one of the regions in GET /v1/relays");
    }

    // passTime is at most 2 to the 53rd (Requests.java), so this can't overflow
    long madeAt = passTime * 1000;

    if (now > madeAt + PASS_LIFE_MILLISECONDS || madeAt > now + MOST_PASS_AHEAD_MILLISECONDS || pass.length != Pass.PASS_BYTES) {
      return false;
    }

    return Crypto.same(pass, Pass.make(relay.passKey(), region, code.getBytes(StandardCharsets.ISO_8859_1), passTime));
  }

  private void checkPass(byte[] pass, Listing listing, long now) throws Refusal {
    if (!passIsGood(listing.region(), listing.code(), pass, listing.passTime(), now)) {
      counts.passesRefused++;
      throw new Refusal(403, "that pass is not good: ask the relay for a fresh one");
    }
  }

  // The listing for this game, if it's there and alive
  private Entry find(String region, String code, long now) {
    Entry entry = byGame.get(key(region, code));
    return entry != null && now - entry.renewedAt < LISTING_LIFE_MILLISECONDS ? entry : null;
  }

  // POST: puts a game on the list. Gives back its owner key, as 32 hex digits.
  public String add(byte[] pass, Listing listing, long now) throws Refusal {
    checkPass(pass, listing, now);

    if (find(listing.region(), listing.code(), now) != null) {
      throw new Refusal(409, "that game is listed already");
    }

    expire(now);

    if (byGame.size() >= MOST_LISTINGS) {
      counts.full++;
      throw new Refusal(503, "the list is full: try again later");
    }

    // A listing of this game whose time ran out is gone by now (expire, above), so the new one goes last, as the newest
    byte[] owner = random.next(OWNER_BYTES);
    byGame.put(key(listing.region(), listing.code()), new Entry(listing, owner, now, now));
    counts.listed++;
    return Crypto.hex(owner);
  }

  // PUT: renews a listing, and changes what it says, with its owner key and a fresh pass
  public void renew(byte[] owner, byte[] pass, Listing listing, long now) throws Refusal {
    checkPass(pass, listing, now);
    Entry old = find(listing.region(), listing.code(), now);

    if (old == null) {
      throw new Refusal(404, "that game is not listed");
    }

    if (!Crypto.same(owner, old.owner)) {
      throw new Refusal(403, "that is not the owner key of that listing");
    }

    old.shown = listing;
    old.renewedAt = now;
    counts.renewed++;
  }

  // DELETE: takes a listing down, with its owner key. The room itself is the relay's, and stays until its host ends it.
  public void remove(String region, String code, byte[] owner, long now) throws Refusal {
    Entry old = find(region, code, now);

    if (old == null) {
      throw new Refusal(404, "that game is not listed");
    }

    if (!Crypto.same(owner, old.owner)) {
      throw new Refusal(403, "that is not the owner key of that listing");
    }

    Arrays.fill(old.owner, (byte) 0);
    byGame.remove(key(region, code));
    counts.ended++;
  }

  // A live listing, as the list shows it, with how long it has been listed in whole seconds
  record Shown(Listing listing, long listedAt) {
  }

  // The live listings of one network version, the newest first, at most `most`
  List<Shown> games(int version, long now, int most) {
    List<Entry> live = new ArrayList<>();

    for (Entry entry : byGame.values()) {
      if (entry.shown.version() == version && now - entry.renewedAt < LISTING_LIFE_MILLISECONDS) {
        live.add(entry);
      }
    }

    // The newest first; two listed at the same moment stay in the order they were listed (Java's sort keeps equal ones in order)
    live.sort(Comparator.comparingLong((Entry entry) -> entry.listedAt).reversed());
    List<Shown> out = new ArrayList<>();

    for (int i = 0; i < live.size() && i < most; i++) {
      out.add(new Shown(live.get(i).shown, live.get(i).listedAt));
    }

    return out;
  }

  // Takes down every listing not renewed in time
  private void expire(long now) {
    Iterator<Entry> entries = byGame.values().iterator();

    while (entries.hasNext()) {
      Entry entry = entries.next();

      if (now - entry.renewedAt >= LISTING_LIFE_MILLISECONDS) {
        Arrays.fill(entry.owner, (byte) 0);
        entries.remove();
        counts.expired++;
      }
    }
  }

  // Called about once a second: takes down what has run out, and gives back the line to write, if any (counts only)
  public List<String> tick(long now) {
    expire(now);

    if (now - statsAt < STATS_MILLISECONDS) {
      return List.of();
    }

    return List.of(countsLine(now));
  }

  // The line of counts since the last one, made now, whatever the time: tick gives one a minute, and the list's server gives one more as
  // it stops, so the last part of a minute isn't lost. Counts only.
  public String countsLine(long now) {
    Counts c = counts;
    String line = "list: in the last " + Math.round((now - statsAt) / 1000.0) + " s: " + c.listed + " games listed, " + c.renewed
        + " renewals, " + c.ended + " taken down, " + c.expired + " ended unrenewed; " + c.passesRefused + " passes refused, " + c.full
        + " refused as the list was full. Now " + byGame.size() + " listed";
    statsAt = now;
    counts = new Counts();
    return line;
  }
}
