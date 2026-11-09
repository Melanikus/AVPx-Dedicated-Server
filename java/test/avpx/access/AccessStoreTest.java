package avpx.access;

import static avpx.testing.Tests.doesNotThrow;
import static avpx.testing.Tests.ok;
import static avpx.testing.Tests.same;
import static avpx.testing.Tests.test;
import static avpx.testing.Tests.throwsWith;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

// The tests of AccessStore.java: requests kept and read back, the owner's decisions taken whole or not at all, approval by the whole id,
// and every file it reads held as hostile input. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
public final class AccessStoreTest {
  private AccessStoreTest() {
  }

  private static final long NOW = 1794268800000L;   // 2026-11-11, in milliseconds
  private static final long DAY = 24L * 60 * 60 * 1000;
  private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

  // Player number n's fingerprint (32 hex digits) and id (96, starting with the fingerprint), different for every n
  private static String fp(int n) {
    return String.format("%032x", n + 1L);
  }

  private static String id(int n) {
    return fp(n) + String.format("%064x", n + 7L);
  }

  private static Path folder() throws IOException {
    return Files.createTempDirectory("avpx-access-test-");
  }

  private static void remove(Path folder) throws IOException {
    try (Stream<Path> all = Files.walk(folder)) {
      for (Path p : all.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(p);
      }
    }
  }

  // A decisions file, as the owner's tools write it: rights for its owner only, where the file system has them
  private static void decide(Path folder, String name, byte[] bytes) throws IOException {
    Path file = folder.resolve(name);
    Files.write(file, bytes);

    if (POSIX) {
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }
  }

  private static void decide(Path folder, String name, String text) throws IOException {
    decide(folder, name, text.getBytes(StandardCharsets.US_ASCII));
  }

  private static String stored(Path folder) throws IOException {
    return Files.readString(folder.resolve(AccessStore.STORE_FILE), StandardCharsets.US_ASCII);
  }

  private static void refusedStore(String text, String why) {
    throwsWith(() -> AccessStore.readEntries(text.getBytes(StandardCharsets.US_ASCII)), "access store: ", why);
  }

  public static void register() {
    test("a request is kept as waiting, written whole, and read back; asking again gives the state and keeps the first name", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        same(store.request(fp(1), id(1), "Ripley", NOW), AccessStore.Reply.WAITING, "a new request: waiting");
        same(stored(folder), "{\"requests\":[{\"fp\":\"" + fp(1) + "\",\"id\":\"" + id(1) + "\",\"name\":\"Ripley\",\"state\":\"waiting\","
            + "\"firstSeen\":" + NOW + "}]}", "written as it is: fingerprint, id, name, state, time, and nothing else");
        same(store.request(fp(1), id(1), "Hicks", NOW + 1000), AccessStore.Reply.WAITING, "asking again: still waiting");
        ok(stored(folder).contains("\"Ripley\"") && !stored(folder).contains("Hicks"), "with the first name kept");
        ok(!store.approved(id(1)), "waiting isn't approved");
        AccessStore again = AccessStore.open(folder);
        same(again.request(fp(1), id(1), "Ripley", NOW), AccessStore.Reply.WAITING, "a store opened afresh has it");

        if (POSIX) {
          same(PosixFilePermissions.toString(Files.getPosixFilePermissions(folder.resolve(AccessStore.STORE_FILE))), "rw-------",
              "the store's file has rights for its owner only (0600)");
        }

        try (Stream<Path> left = Files.list(folder)) {
          same(left.map(p -> p.getFileName().toString()).toList(), List.of(AccessStore.STORE_FILE), "and no file but the store is left");
        }
      } finally {
        remove(folder);
      }
    });

    test("a fingerprint names one player: a request whose fingerprint is a record's but whose id isn't is refused", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Ripley", NOW);
        String sameStart = fp(1) + "f".repeat(64);
        same(store.request(fp(1), sameStart, "Bishop", NOW), AccessStore.Reply.NOT_THEIRS, "another id with Ripley's fingerprint: not theirs");
        ok(!stored(folder).contains("Bishop"), "and nothing of it is kept");
        ok(store.countsLine().contains("1 refused as another's fingerprint"), "counted");
      } finally {
        remove(folder);
      }
    });

    test("approval is by the whole id: the right fingerprint with another id, or the fingerprint alone, is never approved", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Ripley", NOW);
        store.request(fp(0xabb), id(0xabb), "Hicks", NOW);
        decide(folder, "decisions.1", fp(1) + " approved\n" + fp(0xabb) + " approved\n");
        store.turn(NOW);
        ok(store.approved(id(1)) && store.approved(id(0xabb)), "Ripley's and Hicks's own ids: approved");
        ok(!store.approved(fp(1) + "0".repeat(64)), "her fingerprint with another 64 digits after it: not");
        ok(!store.approved(fp(1)), "her fingerprint alone: not");
        ok(!store.approved(id(0xabb).toUpperCase()), "his id in capitals (...ABC...): not");
        ok(!store.approved(null) && !store.approved(id(1) + "0") && !store.approved(id(1).substring(1)), "nor anything but an id");
      } finally {
        remove(folder);
      }
    });

    test("the owner's decisions: waiting to approved or refused, approved to revoked, each applied whole, and the file then deleted", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);

        for (int i = 1; i <= 4; i++) {
          store.request(fp(i), id(i), "Player " + i, NOW);
        }

        decide(folder, "decisions.100", fp(1) + " approved\n" + fp(2) + " refused\n" + fp(3) + " approved\n" + fp(3) + " revoked\n");
        same(store.takeRevoked(NOW), List.of(id(3)), "the turn applies it: player 3, approved then revoked in the same file, is given back by id");
        ok(store.approved(id(1)), "player 1 approved");
        ok(!store.approved(id(2)) && !store.approved(id(3)) && !store.approved(id(4)), "2 refused, 3 revoked, 4 still waiting");
        same(store.request(fp(2), id(2), "x", NOW), AccessStore.Reply.REFUSED, "a refused player asking again: refused, and it stays so");
        same(store.request(fp(3), id(3), "x", NOW), AccessStore.Reply.REVOKED, "a revoked one: revoked");
        same(store.request(fp(1), id(1), "x", NOW), AccessStore.Reply.APPROVED, "an approved one: approved");
        ok(!Files.exists(folder.resolve("decisions.100")), "the file is deleted once applied");
        same(store.takeRevoked(NOW), List.of(), "and a revoke is given back once only");
        ok(AccessStore.open(folder).approved(id(1)), "the decisions are in the store's file: a store opened afresh has them");
      } finally {
        remove(folder);
      }
    });

    test("a decisions file with any bad line, or any move the store doesn't allow, changes nothing, and is deleted", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Player 1", NOW);
        store.request(fp(2), id(2), "Player 2", NOW);
        decide(folder, "decisions.1", fp(2) + " refused\n");
        store.turn(NOW);
        String before = stored(folder);
        List<String> bad = List.of(
            fp(1) + " approved\n" + fp(9) + " approved\n",                  // a fingerprint the store doesn't have
            fp(1) + " revoked\n",                                           // waiting to revoked
            fp(2) + " approved\n",                                          // refused to approved
            fp(1) + " approved\n" + fp(1) + " approved\n",                  // approved to approved
            fp(1) + " waiting\n",                                           // back to waiting
            fp(1) + " approved",                                            // no line end at the end
            fp(1) + " approved\r\n",                                        // a Windows line end
            fp(1) + "  approved\n",                                         // two spaces
            fp(1) + " Approved\n",                                          // a capital
            fp(0xabb).toUpperCase() + " approved\n",                        // capitals in a fingerprint (...ABC)
            fp(1).substring(1) + " approved\n",                             // 31 hex digits
            id(1) + " approved\n",                                          // a whole id, not a fingerprint
            fp(1) + " approved\n\n",                                        // an empty line
            "",                                                             // nothing at all
            fp(1) + " approved\n# a comment\n",                             // anything else
            fp(1) + " approv" + (char) 0xe9 + "d\n",                       // not ASCII (an e with an accent, written as UTF-8 below)
            (fp(1) + " approved\n").repeat(1700));                          // more than 64 KB

        for (int i = 0; i < bad.size(); i++) {
          decide(folder, "decisions." + (10 + i), bad.get(i).getBytes(StandardCharsets.UTF_8));
          store.turn(NOW);
          ok(!Files.exists(folder.resolve("decisions." + (10 + i))), "bad file " + i + " is deleted");
          same(stored(folder), before, "bad file " + i + " changed nothing");
          ok(!store.approved(id(1)), "bad file " + i + " approved nobody");
        }

        ok(store.countsLine().contains((bad.size()) + " decision files refused"), "each counted, as a refused file");
      } finally {
        remove(folder);
      }
    });

    test("a decisions file anyone else could have written or read is refused (on Linux, where files have owners and modes)", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Player 1", NOW);

        if (POSIX) {
          for (String mode : List.of("rw-r--r--", "rw-rw----", "rw-----w-", "rw----r--")) {
            Path file = folder.resolve("decisions.5");
            Files.writeString(file, fp(1) + " approved\n", StandardCharsets.US_ASCII);
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(mode));
            store.turn(NOW);
            ok(!store.approved(id(1)) && !Files.exists(file), "a decisions file of mode " + mode + ": refused, and deleted");
          }

          decide(folder, "decisions.6", fp(1) + " approved\n");
          store.turn(NOW);
          ok(store.approved(id(1)), "the same file with rights for its owner only (0600, as the owner's tools write it): taken");
        } else {
          ok(true, "this file system has no owners and modes: checked on Linux, in CI");
        }
      } finally {
        remove(folder);
      }
    });

    test("the access folder must be the server's own, 0700, and its store file 0600, or the store doesn't open (on Linux)", () -> {
      Path folder = folder();

      try {
        if (POSIX) {
          same(PosixFilePermissions.toString(Files.getPosixFilePermissions(folder)), "rwx------", "(a new temporary folder is 0700)");
          AccessStore.open(folder).request(fp(1), id(1), "Player 1", NOW);
          Files.setPosixFilePermissions(folder.resolve(AccessStore.STORE_FILE), PosixFilePermissions.fromString("rw-r--r--"));
          throwsWith(() -> AccessStore.open(folder), "rights for nobody else (0600)", "a store file others could read");
          Files.setPosixFilePermissions(folder.resolve(AccessStore.STORE_FILE), PosixFilePermissions.fromString("rw-------"));
          doesNotThrow(() -> AccessStore.open(folder), "0600 again: it opens");

          for (String mode : List.of("rwxr-xr-x", "rwx---rwx", "rwxrwx---", "rwx--x--x")) {
            Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString(mode));
            throwsWith(() -> AccessStore.open(folder), "with rights for nobody else (0700)", "an access folder of mode " + mode);
          }

          Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwx------"));
        } else {
          ok(true, "this file system has no owners and modes: checked on Linux, in CI");
        }
      } finally {
        remove(folder);
      }
    });

    test("only files named decisions.<digits> are read, in the order of their numbers; anything else is left alone", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Player 1", NOW);

        for (String other : List.of("decisions.tmp", ".decisions.5", "decisions.12a", "decisions.", "decisions.123456789012345678901",
            "Decisions.5", "decisions.5.new")) {
          decide(folder, other, fp(1) + " approved\n");
        }

        store.turn(NOW);
        ok(!store.approved(id(1)), "none of those names is read: a tool's half-written file is never taken");
        ok(Files.exists(folder.resolve("decisions.tmp")), "and they're left where they are");

        // 9 before 10: a shorter number is an earlier one. So the approve in 9 comes first, and the revoke in 10 then applies.
        decide(folder, "decisions.10", fp(1) + " revoked\n");
        decide(folder, "decisions.9", fp(1) + " approved\n");
        same(store.takeRevoked(NOW), List.of(id(1)), "decisions.9, then decisions.10: approved, then revoked");
      } finally {
        remove(folder);
      }
    });

    test("a decisions file that's a link is never followed: it's refused, and the file it points to is left as it was", () -> {
      Path folder = folder();
      Path outside = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Player 1", NOW);
        Path target = outside.resolve("decisions.1");
        decide(outside, "decisions.1", fp(1) + " approved\n");
        boolean made;

        try {
          Files.createSymbolicLink(folder.resolve("decisions.1"), target);
          made = true;
        } catch (IOException | UnsupportedOperationException e) {
          // Windows lets only some accounts make links: CI's Linux run checks this
          made = false;
        }

        if (made) {
          store.turn(NOW);
          ok(!store.approved(id(1)), "the link isn't read");
          ok(!Files.exists(folder.resolve("decisions.1"), LinkOption.NOFOLLOW_LINKS), "the link itself is deleted");
          ok(Files.exists(target), "and the file it pointed to is still there");
        } else {
          ok(true, "this account can't make a link here, so this is checked on Linux, in CI");
        }
      } finally {
        remove(folder);
        remove(outside);
      }
    });

    test("a waiting request is forgotten after 30 days, and may ask again; a decided one is kept", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Old", NOW);
        store.request(fp(2), id(2), "Decided", NOW);
        decide(folder, "decisions.1", fp(2) + " approved\n");
        store.turn(NOW + 30 * DAY - 1);
        same(store.request(fp(1), id(1), "x", NOW + 30 * DAY - 1), AccessStore.Reply.WAITING, "a millisecond short of 30 days: still there");
        store.turn(NOW + 30 * DAY);
        ok(!stored(folder).contains(fp(1)), "at 30 days: gone from the file");
        ok(store.approved(id(2)), "the approved one is kept");
        same(store.request(fp(1), id(1), "New", NOW + 30 * DAY), AccessStore.Reply.WAITING, "and the forgotten one may ask again");
        ok(stored(folder).contains("\"New\""), "as a new request, with its new name");
      } finally {
        remove(folder);
      }
    });

    test("at most 1,000 waiting: the next is busy, and a request already there still gets its state", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);

        for (int i = 0; i < AccessStore.MOST_WAITING; i++) {
          store.request(fp(i), id(i), "Player", NOW);
        }

        same(store.request(fp(5000), id(5000), "One more", NOW), AccessStore.Reply.BUSY, "the 1,001st waiting: busy");
        same(store.request(fp(0), id(0), "Player", NOW), AccessStore.Reply.WAITING, "one already there: its state");
        ok(store.countsLine().contains("1 refused as busy"), "counted");
      } finally {
        remove(folder);
      }
    });

    test("the store's own file is hostile input too: anything this server wouldn't write stops it opening", () -> {
      String one = "{\"fp\":\"" + fp(1) + "\",\"id\":\"" + id(1) + "\",\"name\":\"Ripley\",\"state\":\"waiting\",\"firstSeen\":1}";
      ok(AccessStore.readEntries(("{\"requests\":[" + one + "]}").getBytes(StandardCharsets.US_ASCII)).size() == 1, "first, a good one reads");
      refusedStore("{\"requests\":[" + one + "],\"more\":1}", "another field at the top");
      refusedStore("{\"request\":[" + one + "]}", "another name for the list");
      refusedStore("[" + one + "]", "a list, not an object");
      refusedStore("{\"requests\":[" + one.replace("\"firstSeen\":1", "\"firstSeen\":1,\"key\":\"x\"") + "]}", "a record with a sixth field");
      refusedStore("{\"requests\":[" + one.replace(",\"id\":\"" + id(1) + "\"", "") + "]}", "a record with no id");
      refusedStore("{\"requests\":[" + one.replace(id(1), id(2)) + "]}", "an id that doesn't start with the record's fingerprint");
      refusedStore("{\"requests\":[" + one.replace(id(1), id(1).substring(2)) + "]}", "an id of 94 digits");
      refusedStore("{\"requests\":[" + one.replace(fp(1), fp(0xabb).toUpperCase()) + "]}", "a fingerprint in capitals (...ABC)");
      refusedStore("{\"requests\":[" + one.replace("Ripley", " Ripley") + "]}", "a name starting with a space");
      refusedStore("{\"requests\":[" + one.replace("Ripley", "Ripley\\u0007") + "]}", "a name with a control character");
      refusedStore("{\"requests\":[" + one.replace("waiting", "maybe") + "]}", "a state there's no such thing as");
      refusedStore("{\"requests\":[" + one.replace("\"firstSeen\":1", "\"firstSeen\":-1") + "]}", "a time before 1970");
      refusedStore("{\"requests\":[" + one.replace("\"firstSeen\":1", "\"firstSeen\":\"1\"") + "]}", "a time that's text");
      refusedStore("{\"requests\":[" + one + "," + one + "]}", "one fingerprint twice");
      refusedStore("not JSON", "not JSON at all");
      throwsWith(() -> AccessStore.open(Path.of("no-such-folder-avpx")), "isn't a folder", "a folder that isn't there");
    });

    test("names: 1 to 15 bytes of printable ASCII but \" and \\, with no space at either end", () -> {
      for (String good : List.of("A", "Melanikus", "Ripley 2", "x".repeat(15), "!#$%&'()*+,-./0", "a~b")) {
        ok(AccessStore.isName(good), "\"" + good + "\" is a name");
      }

      for (String bad : List.of("", "x".repeat(16), " Ripley", "Ripley ", "Rip\"ley", "Rip\\ley", "Rip\nley", "Rip\u0000ley", "Rip\u007fley",
          "Rip" + (char) 0xe9 + "ley", "\t")) {
        ok(!AccessStore.isName(bad), "a name refused: " + bad.length() + " characters");
      }
    });

    // Fourth's vectors (2026-11-09), from the game's own test of its access code, so the game, this server and the owner's tools all make
    // the same code from the same fingerprint
    test("the access code: the fingerprint's first 80 bits, as 16 letters in groups of four, the game's own answers", () -> {
      String[][] vectors = {
          {"00000000000000000000000000000000", "2222-2222-2222-2222"},
          {"ffffffffffffffffffffffffffffffff", "ZZZZ-ZZZZ-ZZZZ-ZZZZ"},
          {"000102030405060708090a0b0c0d0e0f", "222J-62S6-2N52-G42B"},
          {"0123456789abcdef0123456789abcdef", "26KN-CTWB-PH8Y-Y2B5"},
          {"f0e1d2c3b4a5968778695a4b3c2d1e0f", "Y5JX-7JXN-NQDA-GY5B"},
          {"80000000000000000000000000000000", "J222-2222-2222-2222"},
          {"00000000000000000001000000000000", "2222-2222-2222-2223"},
          {"0000000000000000000000ffffffffff", "2222-2222-2222-2222"},
          {"08421084210842108421000000000000", "3333-3333-3333-3333"}};

      for (String[] v : vectors) {
        same(AccessCode.of(v[0]), v[1], v[0]);
      }

      throwsWith(() -> AccessCode.of("ABCDEF" + "0".repeat(26)), "a fingerprint", "capitals");
      throwsWith(() -> AccessCode.of("0".repeat(31)), "a fingerprint", "31 digits");
    });

    test("the counts line holds counts only: no name, no fingerprint and no id", () -> {
      Path folder = folder();

      try {
        AccessStore store = AccessStore.open(folder);
        store.request(fp(1), id(1), "Ripley", NOW);
        String line = store.countsLine();
        ok(line.startsWith("access: 1 new requests"), "it counts the request");
        ok(!line.contains("Ripley") && !line.contains(fp(1)), "and says nothing of who");
        ok(store.countsLine().startsWith("access: 0 new requests"), "and counts afresh after each line");
      } finally {
        remove(folder);
      }
    });
  }
}
