package avpx.access;

import avpx.Fatal;
import avpx.list.Json;
import avpx.v2.Approvals;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// The access store: who has asked to play on this server, and what the owner decided (CRYPTO.md section 6, PROTOCOL.md's access requests,
// server #24). Written 2026-11-09 by Melanikus for AVPx Dedicated Server; Secondary's review of it fixed the same day (the review's
// numbers are given where each fix is).
//
// WHAT'S IN IT. One record for each player that has asked (POST /v1/access-requests): their fingerprint (32 hex digits, for people and
// the owner's tools), their id (96 hex digits, the whole SHA-384 the fingerprint is the start of: what the relay compares), the name
// they chose, its state, and when they first asked. Nothing else: no address, and not the player's keys, which the server never needs
// again (handshake A checks the id of the keys it's given).
//   waiting    asked, and nobody has decided yet. A waiting request is forgotten after 30 days, and may then ask again.
//   approved   the owner said yes: the relay takes this player (handshake A, refusal 22 otherwise)
//   refused    the owner said no. It stays so: asking again changes nothing, unless the owner forgets it (below).
//   revoked    the owner said yes, then took it back. It stays so, and the relay ends that player's sessions at once.
// A fingerprint is in the store once at most: a request whose fingerprint is a record's but whose id isn't (someone whose keys share
// only the first 16 bytes of hash) is refused, so every decision by fingerprint names exactly one player.
//
// WHO WRITES IT: only this server. The file is requests.json in the access folder (Settings.java's accessFolder; on a deployed machine
// /var/lib/avpx, which systemd makes, the only place the server may write: deploy/avpx-java.service). Every write is whole: a new file
// beside it, forced to the disk, then put in its place in one step (a rename), and the folder forced too. So a crash leaves the old file
// or the new one, never half of either.
//
// THE OWNER'S DECISIONS come as files the owner's own tools (kept off the repository, by the owner's rule) drop in the same folder:
//   decisions.<digits>    one decision a line: the fingerprint, one space, then approved, refused, revoked or forgotten, and a line end
//                         (\n); then one last line, "end " and how many decision lines came before it, and a line end. So a file read
//                         while it was still being written can never pass for a shorter one (the review's 2.2).
// The tools write it under another name first (one that doesn't match decisions.<digits>), then rename it without replacing anything,
// so a half-written file is never read, and a new file never lands on one not yet read. Each turn, the server reads them in the order
// of their names, and for each file:
//   - THE FILE IS HOSTILE INPUT (AVP Tao 3): it's looked at by its name, never through a link, and must be a plain file, owned by the
//     server's own user with no rights for anyone else (where the file system has owners), at most 64 KB. It's then opened (never
//     through a link) and read, and looked at again: it must still be the same file, unchanged (the review's 2.1). Then it must be ASCII,
//     every line exactly the shape above, and the end line's number right;
//   - every line must be a move the store allows, for a fingerprint the store has: waiting to approved, refused or forgotten; refused to
//     forgotten; approved to revoked; nothing else. FORGOTTEN takes the record out of the store, so that key may ask again: it's how
//     the owner clears junk a stranger sent, which otherwise fills the room for waiting requests for good (the review's 1.1). An approved
//     player is revoked, never forgotten, since a revoke ends their sessions; and a revoked one stays so. The lines are taken in order,
//     so a file may approve and then revoke the same player;
//   - one bad line refuses the whole file, which changes nothing and is deleted (and counted): a decision is applied whole or not at all;
//   - a good file is applied by writing the store as above, and only then is it deleted. If the store can't be written, nothing changes,
//     and the file stays for the next turn;
//   - a file is deleted only while its name still holds the file the turn read: a new one put there since is read at the next turn (the
//     review's 2.4). Anything under such a name that can't be deleted (a folder, say) is counted once, then left alone, and never counts
//     among the 100 files a turn, so it can't stand in front of the decisions after it (the review's 2.3).
// The tools then read requests.json again to see which decisions took.
//
// WHO MAY TOUCH THE FOLDER (where the file system has owners and modes, as the server's Linux has): the folder must be the server's own
// user's, with rights for nobody else (0700), and requests.json must be its own with none for anyone else. The server's own user is the
// owner the operating system gives a file the server makes there (and deletes again) when the store opens, not anything given on its
// command line (the review's 3.2). This is checked when the store
// opens, which then refuses, so the server doesn't start, with the reason; and again at every turn (the review's 3.1), where it stops the
// server (start, below), and the next start then refuses with the reason. A folder someone else could write is never one this server
// trusts.
//
// THREADS, AND WHY NOTHING WAITS FOR THE DISK (the review's 1.2). Three callers use the store:
//   - the relay's one thread, at every A1 (approved) and every tick (takeRevoked). It carries every game, so it never waits for a disk or
//     for a lock: the records it reads are one table that's swapped whole for a new one after each write, never changed in place, and the
//     revokes reach it through a queue;
//   - the list's connection threads, for a request: a new one is written to the disk, holding the store's lock for writing;
//   - the store's own thread (start), which takes the owner's decisions about once a second. It reads each file without that lock, and
//     takes the lock only to apply what it read and write the store.
// A turn that hangs would stop the revokes: a decisions file swapped, at just the wrong moment, for a named pipe (opening one waits for
// ever for someone to write to it, and Java has no way to open without waiting), or a disk that has stopped. So a watch, on a second
// thread, stops the server if a turn hasn't finished in 60 s: systemd starts it again, and a named pipe is then refused before it's
// opened, as anything but a plain file is.
public final class AccessStore implements Approvals {
  public static final String STORE_FILE = "requests.json";
  public static final int MOST_WAITING = 1000;
  public static final int MOST_RECORDS = 10000;
  public static final long WAITING_LIFE_MILLISECONDS = 30L * 24 * 60 * 60 * 1000;
  public static final int MOST_NAME_BYTES = 15;
  public static final long TURN_MILLISECONDS = 1000;
  public static final long STUCK_MILLISECONDS = 60_000;
  static final int MOST_STORE_BYTES = 4 * 1024 * 1024;
  static final int MOST_DECISION_FILE_BYTES = 64 * 1024;
  static final int MOST_DECISION_FILES_A_TURN = 100;
  static final int MOST_FOLDER_ENTRIES = 10000;
  private static final int TURNS_A_COUNTS_LINE = 60;
  private static final String NEW_STORE_FILE = ".requests.json.new";
  private static final String OWNER_PROBE_FILE = ".owner-probe";
  private static final int STORE_DEPTH = 3;
  private static final int FINGERPRINT_DIGITS = 32;
  private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{32}");
  private static final Pattern ID = Pattern.compile("[0-9a-f]{96}");
  private static final Pattern DECISION_FILE = Pattern.compile("decisions\\.[0-9]{1,20}");
  private static final Pattern DECISION_LINE = Pattern.compile("([0-9a-f]{32}) (approved|refused|revoked|forgotten)");
  private static final Pattern END_LINE = Pattern.compile("end ([1-9][0-9]{0,4})");
  private static final String FORGOTTEN = "forgotten";
  private static final Set<PosixFilePermission> FOLDER_MODE = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
      PosixFilePermission.OWNER_EXECUTE);
  private static final Set<PosixFilePermission> NOBODY_ELSE = EnumSet.of(PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE,
      PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE,
      PosixFilePermission.OTHERS_EXECUTE);

  // A record's state, as the store and the list's answers write it
  public enum State {
    WAITING("waiting"), APPROVED("approved"), REFUSED("refused"), REVOKED("revoked");

    private final String word;

    State(String word) {
      this.word = word;
    }

    public String word() {
      return word;
    }

    static State of(String word) {
      for (State s : values()) {
        if (s.word.equals(word)) {
          return s;
        }
      }

      return null;
    }
  }

  record Entry(String fingerprint, String id, String name, State state, long firstSeen) {
  }

  // A store file that can't be used, with the reason, which never holds a name or a fingerprint from the file
  public static final class Refused extends Exception {
    private static final long serialVersionUID = 1L;

    Refused(String words) {
      super("access store: " + words);
    }
  }

  // What happened since the last line of counts
  private static final class Counts {
    long asked;
    long askedAgain;
    long busy;
    long overNewLimits;
    long notTheirs;
    long expired;
    long decisions;
    long filesRefused;
    long leftAlone;
    long notWritten;
  }

  // What one look at a file found: what was there (what(), to know it again), and its bytes, or null if it isn't one the store may read
  record Looked(String what, byte[] bytes) {
  }

  private final Path folder;
  private final String user;                                // the server's own user where the file system has owners, "" where not
  private final Object writing = new Object();              // held to change the records and write them, and for the counts
  private final Object turning = new Object();              // one turn at a time
  private volatile Map<String, Entry> entries;              // by fingerprint, the first asked first: never changed, only swapped whole
  private final ConcurrentLinkedQueue<String> revoked = new ConcurrentLinkedQueue<>();
  private Counts counts = new Counts();                     // under writing
  private final Map<String, String> leftAlone = new HashMap<>();   // under turning: names that couldn't be deleted, and what was there
  private volatile boolean stopped;                         // the store stopped (start): it approves nobody, and keeps nothing
  private volatile boolean inTurn;
  private volatile long turnStartedAt;                      // System.nanoTime() at the start of the turn going on, while inTurn
  private ScheduledExecutorService runner;
  private Consumer<String> log;
  private Runnable whenFailed;
  private final AtomicBoolean told = new AtomicBoolean();

  private AccessStore(Path folder, String user, Map<String, Entry> entries) {
    this.folder = folder;
    this.user = user;
    this.entries = Collections.unmodifiableMap(entries);
  }

  // ----- The rules both sides share

  // A name as Fourth's page and this server both hold it (PROTOCOL.md): 1 to 15 bytes of printable ASCII (32 to 126) other than " and \,
  // so it never needs an escape anywhere, with no space at either end. Nothing below 32 means a name shown in the owner's terminal can't
  // hold a control sequence. (It may hold ` $ ( ) ; | & < > ', so the owner's tools never put a name on a shell's command line: the
  // review's 5.1, for the kit.)
  public static boolean isName(String name) {
    if (name == null || name.isEmpty() || name.length() > MOST_NAME_BYTES || name.charAt(0) == ' '
        || name.charAt(name.length() - 1) == ' ') {
      return false;
    }

    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);

      if (c < 32 || c > 126 || c == '"' || c == '\\') {
        return false;
      }
    }

    return true;
  }

  public static boolean isFingerprint(String fingerprint) {
    return fingerprint != null && FINGERPRINT.matcher(fingerprint).matches();
  }

  public static boolean isId(String id) {
    return id != null && ID.matcher(id).matches();
  }

  // ----- Looking at files: owners and modes (where the file system has them), and knowing a file again

  private static boolean posix() {
    return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  // What's under a name, never through a link: with its owner and mode where the file system has them
  private static BasicFileAttributes look(Path path) throws IOException {
    return posix() ? Files.readAttributes(path, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS)
        : Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
  }

  // Enough to know a file again: its kind, its number on the disk (Java's fileKey: on Linux the device and inode), its size and its time.
  // Two looks that give the same are taken as the same file, unchanged.
  private static String what(BasicFileAttributes a) {
    String kind = a.isRegularFile() ? "file" : a.isDirectory() ? "folder" : a.isSymbolicLink() ? "link" : "other";
    return kind + " " + a.fileKey() + " " + a.size() + " " + a.lastModifiedTime().toMillis();
  }

  // Whether what was looked at may be read: a plain file (not a link, a folder or a pipe) of at most `most` bytes, and where the file
  // system has owners, this server's own user's with no rights for anyone else
  private static boolean trusted(BasicFileAttributes a, String user, int most) {
    if (!a.isRegularFile() || a.size() > most) {
      return false;
    }

    if (a instanceof PosixFileAttributes p) {
      Set<PosixFilePermission> others = EnumSet.copyOf(NOBODY_ELSE);
      others.retainAll(p.permissions());
      return p.owner().getName().equals(user) && others.isEmpty();
    }

    return true;
  }

  // A file the store reads, looked at, then opened and read, then looked at again (the review's 2.1). Java can't look at a file it has
  // open (C's fstat), so the second look, by name, must find the very same file unchanged: that's how a file swapped in the middle is
  // caught. The bytes are null if it isn't one the store may read, or wasn't the same all the way through. Throws only if nothing is
  // there to look at.
  static Looked readTrusted(Path file, String user, int most) throws IOException {
    BasicFileAttributes before = look(file);
    String what = what(before);

    if (!trusted(before, user, most)) {
      return new Looked(what, null);
    }

    byte[] bytes;

    try (FileChannel channel = FileChannel.open(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      long size = channel.size();

      if (size > most) {
        return new Looked(what, null);
      }

      // One byte more than it should hold, so a file that grew while it was read is seen to have
      ByteBuffer buffer = ByteBuffer.allocate((int) size + 1);
      int n = 0;

      while (n >= 0 && buffer.hasRemaining()) {
        n = channel.read(buffer);
      }

      bytes = Arrays.copyOf(buffer.array(), buffer.position());
      BasicFileAttributes after = look(file);

      if (!trusted(after, user, most) || !what(after).equals(what) || bytes.length != after.size()) {
        return new Looked(what, null);
      }
    } catch (IOException e) {
      return new Looked(what, null);
    }

    return new Looked(what, bytes);
  }

  // What's wrong with the access folder, or null if nothing: it must be a folder (not a link to one), and where the file system has
  // owners, this server's own user's with rights for nobody else (0700). With user null, only that it's a folder (open asks that first,
  // before it makes the file that tells it who the server's own user is).
  private static String folderProblem(Path folder, String user) {
    BasicFileAttributes a;

    try {
      a = look(folder);
    } catch (NoSuchFileException e) {
      a = null;
    } catch (IOException e) {
      return "the access folder's owner and rights could not be read (" + e.getClass().getSimpleName() + ")";
    }

    if (a == null || !a.isDirectory()) {
      return "the access folder isn't a folder, or isn't there (on a deployed machine systemd makes /var/lib/avpx: "
          + "deploy/avpx-java.service)";
    }

    if (user != null && a instanceof PosixFileAttributes p && (!p.owner().getName().equals(user) || !p.permissions().equals(FOLDER_MODE))) {
      return "the access folder must be this server's own user's, with rights for nobody else (0700)";
    }

    return null;
  }

  // The user this server runs as, where the file system has owners, as the operating system itself says: the owner it gives a new file
  // this server makes, in the access folder, which is deleted again at once. Never Java's user.name, which a -Duser.name on the command
  // line would change (the review's 3.2). "" where there are no owners to check. Throws if the file can't be made: then the folder isn't
  // one this server may write, so it isn't the server's own.
  private static String processUser(Path folder) throws IOException {
    if (!posix()) {
      return "";
    }

    Path probe = folder.resolve(OWNER_PROBE_FILE);
    Files.deleteIfExists(probe);

    try {
      // Made new (never one already there, nor through a link), with rights for its owner only
      Files.createFile(probe, ownerOnly());
      return Files.readAttributes(probe, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS).owner().getName();
    } finally {
      Files.deleteIfExists(probe);
    }
  }

  // ----- Opening it

  // The store in folder, read and every record checked: a folder that must already be there, the server's own user's, 0700 (on a deployed
  // machine systemd makes it so). With no requests.json yet, the store is empty.
  public static AccessStore open(Path folder) throws Refused {
    String problem = folderProblem(folder, null);

    if (problem != null) {
      throw new Refused(problem);
    }

    String user;

    try {
      user = processUser(folder);
    } catch (IOException e) {
      throw new Refused("the access folder can't be written to by this server (" + e.getClass().getSimpleName() + "), so it isn't the "
          + "server's own");
    }

    problem = folderProblem(folder, user);

    if (problem != null) {
      throw new Refused(problem);
    }

    Path file = folder.resolve(STORE_FILE);
    byte[] bytes;

    try {
      if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
        return new AccessStore(folder, user, new LinkedHashMap<>());
      }

      bytes = readTrusted(file, user, MOST_STORE_BYTES).bytes();
    } catch (NoSuchFileException e) {
      return new AccessStore(folder, user, new LinkedHashMap<>());
    } catch (IOException e) {
      throw new Refused(STORE_FILE + " could not be read (" + e.getClass().getSimpleName() + ")");
    }

    if (bytes == null) {
      throw new Refused(STORE_FILE + " must be a plain file of at most " + MOST_STORE_BYTES + " bytes, the server's own, with rights for "
          + "nobody else (0600)");
    }

    return new AccessStore(folder, user, readEntries(bytes));
  }

  // The records in a store file's bytes, every one checked: exactly {"requests": [ ... ]}, and each record exactly its five fields
  static Map<String, Entry> readEntries(byte[] bytes) throws Refused {
    Map<String, Object> top;

    try {
      top = Json.readObject(bytes, STORE_DEPTH);
    } catch (Json.Bad e) {
      throw new Refused(STORE_FILE + " isn't JSON as this server writes it (" + e.getMessage() + ")");
    }

    List<Object> list = top == null || top.size() != 1 ? null : Json.list(top.get("requests"));

    if (list == null || list.size() > MOST_RECORDS) {
      throw new Refused(STORE_FILE + " must be {\"requests\": [...]}, with at most " + MOST_RECORDS + " records");
    }

    Map<String, Entry> out = new LinkedHashMap<>();
    int waiting = 0;

    for (int k = 0; k < list.size(); k++) {
      Map<String, Object> r = Json.object(list.get(k));
      String where = "record " + k;

      if (r == null || r.size() != 5 || !(r.get("fp") instanceof String fp) || !(r.get("id") instanceof String id)
          || !(r.get("name") instanceof String name) || !(r.get("state") instanceof String word)
          || !(r.get("firstSeen") instanceof Long firstSeen)) {
        throw new Refused(where + " must be exactly {fp, id, name, state, firstSeen}");
      }

      State state = State.of(word);

      // The fingerprint is the id's first 16 bytes, always. firstSeen is held to its range only, never to the clock: a server whose clock
      // went back must still start.
      if (!isFingerprint(fp) || !isId(id) || !id.startsWith(fp) || !isName(name) || state == null || firstSeen < 0) {
        throw new Refused(where + " has a field that isn't what this server writes");
      }

      if (out.put(fp, new Entry(fp, id, name, state, firstSeen)) != null) {
        throw new Refused(where + " names a fingerprint another record has");
      }

      if (state == State.WAITING && ++waiting > MOST_WAITING) {
        throw new Refused(STORE_FILE + " has more than " + MOST_WAITING + " waiting");
      }
    }

    return out;
  }

  // ----- A player asks

  // What a request gets back: the state of that player's record; NOT_THEIRS when the store has the fingerprint for another id; BUSY when
  // there's no room for one more waiting, or the list's day for new requests is used up; or CLOSED when it couldn't be kept (the store
  // couldn't be written, or has stopped)
  public enum Reply {
    WAITING, APPROVED, REFUSED, REVOKED, NOT_THEIRS, BUSY, CLOSED;

    static Reply of(State s) {
      return switch (s) {
        case WAITING -> WAITING;
        case APPROVED -> APPROVED;
        case REFUSED -> REFUSED;
        case REVOKED -> REVOKED;
      };
    }
  }

  // A request from a player (already checked by the list: the fingerprint and id worked out from good keys, the name to the rules
  // above). A player the store has gets their state, and keeps the name they first asked with. A new one is kept as waiting, if there's
  // room, and if newAllowed says yes: the list's limit on new requests from the sender's address and network (AccessLimits.java), asked
  // only here, for a request that would be kept, so a player asking again never uses it up.
  public Reply request(String fingerprint, String id, String name, long now, BooleanSupplier newAllowed) {
    if (!isFingerprint(fingerprint) || !isId(id) || !id.startsWith(fingerprint) || !isName(name)) {
      throw new IllegalArgumentException("AccessStore.request: a fingerprint, id and name the list has checked");
    }

    synchronized (writing) {
      if (stopped) {
        return Reply.CLOSED;
      }

      Entry known = entries.get(fingerprint);

      if (known != null) {
        if (!known.id().equals(id)) {
          counts.notTheirs++;
          return Reply.NOT_THEIRS;
        }

        counts.askedAgain++;
        return Reply.of(known.state());
      }

      if (waiting() >= MOST_WAITING || entries.size() >= MOST_RECORDS) {
        counts.busy++;
        return Reply.BUSY;
      }

      if (!newAllowed.getAsBoolean()) {
        counts.overNewLimits++;
        return Reply.BUSY;
      }

      Map<String, Entry> next = new LinkedHashMap<>(entries);
      next.put(fingerprint, new Entry(fingerprint, id, name, State.WAITING, now));

      if (!write(next)) {
        return Reply.CLOSED;
      }

      entries = Collections.unmodifiableMap(next);
      counts.asked++;
      return Reply.WAITING;
    }
  }

  private int waiting() {
    int n = 0;

    for (Entry e : entries.values()) {
      if (e.state() == State.WAITING) {
        n++;
      }
    }

    return n;
  }

  // ----- The relay asks: never a lock, never the disk

  // By the whole id: the record is found by its first 32 digits, and must then match all 96. A store that has stopped approves nobody.
  @Override
  public boolean approved(String id) {
    if (stopped || !isId(id)) {
      return false;
    }

    Entry e = entries.get(id.substring(0, FINGERPRINT_DIGITS));
    return e != null && e.id().equals(id) && e.state() == State.APPROVED;
  }

  // The ids revoked by the turns since the relay last asked, each once. The store's own thread takes the decisions (start); this only
  // hands over what it found.
  @Override
  public List<String> takeRevoked(long now) {
    List<String> out = new ArrayList<>();

    for (String id = revoked.poll(); id != null; id = revoked.poll()) {
      out.add(id);
    }

    return out;
  }

  // ----- Each turn: the folder checked, the owner's decisions, and the waiting requests that have run out

  // One turn. Gives back null, or what's wrong (the folder isn't the server's own and 0700 any more, or holds more than the store will
  // look through, so a decision in it might never be seen), and then nothing was taken and the store must stop (start). The waiting
  // requests that have run out go last, so a decision that came in time is taken (the review's 2.5). The store's own thread calls this
  // about once a second; a test may call it itself.
  public String turn(long now) {
    synchronized (turning) {
      String problem = folderProblem(folder, user);

      if (problem == null) {
        problem = takeDecisions();
      }

      if (problem != null) {
        return problem;
      }

      expire(now);
      return null;
    }
  }

  private void expire(long now) {
    synchronized (writing) {
      Map<String, Entry> next = new LinkedHashMap<>();
      int gone = 0;

      for (Entry e : entries.values()) {
        if (e.state() == State.WAITING && (now - e.firstSeen() >= WAITING_LIFE_MILLISECONDS)) {
          gone++;
        } else {
          next.put(e.fingerprint(), e);
        }
      }

      if (gone > 0 && write(next)) {
        entries = Collections.unmodifiableMap(next);
        counts.expired += gone;
      }
    }
  }

  // The decisions files in the folder now, at most MOST_DECISION_FILES_A_TURN of them, in the order of their names (time first: a shorter
  // number is an earlier one), each applied or refused. Null, or what's wrong.
  private String takeDecisions() {
    List<Path> named = new ArrayList<>();

    try (DirectoryStream<Path> all = Files.newDirectoryStream(folder)) {
      int seen = 0;

      for (Path p : all) {
        if (++seen > MOST_FOLDER_ENTRIES) {
          return "the access folder holds more than " + MOST_FOLDER_ENTRIES + " things, so a decision in it might never be seen";
        }

        if (DECISION_FILE.matcher(p.getFileName().toString()).matches()) {
          named.add(p);
        }
      }
    } catch (IOException | DirectoryIteratorException e) {
      return "the access folder could not be read for the owner's decisions (" + e.getClass().getSimpleName() + ")";
    }

    // What's left alone is remembered only while its name is still in the folder
    Set<String> names = new HashSet<>();

    for (Path p : named) {
      names.add(p.getFileName().toString());
    }

    leftAlone.keySet().retainAll(names);
    List<Path> files = new ArrayList<>();

    // Only plain files are decisions. Anything else under such a name is refused and deleted, or, if it can't be, counted once and left
    // alone; so is a file that couldn't be deleted when a turn was done with it. Neither is ever among the 100 a turn.
    for (Path p : named) {
      BasicFileAttributes a;

      try {
        a = look(p);
      } catch (IOException e) {
        // Gone since the folder was read: nothing to take
        continue;
      }

      String what = what(a);

      if (what.equals(leftAlone.get(p.getFileName().toString()))) {
        continue;
      }

      if (a.isRegularFile()) {
        files.add(p);
      } else {
        synchronized (writing) {
          counts.filesRefused++;
        }

        removeIfStill(p, what);
      }
    }

    files.sort(Comparator.comparingInt((Path p) -> p.getFileName().toString().length()).thenComparing(p -> p.getFileName().toString()));

    for (Path file : files.size() > MOST_DECISION_FILES_A_TURN ? files.subList(0, MOST_DECISION_FILES_A_TURN) : files) {
      if (!decide(file)) {
        // The store couldn't be written: the rest wait for the next turn, in their order
        break;
      }
    }

    return null;
  }

  // One decisions file: applied whole and deleted, refused whole and deleted, or (if the store couldn't be written) left. False only for
  // the last. The file is read without the lock for writing, so a request is never kept waiting by a file being read.
  private boolean decide(Path file) {
    Looked looked;

    try {
      looked = readTrusted(file, user, MOST_DECISION_FILE_BYTES);
    } catch (IOException e) {
      // Gone since it was looked at: nothing to take
      return true;
    }

    List<String[]> lines = looked.bytes() == null ? null : decisionLines(looked.bytes());

    synchronized (writing) {
      Map<String, Entry> next = lines == null ? null : applied(lines);

      if (next == null) {
        counts.filesRefused++;
      } else {
        if (!write(next)) {
          return false;
        }

        // The records first, then the revokes: by the time the relay ends a revoked player's sessions, its next A1 is already refused
        entries = Collections.unmodifiableMap(next);

        for (String[] line : lines) {
          if (line[1].equals("revoked")) {
            revoked.add(next.get(line[0]).id());
          }
        }

        counts.decisions += lines.size();
      }
    }

    removeIfStill(file, looked.what());
    return true;
  }

  // A file's decision lines, each [fingerprint, word], or null if the file isn't exactly the shape: ASCII, each line a decision, then
  // the end line with how many there were, then a line end
  static List<String[]> decisionLines(byte[] bytes) {
    for (byte b : bytes) {
      if (b < 0) {
        return null;
      }
    }

    String text = new String(bytes, StandardCharsets.US_ASCII);

    if (text.isEmpty() || !text.endsWith("\n")) {
      return null;
    }

    String[] lines = text.substring(0, text.length() - 1).split("\n", -1);
    Matcher end = END_LINE.matcher(lines[lines.length - 1]);

    if (!end.matches() || Integer.parseInt(end.group(1)) != lines.length - 1) {
      return null;
    }

    List<String[]> out = new ArrayList<>();

    for (int i = 0; i < lines.length - 1; i++) {
      Matcher m = DECISION_LINE.matcher(lines[i]);

      if (!m.matches()) {
        return null;
      }

      out.add(new String[] {m.group(1), m.group(2)});
    }

    return out;
  }

  // The records with these decisions taken in order, or null if any isn't a move the store allows
  private Map<String, Entry> applied(List<String[]> lines) {
    Map<String, Entry> next = new LinkedHashMap<>(entries);

    for (String[] line : lines) {
      Entry e = next.get(line[0]);

      // Forgotten: taken out of the store, from waiting or refused only
      if (line[1].equals(FORGOTTEN)) {
        if (e == null || (e.state() != State.WAITING && e.state() != State.REFUSED)) {
          return null;
        }

        next.remove(line[0]);
        continue;
      }

      State to = State.of(line[1]);
      boolean allowed = e != null && ((e.state() == State.WAITING && (to == State.APPROVED || to == State.REFUSED))
          || (e.state() == State.APPROVED && to == State.REVOKED));

      if (!allowed) {
        return null;
      }

      next.put(e.fingerprint(), new Entry(e.fingerprint(), e.id(), e.name(), to, e.firstSeen()));
    }

    return next;
  }

  // Deletes what the turn is done with, only while its name still holds what the turn looked at: a new file put there since is read at
  // the next turn. Something that can't be deleted is counted once, and left alone from then on.
  private void removeIfStill(Path file, String what) {
    try {
      if (!what(look(file)).equals(what)) {
        return;
      }

      Files.delete(file);
    } catch (NoSuchFileException e) {
      // already gone
    } catch (IOException e) {
      leftAlone.put(file.getFileName().toString(), what);

      synchronized (writing) {
        counts.leftAlone++;
      }
    }
  }

  // ----- Writing it

  // The records as requests.json, whole: a new file, forced to the disk, renamed into place, and the folder forced. False, and the file as
  // it was, if any step fails. Called holding the lock for writing.
  private boolean write(Map<String, Entry> records) {
    List<Object> list = new ArrayList<>();

    for (Entry e : records.values()) {
      Map<String, Object> r = new LinkedHashMap<>();
      r.put("fp", e.fingerprint());
      r.put("id", e.id());
      r.put("name", e.name());
      r.put("state", e.state().word());
      r.put("firstSeen", e.firstSeen());
      list.add(r);
    }

    Map<String, Object> top = new LinkedHashMap<>();
    top.put("requests", list);
    byte[] bytes = Json.write(top).getBytes(StandardCharsets.US_ASCII);
    Path fresh = folder.resolve(NEW_STORE_FILE);

    try {
      Files.deleteIfExists(fresh);

      try (FileChannel out = FileChannel.open(fresh, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), ownerOnly())) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);

        while (buffer.hasRemaining()) {
          out.write(buffer);
        }

        out.force(true);
      }

      Files.move(fresh, folder.resolve(STORE_FILE), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      forceFolder();
      return true;
    } catch (IOException | UnsupportedOperationException e) {
      counts.notWritten++;

      try {
        Files.deleteIfExists(fresh);
      } catch (IOException left) {
        // The next write deletes it first
      }

      return false;
    }
  }

  // 0600 where the file system has POSIX permissions (the server's Linux), and nothing to give where it hasn't (a test on Windows)
  private static FileAttribute<?>[] ownerOnly() {
    if (posix()) {
      return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))};
    }

    return new FileAttribute<?>[0];
  }

  // A rename is safe on the disk only once the folder that holds it is too. Linux lets a folder be opened and forced; Windows doesn't, and
  // its rename is already written through.
  private void forceFolder() throws IOException {
    if (!posix()) {
      return;
    }

    try (FileChannel f = FileChannel.open(folder, StandardOpenOption.READ)) {
      f.force(true);
    }
  }

  // ----- The store's own thread

  // Starts the turns: about once a second the owner's decisions are taken (turn), and once a minute a line of counts goes to log. The
  // store stops if a turn finds something wrong, if a turn hasn't finished in 60 s (seen by a watch on a second thread), or if a turn
  // throws (Fatal.java). Once stopped, it approves nobody and keeps nothing; it says why in log, and whenFailed is told, once: Main then
  // stops the server, for systemd to start it again. now: the time, in milliseconds since 1970.
  public synchronized void start(Consumer<String> log, LongSupplier now, Runnable whenFailed) {
    if (runner != null) {
      throw new IllegalStateException("AccessStore.start: once only");
    }

    this.log = log;
    this.whenFailed = whenFailed;
    runner = Executors.newScheduledThreadPool(2, task -> {
      Thread t = new Thread(task, "access");
      t.setDaemon(true);
      return t;
    });
    int[] turns = {0};

    // With a fixed delay: the next turn is only planned once this one has ended, so a turn that hangs never has others piled up behind it
    runner.scheduleWithFixedDelay(() -> {
      if (stopped) {
        return;
      }

      boolean wentAsExpected = Fatal.turn("access", () -> {
        turnStartedAt = System.nanoTime();
        inTurn = true;
        String problem;

        try {
          problem = turn(now.getAsLong());
        } finally {
          inTurn = false;
        }

        if (problem != null) {
          stop(problem);
        } else if (++turns[0] % TURNS_A_COUNTS_LINE == 0) {
          log.accept(countsLine());
        }
      }, log);

      if (!wentAsExpected) {
        // Fatal has written the line
        stop(null);
      }
    }, TURN_MILLISECONDS, TURN_MILLISECONDS, TimeUnit.MILLISECONDS);

    runner.scheduleAtFixedRate(() -> {
      if (!stopped && stuck(inTurn, turnStartedAt, System.nanoTime())) {
        stop("a turn of the owner's decisions hasn't finished in " + STUCK_MILLISECONDS / 1000 + " s (a decisions file swapped for a named "
            + "pipe, or a disk that has stopped), so a revoke might never be taken");
      }
    }, TURN_MILLISECONDS, TURN_MILLISECONDS, TimeUnit.MILLISECONDS);
  }

  // Whether a turn that started at startedAt is still going at nowNanos, more than STUCK_MILLISECONDS on. System.nanoTime() never goes
  // back, unlike the clock, and is compared by difference, as it must be.
  static boolean stuck(boolean inTurn, long startedAt, long nowNanos) {
    return inTurn && nowNanos - startedAt > TimeUnit.MILLISECONDS.toNanos(STUCK_MILLISECONDS);
  }

  // The store stops: it approves nobody and keeps nothing from now on, and whenFailed is told, once, after the line saying why (none when
  // Fatal has written it)
  private void stop(String words) {
    stopped = true;

    if (told.compareAndSet(false, true)) {
      if (words != null) {
        log.accept("access: " + words + "; the server stops, for systemd to start it again");
      }

      whenFailed.run();
    }
  }

  // Whether the store has stopped (start)
  public boolean stopped() {
    return stopped;
  }

  // The turns end: for the server's own stop. A turn going on is interrupted, and a write it was making is left undone, with the old
  // file in place.
  public synchronized void stopTurns() {
    if (runner != null) {
      runner.shutdownNow();
    }
  }

  // ----- The log

  // The counts since the last line, then cleared: counts only, never a name, a fingerprint or an id
  public String countsLine() {
    synchronized (writing) {
      Counts c = counts;
      counts = new Counts();
      int approvedNow = 0;

      for (Entry e : entries.values()) {
        if (e.state() == State.APPROVED) {
          approvedNow++;
        }
      }

      return "access: " + c.asked + " new requests, " + c.askedAgain + " asked again, " + c.notTheirs + " refused as another's fingerprint, "
          + c.busy + " refused as busy, " + c.overNewLimits + " over the day's limit on new requests, " + c.expired
          + " forgotten after 30 days waiting; " + c.decisions + " decisions applied, " + c.filesRefused + " decision files refused, "
          + c.leftAlone + " that couldn't be deleted and are left alone, " + c.notWritten + " times the store couldn't be written. Now "
          + waiting() + " waiting, " + approvedNow + " approved";
    }
  }
}
