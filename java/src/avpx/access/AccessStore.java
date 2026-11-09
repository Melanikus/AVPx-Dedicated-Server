package avpx.access;

import avpx.list.Json;
import avpx.v2.Approvals;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
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
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// The access store: who has asked to play on this server, and what the owner decided (CRYPTO.md section 6, PROTOCOL.md's access requests,
// server #24). Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// WHAT'S IN IT. One record for each player that has asked (POST /v1/access-requests): their fingerprint (32 hex digits, for people and
// the owner's tools), their id (96 hex digits, the whole SHA-384 the fingerprint is the start of: what the relay compares), the name
// they chose, its state, and when they first asked. Nothing else: no address, and not the player's keys, which the server never needs
// again (handshake A checks the id of the keys it's given).
//   waiting    asked, and nobody has decided yet. A waiting request is forgotten after 30 days, and may then ask again.
//   approved   the owner said yes: the relay takes this player (handshake A, refusal 22 otherwise)
//   refused    the owner said no. It stays so: asking again changes nothing.
//   revoked    the owner said yes, then took it back. It stays so too, and the relay ends that player's sessions at once.
// A fingerprint is in the store once at most: a request whose fingerprint is a record's but whose id isn't (someone whose keys share
// only the first 16 bytes of hash) is refused, so every decision by fingerprint names exactly one player.
//
// WHO WRITES IT: only this server. The file is requests.json in the access folder (Settings.java's accessFolder; on a deployed machine
// /var/lib/avpx, which systemd makes, the only place the server may write: deploy/avpx-java.service). Every write is whole: a new file
// beside it, forced to the disk, then put in its place in one step (a rename), and the folder forced too. So a crash leaves the old file
// or the new one, never half of either.
//
// THE OWNER'S DECISIONS come as files the owner's own tools (kept off the repository, by the owner's rule) drop in the same folder:
//   decisions.<digits>    one decision a line: the fingerprint, one space, then approved, refused or revoked, and a line end (\n)
// The tools write it under another name first (one that doesn't match decisions.<digits>), then rename it, so a half-written file is
// never read. Each turn, the server reads them in the order of their names, and for each file:
//   - THE FILE IS HOSTILE INPUT (AVP Tao 3): it's read only if it's a plain file (not a link), owned by the folder's owner with no rights
//     for anyone else (where the file system has owners), at most 64 KB, ASCII, every line exactly the shape above;
//   - every line must be a move the store allows: waiting to approved or refused, approved to revoked, and nothing else, for a fingerprint
//     the store has; the lines are taken in order, so a file may approve and then revoke the same player;
//   - one bad line refuses the whole file, which changes nothing and is deleted (and counted): a decision is applied whole or not at all;
//   - a good file is applied by writing the store as above, and only then is it deleted. If the store can't be written, nothing changes,
//     and the file stays for the next turn.
// The tools then read requests.json again to see whether the decision took.
//
// WHO MAY TOUCH THE FOLDER (where the file system has owners and modes, as the server's Linux has): the folder must be the server's own
// user's, with rights for nobody else (0700), and requests.json must be its own with none for anyone else; otherwise the store doesn't
// open and the server doesn't start, with the reason. A file someone else could have written is never one this server trusts.
//
// It's used from the list's threads (a request) and the relay's (an A1, a turn), so every call holds the one lock.
public final class AccessStore implements Approvals {
  public static final String STORE_FILE = "requests.json";
  public static final int MOST_WAITING = 1000;
  public static final int MOST_RECORDS = 10000;
  public static final long WAITING_LIFE_MILLISECONDS = 30L * 24 * 60 * 60 * 1000;
  public static final int MOST_NAME_BYTES = 15;
  static final int MOST_STORE_BYTES = 4 * 1024 * 1024;
  static final int MOST_DECISION_FILE_BYTES = 64 * 1024;
  static final int MOST_DECISION_FILES_A_TURN = 100;
  static final int MOST_FOLDER_ENTRIES_A_TURN = 10000;
  private static final String NEW_STORE_FILE = ".requests.json.new";
  private static final int STORE_DEPTH = 3;
  private static final int FINGERPRINT_DIGITS = 32;
  private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{32}");
  private static final Pattern ID = Pattern.compile("[0-9a-f]{96}");
  private static final Pattern DECISION_FILE = Pattern.compile("decisions\\.[0-9]{1,20}");
  private static final Pattern DECISION_LINE = Pattern.compile("([0-9a-f]{32}) (approved|refused|revoked)");
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
    long notTheirs;
    long expired;
    long decisions;
    long filesRefused;
    long notWritten;
  }

  private final Path folder;
  private Map<String, Entry> entries;            // by fingerprint, the first asked first
  private final List<String> revoked = new ArrayList<>();
  private Counts counts = new Counts();

  private AccessStore(Path folder, Map<String, Entry> entries) {
    this.folder = folder;
    this.entries = entries;
  }

  // ----- The rules both sides share

  // A name as Fourth's page and this server both hold it (PROTOCOL.md): 1 to 15 bytes of printable ASCII (32 to 126) other than " and \,
  // so it never needs an escape anywhere, with no space at either end. Nothing below 32 means a name shown in the owner's terminal can't
  // hold a control sequence.
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

  // ----- Owners and modes (where the file system has them)

  private static boolean posix() {
    return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  // Whether a file (never a link's target) is owned by owner, with no rights for anyone else. True where the file system has no owners.
  private static boolean ownOnly(Path file, String owner) throws IOException {
    if (!posix()) {
      return true;
    }

    PosixFileAttributes a = Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    Set<PosixFilePermission> others = EnumSet.copyOf(NOBODY_ELSE);
    others.retainAll(a.permissions());
    return a.owner().getName().equals(owner) && others.isEmpty();
  }

  // The folder's owner where the file system has owners, or "" where it hasn't
  private static String ownerOf(Path folder) throws IOException {
    return posix() ? Files.readAttributes(folder, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS).owner().getName() : "";
  }

  // ----- Opening it

  // The store in folder, read and every record checked: a folder that must already be there, the server's own user's, 0700 (on a deployed
  // machine systemd makes it so). With no requests.json yet, the store is empty.
  public static AccessStore open(Path folder) throws Refused {
    if (!Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS)) {
      throw new Refused("the access folder isn't a folder (on a deployed machine systemd makes /var/lib/avpx: deploy/avpx-java.service)");
    }

    String owner;

    try {
      owner = ownerOf(folder);

      if (posix()) {
        PosixFileAttributes a = Files.readAttributes(folder, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);

        if (!owner.equals(System.getProperty("user.name")) || !a.permissions().equals(FOLDER_MODE)) {
          throw new Refused("the access folder must be this server's own user's, with rights for nobody else (0700)");
        }
      }
    } catch (IOException e) {
      throw new Refused("the access folder's owner and rights could not be read (" + e.getClass().getSimpleName() + ")");
    }

    Path file = folder.resolve(STORE_FILE);
    byte[] bytes;

    try {
      if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
        return new AccessStore(folder, new LinkedHashMap<>());
      }

      if (!ownOnly(file, owner)) {
        throw new Refused(STORE_FILE + " must be the access folder's owner's, with rights for nobody else (0600)");
      }

      bytes = readAtMost(file, MOST_STORE_BYTES);
    } catch (NoSuchFileException e) {
      return new AccessStore(folder, new LinkedHashMap<>());
    } catch (IOException e) {
      throw new Refused(STORE_FILE + " could not be read (" + e.getClass().getSimpleName() + ")");
    }

    if (bytes == null) {
      throw new Refused(STORE_FILE + " is more than " + MOST_STORE_BYTES + " bytes, or not a plain file");
    }

    return new AccessStore(folder, readEntries(bytes));
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

  // At most `most` bytes of a plain file (never one a link points to), or null if it's bigger or isn't a plain file
  private static byte[] readAtMost(Path file, int most) throws IOException {
    BasicFileAttributes attributes = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);

    if (!attributes.isRegularFile() || attributes.size() > most) {
      return null;
    }

    try (SeekableByteChannel channel = Files.newByteChannel(file, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        InputStream in = Channels.newInputStream(channel)) {
      byte[] bytes = in.readNBytes(most + 1);
      return bytes.length > most ? null : bytes;
    }
  }

  // ----- A player asks

  // What a request gets back: the state of that player's record; NOT_THEIRS when the store has the fingerprint for another id; BUSY when
  // there's no room for one more waiting; or CLOSED when it couldn't be kept (the store couldn't be written)
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
  // above). A player the store has gets their state, and keeps the name they first asked with. A new one is kept as waiting.
  public synchronized Reply request(String fingerprint, String id, String name, long now) {
    if (!isFingerprint(fingerprint) || !isId(id) || !id.startsWith(fingerprint) || !isName(name)) {
      throw new IllegalArgumentException("AccessStore.request: a fingerprint, id and name the list has checked");
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

    Map<String, Entry> next = new LinkedHashMap<>(entries);
    next.put(fingerprint, new Entry(fingerprint, id, name, State.WAITING, now));

    if (!write(next)) {
      return Reply.CLOSED;
    }

    entries = next;
    counts.asked++;
    return Reply.WAITING;
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

  // ----- The relay asks

  // By the whole id: the record is found by its first 32 digits, and must then match all 96
  @Override
  public synchronized boolean approved(String id) {
    if (!isId(id)) {
      return false;
    }

    Entry e = entries.get(id.substring(0, FINGERPRINT_DIGITS));
    return e != null && e.id().equals(id) && e.state() == State.APPROVED;
  }

  @Override
  public synchronized List<String> takeRevoked(long now) {
    turn(now);
    List<String> out = List.copyOf(revoked);
    revoked.clear();
    return out;
  }

  // ----- Each turn: the owner's decisions, and the waiting requests that have run out

  // Called about once a second, by the relay and by the list
  public synchronized void turn(long now) {
    expire(now);

    String owner;

    try {
      owner = ownerOf(folder);
    } catch (IOException e) {
      return;
    }

    for (Path file : decisionFiles()) {
      if (!decide(file, owner)) {
        // The store couldn't be written: the rest wait for the next turn, in their order
        return;
      }
    }
  }

  private void expire(long now) {
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
      entries = next;
      counts.expired += gone;
    }
  }

  // The decision files in the folder now, at most MOST_DECISION_FILES_A_TURN of them, in the order of their names (time first: a shorter
  // number is an earlier one)
  private List<Path> decisionFiles() {
    List<Path> out = new ArrayList<>();

    try (DirectoryStream<Path> all = Files.newDirectoryStream(folder)) {
      int seen = 0;

      for (Path p : all) {
        if (++seen > MOST_FOLDER_ENTRIES_A_TURN) {
          break;
        }

        if (DECISION_FILE.matcher(p.getFileName().toString()).matches()) {
          out.add(p);
        }
      }
    } catch (IOException e) {
      return List.of();
    }

    out.sort(Comparator.comparingInt((Path p) -> p.getFileName().toString().length()).thenComparing(p -> p.getFileName().toString()));
    return out.size() > MOST_DECISION_FILES_A_TURN ? out.subList(0, MOST_DECISION_FILES_A_TURN) : out;
  }

  // One decisions file: applied whole and deleted, refused whole and deleted, or (if the store couldn't be written) left. False only for
  // the last.
  private boolean decide(Path file, String owner) {
    List<String[]> lines;

    try {
      byte[] bytes = ownOnly(file, owner) ? readAtMost(file, MOST_DECISION_FILE_BYTES) : null;
      lines = bytes == null ? null : decisionLines(bytes);
    } catch (IOException e) {
      lines = null;
    }

    Map<String, Entry> next = lines == null ? null : applied(lines);

    if (next == null) {
      counts.filesRefused++;
      deleteQuietly(file);
      return true;
    }

    if (!write(next)) {
      return false;
    }

    for (String[] line : lines) {
      if (line[1].equals("revoked")) {
        revoked.add(next.get(line[0]).id());
      }
    }

    entries = next;
    counts.decisions += lines.size();
    deleteQuietly(file);
    return true;
  }

  // A file's lines, each [fingerprint, state], or null if any line isn't exactly the shape (or the file isn't ASCII, or has none)
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

    List<String[]> out = new ArrayList<>();

    for (String line : text.substring(0, text.length() - 1).split("\n", -1)) {
      Matcher m = DECISION_LINE.matcher(line);

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

  private static void deleteQuietly(Path file) {
    try {
      Files.deleteIfExists(file);
    } catch (IOException e) {
      // It's read again next turn: as a decision already taken, it's then refused whole and deleted
    }
  }

  // ----- Writing it

  // The records as requests.json, whole: a new file, forced to the disk, renamed into place, and the folder forced. False, and the file as
  // it was, if any step fails.
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
      deleteQuietly(fresh);
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

  // ----- The log

  // The counts since the last line, then cleared: counts only, never a name, a fingerprint or an id
  public synchronized String countsLine() {
    Counts c = counts;
    counts = new Counts();
    int approvedNow = 0;

    for (Entry e : entries.values()) {
      if (e.state() == State.APPROVED) {
        approvedNow++;
      }
    }

    return "access: " + c.asked + " new requests, " + c.askedAgain + " asked again, " + c.notTheirs + " refused as another's fingerprint, "
        + c.busy + " refused as busy, " + c.expired + " forgotten after 30 days waiting; " + c.decisions + " decisions applied, "
        + c.filesRefused + " decision files refused, " + c.notWritten + " times the store couldn't be written. Now " + waiting()
        + " waiting, " + approvedNow + " approved";
  }
}
