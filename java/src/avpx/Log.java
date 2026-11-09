package avpx;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.function.Supplier;

// The server's log: each line on the screen, with the time, and in a file if one is set, which is kept to a size. Written 2026-11-08 by
// Melanikus for AVPx Dedicated Server, from log.js.
//
// What goes in it is decided where each line is made, and none of those lines ever holds an address, a code, a token or a name (the
// user's ruling: no IPs). This only adds the time, and keeps the file from growing without end: past MOST_FILE_BYTES it's moved to
// <file>.1 (and .1 to .2, up to OLD_FILES), and a new one started.
//
// It's the one place the server writes anything (CODING-STANDARD.md rule 5): tools/CheckStandard.java refuses System.out and System.err
// anywhere else in the server's code. The relay's thread and the list's threads all write to it, so one line is written at a time.
public final class Log {
  public static final long MOST_FILE_BYTES = 10L * 1024 * 1024;
  private static final int OLD_FILES = 3;

  // The time as Node's toISOString writes it: always with its milliseconds, always in UTC
  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  private final Path file;
  private final Supplier<Instant> now;
  private final PrintStream screen;
  private FileChannel open;
  private long size;

  // file: where lines go as well as the screen, or null for the screen only. now: the time (Instant::now for the server). screen: where
  // the screen's lines go (System.out for the server; a test passes one of its own).
  public Log(Path file, Supplier<Instant> now, PrintStream screen) {
    this.file = file;
    this.now = now;
    this.screen = screen;
  }

  // The screen: the one place in the server's code that names it (CODING-STANDARD.md rule 5)
  public static final PrintStream SCREEN = System.out;

  // A log to the screen only, with the real time: for the server before its settings are read
  public static Log screenOnly() {
    return new Log(null, Instant::now, SCREEN);
  }

  // The file is opened once, for adding to its end, and its size read through that same handle, so the size is the size of the very file
  // being written (looking it up by name could give another file's, if it were swapped between)
  private void openFile() throws IOException {
    open = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    size = open.size();
  }

  private void turnOver() throws IOException {
    open.close();
    open = null;

    for (int i = OLD_FILES - 1; i >= 1; i--) {
      moveIfThere(file.resolveSibling(file.getFileName() + "." + i), file.resolveSibling(file.getFileName() + "." + (i + 1)));
    }

    moveIfThere(file, file.resolveSibling(file.getFileName() + ".1"));
    openFile();
  }

  private static void moveIfThere(Path from, Path to) throws IOException {
    try {
      Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
    } catch (NoSuchFileException e) {
      // not there yet
    }
  }

  // Lets go of the file, when the server stops. A line written after this opens it again.
  public synchronized void close() {
    if (open == null) {
      return;
    }

    try {
      open.close();
    } catch (IOException e) {
      screen.print(TIME.format(now.get()) + " log: the log file could not be closed (" + e.getClass().getSimpleName() + ")\n");
    }

    open = null;
  }

  // Writes one line. A line break in it becomes a space, so one call is always one line.
  public synchronized void line(String words) {
    String text = TIME.format(now.get()) + " " + String.valueOf(words).replace('\r', ' ').replace('\n', ' ') + "\n";
    screen.print(text);
    screen.flush();

    if (file == null) {
      return;
    }

    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);

    try {
      if (open == null) {
        openFile();
      }

      if (size + bytes.length > MOST_FILE_BYTES) {
        turnOver();
      }

      ByteBuffer buffer = ByteBuffer.wrap(bytes);

      while (buffer.hasRemaining()) {
        open.write(buffer);
      }

      size += bytes.length;
    } catch (IOException e) {
      screen.print(TIME.format(now.get()) + " log: the log file could not be written (" + e.getClass().getSimpleName()
          + "); lines go to the screen only\n");
      screen.flush();
    }
  }
}
