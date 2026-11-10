package avpx.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

// Proves the checks can fail: breaks the code one thing at a time, in a copy, and runs the check each row names. Every row must make its
// check fail. Written 2026-11-09 by Melanikus for AVPx Dedicated Server, after tools/takeouts.js.
//
// A test that passes only shows the code does what the test looks for. This shows the tests would notice the code going wrong: each row
// of java/tools/takeouts.txt takes out one thing (a limit, a check, a refusal), and a test, or the standard check, must fail on it.
//
//   java -cp java/build/tools avpx.tools.Takeouts       run from the repository's top folder, after java/build.sh; exits 1 if any row
//                                                       isn't noticed, can't find its text, or the unbroken copy fails
//   ... avpx.tools.Takeouts --shard K/N                 the same for one share of the rows: those whose number (from 0), divided by N,
//                                                       leaves K. N runs, K from 0 to N-1, run every row once between them.
//
// WHY SHARES (2026-11-09): each row builds and tests a whole copy, so the rows' time grows with them. At 220 rows the one job no longer
// fit its 45 minutes, and GitHub cancelled it, so no row was proved. .github/workflows/java.yml runs the shares as one job each, side by
// side: N is GitHub's own count of them (strategy.job-total) and K each one's own place (strategy.job-index), so no share can be left out
// or run twice by a list written wrong. Each share checks the unbroken copy first, as the whole run does.
//
// Before any row, the unbroken copy must pass, or every row would "fail" for the wrong reason.
//
// THE ROWS FILE is plain text, so each row reads as what it does. A row is:
//
//     === its name
//     check: tests            (or: standard, or: live)
//     file: java/src/avpx/relay/RelayCore.java
//     <<< from
//     the lines it takes out, whole lines, each exactly as in the file
//     <<< to
//     the lines it puts in their place (none at all, to take them out)
//     >>>
//
// or, for a row that makes a new file, "<<< new file" and that file's lines, or "<<< new file in hex" and its bytes as hex digits (for
// bytes this file, which must be ASCII, can't hold), then ">>>". Lines starting with # between rows are comments. "from" must be in its
// file exactly once.
//
// The checks: "tests" runs java/build.sh in the copy without the live tests; "live" runs it with them (AVPX_LIVE=1), one row at a time,
// because the live tests use fixed ports; "standard" runs CheckStandard on the copy, inside this program. "tests" and "standard" rows run
// several at once.
public final class Takeouts {
  private Takeouts() {
  }

  private static final Path ROWS = Path.of("java", "tools", "takeouts.txt");

  // What a copy holds: the Java version, and what its tests read (the vectors, the example settings) and its standard check checks
  private static final List<String> COPY = List.of("java", "test-vectors", "deploy", ".github");
  private static final String SKIP = "java/build";

  // A row's file: a plain path below the copy's top folder, nothing that could climb out of it
  private static final Pattern PLAIN_PATH = Pattern.compile("[A-Za-z0-9_.][A-Za-z0-9_./-]*");

  // The shell, by its full path, so it can't be another program of that name found first in the PATH
  private static final String SHELL = "/bin/sh";

  private static final Set<String> CHECKS = Set.of("tests", "standard", "live");

  private static final long MOST_MINUTES_A_CHECK = 10;
  private static final int MOST_AT_ONCE = 4;
  private static final int MOST_SHARES = 50;
  private static final Pattern SHARE = Pattern.compile("[0-9]{1,2}/[0-9]{1,2}");

  record Row(int number, String name, String check, String file, String from, String to, byte[] newFile) {
  }

  // The rows, read from the rows file
  static List<Row> read(List<String> lines) {
    List<Row> rows = new ArrayList<>();
    int k = 0;

    while (k < lines.size()) {
      String line = lines.get(k);

      if (line.isBlank() || line.startsWith("#")) {
        k++;
        continue;
      }

      if (!line.startsWith("=== ")) {
        throw new IllegalArgumentException("takeouts.txt line " + (k + 1) + ": a row starts with \"=== \" and its name");
      }

      String name = line.substring(4);
      String check = field(lines, k + 1, "check: ");
      String file = field(lines, k + 2, "file: ");

      // Every row is whole: a name, a check that exists, a plain file path, and its text (as Node's takeouts-file test asked of its rows)
      if (name.isBlank() || !CHECKS.contains(check) || !PLAIN_PATH.matcher(file).matches() || file.contains("..")) {
        throw new IllegalArgumentException("takeouts.txt line " + (k + 1) + ": a row needs a name, a check (tests, standard or live) and a "
            + "plain file path");
      }
      k += 3;
      String block = k < lines.size() ? lines.get(k) : "";
      k++;
      StringBuilder first = new StringBuilder();
      StringBuilder second = new StringBuilder();
      StringBuilder into = first;
      boolean sawTo = false;

      while (k < lines.size() && !lines.get(k).equals(">>>")) {
        if (block.equals("<<< from") && lines.get(k).equals("<<< to")) {
          into = second;
          sawTo = true;
        } else {
          into.append(lines.get(k)).append('\n');
        }

        k++;
      }

      if (k >= lines.size()) {
        throw new IllegalArgumentException("takeouts.txt: row \"" + name + "\" has no >>> at its end");
      }

      k++;

      switch (block) {
        case "<<< from" -> {
          if (!sawTo) {
            throw new IllegalArgumentException("takeouts.txt: row \"" + name + "\" has a from but no <<< to");
          }

          rows.add(new Row(rows.size(), name, check, file, first.toString(), second.toString(), null));
        }
        case "<<< new file" -> rows.add(new Row(rows.size(), name, check, file, null, null,
            first.toString().getBytes(StandardCharsets.US_ASCII)));
        case "<<< new file in hex" -> rows.add(new Row(rows.size(), name, check, file, null, null,
            HexFormat.of().parseHex(first.toString().replaceAll("\\s", ""))));
        default -> throw new IllegalArgumentException("takeouts.txt: row \"" + name + "\" needs <<< from, <<< new file or <<< new file in hex");
      }
    }

    return rows;
  }

  private static String field(List<String> lines, int k, String start) {
    if (k >= lines.size() || !lines.get(k).startsWith(start)) {
      throw new IllegalArgumentException("takeouts.txt line " + (k + 1) + ": \"" + start.trim() + "\" was expected");
    }

    return lines.get(k).substring(start.length());
  }

  // ----- Copies

  private static Path makeCopy(Path root) throws IOException {
    Path where = Files.createTempDirectory("avpx-takeouts-");

    for (String item : COPY) {
      Path from = root.resolve(item);

      if (!Files.exists(from)) {
        continue;
      }

      try (Stream<Path> all = Files.walk(from)) {
        for (Path p : all.toList()) {
          String rel = root.relativize(p).toString().replace('\\', '/');

          if (rel.equals(SKIP) || rel.startsWith(SKIP + "/")) {
            continue;
          }

          Path to = where.resolve(rel);

          if (Files.isDirectory(p)) {
            Files.createDirectories(to);
          } else {
            Files.createDirectories(to.getParent());
            Files.copy(p, to);
          }
        }
      }
    }

    return where;
  }

  private static void remove(Path where) {
    try (Stream<Path> all = Files.walk(where)) {
      for (Path p : all.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(p);
      }
    } catch (IOException e) {
      // A copy left in the temporary folder is only untidy: the system clears it
    }
  }

  // The file a row changes, in the copy, held to the copy: a plain path, and, once resolved, still inside it
  private static Path inCopy(Path copy, String file) {
    if (!PLAIN_PATH.matcher(file).matches() || file.contains("..")) {
      throw new IllegalArgumentException("not a plain path: " + file);
    }

    Path target = copy.resolve(file).normalize();

    if (!target.startsWith(copy)) {
      throw new IllegalArgumentException("a path outside the copy: " + file);
    }

    return target;
  }

  // ----- Checks

  // Runs a check in a copy, and says whether it passed. The standard check runs here, inside this program, on the copy. The tests run in a
  // program of their own, and nothing in what's started comes from outside: the shell by its fixed full path, and the copy's own build.sh
  // as an argument of its own, in the copy's folder (build.sh reads JAVA_HOME for itself).
  private static boolean passes(Path copy, String check) throws IOException, InterruptedException {
    if (check.equals("standard")) {
      return CheckStandard.check(copy).problems().isEmpty();
    }

    ProcessBuilder builder = new ProcessBuilder(SHELL, "java/build.sh");
    builder.directory(copy.toFile());
    builder.redirectErrorStream(true);
    builder.redirectOutput(ProcessBuilder.Redirect.DISCARD);
    Map<String, String> env = builder.environment();
    env.remove("AVPX_LIVE");

    if (check.equals("live")) {
      env.put("AVPX_LIVE", "1");
    }

    Process process = builder.start();

    if (!process.waitFor(MOST_MINUTES_A_CHECK, TimeUnit.MINUTES)) {
      process.destroyForcibly();
      process.waitFor();
      return false;
    }

    return process.exitValue() == 0;
  }

  // One row in a copy of its own: what to say about it, and whether it's bad (not noticed, or not run)
  private record Result(String line, boolean bad) {
  }

  private static Result run(Path root, Row row) throws IOException, InterruptedException {
    Path copy = makeCopy(root);

    try {
      Path file = inCopy(copy, row.file());

      if (row.newFile() != null) {
        Files.createDirectories(file.getParent());
        Files.write(file, row.newFile());
      } else {
        if (!Files.exists(file)) {
          return new Result("row " + row.number() + " CAN'T RUN, no such file: " + row.name(), true);
        }

        String text = Files.readString(file, StandardCharsets.ISO_8859_1).replace("\r", "");

        if (text.split(Pattern.quote(row.from()), -1).length != 2) {
          return new Result("row " + row.number() + " CAN'T FIND ITS TEXT once: " + row.name(), true);
        }

        Files.writeString(file, text.replace(row.from(), row.to()), StandardCharsets.ISO_8859_1);
      }

      boolean passed = passes(copy, row.check());
      return new Result("row " + row.number() + " " + (passed ? "NOT NOTICED" : "noticed") + " (" + row.check() + "): " + row.name(), passed);
    } finally {
      remove(copy);
    }
  }

  // The share of the rows asked for: {K, N}, or {0, 1} (every row) when nothing is asked. Null for anything else.
  static int[] shareOf(String[] args) {
    if (args.length == 0) {
      return new int[] {0, 1};
    }

    if (args.length != 2 || !args[0].equals("--shard") || !SHARE.matcher(args[1]).matches()) {
      return null;
    }

    String[] parts = args[1].split("/");
    int k = digits(parts[0]);
    int n = digits(parts[1]);
    return n >= 1 && n <= MOST_SHARES && k < n ? new int[] {k, n} : null;
  }

  // A number written in decimal digits only, worked out digit by digit, with no parse that could throw (SHARE has already held it to one
  // or two digits)
  private static int digits(String text) {
    int value = 0;

    for (int i = 0; i < text.length(); i++) {
      value = value * 10 + (text.charAt(i) - '0');
    }

    return value;
  }

  public static void main(String[] args) throws Exception {
    Path root = Path.of("").toAbsolutePath();
    int[] share = shareOf(args);

    if (share == null) {
      System.out.println("use: Takeouts, or Takeouts --shard K/N (N from 1 to " + MOST_SHARES + ", K from 0 to N-1)");
      System.exit(2);
    }

    List<Row> all = read(Files.readAllLines(root.resolve(ROWS), StandardCharsets.US_ASCII));
    List<Row> rows = new ArrayList<>();

    for (int i = 0; i < all.size(); i++) {
      if (i % share[1] == share[0]) {
        rows.add(all.get(i));
      }
    }

    System.out.println("share " + share[0] + " of " + share[1] + ": " + rows.size() + " of the " + all.size() + " rows");

    // The unbroken copy first: its tests (with the live ones) and its standard must pass
    Path base = makeCopy(root);
    boolean baseLive;
    boolean baseStandard;

    try {
      baseLive = passes(base, "live");
      baseStandard = passes(base, "standard");
    } finally {
      remove(base);
    }

    if (!baseLive || !baseStandard) {
      System.out.println("THE UNBROKEN COPY FAILS (tests " + (baseLive ? "pass" : "fail") + ", standard " + (baseStandard ? "passes" : "fails")
          + "): nothing below would mean anything");
      System.exit(1);
    }

    System.out.println("the unbroken copy passes its tests, the live ones too, and the standard");

    List<Row> together = new ArrayList<>();
    List<Row> oneAtATime = new ArrayList<>();

    for (Row row : rows) {
      (row.check().equals("live") ? oneAtATime : together).add(row);
    }

    List<Result> results = new ArrayList<>();
    ExecutorService pool = Executors.newFixedThreadPool(Math.min(MOST_AT_ONCE, Runtime.getRuntime().availableProcessors()));

    try {
      List<Future<Result>> pending = new ArrayList<>();

      for (Row row : together) {
        pending.add(pool.submit(() -> run(root, row)));
      }

      for (Future<Result> f : pending) {
        try {
          results.add(f.get());
        } catch (ExecutionException e) {
          results.add(new Result("a row CAN'T RUN: " + e.getCause(), true));
        }
      }
    } finally {
      pool.shutdown();
    }

    for (Row row : oneAtATime) {
      results.add(run(root, row));
    }

    int bad = 0;

    for (Result r : results) {
      System.out.println(r.line());
      bad += r.bad() ? 1 : 0;
    }

    System.out.println(rows.size() + " rows, " + bad + " not noticed or not run");
    System.exit(bad == 0 ? 0 : 1);
  }
}
