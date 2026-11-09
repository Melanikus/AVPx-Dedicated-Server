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
// because the live tests use fixed ports; "standard" runs CheckStandard in the copy. "tests" and "standard" rows run several at once.
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

  // Runs a check in a copy, and says whether it passed
  private static boolean passes(Path copy, String check, Path tools) throws IOException, InterruptedException {
    String java = Path.of(System.getenv("JAVA_HOME"), "bin", "java").toString();
    ProcessBuilder builder = check.equals("standard")
        ? new ProcessBuilder(java, "-cp", tools.toString(), "avpx.tools.CheckStandard")
        : new ProcessBuilder(SHELL, "java/build.sh");
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

  private static Result run(Path root, Row row, Path tools) throws IOException, InterruptedException {
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

      boolean passed = passes(copy, row.check(), tools);
      return new Result("row " + row.number() + " " + (passed ? "NOT NOTICED" : "noticed") + " (" + row.check() + "): " + row.name(), passed);
    } finally {
      remove(copy);
    }
  }

  public static void main(String[] args) throws Exception {
    Path root = Path.of("").toAbsolutePath();
    Path tools = root.resolve(Path.of("java", "build", "tools"));
    List<Row> rows = read(Files.readAllLines(root.resolve(ROWS), StandardCharsets.US_ASCII));

    // The unbroken copy first: its tests (with the live ones) and its standard must pass
    Path base = makeCopy(root);
    boolean baseLive;
    boolean baseStandard;

    try {
      baseLive = passes(base, "live", tools);
      baseStandard = passes(base, "standard", tools);
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
        pending.add(pool.submit(() -> run(root, row, tools)));
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
      results.add(run(root, row, tools));
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
