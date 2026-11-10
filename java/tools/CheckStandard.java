package avpx.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

// Checks the Java version against CODING-STANDARD.md's rules, and says each one it breaks, by file and line. Written 2026-11-09 by
// Melanikus for AVPx Dedicated Server.
//
//   java -cp java/build/tools avpx.tools.CheckStandard       run from the repository's top folder (build.sh compiles it)
//
// It checks the folder it's run in, and nothing given on its command line, so nothing can point it anywhere else (Takeouts.java, which is
// in this package, has it check Takeouts' own copies, from inside Takeouts' program). It exits 1 if any rule is broken, 0 if none.
// Rules 1, 2 (no compiled code, no package-fetching build file), 6 and 7 hold for every file in the repository; the others for the Java
// code:
//
//   1. Every file is ASCII: every byte of every file in the repository.
//   2. No third-party code: module-info.java names no module it needs, so javac itself can use nothing but java.base; every import is
//      Java's own (java., javax.) or ours (avpx.); and nowhere in the repository is there a build file that fetches packages
//      (Maven's, Gradle's, npm's, yarn's, pnpm's, or a node_modules folder) or any compiled code at all (.jar, .class, .dll, ...):
//      nothing precompiled from outside (AVP Tao 1).
//   3. No code made from text: none of the ways Java turns text or bytes into code, or reaches past its own safety (reflection, scripts,
//      class loaders, reading Java objects back from bytes, native code).
//   4. The server starts no other program: only java/tools/ may.
//   5. The server writes nothing but through its log: the screen is named only in Log.java, and no stack trace is printed.
//   6. A finding is fixed, never hidden: nothing that tells javac or a scanner to look away, and no file that does.
//   7. Every action a workflow uses is pinned to a full commit hash.
//   8. Every test runs: every file in java/test that ends in Test.java is named in AllTests.java, or it would never run.
//  11. Bytes are compared in the same time, whatever they hold: no Arrays.equals, Arrays.mismatch, Arrays.compare (or compareUnsigned)
//      or Arrays.deepEquals in java/src or java/tools, nor a method reference to any of Arrays' (Arrays::equals), nor Objects.deepEquals,
//      and no static import of java.util.Arrays (which would let them be written without "Arrays."), only
//      MessageDigest.isEqual (rules 9 and 10 are a reviewer's).
//
// This file is the one place the words rules 3 to 6 and 11 look for are listed, so it leaves its own text out of those rules, and so does
// java/tools/takeouts.txt, whose rows put those words into a copy on purpose, to prove this check notices them. The words are written in
// pieces here, so no other tool that looks for them (a scanner's own search, say) finds them in this file either.
public final class CheckStandard {
  private CheckStandard() {
  }

  private static final String SELF = "java/tools/CheckStandard.java";
  private static final String ROWS = "java/tools/takeouts.txt";

  // Rule 2: compiled code, and the files of build tools that fetch packages
  private static final Set<String> COMPILED = Set.of(".jar", ".war", ".ear", ".class", ".so", ".dll", ".dylib", ".exe", ".o", ".obj", ".a",
      ".lib", ".pyc", ".node", ".jmod");
  // Java's (Maven, Gradle), and Node's (npm, yarn, pnpm): this repository was Node's until 2026-11-08, and a Node tree must not creep back
  private static final Set<String> BUILD_FILES = Set.of("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
      "settings.gradle.kts", "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", "package.json", "package-lock.json", "npm-shrinkwrap.json",
      "yarn.lock", "pnpm-lock.yaml", "pnpm-workspace.yaml");
  private static final Set<String> BUILD_FOLDERS = Set.of(".mvn", ".gradle", "node_modules");
  private static final Pattern IMPORT = Pattern.compile("^\\s*import\\s+(static\\s+)?([A-Za-z0-9_.*]+)\\s*;");
  private static final Pattern REQUIRES = Pattern.compile("^\\s*requires\\b");

  // Rule 3: the ways Java makes code from text or bytes, or reaches past its own checks
  private static final List<String> FROM_TEXT = List.of("java.lang." + "reflect", "Class." + "forName", "getDeclared" + "Method",
      "getDeclared" + "Field", "set" + "Accessible", "Method" + "Handles", "javax." + "script", "Class" + "Loader", "define" + "Class",
      "Object" + "InputStream", "XML" + "Decoder", "System." + "loadLibrary", "System." + "load(", "sun." + "misc", "jdk." + "internal",
      "Un" + "safe");
  private static final Pattern NATIVE = Pattern.compile("\\b" + "nat" + "ive\\b");

  // Rule 4: starting another program (Runtime.getRuntime() alone is fine: Main uses it to be told when to stop; its exec is what starts one)
  private static final List<String> PROGRAMS = List.of("Process" + "Builder", "Process" + "Handle", ".ex" + "ec(");

  // Rule 5: the screen, and stack traces
  private static final List<String> SCREEN = List.of("System." + "out", "System." + "err", "print" + "StackTrace");
  private static final String LOG = "java/src/avpx/Log.java";

  // Rule 6: the words that tell javac or a scanner to look away, and the files that do
  private static final List<String> SILENCERS = List.of("@Suppress" + "Warnings", "NO" + "SONAR", "Suppress" + "FBWarnings",
      "code" + "ql[", "lg" + "tm[", "snyk" + ":ignore", "deep" + "code ignore", "no" + "semgrep", "eslint" + "-disable", "istanbul " + "ignore");
  private static final Set<String> SILENCER_FILES = Set.of(".snyk", ".dcignore", ".eslintignore");

  // Rule 7
  private static final Pattern USES = Pattern.compile("^\\s*-?\\s*uses:\\s*([^\\s#]+)");
  private static final Pattern PINNED = Pattern.compile(".*@[0-9a-f]{40}");

  // Rule 8
  private static final String ALL_TESTS = "java/test/avpx/AllTests.java";

  // Rule 11: the compares that stop at the first byte that differs, so the time they take says how much of a guess was right, and the
  // static import that would let them be written with no "Arrays." in front (Secondary's re-check, 2026-11-10)
  private static final List<String> TIMED_COMPARES = List.of("Arrays." + "equals(", "Arrays." + "mismatch(", "Arrays." + "compare",
      "Arrays." + "deepEquals(", "import static java.util." + "Arrays", "Arrays" + "::", "Objects." + "deepEquals(");

  // What one check found, and how much it looked at. Each check has its own, so Takeouts.java can check several copies at once.
  private final List<String> problems = new ArrayList<>();
  private int filesChecked;
  private int javaFilesChecked;

  private void say(String file, int line, String words) {
    problems.add(file + (line > 0 ? ":" + line : "") + ": " + words);
  }

  public static void main(String[] args) throws IOException {
    CheckStandard found = check(Path.of("").toAbsolutePath());

    for (String p : found.problems) {
      System.out.println(p);
    }

    System.out.println("Checked " + found.filesChecked + " files (" + found.javaFilesChecked + " Java) against CODING-STANDARD.md: "
        + found.problems.size() + " problems");
    System.exit(found.problems.isEmpty() ? 0 : 1);
  }

  // Every rule, on every file in the folder given: main gives it the folder it's run in, and Takeouts.java its copies
  static CheckStandard check(Path root) throws IOException {
    CheckStandard found = new CheckStandard();
    found.checkAll(root);
    return found;
  }

  // Each rule broken, as "file:line: which rule, and why"; none at all when every rule holds
  List<String> problems() {
    return List.copyOf(problems);
  }

  private void checkAll(Path root) throws IOException {
    List<String> files = new ArrayList<>();

    try (Stream<Path> all = Files.walk(root)) {
      for (Path p : all.toList()) {
        String rel = root.relativize(p).toString().replace('\\', '/');

        if (rel.isEmpty() || rel.equals(".git") || rel.startsWith(".git/") || rel.equals("java/build") || rel.startsWith("java/build/")) {
          continue;
        }

        if (Files.isDirectory(p)) {
          String name = p.getFileName().toString();

          if (BUILD_FOLDERS.contains(name)) {
            say(rel, 0, "rule 2: a build tool's folder, which fetches packages");
          }

          continue;
        }

        files.add(rel);
      }
    }

    int javaFiles = 0;

    for (String file : files) {
      checkAnyFile(root, file);

      if (file.startsWith("java/")) {
        checkJavaFolderFile(root, file);
        javaFiles += file.endsWith(".java") ? 1 : 0;
      }
    }

    checkEveryTestRuns(root, files);

    if (javaFiles == 0) {
      problems.add("no Java files were found to check, which would mean nothing was checked");
    }

    filesChecked = files.size();
    javaFilesChecked = javaFiles;
  }

  // Rules 1, 2, 6 and 7, on every file in the repository
  private void checkAnyFile(Path root, String file) throws IOException {
    byte[] bytes = Files.readAllBytes(root.resolve(file));
    int line = 1;

    for (byte b : bytes) {
      int c = b & 0xff;

      if (c == '\n') {
        line++;
      } else if ((c < 0x20 || c > 0x7e) && c != '\t' && c != '\r') {
        say(file, line, "rule 1: a byte that isn't printable ASCII (0x" + Integer.toHexString(c) + ")");
        break;
      }
    }

    if (!file.equals(SELF) && !file.equals(ROWS)) {
      String[] lines = new String(bytes, StandardCharsets.ISO_8859_1).split("\n", -1);

      for (int k = 0; k < lines.length; k++) {
        for (String word : SILENCERS) {
          if (lines[k].contains(word)) {
            say(file, k + 1, "rule 6: \"" + word + "\" tells javac or a scanner to look away");
          }
        }
      }
    }

    String name = file.substring(file.lastIndexOf('/') + 1);
    int dot = name.lastIndexOf('.');
    String kind = dot < 0 ? "" : name.substring(dot).toLowerCase(Locale.ROOT);

    if (COMPILED.contains(kind)) {
      say(file, 0, "rule 2: compiled code, which nothing here may hold (open-source code comes as source, and we build it)");
    }

    if (BUILD_FILES.contains(name)) {
      say(file, 0, "rule 2: a build tool's file, which fetches packages");
    }

    if (SILENCER_FILES.contains(name)) {
      say(file, 0, "rule 6: a file that tells a scanner to look away");
    }

    if (file.startsWith(".github/workflows/")) {
      List<String> lines = Files.readAllLines(root.resolve(file), StandardCharsets.ISO_8859_1);

      for (int k = 0; k < lines.size(); k++) {
        Matcher m = USES.matcher(lines.get(k));

        if (m.find() && !m.group(1).startsWith("./") && !PINNED.matcher(m.group(1)).matches()) {
          say(file, k + 1, "rule 7: \"" + m.group(1) + "\" isn't pinned to a full commit hash");
        }
      }
    }
  }

  // Rules 2 to 5, and 11, on a Java file under java/
  private void checkJavaFolderFile(Path root, String file) throws IOException {
    if (!file.endsWith(".java") || file.equals(SELF) || file.equals(ROWS)) {
      return;
    }

    String[] lines = Files.readString(root.resolve(file), StandardCharsets.ISO_8859_1).split("\n", -1);
    boolean isModuleInfo = file.endsWith("/module-info.java");

    for (int k = 0; k < lines.length; k++) {
      String text = lines[k];
      int n = k + 1;
      Matcher imported = IMPORT.matcher(text);

      if (imported.find()) {
        String what = imported.group(2);

        if (!(what.startsWith("java.") || what.startsWith("javax.") || what.startsWith("avpx."))) {
          say(file, n, "rule 2: an import of \"" + what + "\", which is neither Java's own nor ours");
        }
      }

      if (isModuleInfo && REQUIRES.matcher(text).find()) {
        say(file, n, "rule 2: module-info.java names a module it needs; the server may use only java.base");
      }

      for (String word : FROM_TEXT) {
        if (text.contains(word)) {
          say(file, n, "rule 3: " + word + ", a way to make code from text or bytes, or to reach past Java's own checks");
        }
      }

      if (NATIVE.matcher(text).find()) {
        say(file, n, "rule 3: native code");
      }

      if (!file.startsWith("java/tools/")) {
        for (String word : PROGRAMS) {
          if (text.contains(word)) {
            say(file, n, "rule 4: " + word + " outside java/tools/: the server starts no other program");
          }
        }
      }

      if (file.startsWith("java/src/") && !file.equals(LOG)) {
        for (String word : SCREEN) {
          if (text.contains(word)) {
            say(file, n, "rule 5: " + word + " in the server's own code (it writes only through Log.java)");
          }
        }
      }

      if (file.startsWith("java/src/") || file.startsWith("java/tools/")) {
        for (String word : TIMED_COMPARES) {
          if (text.contains(word)) {
            say(file, n, "rule 11: " + word + ", a compare that stops at the first byte that differs (or a way to write one without its name):"
                + " compare bytes with MessageDigest.isEqual");
          }
        }
      }
    }
  }

  // Rule 8: every test file is named in AllTests.java
  private void checkEveryTestRuns(Path root, List<String> files) throws IOException {
    if (!files.contains(ALL_TESTS)) {
      say(ALL_TESTS, 0, "rule 8: AllTests.java isn't there, so no test would run");
      return;
    }

    String all = Files.readString(root.resolve(ALL_TESTS), StandardCharsets.ISO_8859_1);

    for (String file : files) {
      if (file.startsWith("java/test/") && file.endsWith("Test.java")) {
        String name = file.substring(file.lastIndexOf('/') + 1, file.length() - ".java".length());

        if (!all.contains(name + ".register();")) {
          say(file, 0, "rule 8: " + name + " isn't named in AllTests.java, so its tests would never run");
        }
      }
    }
  }
}
