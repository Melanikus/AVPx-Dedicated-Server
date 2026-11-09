package avpx.tools;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

// Makes test-vectors/crypto-kat/: the published known-answer tests for protocol version 2's primitives (CRYPTO.md section 2), taken
// from their sources as they are, kept to the cases v2 uses, and written in one plain JSON shape every reader here can read. Written
// 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   java -cp java/build/tools avpx.tools.MakeCryptoKat       run from the repository's top folder (build.sh compiles it)
//
// WHY: a primitive that computes the wrong answer can still look fine in every test we write ourselves, because our tests and our code
// can share the same mistake. A known answer from the people who wrote the standard can't. So the server and the game both check their
// primitives against these.
//
// WHERE THE CASES COME FROM: two independent sources for each, where both exist, so a bad copy of one shows up against the other:
//   - NIST: CAVP's response files (AES-GCM, ECC CDH, ECDSA) and the ACVP server's JSON (ML-KEM, ML-DSA, HKDF);
//   - Wycheproof (C2SP), which adds cases that must be refused: invalid points, bad signatures, wrong lengths.
// Each folder's PROVENANCE.md says where each file came from, its SHA-256, the commit, the date, the licence and exactly which cases
// were taken.
//
// WHAT IT READS: only the folder crypto-kat-sources/ beside the repository's top folder (../crypto-kat-sources from where it's run), and
// nothing given on its command line, so nothing can point it anywhere else. That folder is outside the repository on purpose: git never
// sees it, and nor does CheckStandard, which reads every file inside (some sources aren't ASCII, as NIST's zips and a form feed in RFC
// 5869 aren't). It holds the files as fetched (PROVENANCE.md says from where), laid out as
// acvp/, wycheproof/, rfc/, and nist-gcm/, nist-ecdh/ and nist-ecdsa/ with NIST's zips. EVERY ONE IS CHECKED against its SHA-256 below
// before it's read, so a file that isn't the very one the provenance names is refused, and nothing here ever goes online. A zip is read
// in place, and only the files named here are taken out of it.
//
// THE SHAPE, the same in every file, which the server's strict JSON reader takes as it is:
//   { "primitive", "source", "about", "count", "cases": [ { "id", ..., "result" } ] }
//   - every byte string is hex in small letters, "" for none;
//   - every number is a whole number;
//   - "result" is "valid" (the answer must come out exactly so), "invalid" (it must be refused), or, for Wycheproof's ECDH only,
//     "acceptable" (either is allowed);
//   - no true, false or null, and every string is printable ASCII with no escapes but \" and \\.
// Nothing in a case is changed, only written out: the bytes of every key, message and answer are the source's own.
//
// The files it makes are byte for byte the ones the first version of this, in JavaScript, made (2026-11-09, commit d9c4cbe): this was
// checked by making them again and comparing.
public final class MakeCryptoKat {
  private MakeCryptoKat() {
  }

  private static final Path SOURCES = Path.of("..", "crypto-kat-sources");
  private static final Path OUT = Path.of("test-vectors", "crypto-kat");

  // The SHA-256 of every source file it reads, as fetched (PROVENANCE.md). A file that doesn't match is refused.
  private static final Map<String, String> PINNED = Map.ofEntries(
      Map.entry("nist-gcm/gcmtestvectors.zip", "f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023"),
      Map.entry("nist-ecdh/ecccdhtestvectors.zip", "5fff092551f2d72e89a3d9362711878708f9a14b502f0dfae819649105b0ea39"),
      Map.entry("nist-ecdsa/186-4ecdsatestvectors.zip", "fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752"),
      Map.entry("rfc/rfc5869.txt", "7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c"),
      Map.entry("acvp/KDA-HKDF-Sp800-56Cr2/prompt.json", "2d27b1b69549f383b7583700f7e0622b33debb254db37bf83eb524102a1e3d9c"),
      Map.entry("acvp/KDA-HKDF-Sp800-56Cr2/expectedResults.json", "de35a4b7b3bc795b9c1b7bba4a28407bcfe2941568d097eadf9de57ff2e76395"),
      Map.entry("acvp/ML-KEM-keyGen-FIPS203/prompt.json", "3f9ce34f6c836c77958bad2729e837c3b213f44ac36c3065976e7acca6389523"),
      Map.entry("acvp/ML-KEM-keyGen-FIPS203/expectedResults.json", "a253d0ad91c95ebea5b409673defef0aa49d65d4ed72286399e2e798ddf073a4"),
      Map.entry("acvp/ML-KEM-encapDecap-FIPS203/prompt.json", "998e22dfb12efb14ce9fdff911ca634b13612819a1806f25da69adba7e16db91"),
      Map.entry("acvp/ML-KEM-encapDecap-FIPS203/expectedResults.json", "9089ec6ff2424da9f2782b89b2f831a329a3e28d6e5e24b802b78ff36ac61cdf"),
      Map.entry("acvp/ML-DSA-keyGen-FIPS204/prompt.json", "43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef"),
      Map.entry("acvp/ML-DSA-keyGen-FIPS204/expectedResults.json", "361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df"),
      Map.entry("acvp/ML-DSA-sigVer-FIPS204/prompt.json", "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"),
      Map.entry("acvp/ML-DSA-sigVer-FIPS204/expectedResults.json", "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6"),
      Map.entry("acvp/ML-DSA-sigGen-FIPS204/prompt.json", "447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d"),
      Map.entry("acvp/ML-DSA-sigGen-FIPS204/expectedResults.json", "228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb"),
      Map.entry("wycheproof/aes_gcm_test.json", "985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7"),
      Map.entry("wycheproof/hkdf_sha384_test.json", "69ff6ea3657bb9c1b8cdffbbb4e7832353d08fd15c0d9997b03f7a6b180e3678"),
      Map.entry("wycheproof/hmac_sha384_test.json", "28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0"),
      Map.entry("wycheproof/ecdh_secp384r1_ecpoint_test.json", "ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3"),
      Map.entry("wycheproof/ecdh_secp384r1_test.json", "25a9c41573dbea97c5b4be2dd00369fa68dc37ac8f41807d8e16226d188ec6a7"),
      Map.entry("wycheproof/ecdsa_secp384r1_sha384_p1363_test.json", "e27344bf6daae75fa19663620883809f91c79fc4b4420eff9eae8036b34476be"),
      Map.entry("wycheproof/mlkem_1024_keygen_seed_test.json", "cd9241bf5d65a78e005866ea2c660615c17f50caa9afc2b96fd1573cc65617b5"),
      Map.entry("wycheproof/mlkem_1024_encaps_test.json", "da41e8daf57e40a6b334a722e3f56067817352f5583fdb2434da1a2cd611358e"),
      Map.entry("wycheproof/mlkem_1024_test.json", "17c5b764d78c05522f1980fcb41d82add573f11de5d13004ae0b83bf46d9c43a"),
      Map.entry("wycheproof/mlkem_1024_semi_expanded_decaps_test.json", "a4a7c88152df3d8d4b3f33aad584167dfaff67195cfde08aac4b981030b4d05c"),
      Map.entry("wycheproof/mldsa_87_verify_test.json", "54adffe10f6dad7941ffd97f77ad4e5c85cb3a54d44cf5ce1c95cb1757b9ba14"));

  // AES-256-GCM as v2 seals with it (CRYPTO.md section 5): a 12-byte IV and a 16-byte tag
  private static final int GCM_IV_BITS = 96;
  private static final int GCM_TAG_BITS = 128;
  // A P-384 number's size, and so each coordinate's, the private key's and the shared secret's
  private static final int P384_BYTES = 48;
  // The most a JSON source may nest: theirs go 5 deep, and a source that goes deeper isn't one of these
  private static final int MOST_JSON_DEPTH = 64;

  public static void main(String[] args) throws IOException {
    if (args.length != 0) {
      throw new IllegalArgumentException("it takes nothing on its command line: it reads ../crypto-kat-sources/, beside the repository");
    }

    // Every source is checked before anything is written, so a wrong one leaves the files as they were
    for (String name : PINNED.keySet()) {
      source(name);
    }

    aesGcm();
    hkdf();
    hmac();
    ecdh();
    ecdsa();
    mlKem();
    mlDsa();
  }

  // ----- Small helpers

  // A case, its fields in the order they're written
  private static final class Case {
    final Map<String, Object> fields = new LinkedHashMap<>();

    Case put(String name, String value) {
      fields.put(name, value);
      return this;
    }

    Case put(String name, long value) {
      fields.put(name, value);
      return this;
    }
  }

  // Hex in small letters, checked to be hex: a source with anything else in a byte field is a source to look at, not to guess about
  private static String hex(String text, String what) {
    String h = (text == null ? "" : text).trim().toLowerCase(Locale.ROOT);

    if (!h.matches("([0-9a-f]{2})*")) {
      throw new IllegalStateException(what + ": not whole bytes of hex: " + h.substring(0, Math.min(40, h.length())));
    }

    return h;
  }

  // Free text from a source (a comment, a reason), kept to printable ASCII so every reader takes it: anything else becomes "?"
  private static String words(String text) {
    return (text == null ? "" : text).replaceAll("[^\\x20-\\x7e]", "?").replaceAll("[\"\\\\]", "'");
  }

  // A big-endian number in hex, padded on the left to a fixed number of bytes (CAVP sometimes leaves off leading zeros)
  private static String padded(String text, int bytes, String what) {
    String h = hex(text.length() % 2 == 1 ? "0" + text : text, what);

    if (h.length() > bytes * 2) {
      throw new IllegalStateException(what + ": longer than " + bytes + " bytes");
    }

    return "0".repeat(bytes * 2 - h.length()) + h;
  }

  // The same, but a longer number is kept as it is
  private static String atLeast(String text, int bytes, String what) {
    String h = hex(text.length() % 2 == 1 ? "0" + text : text, what);
    return h.length() >= bytes * 2 ? h : "0".repeat(bytes * 2 - h.length()) + h;
  }

  private static String point(String x, String y, String what) {
    return "04" + padded(x, P384_BYTES, what + " x") + padded(y, P384_BYTES, what + " y");
  }

  // A source file's bytes, once its SHA-256 is the pinned one
  private static byte[] source(String name) throws IOException {
    String want = PINNED.get(name);

    if (want == null) {
      throw new IllegalStateException(name + ": not one of the pinned sources");
    }

    byte[] bytes = Files.readAllBytes(SOURCES.resolve(name));

    try {
      String got = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));

      if (!got.equals(want)) {
        throw new IllegalStateException(name + ": its SHA-256 is " + got + ", not the pinned " + want);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 isn't there", e);
    }

    return bytes;
  }

  // One file out of a pinned zip. Its name has to be exactly the one asked for, and every name in the zip has to be a plain one that
  // stays inside it, or the zip isn't taken at all.
  private static String fromZip(String zip, String member) throws IOException {
    source(zip);

    try (ZipFile z = new ZipFile(SOURCES.resolve(zip).toFile())) {
      for (ZipEntry e : java.util.Collections.list(z.entries())) {
        String n = e.getName();

        if (n.contains("..") || n.startsWith("/") || n.startsWith("\\") || n.contains(":")) {
          throw new IllegalStateException(zip + ": a name that could leave the zip: " + n);
        }
      }

      ZipEntry e = z.getEntry(member);

      if (e == null) {
        throw new IllegalStateException(zip + ": no " + member + " in it");
      }

      try (InputStream in = z.getInputStream(e)) {
        return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
      }
    }
  }

  // Writes one file of the shape above. Its text is refused if anything in it isn't printable ASCII, or is escaped other than \" and \\.
  private static void write(String folder, String name, String primitive, String source, String about, List<Case> cases) throws IOException {
    Map<String, Object> top = new LinkedHashMap<>();
    top.put("primitive", primitive);
    top.put("source", source);
    top.put("about", about);
    top.put("count", (long) cases.size());
    StringBuilder text = new StringBuilder();
    text.append("{\n");
    int i = 0;

    for (Map.Entry<String, Object> e : top.entrySet()) {
      text.append("  ").append(quoted(e.getKey())).append(": ").append(value(e.getValue())).append(",\n");
      i++;
    }

    text.append("  \"cases\": ");

    if (cases.isEmpty()) {
      text.append("[]");
    } else {
      text.append("[\n");

      for (int c = 0; c < cases.size(); c++) {
        text.append("    {\n");
        int f = 0;

        for (Map.Entry<String, Object> e : cases.get(c).fields.entrySet()) {
          text.append("      ").append(quoted(e.getKey())).append(": ").append(value(e.getValue()));
          text.append(++f < cases.get(c).fields.size() ? ",\n" : "\n");
        }

        text.append(c + 1 < cases.size() ? "    },\n" : "    }\n");
      }

      text.append("  ]");
    }

    text.append("\n}\n");
    String all = text.toString();

    if (i != 4 || !all.matches("[\\n\\x20-\\x7e]*") || all.matches("(?s).*\\\\(u|[bfnrt/]).*")) {
      throw new IllegalStateException(folder + "/" + name + ": something isn't printable ASCII, or is escaped other than \\\" and \\\\");
    }

    Path dir = OUT.resolve(folder);
    Files.createDirectories(dir);
    Files.writeString(dir.resolve(name), all, StandardCharsets.US_ASCII);
    System.out.println(folder + "/" + name + ": " + cases.size() + " cases");
  }

  // A string as JSON writes it: quotes and backslashes escaped. Nothing else that would need escaping is ever written (see write).
  private static String quoted(String s) {
    return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
  }

  private static String value(Object v) {
    if (v instanceof String s) {
      return quoted(s);
    }

    if (v instanceof Long n) {
      return Long.toString(n);
    }

    throw new IllegalStateException("a value that's neither text nor a whole number");
  }

  // ----- Reading JSON sources: a reader of its own, since the sources have true, false and escaped characters (a backslash, a u and four
  // hex digits; written out in words here because javac reads those six characters as a character even in a comment), which the server's strict reader
  // refuses on purpose. Each value keeps what it is; nothing is guessed.

  private static final class J {
    final String str;
    final Long num;
    final Boolean bool;
    final List<J> arr;
    final Map<String, J> obj;

    private J(String str, Long num, Boolean bool, List<J> arr, Map<String, J> obj) {
      this.str = str;
      this.num = num;
      this.bool = bool;
      this.arr = arr;
      this.obj = obj;
    }

    J get(String key) {
      return obj == null ? null : obj.get(key);
    }

    List<J> list(String key) {
      J j = get(key);
      return j == null || j.arr == null ? List.of() : j.arr;
    }
  }

  // The text of a value: "" for none, a string as it is, a whole number in digits
  private static String text(J j) {
    if (j == null) {
      return "";
    }

    if (j.str != null) {
      return j.str;
    }

    if (j.num != null) {
      return Long.toString(j.num);
    }

    throw new IllegalStateException("a value that isn't text");
  }

  // The first of two values that's a string with something in it, as JavaScript's "a || b" picks it
  private static String either(J a, J b) {
    return a != null && a.str != null && !a.str.isEmpty() ? a.str : text(b);
  }

  private static long whole(J j, String what) {
    if (j == null || j.num == null) {
      throw new IllegalStateException(what + ": not a whole number");
    }

    return j.num;
  }

  private static boolean isTrue(J j) {
    return j != null && Boolean.TRUE.equals(j.bool);
  }

  private static String str(J j) {
    return j == null || j.str == null ? null : j.str;
  }

  private static final class Reader {
    private final String s;
    private int at;

    Reader(String s) {
      this.s = s;
    }

    J read() {
      J j = value(0);
      space();

      if (at != s.length()) {
        throw new IllegalStateException("JSON: something after the end, at " + at);
      }

      return j;
    }

    private void space() {
      while (at < s.length() && " \t\r\n".indexOf(s.charAt(at)) >= 0) {
        at++;
      }
    }

    private J value(int depth) {
      if (depth > MOST_JSON_DEPTH) {
        throw new IllegalStateException("JSON: nested too deep");
      }

      space();

      if (at >= s.length()) {
        throw new IllegalStateException("JSON: it ends too soon");
      }

      char c = s.charAt(at);

      if (c == '{') {
        at++;
        Map<String, J> m = new LinkedHashMap<>();
        space();

        if (s.charAt(at) == '}') {
          at++;
          return new J(null, null, null, null, m);
        }

        while (true) {
          space();
          String key = string();
          space();
          expect(':');
          m.put(key, value(depth + 1));
          space();

          if (s.charAt(at) == ',') {
            at++;
          } else {
            expect('}');
            return new J(null, null, null, null, m);
          }
        }
      }

      if (c == '[') {
        at++;
        List<J> l = new ArrayList<>();
        space();

        if (s.charAt(at) == ']') {
          at++;
          return new J(null, null, null, l, null);
        }

        while (true) {
          l.add(value(depth + 1));
          space();

          if (s.charAt(at) == ',') {
            at++;
          } else {
            expect(']');
            return new J(null, null, null, l, null);
          }
        }
      }

      if (c == '"') {
        return new J(string(), null, null, null, null);
      }

      if (s.startsWith("true", at)) {
        at += 4;
        return new J(null, null, Boolean.TRUE, null, null);
      }

      if (s.startsWith("false", at)) {
        at += 5;
        return new J(null, null, Boolean.FALSE, null, null);
      }

      if (s.startsWith("null", at)) {
        at += 4;
        return new J(null, null, null, null, null);
      }

      Matcher m = NUMBER.matcher(s).region(at, s.length());

      if (!m.lookingAt()) {
        throw new IllegalStateException("JSON: not a value, at " + at);
      }

      at = m.end();

      // Only whole numbers are read: these sources have no other kind, so one would be a source to look at
      if (m.group(1) != null || m.group(2) != null) {
        throw new IllegalStateException("JSON: a number that isn't whole, at " + at);
      }

      return new J(null, Long.parseLong(m.group(0)), null, null, null);
    }

    private void expect(char c) {
      if (at >= s.length() || s.charAt(at) != c) {
        throw new IllegalStateException("JSON: '" + c + "' wanted, at " + at);
      }

      at++;
    }

    private String string() {
      expect('"');
      StringBuilder b = new StringBuilder();

      while (true) {
        if (at >= s.length()) {
          throw new IllegalStateException("JSON: a string that never ends");
        }

        char c = s.charAt(at++);

        if (c == '"') {
          return b.toString();
        }

        if (c != '\\') {
          b.append(c);
          continue;
        }

        char e = s.charAt(at++);

        switch (e) {
          case '"', '\\', '/' -> b.append(e);
          case 'b' -> b.append('\b');
          case 'f' -> b.append('\f');
          case 'n' -> b.append('\n');
          case 'r' -> b.append('\r');
          case 't' -> b.append('\t');
          case 'u' -> {
            b.append((char) Integer.parseInt(s.substring(at, at + 4), 16));
            at += 4;
          }
          default -> throw new IllegalStateException("JSON: an escape that isn't one, at " + at);
        }
      }
    }
  }

  private static final Pattern NUMBER = Pattern.compile("-?(?:0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?");

  private static J json(String name) throws IOException {
    return new Reader(new String(source(name), StandardCharsets.UTF_8)).read();
  }

  // ----- CAVP's .rsp and .txt files: "[section]" lines, then blocks of "Name = value" lines

  private static final class Block {
    final Map<String, String> sections;
    final Map<String, String> fields = new LinkedHashMap<>();

    Block(Map<String, String> sections) {
      this.sections = new LinkedHashMap<>(sections);
    }

    String f(String name) {
      return fields.get(name);
    }
  }

  private static final Pattern SECTION = Pattern.compile("^\\[(.+)\\]$");
  private static final Pattern NAMED = Pattern.compile("^(\\w+)\\s*=\\s*(.*)$");

  private static List<Block> readCavp(String text) {
    List<Block> blocks = new ArrayList<>();
    Map<String, String> sections = new LinkedHashMap<>();
    Block block = null;

    for (String raw : text.split("\\r?\\n", -1)) {
      String line = raw.trim();

      if (line.isEmpty() || line.startsWith("#")) {
        if (block != null) {
          blocks.add(block);
          block = null;
        }
        continue;
      }

      Matcher section = SECTION.matcher(line);

      if (section.matches()) {
        if (block != null) {
          blocks.add(block);
          block = null;
        }

        Matcher named = NAMED.matcher(section.group(1));

        if (named.matches()) {
          sections.put(named.group(1), named.group(2));
        } else {
          sections = new LinkedHashMap<>();
          sections.put("name", section.group(1));
        }
        continue;
      }

      if (block == null) {
        block = new Block(sections);
      }

      Matcher field = NAMED.matcher(line);

      if (field.matches()) {
        block.fields.put(field.group(1), field.group(2));
      } else {
        block.fields.put(line, "");   // a word on its own, as gcmDecrypt's FAIL
      }
    }

    if (block != null) {
      blocks.add(block);
    }

    return blocks;
  }

  // ----- ACVP: the prompt and the expected results side by side, each test with its group and its answer

  private record Acvp(J group, J test, J answer) {
  }

  private static List<Acvp> readAcvp(String folder) throws IOException {
    J prompt = json("acvp/" + folder + "/prompt.json");
    J expected = json("acvp/" + folder + "/expectedResults.json");
    Map<String, J> answers = new LinkedHashMap<>();

    for (J g : expected.list("testGroups")) {
      for (J t : g.list("tests")) {
        answers.put(text(g.get("tgId")) + "/" + text(t.get("tcId")), t);
      }
    }

    List<Acvp> tests = new ArrayList<>();

    for (J g : prompt.list("testGroups")) {
      for (J t : g.list("tests")) {
        J answer = answers.get(text(g.get("tgId")) + "/" + text(t.get("tcId")));

        if (answer == null) {
          throw new IllegalStateException(folder + ": no expected result for group " + text(g.get("tgId")) + ", test " + text(t.get("tcId")));
        }

        tests.add(new Acvp(g, t, answer));
      }
    }

    return tests;
  }

  private static String passed(J b, String what) {
    if (b == null || b.bool == null) {
      throw new IllegalStateException(what + ": testPassed isn't true or false");
    }

    return b.bool ? "valid" : "invalid";
  }

  // ----- Wycheproof: every test, with its group, and its flags as one string ("Normal,EmptySalt")

  private record Wych(J group, J test, String flags) {
  }

  private static List<Wych> readWycheproof(String file) throws IOException {
    J j = json("wycheproof/" + file);
    List<Wych> tests = new ArrayList<>();

    for (J g : j.list("testGroups")) {
      for (J t : g.list("tests")) {
        String result = text(t.get("result"));

        if (!List.of("valid", "invalid", "acceptable").contains(result)) {
          throw new IllegalStateException(file + ": test " + text(t.get("tcId")) + " has the result " + result);
        }

        List<String> flags = new ArrayList<>();

        for (J f : t.list("flags")) {
          flags.add(words(str(f)));
        }

        tests.add(new Wych(g, t, String.join(",", flags)));
      }
    }

    return tests;
  }

  private static <T> List<Case> map(List<T> from, Predicate<T> keep, Function<T, Case> make) {
    List<Case> out = new ArrayList<>();

    for (T t : from) {
      if (keep.test(t)) {
        out.add(make.apply(t));
      }
    }

    return out;
  }

  // ----- AES-256-GCM

  private static boolean ofV2(Block b) {
    return "256".equals(b.sections.get("Keylen")) && Integer.toString(GCM_IV_BITS).equals(b.sections.get("IVlen"))
        && Integer.toString(GCM_TAG_BITS).equals(b.sections.get("Taglen"));
  }

  private static String gcmId(Block b) {
    return "PTlen " + b.sections.get("PTlen") + ", AADlen " + b.sections.get("AADlen") + ", Count " + b.f("Count");
  }

  private static void aesGcm() throws IOException {
    write("aes-256-gcm", "nist-cavp-encrypt.json", "AES-256-GCM", "NIST CAVP gcmEncryptExtIV256.rsp (SP 800-38D)",
        "Keylen 256, IVlen 96 and Taglen 128 only. Encrypting pt with key, iv and aad gives exactly ct and tag.",
        map(readCavp(fromZip("nist-gcm/gcmtestvectors.zip", "gcmEncryptExtIV256.rsp")), MakeCryptoKat::ofV2, b -> new Case()
            .put("id", gcmId(b)).put("key", hex(b.f("Key"), "Key")).put("iv", hex(b.f("IV"), "IV")).put("aad", hex(b.f("AAD"), "AAD"))
            .put("pt", hex(b.f("PT"), "PT")).put("ct", hex(b.f("CT"), "CT")).put("tag", hex(b.f("Tag"), "Tag")).put("result", "valid")));

    write("aes-256-gcm", "nist-cavp-decrypt.json", "AES-256-GCM", "NIST CAVP gcmDecrypt256.rsp (SP 800-38D)",
        "Keylen 256, IVlen 96 and Taglen 128 only. \"valid\": opening ct with key, iv, aad and tag gives exactly pt. \"invalid\": the source says FAIL, so opening it must be refused, and no plaintext given out (pt is \"\").",
        map(readCavp(fromZip("nist-gcm/gcmtestvectors.zip", "gcmDecrypt256.rsp")), MakeCryptoKat::ofV2, b -> {
          boolean fails = b.fields.containsKey("FAIL");
          return new Case().put("id", gcmId(b)).put("key", hex(b.f("Key"), "Key")).put("iv", hex(b.f("IV"), "IV"))
              .put("aad", hex(b.f("AAD"), "AAD")).put("ct", hex(b.f("CT"), "CT")).put("tag", hex(b.f("Tag"), "Tag"))
              .put("pt", fails ? "" : hex(b.f("PT"), "PT")).put("result", fails ? "invalid" : "valid");
        }));

    write("aes-256-gcm", "wycheproof.json", "AES-256-GCM", "Wycheproof testvectors_v1/aes_gcm_test.json",
        "keySize 256, ivSize 96 and tagSize 128 only. \"valid\": sealing msg gives exactly ct and tag, and opening them gives msg. \"invalid\": opening must be refused.",
        map(readWycheproof("aes_gcm_test.json"), w -> whole(w.group.get("keySize"), "keySize") == 256
            && whole(w.group.get("ivSize"), "ivSize") == GCM_IV_BITS && whole(w.group.get("tagSize"), "tagSize") == GCM_TAG_BITS, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("key", hex(text(w.test.get("key")), "key")).put("iv", hex(text(w.test.get("iv")), "iv"))
            .put("aad", hex(text(w.test.get("aad")), "aad")).put("msg", hex(text(w.test.get("msg")), "msg"))
            .put("ct", hex(text(w.test.get("ct")), "ct")).put("tag", hex(text(w.test.get("tag")), "tag")).put("result", text(w.test.get("result")))));
  }

  // ----- HKDF-SHA-384 (and RFC 5869's own cases, which are SHA-256 and SHA-1, to prove an HKDF written by hand)

  private static void hkdf() throws IOException {
    write("hkdf-sha384", "wycheproof.json", "HKDF-SHA-384", "Wycheproof testvectors_v1/hkdf_sha384_test.json",
        "Every case. \"valid\": HKDF-SHA-384(salt, ikm, info) to size bytes gives exactly okm. \"invalid\": that size must be refused (SizeTooLarge: more than 255 x 48 bytes).",
        map(readWycheproof("hkdf_sha384_test.json"), w -> true, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("ikm", hex(text(w.test.get("ikm")), "ikm")).put("salt", hex(text(w.test.get("salt")), "salt"))
            .put("info", hex(text(w.test.get("info")), "info")).put("size", whole(w.test.get("size"), "size"))
            .put("okm", hex(text(w.test.get("okm")), "okm")).put("result", text(w.test.get("result")))));

    // ACVP's KDA with HKDF (SP 800-56C rev 2), the SHA2-384 groups. They're written as a key-establishment's derivation, so they're
    // turned into plain HKDF's three inputs here, by SP 800-56C's own rules as ACVP's groups state them:
    //   - ikm is the shared secret Z, then the auxiliary secret T, since every SHA2-384 group here is "usesHybridSharedSecret" (Z' = Z || T);
    //   - salt is the test's salt as given (all zeros when the group's saltMethod is "default");
    //   - info is the group's fixedInfoPattern "uPartyInfo||vPartyInfo||l", "concatenation": each party's partyId, then its ephemeralData if
    //     it has one, then L in bits as 4 bytes, big-endian.
    // Any group of another shape would need its own rule, so it's refused here rather than guessed at.
    List<Case> cases = new ArrayList<>();

    for (Acvp a : readAcvp("KDA-HKDF-Sp800-56Cr2")) {
      J c = a.group.get("kdfConfiguration");

      if (c == null || !"SHA2-384".equals(str(c.get("hmacAlg")))) {
        continue;
      }

      if (!"hkdf".equals(str(c.get("kdfType"))) || !"uPartyInfo||vPartyInfo||l".equals(str(c.get("fixedInfoPattern")))
          || !"concatenation".equals(str(c.get("fixedInfoEncoding"))) || !isTrue(a.group.get("usesHybridSharedSecret"))
          || a.group.get("multiExpansion") == null || !Boolean.FALSE.equals(a.group.get("multiExpansion").bool)) {
        throw new IllegalStateException("KDA-HKDF group " + text(a.group.get("tgId")) + ": a shape this doesn't turn into plain HKDF");
      }

      J p = a.test.get("kdfParameter");
      long lBits = whole(p.get("l"), "l");

      if (lBits % 8 != 0) {
        throw new IllegalStateException("KDA-HKDF test " + text(a.test.get("tcId")) + ": L isn't whole bytes");
      }

      String info = party(a.test.get("fixedInfoPartyU")) + party(a.test.get("fixedInfoPartyV")) + String.format("%08x", lBits);
      boolean val = "VAL".equals(str(a.group.get("testType")));
      cases.add(new Case().put("id", "tgId " + text(a.group.get("tgId")) + ", tcId " + text(a.test.get("tcId")) + ", " + text(a.group.get("testType")))
          .put("ikm", hex(text(p.get("z")), "z") + hex(text(p.get("t")), "t")).put("salt", hex(text(p.get("salt")), "salt")).put("info", info)
          .put("size", lBits / 8).put("okm", hex(text(val ? a.test.get("dkm") : a.answer.get("dkm")), "dkm"))
          .put("result", val ? passed(a.answer.get("testPassed"), "KDA-HKDF test " + text(a.test.get("tcId"))) : "valid"));
    }

    write("hkdf-sha384", "nist-acvp-kda.json", "HKDF-SHA-384", "NIST ACVP KDA-HKDF-Sp800-56Cr2 (SP 800-56C rev 2)",
        "The SHA2-384 groups, written as plain HKDF: ikm = Z || T, salt as given, info = U partyId || U ephemeralData || V partyId || V ephemeralData || L in bits (4 bytes, big-endian). AFT cases are all \"valid\": HKDF-SHA-384(salt, ikm, info) to size bytes gives exactly okm. VAL cases say whether the okm given is the right one.",
        cases);

    rfc5869();
  }

  private static String party(J x) {
    return hex(text(x.get("partyId")), "partyId") + (str(x.get("ephemeralData")) != null && !str(x.get("ephemeralData")).isEmpty()
        ? hex(text(x.get("ephemeralData")), "ephemeralData") : "");
  }

  // RFC 5869's appendix A: its test cases are SHA-256 and SHA-1 (it has none for SHA-384). They prove an HKDF written by hand over HMAC.
  private static void rfc5869() throws IOException {
    // The page breaks go first (a footer, a form feed, the next page's header), so a value split over two pages reads as one
    String text = new String(source("rfc/rfc5869.txt"), StandardCharsets.ISO_8859_1).replace("\r", "")
        .replaceAll("\\n+Krawczyk & Eronen[^\\n]*\\[Page \\d+\\]\\n\\f\\nRFC 5869[^\\n]*\\n+", "\n");
    // Each test case's heading, then its lines up to the next heading. The table of contents has the same headings, with no "Hash ="
    // after them, so only those with one count.
    Matcher heading = Pattern.compile("A\\.(\\d)\\.\\s+Test Case (\\d+)\\n([\\s\\S]*?)(?=\\nA\\.\\d\\.\\s+Test Case|\\n\\S|\\z)").matcher(text);
    List<Case> cases = new ArrayList<>();

    while (heading.find()) {
      String part = heading.group(3);

      if (!Pattern.compile("Hash\\s*=").matcher(part).find()) {
        continue;
      }

      Matcher hash = Pattern.compile("Hash\\s*=\\s*(SHA-\\d+)").matcher(part);
      Matcher l = Pattern.compile("L\\s*=\\s*(\\d+)").matcher(part);

      if (!hash.find() || !l.find()) {
        throw new IllegalStateException("RFC 5869 test case " + heading.group(2) + ": no Hash or L");
      }

      // Case 7's salt is "not provided (defaults to HashLen zero octets)". HMAC pads a short key with zeros, so no salt and HashLen zero
      // bytes give the same PRK: it's written as "", no salt.
      String salt = Pattern.compile("salt\\s*=\\s*not provided").matcher(part).find() ? "" : take(part, "salt");
      cases.add(new Case().put("id", "RFC 5869 A." + heading.group(2)).put("hash", hash.group(1)).put("ikm", hex(take(part, "IKM"), "IKM"))
          .put("salt", hex(salt == null ? "" : salt, "salt")).put("info", hex(orEmpty(take(part, "info")), "info"))
          .put("size", Long.parseLong(l.group(1))).put("prk", hex(take(part, "PRK"), "PRK")).put("okm", hex(take(part, "OKM"), "OKM"))
          .put("result", "valid"));
    }

    write("hkdf-sha384", "rfc5869.json", "HKDF (SHA-256 and SHA-1)", "RFC 5869, appendix A",
        "All seven test cases, each with its hash. Not SHA-384: RFC 5869 has none. HKDF-Extract(salt, ikm) gives exactly prk, and HKDF-Expand(prk, info) to size bytes gives exactly okm.",
        cases);
  }

  private static String orEmpty(String s) {
    return s == null ? "" : s;
  }

  // A value in a test case: "NAME = 0x..." and the lines after it that are only hex, indented (the last of them ends in "(42 octets)",
  // which is taken off with the rest of the brackets, and can be the last line of the case, with no line end after it)
  private static String take(String part, String name) {
    Matcher m = Pattern.compile(name + "\\s*=\\s*([^\\n]*(?:\\n\\s+[0-9a-fA-F]+(?:\\s*\\(\\d+ octets\\))?\\s*(?=\\n|\\z))*)").matcher(part);

    if (!m.find()) {
      return null;
    }

    return m.group(1).replaceAll("\\(.*?\\)", "").replaceAll("\\s+", "").replaceFirst("^0x", "");
  }

  // ----- HMAC-SHA-384

  private static void hmac() throws IOException {
    write("hmac-sha384", "wycheproof.json", "HMAC-SHA-384", "Wycheproof testvectors_v1/hmac_sha384_test.json",
        "Every case. tagSize is in bits, and a tag shorter than 384 bits is the full tag cut short. \"valid\": HMAC-SHA-384(key, msg) gives exactly tag. \"invalid\": a check of tag must fail.",
        map(readWycheproof("hmac_sha384_test.json"), w -> true, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("keySize", whole(w.group.get("keySize"), "keySize")).put("tagSize", whole(w.group.get("tagSize"), "tagSize"))
            .put("key", hex(text(w.test.get("key")), "key")).put("msg", hex(text(w.test.get("msg")), "msg"))
            .put("tag", hex(text(w.test.get("tag")), "tag")).put("result", text(w.test.get("result")))));
  }

  // ----- ECDH on P-384

  private static String reason(String result) {
    return words(result.replaceFirst("^[PF]\\s*", "").replaceAll("^\\(|\\)$", "").trim());
  }

  private static void ecdh() throws IOException {
    write("ecdh-p384", "nist-cavp.json", "ECDH P-384", "NIST CAVP KAS_ECC_CDH_PrimitiveTest.txt (SP 800-56A), [P-384]",
        "The P-384 section. public is the other side's point, uncompressed (04, X, Y, 97 bytes); private is ours, 48 bytes; ourPublic is the point it makes. ECDH(private, public) gives exactly shared, 48 bytes.",
        map(readCavp(fromZip("nist-ecdh/ecccdhtestvectors.zip", "KAS_ECC_CDH_PrimitiveTest.txt")), b -> "P-384".equals(b.sections.get("name")),
            b -> new Case().put("id", "COUNT " + b.f("COUNT")).put("public", point(b.f("QCAVSx"), b.f("QCAVSy"), "QCAVS"))
                .put("private", padded(b.f("dIUT"), P384_BYTES, "dIUT")).put("ourPublic", point(b.f("QIUTx"), b.f("QIUTy"), "QIUT"))
                .put("shared", padded(b.f("ZIUT"), P384_BYTES, "ZIUT")).put("result", "valid")));

    // Some of its cases have a coordinate too big for 48 bytes ("out of range"). x and y are kept as the source has them (padded to 48
    // bytes when shorter), and the 97-byte point only where both fit: a point that can't be written in 97 bytes is refused by its length.
    List<Case> pkv = new ArrayList<>();
    int n = 0;

    for (Block b : readCavp(fromZip("nist-ecdsa/186-4ecdsatestvectors.zip", "186-4ecdsatestvectors/PKV.rsp"))) {
      if (!"P-384".equals(b.sections.get("name"))) {
        continue;
      }

      String r = orEmpty(b.f("Result")).trim();
      String x = atLeast(b.f("Qx"), P384_BYTES, "Qx");
      String y = atLeast(b.f("Qy"), P384_BYTES, "Qy");
      boolean fits = x.length() == P384_BYTES * 2 && y.length() == P384_BYTES * 2;
      pkv.add(new Case().put("id", "case " + ++n).put("x", x).put("y", y).put("public", fits ? "04" + x + y : "")
          .put("reason", reason(r)).put("result", r.startsWith("P") ? "valid" : "invalid"));
    }

    write("ecdh-p384", "nist-cavp-pkv.json", "P-384 public key check", "NIST CAVP 186-4 PKV.rsp, [P-384]",
        "The P-384 section. x and y are as the source gives them, at least 48 bytes each; public is (04, X, Y) where both fit in 48 bytes, and \"\" where one is longer, which can only be refused. \"valid\": the point is on the curve and may be used. \"invalid\": it must be refused. reason is the source's own words.",
        pkv);

    write("ecdh-p384", "wycheproof-ecpoint.json", "ECDH P-384", "Wycheproof testvectors_v1/ecdh_secp384r1_ecpoint_test.json",
        "Every case. public is the other side's point as X9.62 bytes (04 X Y uncompressed, or 02/03 X compressed), as sent; private is ours. \"valid\": ECDH gives exactly shared. \"invalid\": the point must be refused (off the curve, the wrong length, a bad encoding). \"acceptable\": either is allowed (a compressed point, which v2 never sends, so v2 refuses it).",
        map(readWycheproof("ecdh_secp384r1_ecpoint_test.json"), w -> true, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("public", hex(text(w.test.get("public")), "public")).put("private", hex(text(w.test.get("private")), "private"))
            .put("shared", hex(text(w.test.get("shared")), "shared")).put("result", text(w.test.get("result")))));

    write("ecdh-p384", "wycheproof-der.json", "ECDH P-384", "Wycheproof testvectors_v1/ecdh_secp384r1_test.json",
        "Every case, with the other side's key as a DER SubjectPublicKeyInfo, as Java's X509EncodedKeySpec reads it. Results as in wycheproof-ecpoint.json.",
        map(readWycheproof("ecdh_secp384r1_test.json"), w -> true, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("publicDer", hex(text(w.test.get("public")), "public")).put("private", hex(text(w.test.get("private")), "private"))
            .put("shared", hex(text(w.test.get("shared")), "shared")).put("result", text(w.test.get("result")))));
  }

  // ----- ECDSA on P-384 with SHA-384, signatures as r then s (IEEE P1363, 96 bytes), as v2 sends them (CRYPTO.md section 12)

  private static String p1363(String r, String s, String what) {
    return padded(r, P384_BYTES, what + " R") + padded(s, P384_BYTES, what + " S");
  }

  private static void ecdsa() throws IOException {
    List<Case> ver = new ArrayList<>();
    int n = 0;

    for (Block b : readCavp(fromZip("nist-ecdsa/186-4ecdsatestvectors.zip", "186-4ecdsatestvectors/SigVer.rsp"))) {
      if ("P-384,SHA-384".equals(b.sections.get("name"))) {
        String r = orEmpty(b.f("Result")).trim();
        ver.add(new Case().put("id", "case " + ++n).put("public", point(b.f("Qx"), b.f("Qy"), "Q")).put("msg", hex(b.f("Msg"), "Msg"))
            .put("sig", p1363(b.f("R"), b.f("S"), "sig")).put("reason", reason(r)).put("result", r.startsWith("P") ? "valid" : "invalid"));
      }
    }

    write("ecdsa-p384-sha384", "nist-cavp-sigver.json", "ECDSA P-384 SHA-384", "NIST CAVP 186-4 SigVer.rsp, [P-384,SHA-384]",
        "The [P-384,SHA-384] section. public is (04, X, Y); sig is r then s, 48 bytes each. \"valid\": the signature on msg checks. \"invalid\": it must not. reason is the source's own words.",
        ver);

    List<Case> gen = new ArrayList<>();
    n = 0;

    for (Block b : readCavp(fromZip("nist-ecdsa/186-4ecdsatestvectors.zip", "186-4ecdsatestvectors/SigGen.txt"))) {
      if ("P-384,SHA-384".equals(b.sections.get("name"))) {
        gen.add(new Case().put("id", "case " + ++n).put("private", padded(b.f("d"), P384_BYTES, "d")).put("public", point(b.f("Qx"), b.f("Qy"), "Q"))
            .put("msg", hex(b.f("Msg"), "Msg")).put("k", padded(b.f("k"), P384_BYTES, "k")).put("sig", p1363(b.f("R"), b.f("S"), "sig"))
            .put("result", "valid"));
      }
    }

    write("ecdsa-p384-sha384", "nist-cavp-siggen.json", "ECDSA P-384 SHA-384", "NIST CAVP 186-4 SigGen.txt, [P-384,SHA-384]",
        "The [P-384,SHA-384] section, with the per-signature secret k the source used. Signing msg with private and that k gives exactly sig (r then s); public is the private key's point. A signer that picks its own k makes another signature, which must still check.",
        gen);

    write("ecdsa-p384-sha384", "wycheproof-p1363.json", "ECDSA P-384 SHA-384", "Wycheproof testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json",
        "Every case. public is the group's key, uncompressed (04, X, Y); sig is r then s as given, which may be the wrong length on purpose. \"valid\": the signature on msg checks. \"invalid\": it must not.",
        map(readWycheproof("ecdsa_secp384r1_sha384_p1363_test.json"), w -> true, w -> new Case()
            .put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags)
            .put("public", hex(text(w.group.get("publicKey").get("uncompressed")), "publicKey")).put("msg", hex(text(w.test.get("msg")), "msg"))
            .put("sig", hex(text(w.test.get("sig")), "sig")).put("result", text(w.test.get("result")))));
  }

  // ----- ML-KEM-1024 (FIPS 203)

  private static String id(Acvp a) {
    return "tgId " + text(a.group.get("tgId")) + ", tcId " + text(a.test.get("tcId"));
  }

  private static void mlKem() throws IOException {
    Predicate<Acvp> is1024 = a -> "ML-KEM-1024".equals(str(a.group.get("parameterSet")));

    write("ml-kem-1024", "nist-acvp-keygen.json", "ML-KEM-1024", "NIST ACVP ML-KEM-keyGen-FIPS203",
        "The ML-KEM-1024 group. ML-KEM.KeyGen_internal(d, z) gives exactly ek (1,568 bytes) and dk (3,168 bytes).",
        map(readAcvp("ML-KEM-keyGen-FIPS203"), is1024, a -> new Case().put("id", id(a)).put("d", hex(text(a.test.get("d")), "d"))
            .put("z", hex(text(a.test.get("z")), "z")).put("ek", hex(text(a.answer.get("ek")), "ek")).put("dk", hex(text(a.answer.get("dk")), "dk"))
            .put("result", "valid")));

    List<Case> cases = new ArrayList<>();

    for (Acvp a : readAcvp("ML-KEM-encapDecap-FIPS203")) {
      if (!is1024.test(a)) {
        continue;
      }

      String function = str(a.group.get("function"));

      switch (function == null ? "" : function) {
        case "encapsulation" -> cases.add(new Case().put("id", id(a)).put("function", "encapsulation").put("ek", hex(text(a.test.get("ek")), "ek"))
            .put("m", hex(text(a.test.get("m")), "m")).put("c", hex(text(a.answer.get("c")), "c")).put("k", hex(text(a.answer.get("k")), "k"))
            .put("result", "valid"));
        case "decapsulation" -> cases.add(new Case().put("id", id(a)).put("function", "decapsulation")
            .put("dk", hex(either(a.test.get("dk"), a.group.get("dk")), "dk")).put("c", hex(text(a.test.get("c")), "c"))
            .put("k", hex(text(a.answer.get("k")), "k")).put("result", "valid"));
        case "encapsulationKeyCheck" -> cases.add(new Case().put("id", id(a)).put("function", "encapsulationKeyCheck")
            .put("ek", hex(text(a.test.get("ek")), "ek")).put("result", passed(a.answer.get("testPassed"), id(a))));
        case "decapsulationKeyCheck" -> cases.add(new Case().put("id", id(a)).put("function", "decapsulationKeyCheck")
            .put("dk", hex(text(a.test.get("dk")), "dk")).put("result", passed(a.answer.get("testPassed"), id(a))));
        default -> throw new IllegalStateException("ML-KEM-encapDecap: a function this doesn't know: " + function);
      }
    }

    write("ml-kem-1024", "nist-acvp-encapdecap.json", "ML-KEM-1024", "NIST ACVP ML-KEM-encapDecap-FIPS203",
        "The ML-KEM-1024 groups. \"encapsulation\": ML-KEM.Encaps_internal(ek, m) gives exactly c and k. \"decapsulation\": ML-KEM.Decaps(dk, c) gives exactly k (where c was changed, k is the implicit rejection's, and is still exactly that). \"encapsulationKeyCheck\" and \"decapsulationKeyCheck\": FIPS 203 section 7.2 and 7.3's checks; \"valid\" passes, \"invalid\" must be refused.",
        cases);

    write("ml-kem-1024", "wycheproof-keygen-seed.json", "ML-KEM-1024", "Wycheproof testvectors_v1/mlkem_1024_keygen_seed_test.json",
        "Every case. seed is d then z, 32 bytes each; KeyGen from it gives exactly ek and dk.",
        map(readWycheproof("mlkem_1024_keygen_seed_test.json"), w -> true, w -> wcase(w).put("seed", hex(text(w.test.get("seed")), "seed"))
            .put("ek", hex(text(w.test.get("ek")), "ek")).put("dk", hex(text(w.test.get("dk")), "dk")).put("result", text(w.test.get("result")))));

    write("ml-kem-1024", "wycheproof-encaps.json", "ML-KEM-1024", "Wycheproof testvectors_v1/mlkem_1024_encaps_test.json",
        "Every case. \"valid\": encapsulating to ek with the randomness m gives exactly c and K. \"invalid\": ek must be refused (ModulusOverflow: a coefficient past q, FIPS 203 section 7.2), and c and K are \"\".",
        map(readWycheproof("mlkem_1024_encaps_test.json"), w -> true, w -> wcase(w).put("ek", hex(text(w.test.get("ek")), "ek"))
            .put("m", hex(text(w.test.get("m")), "m")).put("c", hex(text(w.test.get("c")), "c")).put("K", hex(text(w.test.get("K")), "K"))
            .put("result", text(w.test.get("result")))));

    write("ml-kem-1024", "wycheproof-decaps.json", "ML-KEM-1024", "Wycheproof testvectors_v1/mlkem_1024_test.json",
        "Every case. KeyGen from seed (d then z) gives ek; decapsulating c with that key gives exactly K, including where c was changed (implicit rejection). \"invalid\": the case must be refused.",
        map(readWycheproof("mlkem_1024_test.json"), w -> true, w -> wcase(w).put("seed", hex(text(w.test.get("seed")), "seed"))
            .put("ek", hex(text(w.test.get("ek")), "ek")).put("c", hex(text(w.test.get("c")), "c")).put("K", hex(text(w.test.get("K")), "K"))
            .put("result", text(w.test.get("result")))));

    write("ml-kem-1024", "wycheproof-decaps-checked.json", "ML-KEM-1024", "Wycheproof testvectors_v1/mlkem_1024_semi_expanded_decaps_test.json",
        "Every case. \"valid\": decapsulating c with dk gives exactly K. \"invalid\": dk or c must be refused (the wrong length, or a dk that fails FIPS 203 section 7.3's check).",
        map(readWycheproof("mlkem_1024_semi_expanded_decaps_test.json"), w -> true, w -> wcase(w).put("dk", hex(text(w.test.get("dk")), "dk"))
            .put("c", hex(text(w.test.get("c")), "c")).put("ek", hex(text(w.test.get("ek")), "ek")).put("K", hex(text(w.test.get("K")), "K"))
            .put("result", text(w.test.get("result")))));
  }

  // A Wycheproof case's first three fields, which every one of its files starts with
  private static Case wcase(Wych w) {
    return new Case().put("id", "tcId " + text(w.test.get("tcId"))).put("comment", words(str(w.test.get("comment")))).put("flags", w.flags);
  }

  // ----- ML-DSA-87 (FIPS 204): pure ML-DSA through the external interface, with a context, as v2 signs and checks (CRYPTO.md section 12)

  // ACVP leaves externalMu out of the external groups, rather than writing false, so "not true" is the test
  private static boolean pureExternal(J g) {
    return "external".equals(str(g.get("signatureInterface"))) && "pure".equals(str(g.get("preHash"))) && !isTrue(g.get("externalMu"));
  }

  private static void mlDsa() throws IOException {
    Predicate<Acvp> is87 = a -> "ML-DSA-87".equals(str(a.group.get("parameterSet")));

    write("ml-dsa-87", "nist-acvp-keygen.json", "ML-DSA-87", "NIST ACVP ML-DSA-keyGen-FIPS204",
        "The ML-DSA-87 group. ML-DSA.KeyGen_internal(seed) gives exactly pk (2,592 bytes) and sk (4,896 bytes).",
        map(readAcvp("ML-DSA-keyGen-FIPS204"), is87, a -> new Case().put("id", id(a)).put("seed", hex(text(a.test.get("seed")), "seed"))
            .put("pk", hex(text(a.answer.get("pk")), "pk")).put("sk", hex(text(a.answer.get("sk")), "sk")).put("result", "valid")));

    write("ml-dsa-87", "nist-acvp-sigver.json", "ML-DSA-87", "NIST ACVP ML-DSA-sigVer-FIPS204",
        "The ML-DSA-87 groups that are pure ML-DSA through the external interface (ML-DSA.Verify(pk, message, signature, context)). \"valid\": the signature checks. \"invalid\": it must not. context may be \"\" (an empty context).",
        map(readAcvp("ML-DSA-sigVer-FIPS204"), a -> is87.test(a) && pureExternal(a.group), a -> new Case().put("id", id(a))
            .put("pk", hex(either(a.test.get("pk"), a.group.get("pk")), "pk")).put("message", hex(text(a.test.get("message")), "message"))
            .put("context", hex(text(a.test.get("context")), "context")).put("signature", hex(text(a.test.get("signature")), "signature"))
            .put("result", passed(a.answer.get("testPassed"), "sigVer " + text(a.test.get("tcId"))))));

    write("ml-dsa-87", "nist-acvp-siggen.json", "ML-DSA-87", "NIST ACVP ML-DSA-sigGen-FIPS204",
        "The ML-DSA-87 groups that are pure ML-DSA through the external interface. ML-DSA.Sign(sk, message, context) gives exactly signature: \"deterministic\" uses no randomness, and \"hedged\" uses rnd as given.",
        map(readAcvp("ML-DSA-sigGen-FIPS204"), a -> is87.test(a) && pureExternal(a.group), a -> {
          boolean det = isTrue(a.group.get("deterministic"));
          return new Case().put("id", id(a)).put("mode", det ? "deterministic" : "hedged")
              .put("sk", hex(either(a.test.get("sk"), a.group.get("sk")), "sk")).put("message", hex(text(a.test.get("message")), "message"))
              .put("context", hex(text(a.test.get("context")), "context")).put("rnd", det ? "" : hex(text(a.test.get("rnd")), "rnd"))
              .put("signature", hex(text(a.answer.get("signature")), "signature")).put("result", "valid");
        }));

    write("ml-dsa-87", "wycheproof-verify.json", "ML-DSA-87", "Wycheproof testvectors_v1/mldsa_87_verify_test.json",
        "Every case. pk is the group's public key (it can be the wrong length on purpose); context is \"\" where the source gives none. \"valid\": the signature on msg checks. \"invalid\": it, or pk, must be refused.",
        map(readWycheproof("mldsa_87_verify_test.json"), w -> true, w -> wcase(w).put("pk", hex(text(w.group.get("publicKey")), "publicKey"))
            .put("msg", hex(text(w.test.get("msg")), "msg")).put("context", hex(text(w.test.get("ctx")), "ctx"))
            .put("sig", hex(text(w.test.get("sig")), "sig")).put("result", text(w.test.get("result")))));
  }
}
