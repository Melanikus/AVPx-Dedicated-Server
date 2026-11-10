# How we write code here

Written 2026-11-08 by Melanikus; for the Java server from 2026-11-09. **Every rule says why it exists and what enforces it.** A rule a machine checks names that check:
- `java/tools/CheckStandard.java` runs every one of them on every change (GATES.md, "Coding standard"; it's part of the "Java tests" check);
- `java/tools/Takeouts.java` proves each one can fail, by breaking a copy and seeing the check notice.

A rule only a reviewer can check says so. When you add a rule, give it the next number, a plain reason and its check, in the same change as the code that taught it.

## 1. Every file is ASCII
**Why:** a byte that looks like another, or one a tool reads two ways, can hide a change in plain sight. ASCII is the same in every editor and every tool, decades from now.
**Checked by:** CheckStandard, on every byte of every file in the repository. javac reads the sources as ASCII too, and fails on any other byte. Write a character outside ASCII as a number (`(char) 0xe9`).

## 2. No third-party code, and nothing precompiled
**Why:** every package is code we didn't write and can't keep an eye on, and a compiled file can't be read at all (AVP Tao 1). Java's own library does everything this server needs.
**Checked by:** CheckStandard:
- `module-info.java` names no module it needs, so javac itself can use nothing but `java.base`;
- every import is Java's own (`java.`, `javax.`) or ours (`avpx.`);
- nowhere in the repository is there a build file that fetches packages, or any compiled code at all (`.jar`, `.class`, `.dll` and the rest). The build files are Java's (Maven's `pom.xml`, Gradle's) and Node's (`package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `pnpm-workspace.yaml`, and any `node_modules` folder). Node's are there because this server was Node's until 2026-11-08, so a Node tree can't creep back unseen.

## 3. No code made from text
**Why:** text can come from the network, and code made from it could do anything.
**Checked by:** CheckStandard refuses every way Java turns text or bytes into code, or reaches past its own safety: reflection, scripting, class loaders, reading Java objects back from bytes, native code.

## 4. The server starts no other program
**Why:** a program the server starts is a program an attacker could start through it. Only the tools that check the code (`java/tools/`) may.
**Checked by:** CheckStandard.

## 5. The server writes nothing but through its log, and the log never holds an address
**Why:** the user's ruling: no IPs. One way out means one place to check.
**Checked by:** CheckStandard: the screen is named only in `Log.java`, and no stack trace is printed. The tests check what its lines hold: counts and times, never an address, a code, a token or a name.

## 6. A finding is fixed, never hidden
**Why:** a scanner or compiler told to look away is one that isn't working (AVP Tao 1).
**Checked by:** CheckStandard refuses anything that tells javac or a scanner to look away, in any file, and any file that does. The words it looks for are listed in CheckStandard.java itself, written in pieces.

## 7. Every action a workflow uses is pinned to a commit
**Why:** a tag can be moved to other code; a full commit hash can't.
**Checked by:** CheckStandard refuses a `uses:` in `.github/workflows/` that isn't a 40-digit hash or one of our own actions.

## 8. Every test runs
**Why:** a test that's never run proves nothing, and nobody notices it's missing.
**Checked by:** CheckStandard: every file in `java/test` whose name ends in `Test.java` is named in `AllTests.java`.

## 9. Every limit is a named number, written once
**Why:** a limit written in two places drifts apart, and a bare number says nothing about what it's for.
**Checked by:** a reviewer. PROTOCOL.md section 5 (and CRYPTO.md section 17) lists every limit, and the code names each one where it's set.

## 10. Comments in plain words
**Why:** someone decades from now, with nobody to ask, should be able to read why each part is the way it is (AVP Tao 2).
**Checked by:** a reviewer.

## 11. Bytes are compared in the same time, whatever they hold
**Why:** a compare that stops at the first byte that differs takes longer the more of a guess is right, so the time it takes can give away a secret a byte at a time. The server compares keys, ids, passes and tags, and which of them are secret isn't always plain (a scanner can't tell, nor can a reader years from now), so every compare is the kind that can't give anything away.
**Checked by:** CheckStandard: no `Arrays.equals`, `Arrays.mismatch`, `Arrays.compare` (or `Arrays.compareUnsigned`) or `Arrays.deepEquals` in `java/src` or `java/tools`, nor a method reference to them (`Arrays::equals`), nor `Objects.deepEquals`, nor any method called `mismatch` (`ByteBuffer` has one too), and no static import of `java.util.Arrays`, which would let them be written without `Arrays.` in front. Each is looked for with the line's spaces taken out too, so `Arrays.equals (a, b)` is found. Bytes are compared with `MessageDigest.isEqual` (or `Crypto.same`, which also says no two nothings are the same). **A reviewer's to catch,** as a line's text can't show them: `ByteBuffer.equals` and `ByteBuffer.compareTo` (an `equals` like any other), `String.equals` or `List.equals` on what were bytes, and a call broken across two lines. A passing CheckStandard doesn't mean none of these is there. The tests in `java/test` may use either: what they compare is published test vectors and their own made-up values.

## The shell scripts in deploy/

The same rules hold for them, and their own tests hold them to it:
- every one is POSIX `sh`, with `set -eu`;
- `-e` is never switched off and on inside a function: a function that switched it back on would make the next failing return end the script. Exits are caught with `if`/`else`;
- each script's test also breaks copies of it, and must notice.
