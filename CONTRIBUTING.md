# Working on the server

Written 2026-11-09 by Melanikus. Thank you for wanting to help. This server faces the internet, so it's held to more than most code is: read this before your first change.

## The rules, in one place

- **Security first.** Nothing third-party and nothing precompiled: Java SE only, no Maven or Gradle, no library, no jar or other compiled file in the repository. The coding standard's rule 2 refuses all of it (CODING-STANDARD.md).
- **Everything that arrives is hostile.** Every field from the network has a written limit, and anything outside it is refused, with its reason. PROTOCOL.md is the contract: change it only with the code and the tests, in the same change, and say why in it.
- **No IP address is ever written anywhere:** the logs are counts and times.
- **Tests first.** A change comes with the test that would have caught its absence.
- **Take-out rows.** For every check you add, add a row to `java/tools/takeouts.txt` that breaks it in a copy: the Java take-outs check runs every row, and each must be noticed. A test that can't fail proves nothing.
- **Plain words.** Comments say *why*, in words someone decades from now could follow with nobody to ask. Every limit is a named number, written once.
- **A finding is fixed, never hidden.** Nothing that tells a compiler or scanner to look away, anywhere.

## How a change goes

1. **For anything bigger than a typo, open an issue first** (bug or feature), so the shape can be agreed before the work. A security problem never goes in an issue: SECURITY.md says where.
2. **Make the change on a branch of your own fork,** with its tests and take-out rows. Before you push, run what the gates run:
   - `sh java/tools/get-jdk.sh <folder>` once, then `JAVA_HOME=<folder> AVPX_LIVE=1 sh java/build.sh`: the build, every test (the live ones on 127.0.0.1 only), and the coding standard;
   - the take-outs and the smoke test, as java.yml runs them;
   - if you changed `deploy/`, its tests: `sh deploy/test-check-blockers.sh`, `sh deploy/test-remote-deploy.sh` (on Linux), `sh deploy/test-deploy-workflow.sh`, `sh deploy/test-open-for-tester.sh`, `sh deploy/test-firewall.sh` and `sh deploy/test-pull-deploy.sh` (needs jq, so on Linux).
3. **Open a pull request** against `main`, and fill in its checklist.
4. **Every check must be green.** GATES.md lists them, and branch protection requires each one, for everyone, administrators too. Workflows from forks wait for a maintainer to approve their first run.
5. **A maintainer reviews it.** Expect questions: we ask for evidence (the test, the run, the line) rather than take a change on trust, our own included.

## What the gates check

GATES.md has the whole list, with when each fails. In short:
- the Java tests (javac with every warning an error, every test, the coding standard, the same jars from the same code);
- the JDK is the newest of its line;
- the smoke test from outside the process;
- the take-outs;
- CodeQL;
- Snyk Code;
- the deploy blockers and the deploy scripts.

## Licence

To come: the owner's choice. Until it's chosen, contributions can't be merged.
