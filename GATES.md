# The gates: what every change must pass

Written 2026-11-08 by Melanikus; for the Java server from 2026-11-09. Nothing reaches `main` without passing every check below (AVP Tao 1: security is paramount).
- A failing check fails the change, for everyone. Admins can't bypass it, and nothing is report-only.
- A finding is fixed in the code, never hidden: no ignore lists, and no checks switched off for one file.
- A blind spot fails the gate too: a file a scanner can't read, or code it doesn't reach.

## The checks (all required on `main`'s branch protection, with "Include administrators" on)

| Check | Workflow | What it does | When it fails |
|---|---|---|---|
| **Java tests** | java.yml | `sh java/build.sh` with `AVPX_LIVE=1`: javac with every warning an error, then every test, the live ones on 127.0.0.1 included; the coding standard (CheckStandard); and the same jars from the same code, on two filesystems | Any test failing or not run, any warning, any rule broken, two builds that differ |
| **The JDK is the newest Temurin 25** | java.yml | Adoptium's newest Temurin 25 release against the one get-jdk.sh pins | A newer release is out (a quarterly security update: move the pin) |
| **Smoke test, 38 checks, against the running server** | java.yml | `java/tools/Smoke.java` against the server running on 127.0.0.1, from outside its process | Any check failing |
| **Java take-outs** | java.yml | `java/tools/Takeouts.java` over `java/tools/takeouts.txt`: each row breaks one thing in a copy, and the check it names must notice. The rows run in twelve shares side by side (`takeouts-shares`); this check is green only when every share ran to the end and passed | A row not noticed, or not found; a share failed, cancelled or not run |
| **CodeQL (Java)** | java.yml | GitHub's static analysis, language `java-kotlin`, the security-and-quality queries, through `build.sh` | Any result in CodeQL's own SARIF, or any tracked `.java` file CodeQL didn't read |
| **Snyk** | snyk.yml | Snyk Code (static analysis) on the whole repository | Any issue at any severity, or no `SNYK_TOKEN` |
| **Server blockers** | blockers.yml | `deploy/test-check-blockers.sh`: the refusal of every deploy while SERVER-BLOCKERS.md lists anything works, and its own cases would notice the checker going wrong | The refusal's test failing. (A deploy refuses on its own while anything is listed) |
| **Deploy scripts** | blockers.yml | `deploy/test-remote-deploy.sh` and `test-pull-deploy.sh` (the machine's side: putting a commit in place, and fetching a deploy the owner approved, with stand-ins: no machine, no network, no GitHub), `test-deploy-workflow.sh` (deploy.yml's shape, the tools' rules included), `test-open-for-tester.sh` and `test-firewall.sh` (with stand-ins: no firewall touched), and `check-ubuntu-tools.sh` on the runner itself | Any case, take-out or rule failing |
| **Secret scanning and push protection** | GitHub's own | Switched on for the repository | A secret in a push is refused before it lands |

**What isn't a check, and why:**
- **No dependency scan** (OSV-Scanner, Snyk Open Source): the Java server has no Maven or Gradle file and fetches no package, by design, so there's nothing for one to read. A scan that reads nothing can't be told from a broken one, so what proves there's nothing to find is the coding standard's rule 2 (CheckStandard): no build file that fetches packages, no compiled code anywhere in the repository, and a `module-info.java` naming no module but `java.base`.
- **The JDK** is the one thing from outside, and it's held two ways: get-jdk.sh fetches it and checks its signature (by Adoptium's key, pinned by fingerprint), its sha256 and its version before anything runs it; and "The JDK is the newest Temurin 25" fails as soon as a newer security release is out.

## The workflows that aren't checks

- **Deploy** (`deploy.yml`): started by hand, with a commit, as a dry run unless told otherwise. It refuses while SERVER-BLOCKERS.md lists anything. Then it checks the commit is on main and that the latest run of every workflow above, for that commit, succeeded. Then it builds the jars and waits for the owner to approve the `production` environment, and only then records a GitHub deployment for the machine. The machine's own timer (deploy/pull-deploy.sh) takes it, after checking the run, the owner's approval, the commit on main and main's blockers itself. Nothing on GitHub reaches the machine (deploy/README.md, "The machine fetches its own deploys").
- **Test build** (`test-build.yml`): started by hand; builds a commit's jars and prints what the owner checks for a deploy by hand on a test machine, and for installing the machine's own deploy scripts: the jars' SHA-256, and remote-deploy.sh's and pull-deploy.sh's. It reaches no machine.

## Settings on GitHub (PO sets these up)

- **Branch protection on `main`:**
  - every check above required;
  - pull requests only, with at least one approving review;
  - conversations resolved;
  - no force pushes or deletions;
  - "Include administrators" on.
- **Repository settings:** Dependabot alerts and security updates on. Private vulnerability reporting on (SECURITY.md).
- **Code scanning:** CodeQL's default setup off, because GitHub refuses a workflow's results while it's on; CodeQL runs only as java.yml's job.
- **Actions:**
  - only actions from GitHub and verified creators, each pinned by SHA (CODING-STANDARD.md rule 7);
  - the `GITHUB_TOKEN` read-only by default;
  - workflows from forks need approval.
- **The `production` environment:** the owner is its only reviewer. It holds no secret and no variable: once the owner approves a deploy, deploy.yml's record job only records a GitHub deployment, and the machine fetches it itself (deploy/pull-deploy.sh). No cloud role, and no identity token: nothing on GitHub reaches a machine.
