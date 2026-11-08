# The gates: what every change must pass

Written 2026-11-08 by Melanikus. Nothing reaches `main` without passing every check below (AVP Tao 1: security is paramount).
- A failing check fails the change, for everyone. Admins can't bypass it, and nothing is report-only.
- A finding is fixed in the code, never hidden: no ignore lists, and no checks switched off for one file.
- A blind spot fails the gate too: a file a scanner can't read, or code it doesn't reach.

## The checks (all required on `main`'s branch protection, with "Include administrators" on)

| Check | What it does | When it fails |
|---|---|---|
| **Tests** | The server's own tests, on a clean Ubuntu runner, with the language's runtime pinned to one version | Any test failing, or no tests found |
| **CodeQL** | GitHub's static analysis, for the server's language, with the security-and-quality queries | Any alert at any severity |
| **OSV-Scanner** | Every dependency in the lock file, against the OSV database | Any known vulnerability. With no dependencies, the scan must still run and say it found the lock file, or the step fails |
| **Snyk** | Snyk Code (static) and Snyk Open Source (dependencies), on Snyk's free account | Any issue at any severity |
| **No packages** | Refuses any third-party dependency: an npm `dependencies` / `devDependencies` / `node_modules` for Node, or any `require` line in `go.mod` beyond the standard library for Go | Any found |
| **Coding standard** | CODING-STANDARD.md's checks (to come, one rule at a time, each with its reason): every file ASCII; every limit a named constant; no `eval` or `Function(` (Node), no `unsafe` or cgo (Go); no address written to a log | Any found |
| **Secret scanning and push protection** | GitHub's own, switched on for the repository | A secret in a push is refused before it lands |
| **Pinned actions** | Every `uses:` in a workflow is pinned to a full commit SHA, with the version in a comment | One that isn't |

## Which version of each check, by language

- **Node.js:**
  - CodeQL language `javascript-typescript`;
  - Tests are `node --test`, on the pinned Node of the Ubuntu runner, or `actions/setup-node` pinned by SHA;
  - OSV reads `package-lock.json`, an empty one with no dependencies.
- **Go:**
  - CodeQL language `go`;
  - Tests are `go test ./...` and `go vet ./...`, with the Go version pinned in `go.mod` and by `actions/setup-go` by SHA;
  - OSV reads `go.mod` / `go.sum`, plus `govulncheck` for the standard library.

## Settings on GitHub (PO sets these up)

- **Branch protection on `main`:**
  - every check above required;
  - pull requests only, with at least one approving review;
  - conversations resolved;
  - no force pushes or deletions;
  - "Include administrators" on.
- **Repository settings:** Dependabot alerts on (already on), and security updates on. Private vulnerability reporting on (already on).
- **Actions:**
  - only actions from GitHub and verified creators, each pinned by SHA;
  - the `GITHUB_TOKEN` read-only by default;
  - workflows from forks need approval.

## Nothing deployed from here yet

There's no deploy workflow. When the server is first put on a machine, deploying is a separate step that needs the owner's word, and it gets its own gate: the same commit must have passed everything above.
