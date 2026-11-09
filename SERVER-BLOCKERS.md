# What blocks putting the server in the wild

Written 2026-11-09 by Melanikus, at the user's word: "This is a server in the wild. Tao 1 and 3. We CANNOT get it wrong."

**How this file works.** Every deploy workflow, now or later, runs `sh deploy/check-blockers.sh` as its first step. That step refuses to go on while anything is listed under the heading below. Only the word `Nothing.`, on its own, lets a deploy run. It also refuses:
- an empty list;
- a missing heading, or the heading twice;
- a file cut short, without its last line.

An item comes off the list only when it's done, in the commit that shows it, never to let a deploy through. deploy/test-check-blockers.sh proves the refusals work; GATES.md's "Server blockers" check runs it.

## Blocking a deploy

1. Protocol version 2 (CRYPTO.md) is built end to end, in this server and in the game. Version 1, with its messages in the clear, is never put in the wild.
2. The independent security review (#2) is done, and every finding is fixed.
3. Every gate is green and required on main, Snyk included, with branch protection that holds for administrators too.
4. The review of the post-quantum libraries' source (#10) is done.
5. A first deploy, to a test machine nobody else can reach, passes the smoke client.
6. The deploy's AWS command line tool is pinned (#17): `deploy/get-aws-cli.sh` has its version, its sha256 and AWS's key fingerprint, and `deploy/aws-cli-key.asc` is there. Until then the script refuses, and so would a deploy.

End of the list.
