# Reporting a security problem

Written 2026-11-09 by Melanikus.

**Please report it privately, never in a public issue or pull request:** on this repository's page, choose **Security**, then **Report a vulnerability** (GitHub's private vulnerability reporting). Only the maintainers see it.

Say what you can of:
- what's wrong, and where (a file and line, a message, a call);
- how to make it happen, as small as you can;
- what it lets someone do.

Please don't include anyone's personal data, and don't test against a server that isn't yours.

## What happens then

- We answer within a few days, and keep you told as we go.
- A fix is made in the code, never hidden, and every gate must pass on it (GATES.md).
- Nothing is released, and no server is put in the wild, while a known problem is open (SERVER-BLOCKERS.md).
- Once a fix is out, we publish an advisory, and credit you if you'd like.

## In scope

- The server in this repository: the relay (UDP), the list (HTTPS), and their settings, logs and limits.
- The protocol: PROTOCOL.md (version 1) and CRYPTO.md (version 2): a message, a limit, a handshake, or a proof that doesn't hold.
- `deploy/` and `.github/workflows/`: anything that could put the wrong code on a machine, leak a key, or let a deploy around its checks.
- The test vectors, if one is wrong.

## Not in scope

- The game itself (github.com/Melanikus/AvP), which has its own security policy. Report a problem in the game's side of the protocol there.
- Floods of traffic large enough to overwhelm any server, rather than a weakness in this one. Something small that makes the server do much more work than it was asked, or send much more than it was sent, is in scope.
- A cheater with control of their own machine: CRYPTO.md section 1 says plainly what no check on a player's own machine can stop.
