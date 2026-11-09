# For AI agents working in this repository

Written 2026-11-09 by Melanikus, at the owner's word: "Future bots must be instructed to search for replacement tools and understand the criticality of failing scans". You may be reading this long after we're gone, with none of our accounts. These rules still hold.

**Security comes first.** This server faces strangers, and everything it receives from outside is hostile until it's checked. When security is in the way of anything else (speed, convenience, cost, a feature, a deadline), security wins.

## A scan that can't run is a failed scan

Every gate in GATES.md must pass before a change reaches main. If a gate's tool can't be reached, is gone, or its token has expired, **the gate has failed.** It hasn't passed, and it isn't skipped. **Never:**
- skip it, or let the change through without it;
- make it report-only, or lower its threshold;
- add an ignore, a suppression, or an excluded file or folder;
- switch a check off "for now".

**The fix is a replacement:**
1. **Find** a current tool that proves at least what the old one did. TAKING-OVER.md section 6 says what each gate proves, and names candidates.
2. **Treat it as untrusted** until it's checked: get it from its makers' own source, check its signature or published hash, and read what it runs before it runs.
3. **Pin it:** its exact version and its sha256, in the repository, so the same bytes run every time.
4. **Wire it in** so it fails closed: if it can't run, it says "<tool> is unreachable: replace it with an equivalent, see TAKING-OVER.md", and the check fails.
5. **Show it works:** it passes on the code as it is, and fails on a copy with a known problem put in on purpose (`java/tools/takeouts.txt` is how this repository does that).

## Findings are fixed, never hidden

A finding from any gate is fixed in the code. It's never ignored, parked or excluded.

## Read before you change anything

- TAKING-OVER.md: how this server is run, trusted and kept up without us.
- GATES.md: every check, and why.
- SERVER-BLOCKERS.md: what must be done before a server is open to the world. Nothing comes off that list except by being done.
- CODING-STANDARD.md, PROTOCOL.md and CRYPTO.md.

Never commit a key, a token, a password, or anyone's personal data, such as a player's address or name.
