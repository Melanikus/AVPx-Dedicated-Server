## What this changes, and why

<!-- In plain words. Link the issue it closes. -->

## The checklist (CONTRIBUTING.md)

- [ ] Every new or changed behaviour has a test that would have caught its absence.
- [ ] Every new check has a row in `java/tools/takeouts.txt` that breaks it, and the take-outs notice it.
- [ ] Nothing third-party, nothing precompiled, nothing that tells a compiler or scanner to look away.
- [ ] Every new limit is a named number, written once, and in PROTOCOL.md section 5 (or CRYPTO.md section 17).
- [ ] If what the server says or hears changed: PROTOCOL.md (or CRYPTO.md) changed with it, in this same pull request, saying why.
- [ ] No IP address is written anywhere, and the log still holds only counts and times.
- [ ] Comments say why, in plain words.
- [ ] Run before pushing: `AVPX_LIVE=1 sh java/build.sh`, and the `deploy/` tests if `deploy/` changed.

Every check in GATES.md must be green before this merges.
