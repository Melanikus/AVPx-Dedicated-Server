# The formal models

Written 2026-11-09 by Melanikus. CRYPTO.md section 14 promises these: models of version 2's handshakes, in **ProVerif** (INRIA's open-source tool, written in OCaml), proving what CRYPTO.md section 13 asks of them against an attacker who controls the whole network.

**They prove the pattern, not our code.** The code is held to the pattern by the test vectors (CRYPTO.md section 15) and the tests. Each model's header says what's modelled, what isn't, and why.

| Model | What it is | Its queries |
|---|---|---|
| `pqik.pv` | Handshake A, a game and its relay, as CRYPTO.md section 6 has it since 2026-11-09: Noise IK made post-quantum (pqIK), the player's identity key as the game's static key, and only approved players taken | secrecy of what the honest player sends, with forward secrecy (every static key given away afterwards); the relay's authentication to the game, and the honest player's to the relay, both injective, against an attacker that also holds an approved key of its own. Each half alone, given its static secrets too, must hold all three. Not modelled: identity hiding (section 6 argues it) |
| `pqnk.pv` | Handshake A as the code has it until pqIK lands: Noise NK made post-quantum (pqNK), the game anonymous. It goes in the change that brings pqIK into the code | secrecy of what a game sends under its key, with forward secrecy (the relay's static keys given away afterwards); the relay's authentication and transcript agreement, injective, so no replay is taken twice. Each half alone, given the relay's static secret of that half too, must hold both |
| `pqxx.pv` | Handshake B, a joiner and its host, end to end: pqXX, B1 to B5 | secrecy each way, with forward secrecy (every static key given away afterwards); the host's authentication to the joiner (which checks the listing's fingerprint), and the joiner's to the host, both injective. Each half alone, given both sides' static secrets of that half too, must hold all four. Not modelled: the check code, which people compare |

## The hybrid, tested by breaking each half

`run.sh` runs each model as it is, and in variants made from it that give the attacker every ECDH secret, every ML-KEM secret, or both:
- as it is, with ECDH broken, and with ML-KEM broken: **every query must be true**, because either half alone holds;
- with both broken: **every query must be false**. A broken half is broken entirely, in every model: the attacker has that half's static keys from the start, as well as every secret an honest side computes with it, so with both broken it can play either side, and authentication fails as secrecy does. That shows the model isn't trivially true, and that the hybrid is what protects it, as a take-out row does for a test.

## What helps ProVerif finish, and why none of it can make a false proof

pqik and pqxx are big enough that ProVerif ran out of memory or time on them as written. run.sh gives it three kinds of help, and ProVerif's own manual (2.05) says none can turn a false answer into a true one:
- **Secrecy assumptions** in every run: `not attacker(...)` for each secret the variant doesn't give away (run.sh, `secrets`, lists them). ProVerif drops every clause that needs the attacker to know one of them, and checks each one itself: "The use of secrecy assumptions preserves soundness because ProVerif also checks that F cannot be derived; if it can be derived, ProVerif fails with an error message" (section 6.7.2, page 116). A wrong one stops the run, which fails the check, and a run passes only with ProVerif's own "secrecy assumption verified" line for each one, so the log shows it.
- **Names that take no arguments** in pqik's query 1 (`new x[]`). A name's arguments "tune the performance and precision of the analysis", and "the internal representation of names always includes session identifiers (necessary for soundness)" (page 120). At worst a true becomes "cannot be proved", which fails.
- **No phase 1 when one authentication query is asked alone.** Phase 1 gives the static keys away after the sessions, for forward secrecy, so it stays with every secrecy query. But at the change to phase 1 "all processes which have not yet reached phase i >= 1 are discarded" (section 4.1.6), so no event an authentication query asks about can happen after it: a trace that breaks one breaks it before phase 1. The same section: a key disclosed after a session may compromise "the secrecy of the data exchanged during that session [...] but not its authenticity".

Each ProVerif run is also held to a time limit and a memory limit (run.sh's PROOFS_RUN_MINUTES and PROOFS_MEMORY_GIB). A run that reaches either fails, saying which: a limit can only cost a proof, never make one.

Never used here: `axiom` (ProVerif assumes it without proving it), `restriction` (it proves things only on the traces it keeps), and limits on the depth of terms or the number of hypotheses (they cost precision nobody reading the answer could see).

## Running them

- **On GitHub:** the **Proofs** check (`.github/workflows/proofs.yml`) builds ProVerif 2.05 from INRIA's source release, checked by a pinned SHA-256 (INRIA publishes no checksum or signature, so the pin is the only check), with OCaml from Ubuntu's signed archive, and runs `sh proofs/run.sh <group>` on every change, one job for each group (each variant of each query: `sh proofs/run.sh --groups` lists the 32), side by side, each ProVerif run held to 300 minutes and 14 GiB. The check passes only if every group does, and every query is in one.
- **On your own machine:** install ProVerif (from your system's packages, or built from its source at bblanche.gitlabpages.inria.fr/proverif), then `sh proofs/run.sh` for every group in turn, `sh proofs/run.sh pqik-q1` for one query's four variants, or `sh proofs/run.sh pqik-q1-dh-broken` for one. It exits 0 only if every answer is the one it must be.

**Not yet run:** these were written without running ProVerif (it isn't run on the author's machine unasked); the first Proofs run on GitHub is their first check. (Ubuntu 24.04 turned out to have no ProVerif package, so it's built from source.)
