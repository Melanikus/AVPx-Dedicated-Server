# The formal models

Written 2026-11-09 by Melanikus. CRYPTO.md section 14 promises these: models of version 2's handshakes, in **ProVerif** (INRIA's open-source tool, written in OCaml), proving what CRYPTO.md section 13 asks of them against an attacker who controls the whole network.

**They prove the pattern, not our code.** The code is held to the pattern by the test vectors (CRYPTO.md section 15) and the tests. Each model's header says what's modelled, what isn't, and why.

| Model | What it is | Its queries |
|---|---|---|
| `pqik.pv` | Handshake A, a game and its relay, as CRYPTO.md section 6 has it since 2026-11-09: Noise IK made post-quantum (pqIK), the player's identity key as the game's static key, and only approved players taken | secrecy of what the honest player sends, with forward secrecy (every static key given away afterwards); the relay's authentication to the game, and the honest player's to the relay, both injective, against an attacker that also holds an approved key of its own. Each half alone, given its static secrets too, must hold all three. Not modelled: identity hiding (section 6 argues it) |
| `pqnk.pv` | Handshake A as the code has it until pqIK lands: Noise NK made post-quantum (pqNK), the game anonymous. It goes in the change that brings pqIK into the code | secrecy of what a game sends under its key, with forward secrecy (the relay's static keys given away afterwards); the relay's authentication and transcript agreement, injective, so no replay is taken twice |
| `pqxx.pv` | Handshake B, a joiner and its host, end to end: pqXX, B1 to B5 | secrecy each way, with forward secrecy (every static key given away afterwards); the host's authentication to the joiner (which checks the listing's fingerprint), and the joiner's to the host, both injective. Not modelled: the check code, which people compare |

## The hybrid, tested by breaking each half

`run.sh` runs each model as it is, and in variants made from it that give the attacker every ECDH secret, every ML-KEM secret, or both:
- as it is, with ECDH broken, and with ML-KEM broken: **every query must be true**, because either half alone holds;
- with both broken: **the secrecy queries must be false** (pqnk's and pqik's authentication fail too; pqxx's may not, because the attacker learns each secret only as an honest side computes it, after the message it would need to forge, so run.sh doesn't hold it to an answer). That shows the model isn't trivially true, and that the hybrid is what protects it, as a take-out row does for a test.

## Running them

- **On GitHub:** the **Proofs** check (`.github/workflows/proofs.yml`) builds ProVerif 2.05 from INRIA's source release, checked by a pinned SHA-256 (INRIA publishes no checksum or signature, so the pin is the only check), with OCaml from Ubuntu's signed archive, and runs `sh proofs/run.sh <group>` on every change, one job for each group (pqnk, and each query of pqik and pqxx), side by side, each ProVerif run held to 60 minutes. The check passes only if every group does, and every query is in one.
- **On your own machine:** install ProVerif (from your system's packages, or built from its source at bblanche.gitlabpages.inria.fr/proverif), then `sh proofs/run.sh` for every group in turn, or `sh proofs/run.sh pqik-q1` for one. It exits 0 only if every answer is the one it must be.

**Not yet run:** these were written without running ProVerif (it isn't run on the author's machine unasked); the first Proofs run on GitHub is their first check. (Ubuntu 24.04 turned out to have no ProVerif package, so it's built from source.)
