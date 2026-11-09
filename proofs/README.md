# The formal models

Written 2026-11-09 by Melanikus. CRYPTO.md section 14 promises these: models of version 2's handshakes, in **ProVerif** (INRIA's open-source tool, written in OCaml), proving what CRYPTO.md section 13 asks of them against an attacker who controls the whole network.

**They prove the pattern, not our code.** The code is held to the pattern by the test vectors (CRYPTO.md section 15) and the tests. Each model's header says what's modelled, what isn't, and why.

| Model | What it is | Its queries |
|---|---|---|
| `pqnk.pv` | Handshake A, a game and its relay: Noise NK made post-quantum (pqNK), ECDH P-384 with ML-KEM-1024 | secrecy of what a game sends under its key, with forward secrecy (the relay's static keys given away afterwards); the relay's authentication and transcript agreement, injective, so no replay is taken twice |
| `pqxx.pv` | Handshake B, a joiner and its host, end to end: pqXX, B1 to B5 | secrecy each way, with forward secrecy (every static key given away afterwards); the host's authentication to the joiner (which checks the listing's fingerprint), and the joiner's to the host, both injective. Not modelled: the check code, which people compare |

## The hybrid, tested by breaking each half

`run.sh` runs each model as it is, and in variants made from it that give the attacker every ECDH secret, every ML-KEM secret, or both:
- as it is, with ECDH broken, and with ML-KEM broken: **every query must be true**, because either half alone holds;
- with both broken: **the secrecy queries must be false** (pqnk's authentication fails too; pqxx's may not, because the attacker learns each secret only as an honest side computes it, after the message it would need to forge, so run.sh doesn't hold it to an answer). That shows the model isn't trivially true, and that the hybrid is what protects it, as a take-out row does for a test.

## Running them

- **On GitHub:** the **Proofs** check (`.github/workflows/proofs.yml`) installs ProVerif from Ubuntu's signed archive and runs `sh proofs/run.sh` on every change.
- **On your own machine:** install ProVerif (from your system's packages, or built from its source at bblanche.gitlabpages.inria.fr/proverif), then `sh proofs/run.sh`. It exits 0 only if every answer is the one it must be.

**Not yet run:** these were written without running ProVerif (it isn't run on the author's machine unasked); the first Proofs run on GitHub is their first check. Whether Ubuntu 24.04's archive carries a `proverif` package is checked by that run too: if it doesn't, the check fails, and ProVerif is built from source instead.
