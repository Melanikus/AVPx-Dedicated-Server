#!/bin/sh
# MEASURING ONLY (Third, 2026-11-11; branch proofs-measure-7, never merged, never the real Proofs). Round 6's 17 out-of-memory runs, on a
# machine with more memory than GitHub's 16 GB runner: a fresh Ubuntu 24.04 droplet PO makes by the hour, runs by SSH, and destroys after.
# Nothing secret is on it: the models are public, and so is ProVerif.
#
# WHAT IT DOES, in order, and it stops at the first thing that isn't right:
#   1. OCaml from Ubuntu's own signed archive (apt), as proofs.yml installs it;
#   2. ProVerif 2.05 from INRIA's source, the same file proofs.yml pins (its SHA-256 below), checked before it's unpacked (no path
#      outside proverif2.05/, none with ".."), then built with ./build -nointeract, nothing graphical;
#   3. the SHA-256 of every file it runs (run.sh, the three models, measure-clauses.awk) into RESULTS/manifest.txt, so the results say
#      exactly what was run;
#   4. each group, by run.sh itself, measured (PROOFS_SAMPLE_SECONDS=30: memory and ProVerif's counts every 30 s), with GIB gibibytes
#      and at most MINUTES minutes a run, PARALLEL at a time; every group's output in RESULTS/<group>.log, and the model as run and what
#      was measured in RESULTS/kept/. Nothing new starts after 4 hours from the first run, and a run never goes past them.
#   5. RESULTS/summary.txt: each group's start, end, exit and the line run.sh ends it with.
#
# USE (as root, on the droplet; PROOFS is the proofs/ folder of branch proofs-measure-7 at its commit, copied over by PO):
#   GIB=56 MINUTES=60 PARALLEL=1 sh measure-droplet.sh PROOFS RESULTS [group ...]
# With no group named, the 17, the four that show the most first (fast and slow, one of each model): pqxx-q1-kem-broken,
# pqik-q3-kem-broken, pqnk-kem-broken, pqnk-both-broken. On a 64 GB machine, GIB=56 and PARALLEL=1: one run at a time with four
# times GitHub's memory; that's about four runs in the 4 hours. GIB times PARALLEL must leave the machine 4 GiB.
set -eu

PROOFS=${1:?give the proofs folder and the results folder}
RESULTS=${2:?give the results folder}
shift 2
GIB=${GIB:-56}
MINUTES=${MINUTES:-60}
PARALLEL=${PARALLEL:-1}
HOURS_SECONDS=14400
URL=https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
KEY=4871f53c32ab4a04669a060c4886ba5d9080496963fb980a9a62d2c429ceabc4

case "$GIB$MINUTES$PARALLEL" in *[!0-9]*|'') echo 'measure-droplet: GIB, MINUTES and PARALLEL are whole numbers'; exit 2 ;; esac
total_kib=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
if [ $(( (GIB * PARALLEL + 4) * 1048576 )) -gt "$total_kib" ]; then
  echo "measure-droplet: $PARALLEL runs of $GIB GiB, and 4 GiB for the machine, don't fit in its $((total_kib / 1048576)) GiB"; exit 2
fi
for f in run.sh pqik.pv pqnk.pv pqxx.pv measure-clauses.awk; do
  [ -f "$PROOFS/$f" ] || { echo "measure-droplet: there's no $PROOFS/$f"; exit 2; }
done
mkdir -p "$RESULTS/kept"

# 1-2. OCaml and ProVerif, as proofs.yml has them
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends ocaml-nox curl ca-certificates procps
ocamlopt -version
build=/opt/proverif-build
rm -rf "$build" && mkdir -p "$build"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$build/proverif.tar.gz" "$URL"
echo "$KEY  $build/proverif.tar.gz" | sha256sum --check --strict
tar -tzf "$build/proverif.tar.gz" > "$build/proverif.list"
if grep -v '^proverif2\.05/' "$build/proverif.list" | grep -q .; then echo 'measure-droplet: a path outside proverif2.05/'; exit 1; fi
if grep -q '\.\.' "$build/proverif.list"; then echo 'measure-droplet: a path with ..'; exit 1; fi
tar -xzf "$build/proverif.tar.gz" -C "$build"
(cd "$build/proverif2.05" && sh ./build -nointeract)
[ -x "$build/proverif2.05/proverif" ] || { echo 'measure-droplet: the build made no proverif'; exit 1; }
PATH="$build/proverif2.05:$PATH"; export PATH

# 3. What's run, by SHA-256
{
  echo "measure-droplet: $(date -u +%Y-%m-%dT%H:%M:%SZ), GIB=$GIB MINUTES=$MINUTES PARALLEL=$PARALLEL, machine $((total_kib / 1048576)) GiB"
  echo "proverif source $KEY"
  (cd "$PROOFS" && sha256sum run.sh pqik.pv pqnk.pv pqxx.pv measure-clauses.awk)
} > "$RESULTS/manifest.txt"
cat "$RESULTS/manifest.txt"

# 4. The groups
if [ "$#" -eq 0 ]; then
  set -- pqxx-q1-kem-broken pqik-q3-kem-broken pqnk-kem-broken pqnk-both-broken \
    pqik-q2-dh-broken pqik-q2-kem-broken pqik-q2-both-broken pqik-q3-dh-broken pqik-q3-both-broken pqnk-dh-broken \
    pqxx-q1-both-broken pqxx-q2-kem-broken pqxx-q2-both-broken pqxx-q3-kem-broken pqxx-q3-both-broken pqxx-q4-kem-broken pqxx-q4-both-broken
fi
began=$(date +%s)
running=0
one() {
  g=$1; m=$2
  s=$(date -u +%H:%M:%S)
  if PROOFS_RUN_MINUTES=$m PROOFS_MEMORY_GIB=$GIB PROOFS_SAMPLE_SECONDS=30 PROOFS_KEEP_DIR="$RESULTS/kept" \
    sh "$PROOFS/run.sh" "$g" > "$RESULTS/$g.log" 2>&1; then code=0; else code=$?; fi
  echo "$g start=$s end=$(date -u +%H:%M:%S) minutes_allowed=$m exit=$code last: $(grep -E '^(ok|FAIL) ' "$RESULTS/$g.log" | tail -n 1)" >> "$RESULTS/summary.txt"
}
for g in "$@"; do
  case "$g" in *[!a-z0-9-]*|'') echo "measure-droplet: not a group: $g"; exit 2 ;; esac
  left=$(( (HOURS_SECONDS - ($(date +%s) - began)) / 60 ))
  if [ "$left" -lt 5 ]; then echo "$g not run: the 4 hours are up" >> "$RESULTS/summary.txt"; continue; fi
  m=$MINUTES
  if [ "$m" -gt "$left" ]; then m=$left; fi
  one "$g" "$m" &
  running=$((running + 1))
  if [ "$running" -ge "$PARALLEL" ]; then wait; running=0; fi
done
wait

# 5.
echo "measure-droplet: done $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS/summary.txt"
cat "$RESULTS/summary.txt"
