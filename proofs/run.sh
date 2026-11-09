#!/bin/sh
# Runs ProVerif on every model in proofs/, and on the variants that break one half of the hybrid or both, and checks each query gives
# the answer it must. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh proofs/run.sh      needs proverif on the PATH (GitHub's "Proofs" check installs it); exits 0 only if every answer is the one
#                         written below
#
# THE VARIANTS of proofs/pqnk.pv, made here from it, never kept:
#   pqnk          as written                                       every query true
#   dh-broken     the attacker is given every ECDH secret          every query true: ML-KEM alone holds them
#   kem-broken    the attacker is given every ML-KEM secret        every query true: ECDH alone holds them
#   both-broken   the attacker is given both                       every query false: so the model isn't trivially true, and the
#                                                                  hybrid is what protects
# A variant is made by switching on the lines marked LEAKDH or LEAKKEM in pqnk.pv. ProVerif writes one "RESULT ... is true." or
# "RESULT ... is false." line a query, in the order the queries are written; "cannot be proved" counts as neither, and fails.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0

command -v proverif > /dev/null || { echo 'proofs: proverif is not on the PATH'; exit 1; }
proverif -help 2>&1 | head -n 1 || true

# One variant: its name, the sed edits that make it (or nothing), and the answers its queries must give, one word each
variant() {
  name=$1; edits=$2; want=$3
  if [ -n "$edits" ]; then sed "$edits" "$here/pqnk.pv" > "$work/$name.pv"; else cp "$here/pqnk.pv" "$work/$name.pv"; fi
  if ! proverif "$work/$name.pv" > "$work/$name.out" 2>&1; then
    echo "FAIL  $name: ProVerif stopped"; tail -n 20 "$work/$name.out"; failed=1; return 0
  fi
  got=$(grep '^RESULT' "$work/$name.out" | sed -n 's/.* is \(true\)\.$/\1/p; s/.* is \(false\)\.$/\1/p; s/.*cannot be proved.*/unproved/p' | tr '\n' ' ' | sed 's/ $//')
  grep '^RESULT' "$work/$name.out" | sed "s/^/  $name: /"
  if [ "$got" = "$want" ]; then echo "ok    $name: $got"; else echo "FAIL  $name: got \"$got\", must be \"$want\""; failed=1; fi
}

dh='s/(\*LEAKDH //; s/ LEAKDH\*)//'
kem='s/(\*LEAKKEM //; s/ LEAKKEM\*)//'
variant pqnk '' 'true true'
variant dh-broken "$dh" 'true true'
variant kem-broken "$kem" 'true true'
variant both-broken "$dh; $kem" 'false false'

if [ "$failed" -ne 0 ]; then echo 'proofs: some answers are not the ones they must be'; exit 1; fi
echo 'proofs: every answer is the one it must be'
