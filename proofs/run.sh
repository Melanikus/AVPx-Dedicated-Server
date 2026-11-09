#!/bin/sh
# Runs ProVerif on every model in proofs/, and on the variants that break one half of the hybrid or both, and checks each query gives
# the answer it must. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh proofs/run.sh      needs proverif on the PATH (GitHub's "Proofs" check installs it); exits 0 only if every answer is the one
#                         written below
#
# THE VARIANTS of each model, made here from it, never kept:
#   as written     every query true
#   dh-broken      the attacker is given every ECDH secret an honest side computes       every query true: ML-KEM alone holds them
#   kem-broken     the attacker is given every ML-KEM secret an honest side computes     every query true: ECDH alone holds them
#   both-broken    the attacker is given both                                           the secrecy queries false: so the model isn't
#                                                                                       trivially true, and the hybrid is what protects
# In both-broken, pqnk's authentication fails too. pqxx's may not: the attacker learns each secret only when the honest side computes
# it, which in pqXX comes after the message the attacker would need to forge with it, so its answer there isn't held to anything ("*").
# A variant is made by switching on the lines marked LEAKDH or LEAKKEM. ProVerif writes one "RESULT ... is true." or "... is false." line
# a query, in the order the queries are written; "cannot be proved" fails wherever an answer is required.
set -euf

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0

command -v proverif > /dev/null || { echo 'proofs: proverif is not on the PATH'; exit 1; }

# One run: the model, the variant's name, the sed edits that make it (or nothing), and the answers its queries must give, one word each
# ("true", "false", or "*" for either)
variant() {
  model=$1; name=$2; edits=$3; want=$4
  file="$work/$model-$name.pv"
  if [ -n "$edits" ]; then sed "$edits" "$here/$model.pv" > "$file"; else cp "$here/$model.pv" "$file"; fi
  if ! proverif "$file" > "$file.out" 2>&1; then
    echo "FAIL  $model $name: ProVerif stopped"; tail -n 20 "$file.out"; failed=1; return 0
  fi
  grep '^RESULT' "$file.out" | sed "s/^/  $model $name: /"
  got=$(grep '^RESULT' "$file.out" | sed -n 's/.* is \(true\)\.$/\1/p; s/.* is \(false\)\.$/\1/p; s/.*cannot be proved.*/unproved/p' | tr '\n' ' ' | sed 's/ $//')
  # The answers, word by word against what they must be
  set -- $got
  ok=yes
  count=0
  for must in $want; do
    count=$((count + 1))
    answer=${1:-none}
    [ "$#" -gt 0 ] && shift
    if [ "$must" != '*' ] && [ "$must" != "$answer" ]; then ok=no; fi
  done
  [ "$#" -eq 0 ] || ok=no
  if [ "$ok" = yes ]; then echo "ok    $model $name: $got"; else echo "FAIL  $model $name: got \"$got\", must be \"$want\""; failed=1; fi
}

dh='s/(\*LEAKDH //; s/ LEAKDH\*)//'
kem='s/(\*LEAKKEM //; s/ LEAKKEM\*)//'

# pqnk: 1 secrecy, 2 the relay's authentication. Handshake A as the code has it until pqIK lands (CRYPTO.md section 14)
variant pqnk as-written '' 'true true'
variant pqnk dh-broken "$dh" 'true true'
variant pqnk kem-broken "$kem" 'true true'
variant pqnk both-broken "$dh; $kem" 'false false'

# pqik: 1 secrecy, 2 the relay's authentication to the game, 3 the honest player's to the relay. Broken here means broken entirely:
# the attacker gets that half's static secrets as well as every result an honest side computes, so each half alone must hold all three,
# and with both broken every one fails.
variant pqik as-written '' 'true true true'
variant pqik dh-broken "$dh" 'true true true'
variant pqik kem-broken "$kem" 'true true true'
variant pqik both-broken "$dh; $kem" 'false false false'

# pqxx: 1 and 2 secrecy (joiner's, host's), 3 the host's authentication, 4 the joiner's
variant pqxx as-written '' 'true true true true'
variant pqxx dh-broken "$dh" 'true true true true'
variant pqxx kem-broken "$kem" 'true true true true'
variant pqxx both-broken "$dh; $kem" 'false false * *'

if [ "$failed" -ne 0 ]; then echo 'proofs: some answers are not the ones they must be'; exit 1; fi
echo 'proofs: every answer is the one it must be'
