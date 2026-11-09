#!/bin/sh
# FOR MEASURING ONLY, on the proofs-measure branch, which is never merged. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
# The Proofs check had never finished. The first round of measures (2026-11-09) found pqnk's variants ending, and pqik's and pqxx's,
# even as written, running until the runner itself was shut down, with ProVerif's count of clauses still climbing. That looks like
# memory, but only a measure says so. So this runs one model's one variant, the same copy proofs/run.sh makes, and prints:
# - ProVerif's own output, with one "rules inserted" line in 50 kept;
# - every 30 seconds, ProVerif's memory (its resident size) and the machine's;
# and it holds ProVerif to 14 GiB of address space (the runner has 16 GB), so a run that needs more stops with ProVerif's own
# "out of memory", which this then says plainly, instead of the runner being killed with nothing said.
#
#   sh proofs/measure.sh <model> <variant> [settings]
#
#   model     pqnk, pqik or pqxx
#   variant   as-written, dh-broken, kem-broken or both-broken (proofs/run.sh says what each is)
#   settings  nothing, or one or more of a fixed few joined by +, such as q2+names, to see what each changes. These make a "true"
#             no less of a proof:
#             notrace     set reconstructTrace = false.  (only whether the clauses ever finish; its "cannot be proved" answers
#                                                         are expected, and prove nothing either way)
#             depth8      set maxDepth = 8.              (deeper terms are cut short in the clauses: that can only make the
#                                                         attacker stronger, so a "true" is still a proof, and a "false" still
#                                                         needs a real trace)
#             selterm     set selFun = Term.             (which hypothesis ProVerif resolves on first: changes the work, never
#             seltermmax  set selFun = TermMaxsize.       the answer)
#             q1 to q4    only that query of the model, the others made comments. For a query that isn't about secrecy, the
#                         phase-1 line that gives the static keys away after the sessions is taken out too: phase 1 only matters
#                         to secrecy after the fact (forward secrecy), and no event of an authentication query happens in it
#             names       every "new x: t" becomes "new x[]: t": a fresh name no longer carries, inside it, every message its
#                         session took before it. Round 2 found the clauses themselves enormous (pqik q2: 13 GB for 9,336 of
#                         them, about 1.4 MB each), and that's where such size comes from. It only makes ProVerif's picture of
#                         names coarser, which can't hide an attack; to be checked against ProVerif's manual before any proof
#                         rests on it
#   And these, ONLY TO FIND WHAT MAKES THE CLAUSES GROW. Each changes the model, so no answer with them is a proof of ours:
#             dhpk        Diffie-Hellman as dhof(x, dhpub(y)) = dhof(y, dhpub(x)), a shared secret that is a bitstring, in place
#                         of exp on group elements, so no exponent can be put on top of another
#             nobad       pqik only: no bad tester (the approved player whose private keys the attacker holds)
#             bounded     no "!": one session of each role, not any number
#
# Every argument is checked against these lists: nothing else gets into a file name, a sed edit or ProVerif.
set -euf

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || { echo 'measure: give a model, a variant and maybe settings'; exit 2; }
model=$1; variant=$2; setting=${3:-}

case "$model" in pqnk|pqik|pqxx) ;; *) echo 'measure: the model is pqnk, pqik or pqxx'; exit 2 ;; esac

dh='s/(\*LEAKDH //; s/ LEAKDH\*)//'
kem='s/(\*LEAKKEM //; s/ LEAKKEM\*)//'
case "$variant" in
  as-written) edits='' ;;
  dh-broken) edits=$dh ;;
  kem-broken) edits=$kem ;;
  both-broken) edits="$dh; $kem" ;;
  *) echo 'measure: the variant is as-written, dh-broken, kem-broken or both-broken'; exit 2 ;;
esac

first=''; only=0; names=no; dhpk=no; nobad=no; bounded=no
case "$setting" in *++*|+*|*+) echo 'measure: settings are joined by one +'; exit 2 ;; esac
old_ifs=$IFS
IFS=+
for one in $setting; do
  case "$one" in
    notrace) first="$first set reconstructTrace = false." ;;
    depth8) first="$first set maxDepth = 8." ;;
    selterm) first="$first set selFun = Term." ;;
    seltermmax) first="$first set selFun = TermMaxsize." ;;
    q1|q2|q3|q4) [ "$only" -eq 0 ] || { echo 'measure: one query at most'; exit 2; }; only=${one#q} ;;
    names) names=yes ;;
    dhpk) dhpk=yes ;;
    nobad) [ "$model" = pqik ] || { echo 'measure: nobad is for pqik, the only model with a bad tester'; exit 2; }; nobad=yes ;;
    bounded) bounded=yes ;;
    *) echo 'measure: a setting is notrace, depth8, selterm, seltermmax, q1 to q4, names, dhpk, nobad or bounded'; exit 2 ;;
  esac
done
IFS=$old_ifs

command -v proverif > /dev/null || { echo 'measure: proverif is not on the PATH'; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
file="$work/$model-$variant.pv"
{
  # ProVerif's settings first, one a line
  printf '%s' "$first" | sed 's/\. set /.\nset /g; s/^ //' | grep . || true
  if [ -n "$edits" ]; then sed "$edits" "$here/$model.pv"; else cat "$here/$model.pv"; fi
} > "$work/whole.pv"
cp "$work/whole.pv" "$work/before-shape.pv"

# Each change to the model's shape edits lines of a fixed form, and says how many it changed: none means the model moved on, and
# then it stops, since a measure of an unchanged model would say nothing
changed() { n=$(diff "$work/whole.pv" "$work/next.pv" | grep -c '^>' || true); [ "$n" -ge "$2" ] || { echo "measure: $1 changed $n lines, not $2 or more"; exit 2; }; mv "$work/next.pv" "$work/whole.pv"; echo "measure: $1: $n lines"; }
if [ "$names" = yes ]; then
  sed 's/^\( *\)new \([A-Za-z0-9_]*\): /\1new \2[]: /' "$work/whole.pv" > "$work/next.pv"; changed names 4
fi
if [ "$dhpk" = yes ]; then
  sed -e 's/^fun exp(G, exponent): G\.$/fun dhpub(exponent): G.\nfun dhof(exponent, G): bitstring./' \
    -e 's/^equation forall x: exponent, y: exponent; exp(exp(g, x), y) = exp(exp(g, y), x)\.$/equation forall x: exponent, y: exponent; dhof(x, dhpub(y)) = dhof(y, dhpub(x))./' \
    -e 's/G2b(exp(\([A-Za-z0-9_]*\), \([A-Za-z0-9_]*\)))/dhof(\2, \1)/g' \
    -e 's/exp(g, \([A-Za-z0-9_]*\))/dhpub(\1)/g' "$work/whole.pv" > "$work/next.pv"
  changed dhpk 8
  # A use of exp the edits missed would be refused by ProVerif itself at once: exp is no longer declared
fi
if [ "$nobad" = yes ]; then
  sed -e '/^  insert approved(exp(g, adh), kemPub(akem));$/d' -e '/^  insert approved(dhpub(adh), kemPub(akem));$/d' \
    -e '/^  out(c, (adh, akem));$/d' "$work/whole.pv" > "$work/next.pv"
  n=$(diff "$work/whole.pv" "$work/next.pv" | grep -c '^<' || true)
  [ "$n" -eq 2 ] || { echo "measure: nobad took out $n lines, not 2"; exit 2; }
  mv "$work/next.pv" "$work/whole.pv"; echo 'measure: nobad: 2 lines'
fi
if [ "$bounded" = yes ]; then
  sed 's/(! \([A-Z]\)/(\1/' "$work/whole.pv" > "$work/next.pv"; changed bounded 2
fi
# What the settings changed, line for line, so the log shows exactly what ProVerif was given
diff "$work/before-shape.pv" "$work/whole.pv" | head -n 120 || true

if [ "$only" -eq 0 ]; then
  cp "$work/whole.pv" "$file"
else
  # A query starts at a line beginning "query " and ends at the line ending with its "." Every other one becomes a comment.
  awk -v only="$only" '
    /^query / { n++; inside = 1 }
    { line = $0 }
    inside && n != only { line = "(* " $0 " *)" }
    inside && /\.[ \t]*$/ { if (n == only) kept = $0; inside = 0 }
    { print line }
    END { if (n < only) exit 3 }
  ' "$work/whole.pv" > "$file" || { echo "measure: $model has no query $only"; exit 2; }
  # Which one was kept: a secrecy query is "query attacker(...)"; anything else is authentication, which phase 1 can't touch
  kept=$(awk -v only="$only" '/^query / { n++ } n == only && /^query / { print; exit }' "$work/whole.pv")
  case "$kept" in
    'query attacker('*) echo "measure: query $only alone: $kept (secrecy, so phase 1 stays)" ;;
    *)
      grep -q '^  | (phase 1; out(c, (' "$file" || { echo "measure: $model's phase-1 line isn't where this looks for it"; exit 2; }
      sed -i '/^  | (phase 1; out(c, (/d' "$file"
      echo "measure: query $only alone: $kept (authentication, so the phase-1 line is taken out)" ;;
  esac
fi

echo "measure: $model $variant ${setting:-(no setting)}, started $(date -u +%H:%M:%S)"
status=0
# At most 14 GiB of address space for ProVerif alone: past that its own allocation fails, and it says "out of memory"
( ulimit -v 14680064; exec proverif "$file" ) > "$work/out" 2>&1 &
pid=$!
tail -n +1 -f "$work/out" --pid="$pid" | awk '/rules inserted/ { n++; if (n % 50 != 1) next } { print; fflush() }' &
follower=$!
# Every 30 seconds: ProVerif's resident memory, and the machine's. And 320 minutes at most, under the job's 330.
started=$(date +%s)
while kill -0 "$pid" 2> /dev/null; do
  sleep 30
  kill -0 "$pid" 2> /dev/null || break
  rss=$(ps -o rss= -p "$pid" 2> /dev/null | tr -d ' ' || true)
  used=$(free -m | awk '/^Mem:/ { print $3 " of " $2 " MB used" }')
  elapsed=$(( $(date +%s) - started ))
  echo "memory: ${elapsed}s, ProVerif ${rss:-?} KB resident, the machine ${used}"
  if [ "$elapsed" -ge 19200 ]; then echo 'measure: 320 minutes: stopped'; kill "$pid" 2> /dev/null || true; fi
done
wait "$pid" || status=$?
wait "$follower" 2> /dev/null || true
echo "measure: $model $variant ${setting:-(no setting)}, ended $(date -u +%H:%M:%S), ProVerif's exit $status"
if grep -qi 'out of memory' "$work/out"; then echo 'measure: OUT OF MEMORY: ProVerif needed more than 14 GiB'; fi
grep '^RESULT' "$work/out" || echo 'measure: no RESULT line'
exit "$status"
