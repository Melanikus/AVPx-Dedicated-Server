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
#   sh proofs/measure.sh <model> <variant> [setting]
#
#   model     pqnk, pqik or pqxx
#   variant   as-written, dh-broken, kem-broken or both-broken (proofs/run.sh says what each is)
#   setting   nothing, or one of a fixed few, to see what each changes. None makes a "true" less of a proof:
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
#
# Every argument is checked against these lists: nothing else gets into a file name, a sed edit or ProVerif.
set -euf

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

[ "$#" -eq 2 ] || [ "$#" -eq 3 ] || { echo 'measure: give a model, a variant and maybe a setting'; exit 2; }
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

first=''; only=0
case "$setting" in
  '') ;;
  notrace) first='set reconstructTrace = false.' ;;
  depth8) first='set maxDepth = 8.' ;;
  selterm) first='set selFun = Term.' ;;
  seltermmax) first='set selFun = TermMaxsize.' ;;
  q1) only=1 ;;
  q2) only=2 ;;
  q3) only=3 ;;
  q4) only=4 ;;
  *) echo 'measure: the setting is nothing, notrace, depth8, selterm, seltermmax, or q1 to q4'; exit 2 ;;
esac

command -v proverif > /dev/null || { echo 'measure: proverif is not on the PATH'; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
file="$work/$model-$variant.pv"
{
  [ -z "$first" ] || echo "$first"
  if [ -n "$edits" ]; then sed "$edits" "$here/$model.pv"; else cat "$here/$model.pv"; fi
} > "$work/whole.pv"

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
