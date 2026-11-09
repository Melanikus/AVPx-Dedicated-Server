#!/bin/sh
# FOR MEASURING ONLY, on the proofs-measure branch, which is never merged. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
# The Proofs check had never finished: every run was stopped by its 30-minute limit while pqnk's both-broken variant was still going,
# and pqik and pqxx had never run at all. This runs one model's one variant, the same copy proofs/run.sh makes, and prints ProVerif's
# whole output, so each line's time in GitHub's log shows where the time goes: building the clauses ("rules inserted" lines, of which
# one in 50 is kept here), or after them, on a query and its attack.
#
#   sh proofs/measure.sh <model> <variant> [setting]
#
#   model     pqnk, pqik or pqxx
#   variant   as-written, dh-broken, kem-broken or both-broken (proofs/run.sh says what each is)
#   setting   nothing, or one of a fixed few ProVerif settings, put first in the copy, to see what each changes:
#             notrace     set reconstructTrace = false.  (only whether the clauses ever finish; its "cannot be proved" answers
#                                                         are expected, and prove nothing either way)
#             depth8      set maxDepth = 8.              (deeper terms are cut short in the clauses: that can only make the
#                                                         attacker stronger, so a "true" is still a proof, and a "false" still
#                                                         needs a real trace)
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

case "$setting" in
  '') first='' ;;
  notrace) first='set reconstructTrace = false.' ;;
  depth8) first='set maxDepth = 8.' ;;
  *) echo 'measure: the setting is nothing, notrace or depth8'; exit 2 ;;
esac

command -v proverif > /dev/null || { echo 'measure: proverif is not on the PATH'; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
file="$work/$model-$variant.pv"
{
  [ -z "$first" ] || echo "$first"
  if [ -n "$edits" ]; then sed "$edits" "$here/$model.pv"; else cat "$here/$model.pv"; fi
} > "$file"

echo "measure: $model $variant ${setting:-(no setting)}, started $(date -u +%H:%M:%S)"
# One "rules inserted" line in 50, every other line as it is; ProVerif's own result is what this exits with
status=0
# 320 minutes, under the job's 330, so that a run that never ends still says so here (exit 124) rather than only being cancelled
timeout 320m proverif "$file" > "$work/out" 2>&1 &
pid=$!
tail -n +1 -f "$work/out" --pid="$pid" | awk '/rules inserted/ { n++; if (n % 50 != 1) next } { print; fflush() }'
wait "$pid" || status=$?
echo "measure: $model $variant ${setting:-(no setting)}, ended $(date -u +%H:%M:%S), ProVerif's exit $status"
grep '^RESULT' "$work/out" || echo 'measure: no RESULT line'
exit "$status"
