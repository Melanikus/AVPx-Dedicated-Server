#!/bin/sh
# The tests of java/tools/check-codeql.sh, with results files made up here: CodeQL itself isn't run. Written 2026-11-09 by Melanikus for
# AVPx Dedicated Server.
#
#   sh java/tools/test-check-codeql.sh     exits 0 if every case holds, 1 if any doesn't (it needs jq: java.yml runs it on GitHub's
#                                          runner, in the CodeQL job, before CodeQL itself)
#
# Results with nothing found and every file read must pass. Every way CodeQL could have not run, or run and not read, must fail, each
# saying why in its own words. Then broken copies of check-codeql.sh, each with one check taken out, must each make some case fail.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The two Java files the made-up repository tracks, and an empty list
printf 'java/src/A.java\njava/test/B.java\n' > "$work/files"
: > "$work/no-files"

READ_BOTH='"artifacts":[{"location":{"uri":"java/src/A.java"}},{"location":{"uri":"java/test/B.java"}}]'
READ_A='"artifacts":[{"location":{"uri":"java/src/A.java"}}]'
B_IN_A_NOTE='"invocations":[{"toolExecutionNotifications":[{"locations":[{"physicalLocation":{"artifactLocation":{"uri":"java/test/B.java"}}}]}]}]'
FINDING='{"ruleId":"java/made-up-rule","message":{"text":"a made-up finding"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"java/src/A.java"},"region":{"startLine":3}}}]}'

GOOD="{\"runs\":[{\"results\":[],$READ_BOTH}]}"
VIA_NOTE="{\"runs\":[{\"results\":[],$READ_A,$B_IN_A_NOTE}]}"
FOUND="{\"runs\":[{\"results\":[$FINDING],$READ_BOTH}]}"
FOUND_AND_UNREAD="{\"runs\":[{\"results\":[$FINDING],$READ_A}]}"
UNREAD="{\"runs\":[{\"results\":[],$READ_A}]}"
NO_RESULTS_LIST="{\"runs\":[{$READ_BOTH}]}"

# A folder of results: no argument for an empty one, or the text of each file to put in it
folder() {
  rm -rf "$work/out"
  mkdir "$work/out"
  i=0
  for text in "$@"; do
    i=$((i + 1))
    printf '%s\n' "$text" > "$work/out/java-$i.sarif"
  done
}

# The checker given, on the folder made, with the list of tracked files given (the two, unless a second argument says otherwise)
run() {
  if AVPX_CODEQL_FILES="${2:-$work/files}" sh "$1" "$work/out" > "$work/said" 2>&1; then return 0; else return 1; fi
}

all_cases() {
  s=$1
  bad=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$work/said"; }; }
  # It fails, and says these words, which only that failure says
  fails() {
    if run "$s" "${3:-}"; then no "$1: it passed"; elif grep -qF -- "$2" "$work/said"; then :; else no "$1: it failed without saying \"$2\""; fi
  }

  folder "$GOOD"
  if run "$s" && grep -qx 'CodeQL found 0' "$work/said"; then :; else no 'nothing found, and both files read: it passes'; fi
  folder "$VIA_NOTE"
  if run "$s"; then :; else no 'a file CodeQL names only in a notification of its own counts as read: it passes'; fi

  folder
  fails 'no results file at all' 'no results files in'
  if grep -qF 'If CodeQL is unreachable: replace it with an equivalent, see TAKING-OVER.md' "$work/said"; then :; else no 'no results file: it says what to do if CodeQL is unreachable, in the words every gate uses'; fi
  rm -rf "$work/out"
  fails 'no results folder at all' 'no results files in'
  folder "$GOOD" "$GOOD"
  fails 'two results files' '2 results files in'
  folder 'not JSON'
  fails 'a results file that is not JSON' "isn't a results file with CodeQL's runs in it"
  folder '{}'
  fails 'a results file with no runs' "isn't a results file with CodeQL's runs in it"
  folder '{"runs":[]}'
  fails 'a results file whose runs are empty' "isn't a results file with CodeQL's runs in it"
  folder "$NO_RESULTS_LIST"
  fails 'a run with no list of results' 'has no list of results'
  folder "$FOUND"
  fails 'one finding' '1 findings: each one is fixed'
  if grep -qF 'java/made-up-rule  java/src/A.java:3  a made-up finding' "$work/said"; then :; else no 'a finding is written out, rule, file, line and words'; fi
  folder "$UNREAD"
  fails 'a tracked file CodeQL did not read' "CodeQL didn't read java/test/B.java"
  folder "$FOUND_AND_UNREAD"
  fails 'a finding and an unread file: both are said in one run' "CodeQL didn't read java/test/B.java"
  folder "$GOOD"
  fails 'no tracked Java files to check' 'no tracked Java files were found' "$work/no-files"
  return "$bad"
}

failed=0
quiet=no
if all_cases "$here/check-codeql.sh"; then echo 'check-codeql.sh: every case holds'; else echo "$? cases of check-codeql.sh don't hold"; failed=1; fi

quiet=yes
for edit in \
  's/^if \[ "\$#" -ne 1 \] || \[ ! -f "\$1" \]; then$/if false; then/' \
  's/^if ! jq -e .\.runs | type == "array" and length > 0. .*$/if false; then/' \
  's/\[\.runs\[\]\.results\[\]\] | length/[.runs[].results[]?] | length/' \
  's/^if \[ "\$found" != 0 \]; then$/if false; then/' \
  's/grep -Fxq -e "\$f"; then :; else/true; then :; else/' \
  's/^if \[ "\$count" -eq 0 \]; then$/if false; then/' \
  's/^  failed=1$/  :/' \
  's/^if \[ "\$failed" -ne 0 \]; then exit 1; fi$/:/'; do
  sed "$edit" "$here/check-codeql.sh" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$here/check-codeql.sh"; then echo "TAKE-OUT CAN'T RUN, its text isn't in check-codeql.sh: $edit"; failed=1; continue; fi
  if all_cases "$work/broken.sh"; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
