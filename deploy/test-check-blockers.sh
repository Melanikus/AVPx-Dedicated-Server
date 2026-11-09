#!/bin/sh
# The tests of deploy/check-blockers.sh: a deploy may go on only when SERVER-BLOCKERS.md says "Nothing.", and every other shape of the
# file refuses. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-check-blockers.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each case puts a copy of the checker, and one SERVER-BLOCKERS.md, in a folder of its own under the system's temporary folder, and runs
# it there, so the real file is never touched. Then it does the same with three broken copies of the checker (each with one rule taken
# out), and each must make some case fail: so these tests are shown to notice the checker going wrong (AVPX's take-out idea, in sh).
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
checker="$here/check-blockers.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
failed=0

# A SERVER-BLOCKERS.md with the given list and last line
make_file() {
  printf '# What blocks\n\nSome words.\n\n## Blocking a deploy\n\n%s\n\n%s\n' "$1" "$2"
}

# One case: the checker (given as $1) run on the file text in $2, which must exit $3 and, if $4 is given, say it
case_with() {
  dir="$work/case$$_$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')"
  mkdir -p "$dir/deploy"
  cp "$1" "$dir/deploy/check-blockers.sh"
  if [ "$2" != '<none>' ]; then printf '%s' "$2" > "$dir/SERVER-BLOCKERS.md"; fi
  set +e
  said=$(sh "$dir/deploy/check-blockers.sh" 2>&1)
  got=$?
  set -e
  if [ "$got" -ne "$3" ]; then return 1; fi
  if [ -n "${4:-}" ]; then printf '%s' "$said" | grep -qF -- "$4" || return 1; fi
  return 0
}

# Every case, with the checker given as $1. Says FAIL for each that doesn't hold, and gives back how many didn't
all_cases() {
  bad=0
  c() { if ! case_with "$1" "$2" "$3" "${5:-}"; then [ "$quiet" = yes ] || echo "FAIL  $4"; bad=$((bad + 1)); fi; }
  c "$1" "$(cat "$here/../SERVER-BLOCKERS.md")" 1 'the file as it is today refuses' 'lines block a deploy'
  c "$1" "$(make_file 'Nothing.' 'End of the list.')" 0 'only "Nothing." lets a deploy go on'
  c "$1" "$(make_file 'Nothing.' 'End of the list.' | sed 's/$/\r/')" 0 'Windows line ends too'
  c "$1" "$(make_file 'Nothing.   ' 'End of the list.  ')" 0 'spaces at line ends are ignored'
  c "$1" '<none>' 1 'no file' 'there is no SERVER-BLOCKERS.md'
  c "$1" '' 1 'an empty file'
  c "$1" "$(make_file '' 'End of the list.')" 1 'an empty list' 'the list is empty'
  c "$1" "$(make_file '1. Something to do.' 'End of the list.')" 1 'something listed' '1 lines block a deploy'
  c "$1" "$(make_file 'Nothing.
1. Something to do.' 'End of the list.')" 1 '"Nothing." with something else' '2 lines block'
  c "$1" "$(make_file 'nothing.' 'End of the list.')" 1 '"nothing." in small letters'
  c "$1" "$(make_file 'Nothing' 'End of the list.')" 1 '"Nothing" with no full stop'
  c "$1" "$(make_file 'Nothing. Really.' 'End of the list.')" 1 '"Nothing." with more on its line'
  c "$1" "$(make_file 'Nothing.' '')" 1 'cut short: no last line' 'cut short'
  c "$1" "$(make_file 'Nothing.' 'End of the')" 1 'cut short in the last line' 'cut short'
  c "$1" "$(make_file 'Nothing.' 'End of the list.' | sed 's/^## Blocking a deploy$/## Blocking/')" 1 'no heading' 'exactly once'
  c "$1" "$(make_file 'Nothing.' 'End of the list.' | sed 's/^Some words\.$/## Blocking a deploy/')" 1 'the heading twice' 'exactly once'
  c "$1" "$(printf '# What blocks\n\nNothing.\n\nEnd of the list.\n')" 1 '"Nothing." but not under the heading'
  return "$bad"
}

quiet=no
set +e
all_cases "$checker"
bad=$?
set -e

if [ "$bad" -ne 0 ]; then
  echo "$bad cases of check-blockers.sh don't hold"
  failed=1
else
  echo "check-blockers.sh: every case holds"
fi

# The take-outs: each broken copy must make some case fail
quiet=yes
breaks='s/if (n == 1 \&\& item\[1\] == "Nothing.")/if (1)/
s/if (end == 0 || line\[end\] != last)/if (0)/
s/if (found != 1)/if (found == 0)/'
echo "$breaks" | while IFS= read -r edit; do
  sed "$edit" "$checker" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$checker"; then echo "TAKE-OUT CAN'T RUN, its text isn't in the checker: $edit"; exit 1; fi
  set +e
  all_cases "$work/broken.sh"
  noticed=$?
  set -e
  if [ "$noticed" -eq 0 ]; then echo "TAKE-OUT NOT NOTICED: $edit"; exit 1; fi
  echo "take-out noticed ($noticed cases): $edit"
done || failed=1

exit "$failed"
