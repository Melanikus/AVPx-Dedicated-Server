#!/bin/sh
# Refuses a deploy while SERVER-BLOCKERS.md lists anything. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/check-blockers.sh          exits 0 only if the list says "Nothing.", and 1 otherwise, saying why
#   sh deploy/check-blockers.sh --list   says what's listed, and exits 0 (for the gate's report; a deploy never uses this)
#
# Every deploy workflow runs the first form as its first step. It's plain sh and awk, so it needs nothing installed. What it refuses:
# - a file that isn't there;
# - a file with no "## Blocking a deploy" heading, or with it twice;
# - a file cut short: its last line that isn't blank must be "End of the list.";
# - a list that is empty, or holds anything but the one line "Nothing.".
# Blank lines don't count, and spaces at a line's end and Windows line ends are ignored. deploy/test-check-blockers.sh checks each of
# these, and checks that its own checks would notice this file going wrong.
#
# It reads SERVER-BLOCKERS.md from beside the deploy/ folder this script is in, never from a path it's given.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
file="$here/../SERVER-BLOCKERS.md"
mode=${1:-check}

if [ "$mode" != check ] && [ "$mode" != --list ]; then
  echo "use: sh deploy/check-blockers.sh [--list]"
  exit 2
fi

if [ ! -f "$file" ]; then
  echo "SERVER-BLOCKERS.md: there is no SERVER-BLOCKERS.md"
  [ "$mode" = --list ] && exit 0
  exit 1
fi

# awk reads the whole file and decides. It prints the reason (and the listed lines), and ends with 0 only when nothing blocks.
status=0
awk '
  { sub(/\r$/, ""); sub(/[ \t]+$/, ""); line[NR] = $0 }
  END {
    heading = "## Blocking a deploy"; last = "End of the list."
    found = 0
    for (i = 1; i <= NR; i++) if (line[i] == heading) { found++; at = i }
    if (found != 1) { printf "SERVER-BLOCKERS.md: the heading \"%s\" must be there exactly once (it is there %d times)\n", heading, found; exit 1 }
    end = 0
    for (i = NR; i >= 1; i--) if (line[i] != "") { end = i; break }
    if (end == 0 || line[end] != last) { printf "SERVER-BLOCKERS.md: the file is cut short: its last line must be \"%s\"\n", last; exit 1 }
    n = 0
    for (i = at + 1; i < end; i++) if (line[i] != "") { n++; item[n] = line[i] }
    if (n == 0) { print "SERVER-BLOCKERS.md: the list is empty: it must say \"Nothing.\" or name what blocks"; exit 1 }
    if (n == 1 && item[1] == "Nothing.") { print "SERVER-BLOCKERS.md: nothing blocks a deploy"; exit 0 }
    printf "SERVER-BLOCKERS.md: %d lines block a deploy\n", n
    for (i = 1; i <= n; i++) print "  " item[i]
    exit 1
  }
' "$file" || status=$?

if [ "$mode" = --list ]; then
  exit 0
fi

exit "$status"
