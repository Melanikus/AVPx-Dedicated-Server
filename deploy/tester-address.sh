#!/bin/sh
# tester_address <text>: prints the text back if it's exactly one plain IPv4 address, and fails otherwise. Written 2026-11-09 by Melanikus
# for AVPx Dedicated Server. Read by open-for-tester.sh and close-for-tester.sh (". deploy/tester-address.sh"), so both check the same way.
#
# Plain means: four whole numbers from 0 to 255, joined by three dots, each written with no leading 0 (so "010" can't be read as eight
# by one tool and ten by another), no sign and no spaces. 0.0.0.0 (everyone) and 255.255.255.255 (everyone on the network) are refused:
# a rule for either would open the server to all.
tester_address() {
  given=$1
  case "$given" in
    *[!0-9.]*|'') return 1 ;;
  esac
  old_ifs=$IFS
  IFS=.
  # The four parts, split on the dots (set -f keeps a part from ever being read as a file name)
  set -f
  set -- $given
  set +f
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  for part in "$@"; do
    case "$part" in
      ''|0?*) return 1 ;;
    esac
    [ "${#part}" -le 3 ] || return 1
    [ "$part" -le 255 ] || return 1
  done
  joined="$1.$2.$3.$4"
  # The address put back together must be exactly what was given: a dot at the end ("1.2.3.4.") splits into four parts too
  [ "$joined" = "$given" ] || return 1
  [ "$joined" != 0.0.0.0 ] || return 1
  [ "$joined" != 255.255.255.255 ] || return 1
  echo "$joined"
}
