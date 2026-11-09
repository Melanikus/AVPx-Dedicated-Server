#!/bin/sh
# The tests of deploy/open-for-tester.sh, close-for-tester.sh and tester-address.sh, with a stand-in for ufw: no firewall is touched.
# Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-open-for-tester.sh     exits 0 if every case holds, 1 if any doesn't
#
# Then broken copies of the scripts, each with one rule taken out, must each make some case fail.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '#!/bin/sh\necho "ufw $*" >> "$UFW_LOG"\n' > "$work/ufw"
chmod +x "$work/ufw"

# Runs one script ($1, open or close, from the folder $2) with the rest as its arguments; its ufw calls end up in $work/log
run() {
  what=$1; dir=$2; shift 2
  : > "$work/log"
  if AVPX_UFW="$work/ufw" UFW_LOG="$work/log" sh "$dir/$what-for-tester.sh" "$@" > "$work/out" 2>&1; then return 0; else return 1; fi
}

# Every case, with the scripts from the folder $1. Says FAIL for each that doesn't hold (unless quiet), and gives back how many didn't.
all_cases() {
  d=$1
  bad=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$work/out" "$work/log"; }; }

  if run open "$d" 203.0.113.7 && [ "$(cat "$work/log")" = "ufw allow from 203.0.113.7 to any port 443 proto tcp comment avpx tester: the list
ufw allow from 203.0.113.7 to any port 27500:27564 proto udp comment avpx tester: the relay" ]; then :; else no 'open lets one address in, to TCP 443 and UDP 27500-27564 only'; fi
  if grep -q '203\.0\.113\.7' "$work/out"; then no 'open never prints the address'; fi

  if run close "$d" 203.0.113.7 && [ "$(cat "$work/log")" = "ufw delete allow from 203.0.113.7 to any port 443 proto tcp
ufw delete allow from 203.0.113.7 to any port 27500:27564 proto udp" ]; then :; else no 'close takes out exactly those two rules'; fi
  if grep -q '203\.0\.113\.7' "$work/out"; then no 'close never prints the address'; fi

  for good in 1.2.3.4 0.0.0.1 255.255.255.254 10.0.0.255; do
    run open "$d" "$good" || no "a plain address is taken: $good"
  done

  for bad_address in '' 1.2.3 1.2.3.4.5 1.2.3.4. .1.2.3.4 1..2.3 256.1.1.1 1.2.3.999 01.2.3.4 1.2.3.04 1.2.3.0004 0.0.0.0 255.255.255.255 \
    '1.2.3.4 ' ' 1.2.3.4' '1.2.3.4;reboot' '-1.2.3.4' '1.2.3.4/0' 'any' '*' '1.2.3.4,5.6.7.8' '::1'; do
    if run open "$d" "$bad_address" || [ -s "$work/log" ]; then no "refused before ufw is called: [$bad_address]"; fi
    if run close "$d" "$bad_address" || [ -s "$work/log" ]; then no "close refuses it too: [$bad_address]"; fi
  done

  if run open "$d" || [ -s "$work/log" ]; then no 'no address is refused'; fi
  if run open "$d" 1.2.3.4 5.6.7.8 || [ -s "$work/log" ]; then no 'two addresses are refused'; fi
  return "$bad"
}

failed=0
quiet=no
if all_cases "$here"; then echo 'open and close for a tester: every case holds'; else echo "$? cases don't hold"; failed=1; fi

# The take-outs: each broken copy must make some case fail
quiet=yes
for edit in \
  's/^  \[ "\$joined" = "\$given" \] || return 1$/  true/' \
  's/|0?\*) return 1 ;;/) return 1 ;;/' \
  's/^  \[ "\$joined" != 0.0.0.0 \] || return 1$/  true/' \
  's/^    \[ "\$part" -le 255 \] || return 1$/    true/' \
  's/port 443 proto tcp comment/port 1:65535 proto tcp comment/'; do
  rm -rf "$work/broken" && mkdir "$work/broken"
  cp "$here/open-for-tester.sh" "$here/close-for-tester.sh" "$here/tester-address.sh" "$work/broken/"
  for f in "$work/broken/"*.sh; do sed "$edit" "$f" > "$f.new" && mv "$f.new" "$f"; done
  if diff -q "$work/broken/tester-address.sh" "$here/tester-address.sh" > /dev/null && diff -q "$work/broken/open-for-tester.sh" "$here/open-for-tester.sh" > /dev/null; then
    echo "TAKE-OUT CAN'T RUN, its text isn't in the scripts: $edit"; failed=1; continue
  fi
  if all_cases "$work/broken"; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
