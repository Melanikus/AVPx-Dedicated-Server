#!/bin/sh
# The tests of deploy/firewall.sh, with a stand-in for ufw: no firewall is touched. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server.
#
#   sh deploy/test-firewall.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each kind of machine gets exactly its rules and no others, SSH from the owner's address only; anything else, a wrong address among
# it, is refused before ufw is called. Then broken copies of
# firewall.sh, each with one rule taken out, must each make some case fail.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '#!/bin/sh\necho "ufw $*" >> "$UFW_LOG"\n' > "$work/ufw"
chmod +x "$work/ufw"

run() {
  script=$1; shift
  : > "$work/log"
  if AVPX_UFW="$work/ufw" UFW_LOG="$work/log" sh "$script" "$@" > "$work/out" 2>&1; then return 0; else return 1; fi
}

LIST="ufw default deny incoming
ufw default allow outgoing
ufw allow from 203.0.113.9 to any port 22 proto tcp comment SSH, from the owner only
ufw delete allow 22/tcp
ufw allow 443/tcp comment AVPx list (HTTPS)
ufw allow 27500/udp comment AVPx relay control
ufw allow 27501:27564/udp comment AVPx relay, a port per joiner
ufw --force enable
ufw status verbose"
RELAY="ufw default deny incoming
ufw default allow outgoing
ufw allow from 203.0.113.9 to any port 22 proto tcp comment SSH, from the owner only
ufw delete allow 22/tcp
ufw allow 27500/udp comment AVPx relay control
ufw allow 27501:27564/udp comment AVPx relay, a port per joiner
ufw --force enable
ufw status verbose"

all_cases() {
  s=$1
  bad=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$work/out" "$work/log"; }; }
  if run "$s" list 203.0.113.9 && [ "$(cat "$work/log")" = "$LIST" ]; then :; else no 'the list machine gets SSH from the owner only, 443 and the relay ports, nothing more: no 80'; fi
  if run "$s" relay 203.0.113.9 && [ "$(cat "$work/log")" = "$RELAY" ]; then :; else no 'a relay-only machine gets SSH from the owner only and the relay ports: no 443'; fi
  # Every kind of wrong owner address, each refused before ufw is called: none, everyone, everyone on the network, a range, a name,
  # IPv6, a leading 0, a part over 255, too few or too many parts, a space after it
  for address in '' 0.0.0.0 255.255.255.255 203.0.113.0/24 any example.com ::1 203.0.113.09 203.0.113.256 203.0.113 203.0.113.9.1 '203.0.113.9 '; do
    if run "$s" list "$address" || [ -s "$work/log" ]; then no "a wrong owner address, refused before ufw is called: [$address]"; fi
  done
  if run "$s" list 203.0.113.9 extra || [ -s "$work/log" ]; then no 'a third word, refused before ufw is called'; fi
  for wrong in '' test List 'list relay' all '203.0.113.9 list' list; do
    # $wrong is left unquoted on purpose, so "list relay" becomes two arguments and "" none
    if run "$s" $wrong || [ -s "$work/log" ]; then no "refused before ufw is called: [$wrong]"; fi
  done
  return "$bad"
}

failed=0
quiet=no
if all_cases "$here/firewall.sh"; then echo 'firewall.sh: every case holds'; else echo "$? cases of firewall.sh don't hold"; failed=1; fi

quiet=yes
for edit in \
  's/^if \[ "\$kind" = list \]; then$/if true; then/' \
  's/^  list|relay) ;;$/  *) ;;/' \
  's/^"\$ufw" default deny incoming$/true/' \
  's/^\[ "\$#" -eq 2 \] ||/true ||/' \
  's/^owner=\$(tester_address "\$2") ||/owner=$2 ||/' \
  's/^"\$ufw" allow from "\$owner" to any port 22 proto tcp/"$ufw" allow 22\/tcp/' \
  's/^"\$ufw" delete allow 22\/tcp .*$/true/'; do
  sed "$edit" "$here/firewall.sh" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$here/firewall.sh"; then echo "TAKE-OUT CAN'T RUN, its text isn't in firewall.sh: $edit"; failed=1; continue; fi
  if all_cases "$work/broken.sh"; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
