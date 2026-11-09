#!/bin/sh
# The tests of deploy/firewall.sh, with a stand-in for ufw: no firewall is touched. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server.
#
#   sh deploy/test-firewall.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each kind of machine gets exactly its rules and no others; anything else is refused before ufw is called. Then broken copies of
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
ufw allow 22/tcp comment SSH, for the owner
ufw allow 443/tcp comment AVPx list (HTTPS)
ufw allow 80/tcp comment Let us Encrypt check while certbot renews
ufw allow 27500/udp comment AVPx relay control
ufw allow 27501:27564/udp comment AVPx relay, a port per joiner
ufw --force enable
ufw status verbose"
RELAY="ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment SSH, for the owner
ufw allow 27500/udp comment AVPx relay control
ufw allow 27501:27564/udp comment AVPx relay, a port per joiner
ufw --force enable
ufw status verbose"

all_cases() {
  s=$1
  bad=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$work/out" "$work/log"; }; }
  if run "$s" list && [ "$(cat "$work/log")" = "$LIST" ]; then :; else no 'the list machine gets SSH, 443, 80 and the relay ports, nothing more'; fi
  if run "$s" relay && [ "$(cat "$work/log")" = "$RELAY" ]; then :; else no 'a relay-only machine gets SSH and the relay ports only: no 443, no 80'; fi
  for wrong in '' test List 'list relay' all; do
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
  's/^\[ "\$#" -eq 1 \] ||/true ||/'; do
  sed "$edit" "$here/firewall.sh" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$here/firewall.sh"; then echo "TAKE-OUT CAN'T RUN, its text isn't in firewall.sh: $edit"; failed=1; continue; fi
  if all_cases "$work/broken.sh"; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
