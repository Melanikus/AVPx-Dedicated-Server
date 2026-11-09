#!/bin/sh
# The tests of deploy/remote-deploy.sh, with no machine, no network and no AWS. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-remote-deploy.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each case gets a folder of its own that stands in for the machine's / (AVPX_DEPLOY_ROOT), and stand-ins, first on PATH, for the
# commands that would reach out: curl (hands over a source tarball the test made), systemctl (says the service is up, or not, as the
# case asks) and the JDK's java (the smoke client passes, or not). Nothing runs as root, and nothing outside the case's folder changes.
# Then three broken copies of remote-deploy.sh, each with one rule taken out, must each make some case fail.
#
# remote-deploy.sh moves a symbolic link; on Windows, Git Bash makes those only where Windows allows it, so run this on Linux (GitHub's
# runner) when it can't.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/remote-deploy.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
C1=1111111111111111111111111111111111111111
C2=2222222222222222222222222222222222222222

# The stand-ins
fake="$work/fake"
mkdir -p "$fake"
cat > "$fake/curl" <<'STANDIN'
#!/bin/sh
# curl's stand-in: writes the tarball the case made to the --output path, and notes the address asked for
out=''; url=''
while [ "$#" -gt 0 ]; do case "$1" in --output) out=$2; shift 2 ;; --*) shift ;; *) url=$1; shift ;; esac; done
echo "$url" >> "$FAKE_LOG"
cp "$FAKE_TARBALL" "$out"
STANDIN
cat > "$fake/systemctl" <<'STANDIN'
#!/bin/sh
# systemctl's stand-in: notes what it was asked, and says the service is up unless the case says otherwise
echo "systemctl $*" >> "$FAKE_LOG"
if [ "$1" = is-active ]; then exit "${FAKE_ACTIVE:-0}"; fi
exit 0
STANDIN
chmod +x "$fake/curl" "$fake/systemctl"

# A machine for one case: the stand-in JDK, and a source tarball for $1 whose build.sh makes a jar holding $2 (or fails, if $2 is FAIL)
machine() {
  m="$work/m$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')"
  mkdir -p "$m/root/opt/avpx-jdk/bin" "$m/src/AVPx-Dedicated-Server-$1/java"
  cat > "$m/root/opt/avpx-jdk/bin/java" <<'STANDIN'
#!/bin/sh
echo "java $*" >> "$FAKE_LOG"
exit "${FAKE_SMOKE:-0}"
STANDIN
  chmod +x "$m/root/opt/avpx-jdk/bin/java"
  if [ "$2" = FAIL ]; then
    printf '#!/bin/sh\nexit 1\n' > "$m/src/AVPx-Dedicated-Server-$1/java/build.sh"
  else
    printf '#!/bin/sh\nmkdir -p "$(dirname "$0")/build"\nprintf %%s "%s" > "$(dirname "$0")/build/avpx-server.jar"\n' "$2" > "$m/src/AVPx-Dedicated-Server-$1/java/build.sh"
  fi
  tar -czf "$m/source.tar.gz" -C "$m/src" .
  : > "$m/log"
}

# The sha256 of a jar holding $1
sha_of() { printf %s "$1" | sha256sum | cut -d ' ' -f 1; }

# Runs the script under test ($1) on the machine $m with the rest as its arguments; gives back its exit
deploy() {
  s=$1; shift
  if PATH="$fake:$PATH" AVPX_DEPLOY_ROOT="$m/root" FAKE_LOG="$m/log" FAKE_TARBALL="$m/source.tar.gz" sh "$s" "$@" > "$m/out" 2>&1; then
    return 0
  else
    return 1
  fi
}

linked() { [ -L "$m/root/opt/avpx/current" ] && readlink "$m/root/opt/avpx/current"; }

# Every case, with the script given as $1. Says FAIL for each that doesn't hold (unless quiet), and gives back how many didn't.
all_cases() {
  bad=0
  no() { [ "$quiet" = yes ] || echo "FAIL  $1"; bad=$((bad + 1)); }

  machine "$C1" one
  if deploy "$1" "$C1" "$(sha_of one)" && [ "$(linked)" = "$m/root/opt/avpx/releases/$C1" ] && [ "$(cat "$m/root/opt/avpx/releases/$C1/avpx-server.jar")" = one ] \
    && grep -q "codeload.github.com/Melanikus/AVPx-Dedicated-Server/tar.gz/$C1\$" "$m/log" && grep -q 'systemctl restart avpx-java' "$m/log"; then :; else no 'a good deploy is put in place, from that commit, and the service restarted'; fi

  machine "$C1" one
  if ! deploy "$1" "$C1" "$(sha_of other)" && [ ! -e "$m/root/opt/avpx/current" ] && [ ! -e "$m/root/opt/avpx/releases/$C1" ] && grep -q "isn't the one the gates built" "$m/out"; then :; else no 'a jar that is not the tested one is refused, and nothing is put in place'; fi

  # Bad values: each refused before anything is fetched (the stand-ins' log stays empty)
  refused_before_fetch() {
    what=$1; shift
    machine "$C1" one
    if deploy "$@" || [ -s "$m/log" ]; then no "bad values are refused before anything is fetched: $what"; fi
  }
  good=$(sha_of one)
  refused_before_fetch 'one value' "$1" "$C1"
  refused_before_fetch 'three values' "$1" "$C1" "$good" extra
  refused_before_fetch 'a commit of 41' "$1" "${C1}0" "$good"
  refused_before_fetch 'a commit with a capital' "$1" "$(echo "$C1" | tr 1 A)" "$good"
  refused_before_fetch 'a sha256 of 65' "$1" "$C1" "${good}0"
  refused_before_fetch 'a commit with a ; in it' "$1" 'x;reboot' "$good"

  machine "$C1" FAIL
  if ! deploy "$1" "$C1" "$(sha_of one)" && [ ! -e "$m/root/opt/avpx/current" ] && grep -q 'the build or its tests failed' "$m/out"; then :; else no 'a build that fails puts nothing in place'; fi

  machine "$C1" one
  deploy "$1" "$C1" "$(sha_of one)" || true
  mkdir -p "$m/src2/AVPx-Dedicated-Server-$C2/java"
  printf '#!/bin/sh\nmkdir -p "$(dirname "$0")/build"\nprintf %%s two > "$(dirname "$0")/build/avpx-server.jar"\n' > "$m/src2/AVPx-Dedicated-Server-$C2/java/build.sh"
  tar -czf "$m/source.tar.gz" -C "$m/src2" .
  if ! FAKE_SMOKE=1 deploy "$1" "$C2" "$(sha_of two)" && [ "$(linked)" = "$m/root/opt/avpx/releases/$C1" ] && grep -q 'going back to' "$m/out"; then :; else no 'an unhealthy release is rolled back to the one before'; fi

  machine "$C1" one
  mkdir -p "$m/root/opt/avpx/releases/$C1" && printf other > "$m/root/opt/avpx/releases/$C1/avpx-server.jar"
  if ! deploy "$1" "$C1" "$(sha_of one)" && grep -q 'there already, with another jar' "$m/out"; then :; else no 'a release folder holding another jar is refused'; fi

  machine "$C2" one
  if ! deploy "$1" "$C1" "$(sha_of one)" && grep -q "didn't unpack into a folder named for" "$m/out"; then :; else no 'a source that is not that commit is refused'; fi

  return "$bad"
}

failed=0
quiet=no
# (-e is never switched off and on inside a function: a function that switched it back on would make the next failing return end the
# script, so every exit here is caught with if/else)
if all_cases "$script"; then bad=0; else bad=$?; fi
if [ "$bad" -ne 0 ]; then echo "$bad cases of remote-deploy.sh don't hold"; failed=1; else echo 'remote-deploy.sh: every case holds'; fi

# The take-outs: each broken copy must make some case fail
quiet=yes
breaks='s/^\[ "\$got" = "\$want" \] || refuse/true || refuse/
s/^  switch_to "\$before"$/  true/
s/^case "\$commit" in \*\[!0-9a-f\]\*) refuse/case "$commit" in *[!0-9a-fA-Z;x]*) refuse/'
echo "$breaks" | while IFS= read -r edit; do
  sed "$edit" "$script" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$script"; then echo "TAKE-OUT CAN'T RUN, its text isn't in the script: $edit"; exit 1; fi
  if all_cases "$work/broken.sh"; then noticed=0; else noticed=$?; fi
  if [ "$noticed" -eq 0 ]; then echo "TAKE-OUT NOT NOTICED: $edit"; exit 1; fi
  echo "take-out noticed ($noticed cases): $edit"
done || failed=1

exit "$failed"
