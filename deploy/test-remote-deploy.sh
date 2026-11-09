#!/bin/sh
# The tests of deploy/remote-deploy.sh, with no machine, no network and no AWS. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-remote-deploy.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each case gets a folder of its own that stands in for the machine's / (AVPX_DEPLOY_ROOT), and stand-ins, first on PATH, for every
# command that would reach out or need root:
#   git          "fetches" a source tree the case made, and says which commit it is;
#   systemd-run  notes the limits it was asked to run with (the user, the network, what's out of reach), then runs the command;
#   systemctl    says the service is up, or not, as the case asks;
#   chown        notes what it was asked;
#   java         (the stand-in JDK's) the smoke test passes, or not, as the case asks.
# The case's source tree has its own build.sh (two jars) and get-jdk.sh (a stand-in JDK with a release file). Nothing runs as root, and
# nothing outside the case's folder changes. Then broken copies of remote-deploy.sh, each with one rule taken out, must each make some
# case fail.
#
# remote-deploy.sh moves symbolic links; on Windows, Git Bash makes those only where Windows allows it, so run this on Linux (GitHub's
# runner, the "Deploy scripts" check) when it can't.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/remote-deploy.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
C1=1111111111111111111111111111111111111111
C2=2222222222222222222222222222222222222222
PIN='25.0.5+8'

# The stand-ins
fake="$work/fake"
mkdir -p "$fake"
cat > "$fake/git" <<'STANDIN'
#!/bin/sh
# git's stand-in: init makes the folder, fetch copies the case's tree in and notes what was asked, rev-parse says the tree's commit
case "$1" in
  init) mkdir -p "$3" ;;
  fetch) echo "git fetch $*" >> "$FAKE_LOG"; cp -R "$FAKE_TREE/." . ;;
  checkout) ;;
  rev-parse) echo "$FAKE_HEAD" ;;
esac
STANDIN
cat > "$fake/systemd-run" <<'STANDIN'
#!/bin/sh
# systemd-run's stand-in: notes the limits on one line, then runs what comes after --
limits=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -p) limits="$limits $2"; shift 2 ;;
    *) shift ;;
  esac
done
echo "systemd-run$limits :: $*" >> "$FAKE_LOG"
cd "$(echo "$limits" | sed -n 's/.*WorkingDirectory=\([^ ]*\).*/\1/p')"
exec "$@"
STANDIN
cat > "$fake/systemctl" <<'STANDIN'
#!/bin/sh
echo "systemctl $*" >> "$FAKE_LOG"
if [ "$1" = is-active ]; then exit "${FAKE_ACTIVE:-0}"; fi
exit 0
STANDIN
cat > "$fake/chown" <<'STANDIN'
#!/bin/sh
echo "chown $*" >> "$FAKE_LOG"
STANDIN
chmod +x "$fake/git" "$fake/systemd-run" "$fake/systemctl" "$fake/chown"

# A stand-in JDK in the folder $1, saying it's version $2: its java notes how it was called, and the smoke test passes unless FAKE_SMOKE
make_jdk() {
  mkdir -p "$1/bin"
  printf 'JAVA_RUNTIME_VERSION="%s"\n' "$2" > "$1/release"
  printf '#!/bin/sh\necho "java $*" >> "$FAKE_LOG"\nexit "${FAKE_SMOKE:-0}"\n' > "$1/bin/java"
  chmod +x "$1/bin/java"
}

# A machine for one case, $m: its JDK link at version $2 (or none if $2 is NONE), and a source tree for commit $1 whose build.sh makes two
# jars holding $3 (or fails, if $3 is FAIL), and whose get-jdk.sh pins $PIN
machine() {
  m="$work/m$(od -An -N4 -tu4 /dev/urandom | tr -d ' ')"
  mkdir -p "$m/root/opt/avpx/releases" "$m/tree/java/tools"
  if [ "$2" != NONE ]; then
    make_jdk "$m/root/opt/avpx-jdk-$2" "$2"
    ln -s "$m/root/opt/avpx-jdk-$2" "$m/root/opt/avpx-jdk"
  fi
  source_tree "$m/tree" "$3"
  : > "$m/log"
  FAKE_HEAD=$1
}

# A source tree in $1 whose jars hold $2 (or whose build fails, if $2 is FAIL)
source_tree() {
  mkdir -p "$1/java/tools"
  if [ "$2" = FAIL ]; then
    printf '#!/bin/sh\nexit 1\n' > "$1/java/build.sh"
  else
    printf '#!/bin/sh\nmkdir -p "$(dirname "$0")/build"\nprintf %%s "%s" > "$(dirname "$0")/build/avpx-server.jar"\nprintf %%s "smoke %s" > "$(dirname "$0")/build/avpx-smoke.jar"\necho "built with $JAVA_HOME"\n' "$2" "$2" > "$1/java/build.sh"
  fi
  printf "#!/bin/sh\n# the stand-in get-jdk.sh\nJDK_RELEASE='%s'\nmkdir -p \"\$1/bin\"\nprintf 'JAVA_RUNTIME_VERSION=\"%%s\"\\\\n' '%s' > \"\$1/release\"\nprintf '#!/bin/sh\\\\nexit 0\\\\n' > \"\$1/bin/java\"\nchmod +x \"\$1/bin/java\"\necho \"get-jdk into \$1\" >> \"\$FAKE_LOG\"\n" "$PIN" "$PIN" > "$1/java/tools/get-jdk.sh"
}

# The jars' sha256 for a build whose jars hold $1: made the way remote-deploy.sh makes it, in a folder of its own
sha_of() {
  d=$(mktemp -d "$work/sha.XXXXXX")
  printf %s "$1" > "$d/avpx-server.jar"
  printf %s "smoke $1" > "$d/avpx-smoke.jar"
  (cd "$d" && sha256sum avpx-server.jar avpx-smoke.jar) | sha256sum | cut -d ' ' -f 1
}

# Runs the script under test ($1) on the machine $m with the rest as its arguments; gives back 0 or 1
deploy() {
  s=$1; shift
  if PATH="$fake:$PATH" AVPX_DEPLOY_ROOT="$m/root" FAKE_LOG="$m/log" FAKE_TREE="$m/tree" FAKE_HEAD="$FAKE_HEAD" sh "$s" "$@" > "$m/out" 2>&1; then
    return 0
  else
    return 1
  fi
}

linked() { [ -L "$1" ] && readlink "$1"; }
cur() { linked "$m/root/opt/avpx/current"; }

# Every case, with the script given as $1. Says FAIL for each that doesn't hold (unless quiet), and gives back how many didn't.
all_cases() {
  bad=0
  no() { [ "$quiet" = yes ] || echo "FAIL  $1"; bad=$((bad + 1)); }
  s=$1

  # A good deploy, with the JDK the commit pins already there
  machine "$C1" "$PIN" one
  if deploy "$s" "$C1" "$(sha_of one)" && [ "$(cur)" = "$m/root/opt/avpx/releases/$C1" ] \
    && [ "$(cat "$m/root/opt/avpx/releases/$C1/avpx-server.jar")" = one ] && [ "$(cat "$m/root/opt/avpx/releases/$C1/avpx-smoke.jar")" = 'smoke one' ] \
    && grep -q "git fetch -q --depth 1 https://github.com/Melanikus/AVPx-Dedicated-Server.git $C1\$" "$m/log" \
    && grep -q 'systemctl restart avpx-java' "$m/log" && grep -q 'java -jar .*/opt/avpx/current/avpx-smoke.jar --installed$' "$m/log" \
    && ! grep -q 'get-jdk into' "$m/log"; then :; else no 'a good deploy fetches that commit, puts both jars in place, restarts, and runs the installed smoke test'; fi
  # ...and every step that touched fetched code ran as avpx-build, with the settings and the certificate out of reach
  if grep 'systemd-run' "$m/log" | grep -v 'User=avpx-build' | grep -q .; then no 'every fetched-code step runs as avpx-build'; fi
  if grep 'systemd-run' "$m/log" | grep -v 'InaccessiblePaths=/etc/avpx InaccessiblePaths=/etc/letsencrypt' | grep -q .; then no 'with /etc/avpx and /etc/letsencrypt out of reach'; fi
  grep 'systemd-run' "$m/log" | grep 'build.sh' | grep -q 'PrivateNetwork=yes' || no 'the build runs with no network'
  grep -q "chown avpx-build" "$m/log" || no 'the work folder is avpx-build own'

  # The jars aren't the tested ones
  machine "$C1" "$PIN" one
  if ! deploy "$s" "$C1" "$(sha_of other)" && [ ! -e "$m/root/opt/avpx/current" ] && [ ! -e "$m/root/opt/avpx/releases/$C1" ] \
    && grep -q "aren't the ones the gates built" "$m/out"; then :; else no 'jars that are not the tested ones are refused, and nothing is put in place'; fi

  # Bad values: each refused before anything is fetched (the stand-ins' log stays empty)
  refused_before_fetch() {
    what=$1; shift
    machine "$C1" "$PIN" one
    if deploy "$@" || [ -s "$m/log" ]; then no "bad values are refused before anything is fetched: $what"; fi
  }
  good=$(sha_of one)
  refused_before_fetch 'one value' "$s" "$C1"
  refused_before_fetch 'three values' "$s" "$C1" "$good" extra
  refused_before_fetch 'a commit of 41' "$s" "${C1}0" "$good"
  refused_before_fetch 'a commit with a capital' "$s" "$(echo "$C1" | tr 1 A)" "$good"
  refused_before_fetch 'a sha256 of 65' "$s" "$C1" "${good}0"
  refused_before_fetch 'a commit with a ; in it' "$s" 'x;reboot' "$good"

  # What arrives isn't that commit
  machine "$C1" "$PIN" one
  FAKE_HEAD=$C2
  if ! deploy "$s" "$C1" "$(sha_of one)" && [ ! -e "$m/root/opt/avpx/current" ] && grep -q "couldn't fetch exactly" "$m/out"; then :; else no 'a fetch that is not that commit is refused'; fi

  # A build that fails
  machine "$C1" "$PIN" FAIL
  if ! deploy "$s" "$C1" "$(sha_of one)" && [ ! -e "$m/root/opt/avpx/current" ] && grep -q 'the build or its tests failed' "$m/out"; then :; else no 'a build that fails puts nothing in place'; fi

  # The machine's JDK isn't the one the commit pins: the pinned one is fetched, built with, and linked
  machine "$C1" '25.0.4+7' one
  if deploy "$s" "$C1" "$(sha_of one)" && [ "$(linked "$m/root/opt/avpx-jdk")" = "$m/root/opt/avpx-jdk-$PIN" ] \
    && [ -f "$m/root/opt/avpx-jdk-$PIN/release" ] && grep -q 'get-jdk into' "$m/log" \
    && grep 'systemd-run' "$m/log" | grep 'get-jdk' | grep -q 'PrivateNetwork=no'; then :; else no 'a JDK other than the pinned one is replaced by the pinned one, fetched as avpx-build'; fi

  # An unhealthy release goes back to the one before, JDK link and all
  machine "$C1" "$PIN" one
  deploy "$s" "$C1" "$(sha_of one)" || true
  rm -rf "$m/tree" && source_tree "$m/tree" two
  FAKE_HEAD=$C2
  if ! FAKE_SMOKE=1 deploy "$s" "$C2" "$(sha_of two)" && [ "$(cur)" = "$m/root/opt/avpx/releases/$C1" ] && grep -q 'going back to' "$m/out"; then :; else no 'an unhealthy release is rolled back to the one before'; fi

  # An unhealthy first release: nothing to go back to, so the service is stopped
  machine "$C1" "$PIN" one
  if ! FAKE_SMOKE=1 deploy "$s" "$C1" "$(sha_of one)" && grep -q 'systemctl stop avpx-java' "$m/log"; then :; else no 'an unhealthy first release is stopped, not left running'; fi

  # A release folder holding other jars
  machine "$C1" "$PIN" one
  mkdir -p "$m/root/opt/avpx/releases/$C1" && printf other > "$m/root/opt/avpx/releases/$C1/avpx-server.jar" && printf other > "$m/root/opt/avpx/releases/$C1/avpx-smoke.jar"
  if ! deploy "$s" "$C1" "$(sha_of one)" && grep -q 'there already, with other jars' "$m/out"; then :; else no 'a release folder holding other jars is refused'; fi

  # Old releases go: after five deploys, the newest three (the one in place among them) are kept
  machine "$C1" "$PIN" one
  for n in 1 2 3 4 5; do
    c=$(printf '%040d' "$n" | tr 0-9 a-j)
    rm -rf "$m/tree" && source_tree "$m/tree" "r$n"
    FAKE_HEAD=$c
    deploy "$s" "$c" "$(sha_of "r$n")" || true
    sleep 1
  done
  if [ "$(ls -1 "$m/root/opt/avpx/releases" | wc -l)" -eq 3 ] && [ -e "$m/root/opt/avpx/releases/$(printf '%040d' 5 | tr 0-9 a-j)" ]; then :; else no 'old releases are removed, and the newest kept'; fi

  return "$bad"
}

failed=0
quiet=no
# (-e is never switched off and on inside a function: every exit here is caught with if/else)
if all_cases "$script"; then bad=0; else bad=$?; fi
if [ "$bad" -ne 0 ]; then echo "$bad cases of remote-deploy.sh don't hold"; failed=1; else echo 'remote-deploy.sh: every case holds'; fi

# The take-outs: each broken copy must make some case fail
quiet=yes
breaks='s/^\[ "\$got" = "\$want" \] || refuse/true || refuse/
s/^  switch "\$current" "\$before"$/  true/
s/^case "\$commit" in \*\[!0-9a-f\]\*) refuse/case "$commit" in *[!0-9a-fA-Z;x]*) refuse/
s/^as_builder no-network env/as_builder network env/
s/ -p InaccessiblePaths=\/etc\/avpx / /
s/^  systemctl stop "\$service" || true$/  true/
s/^  as_builder network sh "\$tree\/java\/tools\/get-jdk.sh"/  true "$tree\/java\/tools\/get-jdk.sh"/'
echo "$breaks" | while IFS= read -r edit; do
  sed "$edit" "$script" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$script"; then echo "TAKE-OUT CAN'T RUN, its text isn't in the script: $edit"; exit 1; fi
  if all_cases "$work/broken.sh"; then noticed=0; else noticed=$?; fi
  if [ "$noticed" -eq 0 ]; then echo "TAKE-OUT NOT NOTICED: $edit"; exit 1; fi
  echo "take-out noticed ($noticed cases): $edit"
done || failed=1

exit "$failed"
