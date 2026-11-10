#!/bin/sh
# The tests of deploy/pull-deploy.sh, with no machine, no network and no GitHub. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server.
#
#   sh deploy/test-pull-deploy.sh     exits 0 if every case holds, 1 if any doesn't
#
# Each case gets a folder of its own that stands in for the machine's / (AVPX_DEPLOY_ROOT), with stand-ins in its usr/bin for everything
# that would reach out or need root:
#   curl          GitHub's API: answers each question with the case's own file for it (or fails, as curl --fail does, if there's none),
#                 and notes each question and the words it was asked with;
#   systemd-run   notes the user and the network it was asked to run with, then runs the command, in the folder it names;
#   git           "fetches" main: a tree the case made (its deploy/check-blockers.sh is the real one, and its SERVER-BLOCKERS.md the
#                 case's own), and says a commit is on main only if the case lists it;
#   jq            the real one, from /usr/bin (so run this where jq is: GitHub's runner, the "Deploy scripts" check);
#   flock         notes what it was asked, and says the lock is held only if the case says another pull holds it;
# and chown, first on PATH, which only notes what it's asked. root's installed remote-deploy.sh is a stand-in that notes what it was
# given, and whether "taking" was written down before it started, and ends as the case asks. Nothing runs as root, and nothing outside
# the case's folder changes. Then broken copies of pull-deploy.sh, each with one check taken out, must each make some case fail.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/pull-deploy.sh"
jq_real=$(command -v jq || true)
[ -n "$jq_real" ] || { echo 'test-pull-deploy.sh needs jq (it runs on GitHub'"'"'s Ubuntu runner, which has it)'; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

C1=1111111111111111111111111111111111111111
C9=9999999999999999999999999999999999999999
JARS=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
API='https://api.github.com/repos/Melanikus/AVPx-Dedicated-Server'

# chown's stand-in, first on PATH
mkdir -p "$work/path"
printf '#!/bin/sh\necho "chown $*" >> "$FAKE_LOG"\n' > "$work/path/chown"
chmod +x "$work/path/chown"

# One case's machine: $1 its folder. FAKE_* set by the case say what GitHub, git and remote-deploy.sh answer.
machine() {
  m=$1
  mkdir -p "$m/usr/bin" "$m/var/lib" "$m/usr/local/lib/avpx-pull" "$m/api"
  cat > "$m/usr/bin/curl" <<'STANDIN'
#!/bin/sh
# curl's stand-in: the last word is the URL, and -o names the file the answer goes to
out=''
url=''
words="$*"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
echo "curl $words" >> "$FAKE_LOG"
answer="$FAKE_API/$(printf '%s' "${url#"$FAKE_BASE"/}" | tr '/?&=' '____')"
[ -f "$answer" ] || exit 22
cp "$answer" "$out"
STANDIN
  cat > "$m/usr/bin/systemd-run" <<'STANDIN'
#!/bin/sh
# systemd-run's stand-in: notes the user and the network, then runs what comes after --, in the working folder it names
user=''
net=''
dir=.
while [ "$#" -gt 0 ]; do
  case "$1" in
    --) shift; break ;;
    -p) case "$2" in User=*) user=${2#User=} ;; PrivateNetwork=*) net=${2#PrivateNetwork=} ;; WorkingDirectory=*) dir=${2#WorkingDirectory=} ;; esac; shift 2 ;;
    *) shift ;;
  esac
done
echo "as $user, private network $net: $1" >> "$FAKE_LOG"
cd "$dir" && exec "$@"
STANDIN
  cat > "$m/usr/bin/git" <<'STANDIN'
#!/bin/sh
# git's stand-in: init makes the folder, fetch copies the case's main in, merge-base says whether the commit is on main
case "$1" in
  init) mkdir -p "$3" ;;
  fetch) echo "git $*" >> "$FAKE_LOG"; cp -R "$FAKE_MAIN/." . ;;
  checkout) ;;
  merge-base) case " $FAKE_ON_MAIN " in *" $3 "*) exit 0 ;; *) exit 1 ;; esac ;;
esac
STANDIN
  printf '#!/bin/sh\nexec "%s" "$@"\n' "$jq_real" > "$m/usr/bin/jq"
  printf '#!/bin/sh\necho "flock $*" >> "$FAKE_LOG"\n[ "$FAKE_LOCK_HELD" = no ]\n' > "$m/usr/bin/flock"
  cat > "$m/usr/local/lib/avpx-pull/remote-deploy.sh" <<'STANDIN'
#!/bin/sh
echo "remote-deploy.sh $*" >> "$FAKE_LOG"
if grep -q ': taking ' "$FAKE_TAKEN"; then echo 'remote-deploy.sh found "taking" written down' >> "$FAKE_LOG"; fi
exit "$FAKE_DEPLOY_EXIT"
STANDIN
  chmod +x "$m/usr/bin/curl" "$m/usr/bin/systemd-run" "$m/usr/bin/git" "$m/usr/bin/jq" "$m/usr/bin/flock"
  # main, as git would fetch it: the real check-blockers.sh, and a list saying Nothing unless the case says otherwise
  mkdir -p "$m/main/deploy"
  cp "$here/check-blockers.sh" "$m/main/deploy/check-blockers.sh"
  printf '# What blocks\n\n## Blocking a deploy\n\nNothing.\n\nEnd of the list.\n' > "$m/main/SERVER-BLOCKERS.md"
}

# GitHub's answers for a case, each as the file its question is answered from
deployments() { printf '%s' "$2" > "$1/api/deployments_environment_avpx-nyc3_per_page_1"; }
run_answer() { printf '%s' "$2" > "$1/api/actions_runs_${3:-4242}"; }
approvals() { printf '%s' "$2" > "$1/api/actions_runs_${3:-4242}_approvals"; }

GOOD_DEPLOYMENT="[{\"id\":7001,\"sha\":\"$C1\",\"environment\":\"avpx-nyc3\",\"creator\":{\"login\":\"github-actions[bot]\",\"id\":41898282},\"payload\":{\"jarsSha256\":\"$JARS\",\"runId\":4242}}]"
GOOD_RUN="{\"path\":\".github/workflows/deploy.yml\",\"event\":\"workflow_dispatch\",\"head_branch\":\"main\",\"status\":\"completed\",\"conclusion\":\"success\",\"run_attempt\":1,\"display_title\":\"Deploy $C1 to nyc3\"}"
GOOD_APPROVAL='[{"state":"approved","user":{"login":"Melanikus","id":78985790},"environments":[{"name":"production"}]}]'

# A case that would be taken, every answer good: $1 its folder
good_case() {
  machine "$1"
  deployments "$1" "$GOOD_DEPLOYMENT"
  run_answer "$1" "$GOOD_RUN"
  approvals "$1" "$GOOD_APPROVAL"
}

# Runs pull-deploy.sh (or $SCRIPT, a broken copy) on the case $1, with machine nyc3 unless more words are given
pull() {
  m=$1
  shift
  [ "$#" -gt 0 ] || set -- nyc3
  : > "$m/log"
  if PATH="$work/path:$PATH" AVPX_DEPLOY_ROOT="$m" FAKE_LOG="$m/log" FAKE_API="$m/api" FAKE_BASE="$API" FAKE_MAIN="$m/main" \
    FAKE_ON_MAIN="${ON_MAIN-$C1}" FAKE_DEPLOY_EXIT="${DEPLOY_EXIT:-0}" FAKE_LOCK_HELD="${LOCK_HELD:-no}" \
    FAKE_TAKEN="$m/var/lib/avpx-pull/taken" sh "${SCRIPT:-$script}" "$@" > "$m/out" 2>&1; then
    return 0
  fi
  return 1
}

deployed() { grep -q "^remote-deploy.sh $C1 $JARS$" "$1/log"; }
noted() { grep -q "^7001 run 4242: $2" "$1/var/lib/avpx-pull/taken"; }

all_cases() {
  bad=0
  n=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$m/out"; }; }
  next() { n=$((n + 1)); c="$work/case$n.$1"; rm -rf "$c"; }

  # The good one: every check holds, and only then remote-deploy.sh, with the commit and the jars
  next good; good_case "$c"
  if pull "$c" && deployed "$c" && noted "$c" "deployed $C1"; then :; else no 'an approved deploy is taken: remote-deploy.sh with its commit and jars'; fi
  grep -q "^as avpx-build, private network no: $c/usr/bin/curl" "$c/log" || no 'GitHub is asked as avpx-build'
  grep -q "^as avpx-build, private network yes: $c/usr/bin/jq" "$c/log" || no 'its answers are read as avpx-build, with no network'
  grep -q -- "--proto =https --tlsv1.2 --max-time 30 --max-filesize 1048576" "$c/log" || no 'every question is HTTPS only, with a time limit and a size cap'
  if grep -qi 'authorization' "$c/log"; then no 'no token is ever sent'; fi
  grep -q '^flock -n 9$' "$c/log" || no 'the run holds the lock, and never waits for it'
  if grep -q '^remote-deploy.sh found "taking" written down$' "$c/log" && noted "$c" "taking $C1"; then :; else
    no '"taking" is written down before remote-deploy.sh starts'; fi
  # The same again: taken already, and nothing but the one question
  if pull "$c" && ! deployed "$c" && grep -q 'taken already' "$c/out" && [ "$(grep -c '^curl ' "$c/log")" -eq 1 ]; then :; else
    no 'a deployment taken already is never taken again, and costs one question'; fi

  # None yet
  next none; machine "$c"; deployments "$c" '[]'
  if pull "$c" && ! deployed "$c" && grep -q 'no deployment' "$c/out"; then :; else no 'no deployment: nothing, and no error'; fi

  # The deployment itself, each field wrong in turn: refused, nothing deployed
  for wrong in \
    'creator: someone else|s/"login":"github-actions\[bot\]"/"login":"melanikus"/' \
    'creator: another number|s/"id":41898282/"id":41898283/' \
    'another environment|s/"environment":"avpx-nyc3"/"environment":"avpx-paris"/' \
    'jars not 64 hex|s/"jarsSha256":"a*"/"jarsSha256":"aaa"/' \
    'a run number of 0|s/"runId":4242/"runId":0/' \
    'a commit of 39 digits|s/"sha":"1*"/"sha":"111111111111111111111111111111111111111"/' \
    'a line break in the commit|s/"sha":"1*"/"sha":"1111111111111111111111111111111111111111\\n1111111111111111111111111111111111111111"/' \
    'the payload as text|s/"payload":{[^}]*}/"payload":"jarsSha256"/' \
    'an object, not a list|s/^\[\(.*\)\]$/\1/'; do
    next deployment; good_case "$c"
    deployments "$c" "$(printf '%s' "$GOOD_DEPLOYMENT" | sed "${wrong#*|}")"
    if pull "$c" || deployed "$c"; then no "a deployment refused for: ${wrong%%|*}"; fi
  done

  # Its run, each field wrong in turn: refused and noted, nothing deployed
  for wrong in \
    'another workflow|s|deploy\.yml|test-build.yml|' \
    'started by a push|s/workflow_dispatch/push/' \
    'from another branch|s/"head_branch":"main"/"head_branch":"v2"/' \
    'failed|s/"conclusion":"success"/"conclusion":"failure"/' \
    'cancelled|s/"conclusion":"success"/"conclusion":"cancelled"/' \
    'run again|s/"run_attempt":1/"run_attempt":2/' \
    'no attempt|s/,"run_attempt":1//' \
    'its attempt as text|s/"run_attempt":1/"run_attempt":"1"/' \
    'for another commit|s/"Deploy 1/"Deploy 9/' \
    'for another machine|s/ to nyc3"/ to paris"/' \
    'a dry run|s/ to nyc3"/ to nyc3 (dry run)"/' \
    'a line break in its name|s/ to nyc3"/ to nyc3\\nDeploy x"/' \
    'a line break at the end of its name|s/ to nyc3"/ to nyc3\\n"/' \
    'no name|s/,"display_title":"[^"]*"//'; do
    next run; good_case "$c"
    run_answer "$c" "$(printf '%s' "$GOOD_RUN" | sed "${wrong#*|}")"
    if pull "$c" || deployed "$c" || ! noted "$c" 'refused'; then no "a run refused and noted: ${wrong%%|*}"; fi
  done

  # A run not finished yet: nothing now, and nothing noted, so it's asked again next time
  next unfinished; good_case "$c"
  run_answer "$c" '{"path":".github/workflows/deploy.yml","event":"workflow_dispatch","head_branch":"main","status":"in_progress","conclusion":null}'
  if pull "$c" && ! deployed "$c" && ! grep -q '^7001 ' "$c/var/lib/avpx-pull/taken"; then :; else no 'a run not finished is asked again next time'; fi

  # The approval, each way it isn't the owner's of production: refused and noted
  for wrong in \
    'none at all|[]' \
    'another login|[{"state":"approved","user":{"login":"Mallory","id":78985790},"environments":[{"name":"production"}]}]' \
    'the login, another number|[{"state":"approved","user":{"login":"Melanikus","id":1},"environments":[{"name":"production"}]}]' \
    'another environment|[{"state":"approved","user":{"login":"Melanikus","id":78985790},"environments":[{"name":"staging"}]}]' \
    'rejected|[{"state":"rejected","user":{"login":"Melanikus","id":78985790},"environments":[{"name":"production"}]}]' \
    'an object, not a list|{"state":"approved","user":{"login":"Melanikus","id":78985790},"environments":[{"name":"production"}]}'; do
    next approval; good_case "$c"
    approvals "$c" "${wrong#*|}"
    if pull "$c" || deployed "$c" || ! noted "$c" 'refused'; then no "an approval refused and noted: ${wrong%%|*}"; fi
  done

  # An approval jq can't read (no environments to look through): refused, nothing noted, so it's asked again next time
  next approvalunread; good_case "$c"
  approvals "$c" '[{"state":"approved","user":{"login":"Melanikus","id":78985790}}]'
  if pull "$c" || deployed "$c" || grep -q '^7001 ' "$c/var/lib/avpx-pull/taken"; then no 'an approval jq cannot read is asked again next time, nothing noted'; fi

  # A run an earlier deployment named already: refused and noted, whatever became of the earlier one, before its run is asked about
  next runused; good_case "$c"
  mkdir -p "$c/var/lib/avpx-pull"
  printf '6999 run 4242: deployed %s\n' "$C9" > "$c/var/lib/avpx-pull/taken"
  if pull "$c" || deployed "$c" || ! noted "$c" 'refused: its run was named by deployment 6999 already' || [ "$(grep -c '^curl ' "$c/log")" -ne 1 ]; then
    no 'one approved run, one deploy: a second deployment naming it is refused'; fi

  # Another pull holds the lock: this one stops before asking anything, and notes nothing
  next locked; good_case "$c"
  if LOCK_HELD=yes pull "$c" || grep -q '^curl ' "$c/log" || [ -s "$c/var/lib/avpx-pull/taken" ] || ! grep -q 'another pull is running' "$c/out"; then
    no 'with another pull running, this one stops, saying so, and changes nothing'; fi

  # The commit not on main
  next offmain; good_case "$c"
  if ON_MAIN="$C9" pull "$c" || deployed "$c" || ! noted "$c" "refused: the commit isn't on main"; then no 'a commit not on main is refused'; fi

  # main's SERVER-BLOCKERS.md lists something: refused before anything is deployed
  next blocked; good_case "$c"
  printf '# What blocks\n\n## Blocking a deploy\n\n1. Something.\n\nEnd of the list.\n' > "$c/main/SERVER-BLOCKERS.md"
  if pull "$c" || deployed "$c" || ! noted "$c" "refused: main's SERVER-BLOCKERS.md lists something"; then no 'a blocker on main refuses the deploy'; fi
  grep -q "^as avpx-build, private network yes: sh" "$c/log" || no 'main'"'"'s check-blockers.sh runs as avpx-build, with no network'

  # remote-deploy.sh refuses or rolls back: said, and noted
  next rolledback; good_case "$c"
  if DEPLOY_EXIT=1 pull "$c" || ! noted "$c" 'remote-deploy.sh refused'; then no 'a deploy remote-deploy.sh refused is said and noted'; fi

  # GitHub not answering: refused, nothing noted (asked again next time)
  next noanswer; machine "$c"
  if pull "$c" || [ -s "$c/var/lib/avpx-pull/taken" ]; then no 'no answer from GitHub: nothing noted, so it is asked again'; fi

  # The machine's name, each wrong: refused before GitHub is asked
  for name in Nyc3 'ny c3' 'abcdefghijklmnopq' ''; do
    next name; good_case "$c"
    if pull "$c" "$name" || grep -q '^curl ' "$c/log"; then no "a machine name refused before anything is asked: [$name]"; fi
  done
  next twowords; good_case "$c"
  if pull "$c" nyc3 paris || grep -q '^curl ' "$c/log"; then no 'two machine names refused'; fi

  return "$bad"
}

failed=0
quiet=no
SCRIPT=''
if all_cases; then echo 'pull-deploy.sh: every case holds'; else echo "$? cases of pull-deploy.sh don't hold"; failed=1; fi

# The take-outs: broken copies, each with one check taken out, must each make some case fail
quiet=yes
for edit in \
  's/github-actions\\\\\[bot\\\\\] 41898282 \$environment/.* .* $environment/' \
  's/^if grep -q "\^\$id " "\$taken"; then$/if false; then/' \
  "s/'\\\\.github\\/workflows\\/deploy\\\\.yml workflow_dispatch main completed success'/'.*'/" \
  's/^if ! one_line_like "\$approved" .*$/if false; then/' \
  's/^if ! as_builder no-network sh -c .cd main .*merge-base.*$/if false; then/' \
  's/^if ! as_builder no-network sh main\/deploy\/check-blockers.sh; then$/if false; then/' \
  's/ --proto .=https. --tlsv1.2 / /' \
  's/^if \[ -n "\$earlier" \]; then$/if false; then/' \
  's/^if \[ "\$attempt" != first \]; then$/if false; then/' \
  's/^if \[ "\$named" != same \]; then$/if false; then/' \
  "s/'if \\.display_title == \\\$want then \"same\" else \"other\" end'/'.display_title'/; s/^if \\[ \"\\\$named\" != same \\]; then\$/if [ \"\\\$named\" != \"Deploy \\\$commit to \\\$machine\" ]; then/" \
  's/^"\$flock" -n 9 || /true || /' \
  's/^note "taking \$commit"$/:/' \
  's/\(| length | tostring end.\) 2>\/dev\/null) || refuse .*$/\1 2>\/dev\/null) || approved=""/'; do
  sed "$edit" "$script" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$script"; then echo "TAKE-OUT CAN'T RUN, its text isn't in pull-deploy.sh: $edit"; failed=1; continue; fi
  if SCRIPT="$work/broken.sh" all_cases; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
