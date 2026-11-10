#!/bin/sh
# The machine fetches its own deploys: run by root's timer (deploy/avpx-pull.timer, every 5 minutes), it asks GitHub whether the owner
# has approved a new deploy for this machine, checks everything about it, and only then puts it in place with remote-deploy.sh.
# Written 2026-11-09 by Melanikus for AVPx Dedicated Server, by the owner's ruling of that night: "nyc3 pulls its deploys". It replaces
# the AWS Systems Manager route, which needed a cloud account and a machine of AWS's ("Remove it; item 5 guards the pull route").
#
#   sh pull-deploy.sh <machine>      once; the timer runs it, from /usr/local/lib/avpx-pull/, as root. <machine> is the region, nyc3
#
# HOW A DEPLOY GETS HERE, end to end:
#   1. On GitHub, the owner starts the Deploy workflow (.github/workflows/deploy.yml) with a commit. It refuses while SERVER-BLOCKERS.md
#      lists anything, checks the commit is on main with every gate green, builds the two jars, and waits for the owner to approve its
#      "production" environment. Then it records a GitHub deployment for environment avpx-<machine>: the commit, the jars' SHA-256, and
#      its own run's id. That's all it does: GitHub never reaches this machine, and no key or token is kept anywhere.
#   2. Here, every 5 minutes, this asks GitHub's public API, with no token, for the newest deployment for avpx-<machine>. Nothing new
#      since the last one taken: it stops (one call to GitHub; the run's and the approval's are asked only for a new deployment, which
#      keeps it well under GitHub's 60 calls an hour for an address with no token). Only the newest is ever looked at: two Deploys
#      recorded within 5 minutes, and only the second is taken; the first never is.
#   3. A new one is held to every one of these, or refused:
#      - GitHub's own Actions made it (its creator is github-actions[bot]): only a workflow can, and only deploy.yml has the right;
#      - no deployment before it named the same run: one approval puts one deploy on the machine, never a second;
#      - its run is .github/workflows/deploy.yml, started by hand (workflow_dispatch), from main, and finished with success. A run not
#        finished yet is asked again next time;
#      - that run is in its first attempt: a run done again (GitHub's "Re-run") never counts, however it ends;
#      - that run's name is exactly "Deploy <the deployment's commit> to <machine>" (deploy.yml's run-name, made from what the owner
#        typed when starting it). So the run the owner approved was for this very commit and this very machine, and not a dry run,
#        whoever wrote the deployment: the record can't point an old approval at another commit;
#      - the owner approved that run's "production" environment: GitHub's record of the approval names the owner by login AND by number
#        (OWNER_LOGIN and OWNER_ID below), since a login can be renamed and taken by someone else, and a number can't;
#      - the commit is on main, fetched with git;
#      - main's own SERVER-BLOCKERS.md, as main is now, lists nothing (deploy/check-blockers.sh). This comes before anything is built or
#        installed. It can't come before the fetch: it's main's current list that counts, and that has to be fetched.
#   4. Only then: remote-deploy.sh, root's installed copy, with the commit and the jars' SHA-256. It fetches the commit again, builds it
#      with no rights and no network, takes the jars only if they're byte for byte the ones GitHub built, switches, checks the server is
#      healthy, and goes back to the old release if not (remote-deploy.sh says each step).
#   5. Every deployment looked at is written in /var/lib/avpx-pull/taken, with its run and what became of it, so no deployment, and no
#      run, is ever taken twice. "taking" is written before remote-deploy.sh starts, so a deploy begun is never begun again, whatever
#      happens after. One that was refused stays refused: the owner starts a new Deploy.
#
# ONE AT A TIME: the whole script holds a lock (/var/lib/avpx-pull/lock, through flock), so a run by hand while the timer's is going
# stops at once, saying so, rather than two deploying together. (The timer never overlaps itself: its unit is a oneshot.)
#
# WHAT RUNS AS ROOT is only what the owner installed by hand (deploy/README.md, "The machine fetches its own deploys"): this script and
# remote-deploy.sh, copied once from a commit and checked by their SHA-256. NOTHING FETCHED EVER RUNS AS ROOT, and no answer from GitHub
# can change what does: every call to GitHub, every reading of its answers, the git fetch and main's check-blockers.sh run as avpx-build,
# a user with no rights, through systemd-run, with the settings and the certificate's key out of reach. Root takes back from them only a
# few short values (the deployment's number, the commit, the jars' SHA-256, the run's number), each held here to its exact shape.
#
# GITHUB'S ANSWERS ARE HOSTILE INPUT (AVP Tao 3): each is at most MOST_ANSWER_BYTES, within 30 s, over HTTPS only (TLS 1.2 or newer),
# and read by jq into one line that must match its pattern exactly, or nothing more happens. A field missing, of another type, or with a
# line break in it fails the pattern, or jq itself, and either refuses.
#
# THE SERVER DOESN'T NEED THIS: the timer is the one place the machine talks to GitHub. With it off (systemctl disable --now
# avpx-pull.timer) the server runs exactly as before, and deploys are done by hand (deploy/README.md, remote-deploy.sh in the console).
#
# AVPX_DEPLOY_ROOT: only deploy/test-pull-deploy.sh sets it, to a folder that stands in for /, with stand-ins in its usr/bin, so every
# step can be tested with no machine and no network. On a real machine it's never set.
set -eu

root=${AVPX_DEPLOY_ROOT:-}

# Who may approve a deploy, and where the server's code is: a successor changes these here, in the installed copy too
OWNER_LOGIN='Melanikus'
OWNER_ID='78985790'
REPOSITORY='Melanikus/AVPx-Dedicated-Server'
# The most any one answer from GitHub may be. curl's --max-filesize stops a transfer part way through only from curl 8.4 on (before, it
# went by the size the server announced); Ubuntu 24.04's curl is 8.5.
MOST_ANSWER_BYTES=1048576
builder=avpx-build

curl="$root/usr/bin/curl"
jq="$root/usr/bin/jq"
git="$root/usr/bin/git"
flock="$root/usr/bin/flock"
systemd_run="$root/usr/bin/systemd-run"
installed="$root/usr/local/lib/avpx-pull"
state="$root/var/lib/avpx-pull"
api="https://api.github.com/repos/$REPOSITORY"
repo="https://github.com/$REPOSITORY.git"

say() { echo "pull: $*"; }
refuse() { say "$*"; exit 1; }

# The machine's name: a region's, 1 to 16 small letters, digits and -, as the server's own settings hold one
[ "$#" -eq 1 ] || refuse 'give exactly the machine, such as nyc3'
machine=$1
case "$machine" in ''|*[!a-z0-9-]*) refuse 'the machine must be 1 to 16 small letters, digits and -' ;; esac
[ "${#machine}" -le 16 ] || refuse 'the machine must be 1 to 16 small letters, digits and -'
environment="avpx-$machine"

mkdir -p "$state"
chmod 0700 "$state"

# One at a time: the lock is held on file descriptor 9 until the script ends, however it ends
exec 9> "$state/lock"
"$flock" -n 9 || refuse 'another pull is running (it holds /var/lib/avpx-pull/lock): this one stops, and changes nothing'

taken="$state/taken"
[ -f "$taken" ] || : > "$taken"

# The work folder: root's, in /var/lib (avpx-build's steps have a /tmp of their own), lent to avpx-build, removed whatever happens
work=$(mktemp -d "$root/var/lib/avpx-pull-work.XXXXXXXXXX")
trap 'rm -rf "$work"' EXIT
chown "$builder" "$work"
chmod 0700 "$work"

# Runs a command as avpx-build, as remote-deploy.sh does: no rights, the settings and the certificate's key out of reach, writing only
# in $work, and git reading no settings from outside it. $1 is "network" or "no-network".
as_builder() {
  if [ "$1" = network ]; then private=no; else private=yes; fi
  shift
  "$systemd_run" --quiet --wait --pipe --collect -p User="$builder" -p PrivateNetwork="$private" -p NoNewPrivileges=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p InaccessiblePaths=/etc/avpx \
    -p ReadWritePaths="$work" -p WorkingDirectory="$work" \
    --setenv=HOME="$work" --setenv=GIT_CONFIG_NOSYSTEM=1 --setenv=GIT_CONFIG_GLOBAL=/dev/null -- "$@"
}

# One question to GitHub's API, as avpx-build, its answer into $work/$2. -q first, so curl reads no ~/.curlrc. A User-Agent of the
# program's own (GitHub refuses a call with none), and nothing about who runs it.
ask() {
  as_builder network "$curl" -q --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 30 --max-filesize "$MOST_ANSWER_BYTES" \
    -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' -H 'User-Agent: avpx-pull' \
    -o "$work/$2" "$api/$1"
}

# jq's reading of an answer, as avpx-build with no network: the answer's file, then jq's own words (any --arg, then the filter). Its
# one line of output is what the caller holds to a pattern.
read_answer() {
  file=$1
  shift
  as_builder no-network "$jq" -r "$@" "$work/$file"
}

# Whether text is exactly one line matching the extended pattern
one_line_like() {
  [ "$(printf '%s\n' "$1" | wc -l)" -eq 1 ] && printf '%s\n' "$1" | grep -Eqx "$2"
}

# What became of the deployment $id, from the run $run, written down so neither is ever taken again: "<id> run <run>: <what>"
note() {
  printf '%s run %s: %s\n' "$id" "$run" "$1" >> "$taken"
}

# 1. The newest deployment for this machine
ask "deployments?environment=$environment&per_page=1" deployments.json || refuse 'GitHub could not be asked (it is asked again next time)'
newest=$(read_answer deployments.json 'if type != "array" then "not a list" elif length == 0 then "none" else (.[0] | [(.id | tostring),
  .sha, .creator.login, (.creator.id | tostring), .environment, .payload.jarsSha256, (.payload.runId | tostring)] | join(" ")) end') \
  || refuse "GitHub's answer for the deployments could not be read"

if [ "$newest" = none ]; then
  say "no deployment for $environment yet"
  exit 0
fi

one_line_like "$newest" "[1-9][0-9]{0,15} [0-9a-f]{40} github-actions\\[bot\\] 41898282 $environment [0-9a-f]{64} [1-9][0-9]{0,15}" \
  || refuse "the newest deployment for $environment isn't one deploy.yml makes: nothing taken"
set -f
set -- $newest
set +f
id=$1
commit=$2
jars=$6
run=$7

if grep -q "^$id " "$taken"; then
  say "deployment $id was taken already: nothing new"
  exit 0
fi

say "deployment $id: $commit, from run $run"

# One approval, one deploy: a deployment naming a run that an earlier deployment named is refused, whatever became of the earlier one
earlier=$(grep -E "^[0-9]+ run $run: " "$taken" | head -n 1 | cut -d ' ' -f 1)
if [ -n "$earlier" ]; then
  note "refused: its run was named by deployment $earlier already"
  refuse "deployment $id: run $run was named by deployment $earlier already, and one approval puts one deploy on the machine"
fi

# 2. Its run: deploy.yml, started by hand, from main, finished with success, in its first attempt, and named for this commit and machine
ask "actions/runs/$run" run.json || refuse 'GitHub could not be asked about the run (it is asked again next time)'
how=$(read_answer run.json '[.path, .event, .head_branch, .status, (.conclusion // "none")] | join(" ")') \
  || refuse "GitHub's answer for the run could not be read (it is asked again next time)"
# The attempt and the name are compared inside jq, as JSON values, whole: the shell's $(...) drops line breaks at the end of what it's
# given, so a name with one there would compare equal outside jq (Secondary's re-check, R-2)
attempt=$(read_answer run.json 'if .run_attempt == 1 then "first" else "again" end') \
  || refuse "GitHub's answer for the run could not be read (it is asked again next time)"
named=$(read_answer run.json --arg want "Deploy $commit to $machine" 'if .display_title == $want then "same" else "other" end') \
  || refuse "GitHub's answer for the run could not be read (it is asked again next time)"

if one_line_like "$how" '\.github/workflows/deploy\.yml workflow_dispatch main (queued|in_progress|waiting|requested|pending) none'; then
  say "run $run hasn't finished yet: asked again next time"
  exit 0
fi

if ! one_line_like "$how" '\.github/workflows/deploy\.yml workflow_dispatch main completed success'; then
  note "refused: its run isn't deploy.yml, started by hand from main, finished with success"
  refuse "deployment $id: its run isn't deploy.yml, started by hand from main, finished with success"
fi

if [ "$attempt" != first ]; then
  note "refused: its run was run again, and only a run's first attempt counts"
  refuse "deployment $id: run $run was run again, and only a run's first attempt counts (the owner starts a new Deploy)"
fi

if [ "$named" != same ]; then
  note "refused: its run was for another commit or machine, or a dry run (its name isn't \"Deploy $commit to $machine\")"
  refuse "deployment $id: run $run was for another commit or machine, or a dry run: its name isn't \"Deploy $commit to $machine\""
fi

# 3. The owner's own approval of that run's production environment, by login and by number. An answer jq can't read is asked again
# next time, as an answer that couldn't be had is.
ask "actions/runs/$run/approvals" approvals.json || refuse 'GitHub could not be asked about the approval (it is asked again next time)'
approved=$(read_answer approvals.json --arg login "$OWNER_LOGIN" --argjson number "$OWNER_ID" 'if type != "array" then "not a list" else
  [.[] | select(.state == "approved" and .user.login == $login and .user.id == $number and any(.environments[]; .name == "production"))]
  | length | tostring end' 2>/dev/null) || refuse "GitHub's answer for the approval could not be read (it is asked again next time)"

if ! one_line_like "$approved" '[1-9][0-9]{0,3}'; then
  note "refused: the owner didn't approve its run's production environment"
  refuse "deployment $id: the owner ($OWNER_LOGIN, $OWNER_ID) didn't approve run $run's production environment"
fi

# 4. The commit on main, and main's own list of blockers, as avpx-build, before anything is built or installed
as_builder network sh -c '"$1" init -q main && cd main && "$1" fetch -q "$2" "+refs/heads/main:refs/remotes/origin/main" \
  && "$1" checkout -q --detach refs/remotes/origin/main' fetch "$git" "$repo" || refuse 'main could not be fetched (it is asked again next time)'

if ! as_builder no-network sh -c 'cd main && "$1" merge-base --is-ancestor "$2" HEAD' onmain "$git" "$commit"; then
  note "refused: the commit isn't on main"
  refuse "deployment $id: $commit isn't on main"
fi

if ! as_builder no-network sh main/deploy/check-blockers.sh; then
  note "refused: main's SERVER-BLOCKERS.md lists something"
  refuse "deployment $id: main's SERVER-BLOCKERS.md lists something, so nothing is deployed"
fi

# 5. Only now, root's own copy of remote-deploy.sh. "taking" is written first: if it can't be, nothing starts, and once it is, this
# deployment is never begun again, even if what becomes of it can't be written down after.
say "deployment $id: every check holds; putting $commit in place"
note "taking $commit"

if sh "$installed/remote-deploy.sh" "$commit" "$jars"; then
  note "deployed $commit"
  say "deployment $id: $commit is in place"
else
  note "remote-deploy.sh refused or rolled back"
  refuse "deployment $id: remote-deploy.sh refused it, or put the old release back (its lines above say why)"
fi
