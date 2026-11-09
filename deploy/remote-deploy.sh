#!/bin/sh
# Puts one commit of the server on this machine, or leaves the one already there. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server.
#
#   sh remote-deploy.sh <commit> <jars sha256>
#
# Run as root by the SSM document avpx-deploy (deploy/avpx-deploy.ssm.json, made from this file by deploy/make-ssm-document.sh), which
# the owner runs by hand on a test machine, or GitHub's deploy workflow runs once the owner has approved it. Nobody logs in to do this.
#
# WHAT IT DOES, in order, stopping at the first thing that fails:
#   1. checks its two values again: the commit is 40 hex digits, the jars' sha256 64;
#   2. fetches exactly that commit with git, which names every file by its hash, so what arrives IS that commit;
#   3. holds the machine's JDK to the commit's own pin (JDK_RELEASE in java/tools/get-jdk.sh): if they differ, the commit's get-jdk.sh
#      fetches and checks the pinned JDK (its signature, its sha256, its version) into a folder of its own;
#   4. builds both jars with that JDK (java/build.sh, which also runs the tests), with no network;
#   5. checks both jars, the server (avpx-server.jar) and its smoke test (avpx-smoke.jar), are byte for byte the ones the gates built and
#      tested. What it's given is the SHA-256 of what `sha256sum avpx-server.jar avpx-smoke.jar` prints in the build folder, the same
#      on both sides. The build is the same on any machine (java.yml checks that), so a different value means something differs, and
#      nothing is put in place;
#   6. puts the jars in /opt/avpx/releases/<commit> (and a new JDK in /opt/avpx-jdk-<version>), and moves /opt/avpx/current (and the
#      /opt/avpx-jdk link) to them, each in one step;
#   7. restarts the service, and checks it's healthy (HEALTH below);
#   8. if anything from step 6 on fails, moves both links back, restarts the release before, and fails. With no release before, it
#      stops the service, so a broken server is never left running;
#   9. keeps the newest few releases, and the one before, and removes older ones.
#
# WHO DOES WHAT: steps 2 to 4 handle code fetched from the network, so they run as the user avpx-build, which has no rights and owns
# nothing, through systemd-run, with /etc/avpx (the settings and the pass key) and /etc/letsencrypt (the certificate's key) out of reach,
# and the build with no network at all. Only root's own lines here read what they made, check it, and put it in place. The settings
# and the certificate are never touched: only /opt/avpx and /opt/avpx-jdk* change.
#
# Root reads only three files avpx-build made: get-jdk.sh's pin, and the two jars. Each must be a plain file reached with no link on the
# way, or avpx-build could point root at something it can't read itself, such as the settings (own_file below).
#
# AVPX_DEPLOY_ROOT: only deploy/test-remote-deploy.sh sets it, to a folder that stands in for /, so every step can be tested with no
# machine. On a real machine it's never set.
set -eu

root=${AVPX_DEPLOY_ROOT:-}
releases="$root/opt/avpx/releases"
current="$root/opt/avpx/current"
jdk="$root/opt/avpx-jdk"
service=avpx-java
builder=avpx-build
repo='https://github.com/Melanikus/AVPx-Dedicated-Server.git'
kept_releases=3

say() { echo "deploy: $*"; }
refuse() { say "$*"; exit 1; }

# 1. The two values, checked again here: the SSM document checks them too, but this script trusts nothing it's given
[ "$#" -eq 2 ] || refuse "give exactly the commit and the jars' sha256"
commit=$1
want=$2
case "$commit" in *[!0-9a-f]*) refuse 'the commit must be 40 hex digits, small letters' ;; esac
case "$want" in *[!0-9a-f]*) refuse "the jars' sha256 must be 64 hex digits, small letters" ;; esac
[ "${#commit}" -eq 40 ] || refuse 'the commit must be 40 hex digits, small letters'
[ "${#want}" -eq 64 ] || refuse "the jars' sha256 must be 64 hex digits, small letters"

# The work folder is in /var/lib, which only root can write to, and not in /tmp: avpx-build's steps run with a /tmp of their own
# (PrivateTmp), so they'd never see a folder in the machine's /tmp. It's removed at the end, whatever happens.
work=$(mktemp -d "$root/var/lib/avpx-deploy.XXXXXXXXXX")
trap 'rm -rf "$work"' EXIT
chown "$builder" "$work"
chmod 0700 "$work"

# Runs a command as avpx-build: no rights, the settings and the certificate out of reach, writing only in $work. $1 is "network" or
# "no-network".
#   - /etc/avpx must be there (it holds the settings). /etc/letsencrypt is there only once certbot has run, so its "-" tells systemd to
#     let it be missing (a test machine has no certificate from Let's Encrypt); when it's there, it's out of reach.
#   - HOME is the work folder, and git reads no settings from outside it (GIT_CONFIG_NOSYSTEM, GIT_CONFIG_GLOBAL), so nothing set on the
#     machine changes how the commit is fetched. avpx-build has no home of its own.
as_builder() {
  if [ "$1" = network ]; then private=no; else private=yes; fi
  shift
  systemd-run --quiet --wait --pipe --collect -p User="$builder" -p PrivateNetwork="$private" -p NoNewPrivileges=yes \
    -p ProtectSystem=strict -p ProtectHome=yes -p PrivateTmp=yes -p InaccessiblePaths=/etc/avpx -p InaccessiblePaths=-/etc/letsencrypt \
    -p ReadWritePaths="$work" -p WorkingDirectory="$work" \
    --setenv=HOME="$work" --setenv=GIT_CONFIG_NOSYSTEM=1 --setenv=GIT_CONFIG_GLOBAL=/dev/null -- "$@"
}

# A file avpx-build made, which root is about to read: true only if it's a plain file and no part of its path below $work is a link.
# (Every avpx-build step has ended by then, so nothing can change it between this check and the read.)
own_file() {
  [ -f "$1" ] && [ ! -L "$1" ] && [ "$(readlink -f -- "$1")" = "$(readlink -f -- "$work")/${1#"$work"/}" ]
}

# 2. Exactly that commit, fetched with git, as avpx-build
say "fetching $commit"
as_builder network sh -c 'git init -q src && cd src && git fetch -q --depth 1 "$1" "$2" && git checkout -q FETCH_HEAD && [ "$(git rev-parse HEAD)" = "$2" ]' \
  fetch "$repo" "$commit" || refuse "couldn't fetch exactly $commit"
tree="$work/src"
own_file "$tree/java/tools/get-jdk.sh" || refuse "the commit's java/tools/get-jdk.sh isn't a plain file"

# 3. The JDK the commit pins, and the one this machine has
pinned=$(sed -n "s/^JDK_RELEASE='\([0-9.]*+[0-9]*\)'\$/\1/p" "$tree/java/tools/get-jdk.sh")
[ -n "$pinned" ] || refuse "the commit's java/tools/get-jdk.sh names no JDK_RELEASE this can read"
have=''
if [ -f "$jdk/release" ]; then have=$(sed -n 's/^JAVA_RUNTIME_VERSION="\(.*\)"$/\1/p' "$jdk/release"); fi
new_jdk=''
build_jdk="$jdk"
if [ "$have" != "$pinned" ]; then
  say "this machine's JDK is ${have:-none}, and the commit pins $pinned: fetching that one, checked by its signature, sha256 and version"
  as_builder network sh "$tree/java/tools/get-jdk.sh" "$work/jdk" || refuse "the commit's get-jdk.sh couldn't fetch and check JDK $pinned"
  [ -d "$work/jdk" ] && [ ! -L "$work/jdk" ] || refuse "the commit's get-jdk.sh left no JDK folder"
  new_jdk="$root/opt/avpx-jdk-$pinned"
  build_jdk="$work/jdk"
fi

# 4. The build, as avpx-build, with no network
say 'building, and running the tests'
as_builder no-network env JAVA_HOME="$build_jdk" sh "$tree/java/build.sh" > "$work/build.log" 2>&1 || { tail -n 20 "$work/build.log"; refuse 'the build or its tests failed'; }

# 5. The very jars the gates tested: the SHA-256 of what sha256sum prints for both, in the build folder
jars_sha() { (cd "$1" && sha256sum avpx-server.jar avpx-smoke.jar) | sha256sum | cut -d ' ' -f 1; }
own_file "$tree/java/build/avpx-server.jar" && own_file "$tree/java/build/avpx-smoke.jar" || refuse "the build didn't make both jars as plain files"
got=$(jars_sha "$tree/java/build")
[ "$got" = "$want" ] || refuse "the jars built here ($got) aren't the ones the gates built and tested ($want); nothing was put in place"

# 6. In place, owned by root, and each link moved in one step (a new link, then renamed over the old)
release="$releases/$commit"
if [ -e "$release" ]; then
  [ "$(jars_sha "$release")" = "$want" ] || refuse "$release is there already, with other jars"
else
  mkdir -p "$release"
  cp "$tree/java/build/avpx-server.jar" "$tree/java/build/avpx-smoke.jar" "$release/"
  chmod 0644 "$release/avpx-server.jar" "$release/avpx-smoke.jar"
fi

if [ -n "$new_jdk" ]; then
  [ -L "$jdk" ] || [ ! -e "$jdk" ] || refuse "$jdk must be a link to a JDK's own folder, so it can be moved"
  if [ ! -e "$new_jdk" ]; then
    mv "$work/jdk" "$new_jdk"
    chown -R root:root "$new_jdk"
    chmod -R go-w,u-s,g-s "$new_jdk"
  fi
fi

before=''
if [ -L "$current" ]; then before=$(readlink "$current"); fi
before_jdk=''
if [ -L "$jdk" ]; then before_jdk=$(readlink "$jdk"); fi

switch() {
  ln -sfn "$2" "$1.next"
  mv -fT "$1.next" "$1"
}

# HEALTH: the service runs, and the smoke test passes against it. With --installed (java/tools/Smoke.java), it reads
# /etc/avpx/settings.json, talks to 127.0.0.1 only on the settings' ports, trusts only the certificate the settings name (which must
# cover this machine's relay host name: deploy/README.md), runs its 32 checks, and changes nothing that stays: its one room is closed
# and its one listing (network version 65535, which no game uses) taken down. On a relay-only machine (settings with no list) it runs
# the relay's checks only, and says the list's weren't run. Gives back 0 when healthy.
healthy() {
  systemctl is-active --quiet "$service" || return 1
  "$jdk/bin/java" -jar "$current/avpx-smoke.jar" --installed || return 1
}

switch "$current" "$release"
if [ -n "$new_jdk" ]; then switch "$jdk" "$new_jdk"; fi
say "switched to $commit; restarting"
if systemctl restart "$service" && healthy; then
  say "$commit is in place, and healthy"

  # 9. The newest few releases, the one in place and the one before are kept; older ones go
  ls -1t "$releases" | tail -n +"$((kept_releases + 1))" | while IFS= read -r old; do
    case "$old" in *[!0-9a-f]*|'') continue ;; esac
    [ "$releases/$old" = "$release" ] || [ "$releases/$old" = "$before" ] || rm -rf "${releases:?}/$old"
  done
  exit 0
fi

# 8. Back to the one before, or stopped
if [ -n "$before" ]; then
  say "$commit isn't healthy: going back to $before"
  switch "$current" "$before"
  if [ -n "$new_jdk" ] && [ -n "$before_jdk" ]; then switch "$jdk" "$before_jdk"; fi
  systemctl restart "$service" || true
  if healthy; then say 'the release before is back, and healthy'; else say 'THE RELEASE BEFORE IS BACK, BUT NOT HEALTHY EITHER'; fi
else
  say "$commit isn't healthy, and there's no release before it: the service is stopped, so nothing broken is left running"
  systemctl stop "$service" || true
fi
exit 1
