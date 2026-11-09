#!/bin/sh
# Puts one commit of the server on this machine, or leaves the one already there. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server.
#
#   sh remote-deploy.sh <commit> <jar sha256>
#
# Run as root by the SSM document avpx-deploy (deploy/avpx-deploy.ssm.json, made from this file by deploy/make-ssm-document.sh), which
# GitHub's deploy workflow asks AWS to run once the user has approved it. Nobody logs in to do this.
#
# WHAT IT DOES, in order, stopping at the first thing that fails:
#   1. checks its two values again: the commit is 40 hex digits, the jar's sha256 64;
#   2. fetches the source of exactly that commit from GitHub, over HTTPS, and unpacks it;
#   3. builds the jar there with the pinned JDK (java/build.sh, which also runs the tests);
#   4. checks the jar is byte for byte the one the gates built and tested: its sha256 must be the one it was given. The build is the same
#      every time (java.yml checks that), so a different sha256 means something differs, and nothing is put in place;
#   5. puts it in /opt/avpx/releases/<commit>, and moves the /opt/avpx/current link to it in one step;
#   6. restarts the service, and checks it's healthy (section HEALTH below);
#   7. if anything from step 5 on fails, moves the link back to the release before, restarts that, and fails.
# The settings (/etc/avpx/settings.json) and the certificate are never touched: only /opt/avpx changes.
#
# AVPX_DEPLOY_ROOT: only deploy/test-remote-deploy.sh sets it, to a folder that stands in for /, so every step can be tested with no
# machine. On a real machine it's never set.
set -eu

root=${AVPX_DEPLOY_ROOT:-}
releases="$root/opt/avpx/releases"
current="$root/opt/avpx/current"
jdk="$root/opt/avpx-jdk"
service=avpx-java
source_url='https://codeload.github.com/Melanikus/AVPx-Dedicated-Server/tar.gz'

say() { echo "deploy: $*"; }
refuse() { say "$*"; exit 1; }

# 1. The two values, checked again here: the SSM document checks them too, but this script trusts nothing it's given
[ "$#" -eq 2 ] || refuse "give exactly the commit and the jar's sha256"
commit=$1
want=$2
case "$commit" in *[!0-9a-f]*) refuse 'the commit must be 40 hex digits, small letters' ;; esac
case "$want" in *[!0-9a-f]*) refuse "the jar's sha256 must be 64 hex digits, small letters" ;; esac
[ "${#commit}" -eq 40 ] || refuse 'the commit must be 40 hex digits, small letters'
[ "${#want}" -eq 64 ] || refuse "the jar's sha256 must be 64 hex digits, small letters"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 2. The source of exactly that commit
say "fetching the source of $commit"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$work/source.tar.gz" "$source_url/$commit"
tar -xzf "$work/source.tar.gz" -C "$work"
tree="$work/AVPx-Dedicated-Server-$commit"
[ -d "$tree" ] || refuse "the source didn't unpack into a folder named for $commit"

# 3. The build, with the pinned JDK
say 'building, and running the tests'
JAVA_HOME="$jdk" sh "$tree/java/build.sh" > "$work/build.log" 2>&1 || { tail -n 20 "$work/build.log"; refuse 'the build or its tests failed'; }

# 4. The very jar the gates tested
got=$(sha256sum "$tree/java/build/avpx-server.jar" | cut -d ' ' -f 1)
[ "$got" = "$want" ] || refuse "the jar built here ($got) isn't the one the gates built and tested ($want); nothing was put in place"

# 5. In place, and the link moved in one step (a new link, then renamed over the old)
before=''
if [ -L "$current" ]; then before=$(readlink "$current"); fi
release="$releases/$commit"
if [ -e "$release" ]; then
  [ "$(sha256sum "$release/avpx-server.jar" | cut -d ' ' -f 1)" = "$want" ] || refuse "$release is there already, with another jar"
else
  mkdir -p "$release"
  cp "$tree/java/build/avpx-server.jar" "$release/avpx-server.jar"
  chmod 0644 "$release/avpx-server.jar"
fi

switch_to() {
  ln -sfn "$1" "$current.next"
  mv -fT "$current.next" "$current"
}

# HEALTH: the service runs, and Primary's Java smoke client passes against it (its exact command: see deploy/README.md, "The health
# check"). Gives back 0 when healthy.
healthy() {
  systemctl is-active --quiet "$service" || return 1
  "$jdk/bin/java" -cp "$current/avpx-server.jar" avpx.tools.Smoke --installed || return 1
}

switch_to "$release"
say "switched to $commit; restarting"
if systemctl restart "$service" && healthy; then
  say "$commit is in place, and healthy"
  exit 0
fi

# 7. Back to the one before
if [ -n "$before" ]; then
  say "$commit isn't healthy: going back to $before"
  switch_to "$before"
  systemctl restart "$service" || true
  healthy && say 'the release before is back, and healthy' || say 'THE RELEASE BEFORE IS BACK, BUT NOT HEALTHY EITHER'
else
  say "$commit isn't healthy, and there's no release before it to go back to"
fi
exit 1
