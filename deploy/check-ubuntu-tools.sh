#!/bin/sh
# Checks the tools the deploy workflow takes from GitHub's runner are Ubuntu's own, as Ubuntu shipped them. Written 2026-11-09 by
# Melanikus for AVPx Dedicated Server.
#
#   sh deploy/check-ubuntu-tools.sh     exits 0 if every tool below is Ubuntu's and unchanged, 1 if any isn't
#
# The deploy workflow uses five commands from the runner, always by their full path in /usr/bin, never by name (so nothing put earlier
# on PATH can stand in for one): curl, jq, gpg, unzip and sha256sum. Each must be:
#   1. a file that the Ubuntu package named below installed (dpkg says which package a file came from);
#   2. unchanged since that package put it there, and so must the package's other files and those of the library it runs on
#      (dpkg --verify compares each file with the checksum the package came with, and says nothing if all match).
#
# WHAT THIS CAN'T DO: it trusts GitHub's runner itself, as every step on it must, since a runner that lies can lie to any check. What it
# rules out is a tool that isn't Ubuntu's, such as one a runner update installed from somewhere else, or one changed after it was
# installed.
set -eu

# Only Ubuntu's own folders, so dpkg and sed here are Ubuntu's too, whatever the runner put earlier on PATH
PATH=/usr/bin:/bin
export PATH

# Each tool and the package it must come from
TOOLS='curl:curl jq:jq gpg:gpg unzip:unzip sha256sum:coreutils'
# The packages dpkg --verify checks: the tools' own, and the libraries curl and jq run on
PACKAGES='curl libcurl4t64 jq libjq1 libonig5 gpg unzip coreutils'

bad=0
for pair in $TOOLS; do
  tool=${pair%%:*}
  package=${pair#*:}
  # dpkg -S answers "package: /usr/bin/tool" (or "package:amd64: ..."), or fails if no package installed that file
  owner=$(dpkg -S "/usr/bin/$tool" 2>/dev/null | sed -n '1s/^\([^:]*\).*/\1/p') || owner=''
  if [ "$owner" = "$package" ]; then
    echo "ubuntu-tools: /usr/bin/$tool is from Ubuntu's $package $(dpkg-query -W -f='${Version}' "$package")"
  else
    echo "ubuntu-tools: /usr/bin/$tool isn't from Ubuntu's $package package (dpkg says: ${owner:-no package})"
    bad=1
  fi
done

# $PACKAGES is left unquoted on purpose, so each name is one argument. A package that isn't installed makes dpkg say so, which counts
# as a change too.
changed=$(dpkg --verify $PACKAGES 2>&1) || true
if [ -n "$changed" ]; then
  echo "ubuntu-tools: files of these packages aren't as Ubuntu shipped them:"
  printf '%s\n' "$changed" | sed 's/^/  /'
  bad=1
fi

if [ "$bad" -ne 0 ]; then exit 1; fi
echo "ubuntu-tools: every tool is Ubuntu's own, unchanged"
