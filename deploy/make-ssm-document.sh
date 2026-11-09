#!/bin/sh
# Writes deploy/avpx-deploy.ssm.json, the SSM document "avpx-deploy", from deploy/remote-deploy.sh. Written 2026-11-09 by Melanikus for
# AVPx Dedicated Server.
#
#   sh deploy/make-ssm-document.sh            writes the document
#   sh deploy/make-ssm-document.sh --check    exits 1 if the document in the repository isn't what this would write
#
# WHY A DOCUMENT MADE FROM THE SCRIPT: the script is what's tested (deploy/test-remote-deploy.sh), and the document is what AWS runs.
# Making one from the other means they can't drift: the "Deploy scripts" check runs --check on every change.
#
# The document takes two values, and AWS itself refuses any other shape before anything runs (allowedPattern):
#   commit      40 hex digits, small letters
#   jarSha256   64 hex digits, small letters
# It writes the script to a file of its own, runs it with those two values, and removes it. The owner registers the document once, by
# hand, from this file (deploy/README.md); the GitHub role may only run it, never change it.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/remote-deploy.sh"
document="$here/avpx-deploy.ssm.json"
marker=AVPX_DEPLOY_SCRIPT

# One JSON string from one line: \ and " written as JSON writes them. The script has no tabs or other control characters
# (CODING-STANDARD.md rule 1 keeps every file to printable ASCII and plain line ends).
json_line() { printf '        "%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }

make() {
  cat <<'HEAD'
{
  "schemaVersion": "2.2",
  "description": "AVPx Dedicated Server: puts one commit of the Java server on this machine, only if its jar is the one the gates tested (deploy/remote-deploy.sh). Made by deploy/make-ssm-document.sh; never edit by hand.",
  "parameters": {
    "commit": {
      "type": "String",
      "description": "The commit to put in place: 40 hex digits, small letters.",
      "allowedPattern": "^[0-9a-f]{40}$"
    },
    "jarSha256": {
      "type": "String",
      "description": "The SHA-256 of the jar the gates built and tested for that commit: 64 hex digits, small letters.",
      "allowedPattern": "^[0-9a-f]{64}$"
    }
  },
  "mainSteps": [
    {
      "action": "aws:runShellScript",
      "name": "deploy",
      "inputs": {
        "timeoutSeconds": "1800",
        "runCommand": [
HEAD
  json_line 'set -eu'; echo ','
  json_line 'script=$(mktemp)'; echo ','
  json_line "cat > \"\$script\" <<'$marker'"; echo ','
  while IFS= read -r line || [ -n "$line" ]; do
    json_line "$line"; echo ','
  done < "$script"
  json_line "$marker"; echo ','
  json_line 'status=0'; echo ','
  json_line "sh \"\$script\" '{{ commit }}' '{{ jarSha256 }}' || status=\$?"; echo ','
  json_line 'rm -f "$script"'; echo ','
  json_line 'exit "$status"'; echo
  cat <<'TAIL'
        ]
      }
    }
  ]
}
TAIL
}

if grep -q "^$marker\$" "$script"; then
  echo "make-ssm-document: remote-deploy.sh holds the line $marker, which would end the script early inside the document"
  exit 1
fi

if [ "${1:-}" = --check ]; then
  if make | cmp -s - "$document"; then
    echo 'avpx-deploy.ssm.json is what remote-deploy.sh makes'
    exit 0
  fi
  echo 'avpx-deploy.ssm.json is NOT what remote-deploy.sh makes: run sh deploy/make-ssm-document.sh, and commit both'
  exit 1
fi

make > "$document"
echo "wrote $document"
