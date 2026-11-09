#!/bin/sh
# The tests of .github/workflows/deploy.yml's shape, with no GitHub and no AWS. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-deploy-workflow.sh     exits 0 if every rule holds, 1 if any doesn't
#
# A deploy workflow that lost one of these would put the server out with less checking than it promises, and nothing else would notice:
#   1. it starts only by hand (workflow_dispatch), never on a push, a pull request or a timer;
#   2. a dry run is what it does unless told otherwise;
#   3. its first job runs the blockers check, in the form that refuses (no --list), and every later job needs the one before;
#   4. only the deploy job may ask for an identity token (id-token: write, once in the file), and that job waits for "production";
#   5. no action but checkout, and no secret: the role, machine and region come from variables;
#   6. every other workflow is in REQUIRED, by its file, so a commit must have passed it, and a workflow added later can't be forgotten;
#      and the deploy's own jobs are named "Deploy: ...", so none can stand in for a required one.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
flows="$here/../.github/workflows"
file="$flows/deploy.yml"
bad=0
no() { echo "FAIL  $1"; bad=$((bad + 1)); }

# 1. By hand only
on_block=$(awk '/^on:/{f=1; next} /^[a-z]/{f=0} f' "$file")
printf '%s\n' "$on_block" | grep -q '^  workflow_dispatch:' || no 'it starts by hand (workflow_dispatch)'
if printf '%s\n' "$on_block" | grep -Eq '^  (push|pull_request|pull_request_target|schedule|workflow_run|repository_dispatch):'; then no 'it starts on nothing but workflow_dispatch'; fi

# 2. A dry run unless told otherwise
awk '/^      dry_run:/{f=1} f && /default:/{print; exit}' "$file" | grep -q 'default: true' || no 'dry_run defaults to true'

# 3. The blockers first, and each job needing the one before
job_of() { awk -v job="$1" '$0 ~ "^  " job ":$" {f=1; next} /^  [a-z][a-z-]*:$/{f=0} f' "$file"; }
job_of blockers | grep -q 'run: sh deploy/check-blockers.sh$' || no 'the blockers job runs sh deploy/check-blockers.sh, the refusing form'
if job_of blockers | grep -q 'needs:'; then no 'the blockers job is the first, needing nothing'; fi
job_of gates | grep -q 'needs: blockers$' || no 'gates needs blockers'
job_of build | grep -q 'needs: gates$' || no 'build needs gates'
job_of deploy | grep -q 'needs: build$' || no 'deploy needs build'

# 4. The identity token in the deploy job only, behind "production"
[ "$(grep -v '^[[:space:]]*#' "$file" | grep -c 'id-token: write')" -eq 1 ] || no 'id-token: write is in the file exactly once, comments aside'
job_of deploy | grep -q 'id-token: write' || no 'and it is in the deploy job'
job_of deploy | grep -q 'environment: production$' || no 'the deploy job waits for the production environment'
grep -q '^  contents: read$' "$file" || no 'the workflow as a whole may only read'

# 5. No action but checkout, and no secret
if grep -E '^\s*-?\s*uses:' "$file" | grep -v 'uses: actions/checkout@' | grep -q .; then no 'no action but actions/checkout'; fi
if grep -q 'secrets\.' "$file"; then no 'no secret is read'; fi

# 6. Every other workflow is required, by its file; and the deploy's own jobs are all named "Deploy: ...", so none can stand in for one
required=$(grep -E "^  REQUIRED: '" "$file" | sed "s/^  REQUIRED: '//; s/'$//")
[ -n "$required" ] || no 'REQUIRED is there'
for other in "$flows"/*.yml; do
  [ "$other" = "$file" ] && continue
  case " $required " in *" $(basename "$other") "*) ;; *) no "the workflow $(basename "$other") is in REQUIRED" ;; esac
done
if grep -E '^    name: ' "$file" | grep -v "^    name: 'Deploy: " | grep -q .; then no 'every job of deploy.yml is named "Deploy: ..."'; fi

if [ "$bad" -ne 0 ]; then
  echo "$bad rules of deploy.yml don't hold"
  exit 1
fi
echo 'deploy.yml: every rule holds'
