#!/bin/sh
# The tests of .github/workflows/deploy.yml's shape, with no GitHub. Written 2026-11-09 by Melanikus for AVPx Dedicated Server; for the
# pull route the same night (the record job in place of the AWS one).
#
#   sh deploy/test-deploy-workflow.sh     exits 0 if every rule holds, 1 if any doesn't
#
# A deploy workflow that lost one of these would put the server out with less checking than it promises, and nothing else would notice:
#   1. it starts only by hand (workflow_dispatch), never on a push, a pull request or a timer;
#   2. a dry run is what it does unless told otherwise;
#   3. its first job runs the blockers check, in the form that refuses (no --list), and every later job needs the one before;
#   4. only the record job may write anything, and only deployments (deployments: write, once in the file), and that job waits for the
#      owner's approval of "production". No job may ask for an identity token (id-token: write): nothing here goes to any cloud;
#   5. no action but checkout, and no secret;
#   6. every other workflow is in REQUIRED, by its file, so a commit must have passed it, and a workflow added later can't be forgotten;
#      and the deploy's own jobs are named "Deploy: ...", so none can stand in for a required one;
#   7. the tools: gh and aws never; curl and jq only by their full path in /usr/bin, in a job that first checks they're Ubuntu's own
#      (deploy/check-ubuntu-tools.sh);
#   8. the run's name is "Deploy <commit> to <machine>", with " (dry run)" after it for a dry run: the machine requires that name for
#      the deployment's own commit and machine (deploy/pull-deploy.sh), so an approval counts only for what it was given for;
#   9. it runs from main only: the blockers job's first step refuses a run started from any other branch, so the list it reads is main's;
#  10. no other workflow can write deployments: each workflow sets its own permissions at the top, none asks for write-all, and only
#      deploy.yml has deployments: write. So only its record job can make a deployment, whatever the repository's default token allows
#      (Secondary's review of the pull route, P-1);
#  11. no workflow names a test's own hook: AVPX_DEPLOY_ROOT, AVPX_UFW and AVPX_CODEQL_FILES each swap a real tool or list for a test's
#      stand-in, and AVPX_IN_TAKEOUT makes this test skip its take-outs. Each is for a test's own use only (Secondary's review of the
#      gates failing closed, G-3).
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
job_of record | grep -q 'needs: build$' || no 'record needs build'

# 4. Writing deployments in the record job only, behind "production"; no identity token anywhere
code_lines=$(grep -v '^[[:space:]]*#' "$file")
[ "$(printf '%s\n' "$code_lines" | grep -c 'deployments: write')" -eq 1 ] || no 'deployments: write is in the file exactly once, comments aside'
job_of record | grep -q 'deployments: write' || no 'and it is in the record job'
job_of record | grep -q 'environment: production$' || no 'the record job waits for the production environment'
if printf '%s\n' "$code_lines" | grep -q 'id-token:'; then no 'no job asks for an identity token'; fi
if printf '%s\n' "$code_lines" | grep -Eq '^ +(contents|actions|packages|pull-requests|issues|statuses|checks|pages|security-events): write'; then
  no 'nothing but deployments is ever written'
fi
grep -q '^  contents: read$' "$file" || no 'the workflow as a whole may only read'

# 5. No action but checkout, and no secret
if grep -E '^\s*-?\s*uses:' "$file" | grep -v 'uses: actions/checkout@' | grep -q .; then no 'no action but actions/checkout'; fi
if grep -q 'secrets\.' "$file"; then no 'no secret is read'; fi

# 6. Every other workflow is required, by its file; and the deploy's own jobs are all named "Deploy: ...", so none can stand in for one
required=$(grep -E "^  REQUIRED: '" "$file" | sed "s/^  REQUIRED: '//; s/'$//")
[ -n "$required" ] || no 'REQUIRED is there'
for other in "$flows"/*.yml; do
  [ "$other" = "$file" ] && continue
  # A workflow started by hand only (such as test-build.yml) never runs on a push, so it can't be required
  if ! awk '/^on:/{f=1; next} /^[a-z]/{f=0} f' "$other" | grep -Eq '^  (push|pull_request|schedule):'; then continue; fi
  case " $required " in *" $(basename "$other") "*) ;; *) no "the workflow $(basename "$other") is in REQUIRED" ;; esac
done
if grep -E '^    name: ' "$file" | grep -v "^    name: 'Deploy: " | grep -q .; then no 'every job of deploy.yml is named "Deploy: ..."'; fi

# 7. The tools. What runs is every line but comments and the steps' names (a name such as "curl and jq are Ubuntu's own" runs nothing).
code=$(grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*- name:' -e '^[[:space:]]*name:' "$file")
by_name() { printf '%s\n' "$code" | grep -Eq "(^|[[:space:];|&(])$1[[:space:]]"; }
if by_name gh; then no 'gh is not used'; fi
if by_name aws; then no 'aws is not used: nothing here goes to any cloud'; fi
if by_name curl || by_name jq; then no 'curl and jq are used only by their full path, /usr/bin/curl and /usr/bin/jq'; fi
# The line number in the job $1 of the first line matching $2 (a fixed text), or nothing
first() { job_of "$1" | grep -n -F -- "$2" | head -n 1 | cut -d: -f1; }
for job in blockers gates build record; do
  use=$(first "$job" '/usr/bin/curl'); jq_use=$(first "$job" '/usr/bin/jq')
  if [ -z "$use" ] || { [ -n "$jq_use" ] && [ "$jq_use" -lt "$use" ]; }; then use=$jq_use; fi
  check=$(first "$job" 'run: sh deploy/check-ubuntu-tools.sh')
  if [ -n "$use" ] && { [ -z "$check" ] || [ "$check" -gt "$use" ]; }; then no "the $job job checks curl and jq are Ubuntu's own before it uses them"; fi
done

# 8. The run's name, exactly
grep -qxF "run-name: Deploy \${{ inputs.commit }} to \${{ inputs.machine }}\${{ inputs.dry_run && ' (dry run)' || '' }}" "$file" \
  || no 'the run is named "Deploy <commit> to <machine>", with " (dry run)" after it for a dry run'

# 9. From main only: the blockers job's first step is the one that refuses any other branch
job_of blockers | grep -m 1 -- '^      - ' | grep -qx '      - name: Started from main' || no 'the blockers job starts by checking it was started from main'
job_of blockers | grep -qxF '          [ "$GITHUB_REF" = refs/heads/main ] || { echo "deploy.yml runs from main only, and this run was started from $GITHUB_REF"; exit 1; }' \
  || no 'and that step refuses a run started from any branch but main'

# 10. Only deploy.yml can write deployments
for f in "$flows"/*.yml; do
  name=$(basename "$f")
  grep -q '^permissions:' "$f" || no "$name sets its own permissions at the top"
  if grep -v '^[[:space:]]*#' "$f" | grep -q 'write-all'; then no "$name never asks for write-all"; fi
  [ "$f" = "$file" ] && continue
  if grep -v '^[[:space:]]*#' "$f" | grep -q 'deployments: write'; then no "$name can't write deployments: only deploy.yml's record job can"; fi
done

# 11. No test's hook in any workflow, comments aside
for f in "$flows"/*.yml; do
  if grep -v '^[[:space:]]*#' "$f" | grep -Eq 'AVPX_(DEPLOY_ROOT|UFW|CODEQL_FILES|IN_TAKEOUT)'; then
    no "$(basename "$f") names none of the tests' own hooks (AVPX_DEPLOY_ROOT, AVPX_UFW, AVPX_CODEQL_FILES, AVPX_IN_TAKEOUT)"
  fi
done

if [ "$bad" -ne 0 ]; then
  echo "$bad rules of deploy.yml don't hold"
  exit 1
fi
echo 'deploy.yml: every rule holds'

# The take-outs: broken copies of deploy.yml, each with one rule taken out, must each be caught. Each runs this test again, in a folder
# of its own holding the copy; AVPX_IN_TAKEOUT tells that run not to start take-outs of its own.
[ "${AVPX_IN_TAKEOUT:-}" = yes ] && exit 0
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/deploy" "$t/.github/workflows"
cp "$here/test-deploy-workflow.sh" "$t/deploy/test-deploy-workflow.sh"
cp "$flows"/*.yml "$t/.github/workflows/"
failed=0
for edit in \
  's|/usr/bin/jq -r .status|jq -r .status|' \
  's|^\(            \)/usr/bin/curl -q|\1curl -q|' \
  's|ask "compare/\$COMMIT...main" > compare.json|gh api "repos/$GITHUB_REPOSITORY/compare/$COMMIT...main" > compare.json|' \
  's|^        run: sh deploy/check-ubuntu-tools.sh$|        run: true|' \
  's|^    environment: production$|    environment: staging|' \
  's|^    timeout-minutes: 20$|    timeout-minutes: 20\n    permissions:\n      deployments: write|' \
  's|^      deployments: write$|      deployments: write\n      id-token: write|' \
  's|^    needs: build$|    needs: gates|' \
  's|^run-name: .*$|run-name: Deploy|' \
  's#^          \[ "\$GITHUB_REF" = refs/heads/main \] || #          true || #' \
  's|^permissions:$|# permissions:|'; do
  sed "$edit" "$file" > "$t/.github/workflows/deploy.yml"
  if cmp -s "$t/.github/workflows/deploy.yml" "$file"; then echo "TAKE-OUT CAN'T RUN, its text isn't in deploy.yml: $edit"; failed=1; continue; fi
  if AVPX_IN_TAKEOUT=yes sh "$t/deploy/test-deploy-workflow.sh" > "$t/out" 2>&1; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed: $edit"; fi
done

# And another workflow broken the same way: test-build.yml given the right to write deployments, left with no permissions of its own,
# or setting a test's hook
cp "$file" "$t/.github/workflows/deploy.yml"
other="$flows/test-build.yml"
for edit in \
  's|^  contents: read$|  contents: read\n  deployments: write|' \
  's|^permissions:$|# permissions:|' \
  's|^  contents: read$|  contents: write-all|' \
  's|^permissions:$|env:\n  AVPX_CODEQL_FILES: /dev/null\npermissions:|'; do
  sed "$edit" "$other" > "$t/.github/workflows/test-build.yml"
  if cmp -s "$t/.github/workflows/test-build.yml" "$other"; then echo "TAKE-OUT CAN'T RUN, its text isn't in test-build.yml: $edit"; failed=1; continue; fi
  if AVPX_IN_TAKEOUT=yes sh "$t/deploy/test-deploy-workflow.sh" > "$t/out" 2>&1; then echo "TAKE-OUT NOT NOTICED (test-build.yml): $edit"; failed=1; else echo "take-out noticed (test-build.yml): $edit"; fi
done
exit "$failed"
