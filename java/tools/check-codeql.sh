#!/bin/sh
# The "CodeQL (Java)" gate's verdict (java.yml), read from CodeQL's own results file. Written 2026-11-09 by Melanikus for AVPx Dedicated
# Server. These checks were written into java.yml itself until then; they moved here so java/tools/test-check-codeql.sh can hold them to
# failing whenever they must.
#
#   sh java/tools/check-codeql.sh <folder>     <folder> is where github/codeql-action/analyze wrote its results (its `output`). Exits 0
#                                              only if CodeQL found nothing at all and read every Java file git tracks under java/
#
# A gate never passes for want of its tool (the owner's "built to outlive us", 2026-11-09): CodeQL that couldn't be fetched, couldn't
# run, or ran and read nothing, is a failed check, never a passed one. So this fails, saying which, on:
#   1. no results file in <folder>, or more than one;
#   2. a results file jq can't read, or one with no runs of CodeQL in it;
#   3. a run with no list of results, since it can't be told to have found nothing;
#   4. any finding at all, at any severity (GATES.md). Each one is written out: its rule, its file and line, its words, and for a finding
#      about data, where that data came from, so this log alone says what to fix;
#   5. any file CodeQL says it couldn't read: a notification of level "error" that names a file;
#   6. any tracked .java file CodeQL didn't read: a blind spot fails the gate too. There must be some to check, too.
# It goes on after 4, so one run shows the findings and every file that wasn't read.
#
# WHAT COUNTS AS READ (Secondary's review of this script, G-1): only a file CodeQL names in its notification that lists the files it
# extracted, the one whose id is EXTRACTED_ID below. Not a file named in any other notification, since CodeQL writes notifications for
# the files it failed to extract too, and not the list of files its results point to. If CodeQL ever renames that notification, every
# file shows as not read, and this says which notifications it did write: the check fails, never passes, until EXTRACTED_ID is moved.
#
# AVPX_CODEQL_FILES: only java/tools/test-check-codeql.sh sets it, to a file listing the Java files it pretends git tracks. No workflow
# may name it (deploy/test-deploy-workflow.sh checks), and in java.yml the list is git's own.
set -eu

folder=${1:?say the folder CodeQL wrote its results to}
failed=0
EXTRACTED_ID='java/diagnostics/successfully-extracted-files'

# 1. Exactly one results file. A pattern that matches nothing stays as it's written, so [ -f ] tells none from one.
set -- "$folder"/*.sarif
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  if [ -f "$1" ]; then n=$#; else n=no; fi
  echo "codeql: $n results files in $folder, where there must be exactly one: CodeQL didn't run as it should, so this fails rather than passing unread. If CodeQL is unreachable: replace it with an equivalent, see TAKING-OVER.md"
  exit 1
fi
sarif=$1

# 2. Something jq can read, holding at least one run of CodeQL
if ! jq -e '.runs | type == "array" and length > 0' "$sarif" > /dev/null 2>&1; then
  echo "codeql: $sarif isn't a results file with CodeQL's runs in it, so nothing it says can be trusted: this fails"
  exit 1
fi

# 3. Every run's results, counted from the file itself, never from CodeQL's summary. A run without a list of results makes jq fail here.
if ! found=$(jq '[.runs[].results[]] | length' "$sarif" 2> /dev/null); then
  echo "codeql: a run in $sarif has no list of results, so it can't be told to have found nothing: this fails"
  exit 1
fi
echo "CodeQL found $found"

# 4. Nothing found, at any severity
if [ "$found" != 0 ]; then
  jq -r '.runs[].results[]
    | "\(.ruleId)  \(.locations[0].physicalLocation.artifactLocation.uri):\(.locations[0].physicalLocation.region.startLine)  \(.message.text)",
      (.codeFlows[]?.threadFlows[]?.locations[0].location.physicalLocation
        | "    its data comes from \(.artifactLocation.uri):\(.region.startLine)")' "$sarif"
  echo "codeql: $found findings: each one is fixed in the code, never dismissed (CODING-STANDARD.md rule 6)"
  failed=1
fi

# 5. Every file a notification of level "error" names: CodeQL couldn't read it
if ! unreadable=$(jq -r '.runs[].invocations[]?.toolExecutionNotifications[]? | select(.level == "error")
  | .locations[]?.physicalLocation.artifactLocation.uri | strings' "$sarif" 2> /dev/null); then
  echo "codeql: the notifications in $sarif can't be read, so what CodeQL read can't be told: this fails"
  exit 1
fi

while IFS= read -r f; do
  if [ -z "$f" ]; then continue; fi
  echo "codeql: CodeQL couldn't read $f (a notification of level error names it)"
  failed=1
done <<EOF
$unreadable
EOF

# 6. Every tracked Java file read: named in the notification of extracted files, and in no error
if [ -n "${AVPX_CODEQL_FILES:-}" ]; then tracked=$(cat "$AVPX_CODEQL_FILES"); else tracked=$(git ls-files 'java/*.java'); fi
read_files=$(jq -r --arg id "$EXTRACTED_ID" '.runs[].invocations[]?.toolExecutionNotifications[]? | select(.descriptor.id == $id)
  | .locations[]?.physicalLocation.artifactLocation.uri | strings' "$sarif")
count=0
missing=0

while IFS= read -r f; do
  if [ -z "$f" ]; then continue; fi
  count=$((count + 1))
  if printf '%s\n' "$unreadable" | grep -Fxq -e "$f"; then continue; fi
  if printf '%s\n' "$read_files" | grep -Fxq -e "$f"; then :; else echo "codeql: CodeQL didn't read $f"; failed=1; missing=1; fi
done <<EOF
$tracked
EOF

if [ "$missing" -ne 0 ]; then
  echo "codeql: a file counts as read only if CodeQL's notification $EXTRACTED_ID names it. The notifications it wrote: $(jq -r \
    '[.runs[].invocations[]?.toolExecutionNotifications[]?.descriptor.id | strings] | unique | join(", ")' "$sarif")"
fi

echo "$count Java files are tracked"
if [ "$count" -eq 0 ]; then
  echo "codeql: no tracked Java files were found to check, so a scan that read nothing can't be told from one that read everything: this fails"
  failed=1
fi

if [ "$failed" -ne 0 ]; then exit 1; fi
echo "codeql: nothing found, and every one of the $count Java files was read"
