#!/bin/sh
# Fetches the AWS command line tool (version 2) that the deploy workflow sends a deploy with, and checks it is exactly the pinned one
# before anything in it runs. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/get-aws-cli.sh <folder>      <folder>/bin/aws, or the script fails and nothing is there
#
# WHY NOT THE RUNNER'S OWN: GitHub's runner comes with an aws, but which version it is, and where it came from, changes whenever GitHub
# updates the runner. The deploy job is the one place where a swapped tool could do real harm, because it holds the role that runs
# commands on the machine. So the deploy uses only this one, and only once all three of these hold (the same three java/tools/get-jdk.sh
# checks for the JDK):
#   1. its signature is good, made by AWS's key, the one whose fingerprint is pinned below. The key is in deploy/aws-cli-key.asc, copied
#      from AWS's own page, but it's trusted only if it is the key with that fingerprint, so the check rests on the fingerprint written
#      here, not on the file;
#   2. its sha256 is the one pinned below;
#   3. it says it is the version pinned below.
# Only then is it unpacked, and its own installer run.
#
# NOT PINNED YET (card #17): the three lines below say "not-pinned-yet", and deploy/aws-cli-key.asc isn't there, until they're looked
# up: the version and its sha256 from the release, and the key and its fingerprint from AWS's page "Verify the integrity and
# authenticity of the AWS CLI installer files". Until then this refuses, so the deploy can't send anything. A new version changes the
# version and sha256 lines together, in one commit, looked up the same way. If AWS's key expires (gpg then says EXPKEYSIG, not GOODSIG),
# this refuses too, until aws-cli-key.asc is copied again from that page.
set -eu

AWS_CLI_VERSION='not-pinned-yet'
AWS_CLI_SHA256='not-pinned-yet'
AWS_FINGERPRINT='not-pinned-yet'

# Only Ubuntu's own folders, so curl, gpg, unzip, sha256sum and the rest are Ubuntu's (deploy/check-ubuntu-tools.sh checks those), and
# nothing the runner put earlier on PATH can stand in for one
PATH=/usr/bin:/bin
export PATH

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
key_file="$here/aws-cli-key.asc"
dest="${1:?say where the AWS CLI goes}"

say() { echo "get-aws-cli: $*" >&2; }

# The pins must be there, each in its shape, before anything is fetched
if ! printf '%s' "$AWS_CLI_VERSION" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || ! printf '%s' "$AWS_CLI_SHA256" | grep -Eqx '[0-9a-f]{64}' \
  || ! printf '%s' "$AWS_FINGERPRINT" | grep -Eqx '[0-9A-F]{40}' || [ ! -f "$key_file" ]; then
  say "the AWS CLI isn't pinned yet (card #17): its version, its sha256, AWS's key fingerprint, and deploy/aws-cli-key.asc"
  exit 1
fi
url="https://awscli.amazonaws.com/awscli-exe-linux-x86_64-$AWS_CLI_VERSION.zip"

if [ -e "$dest" ]; then
  say "$dest is there already; this only fills a folder that isn't"
  exit 1
fi

# The work folder goes at the end, whatever happens; so does $dest, unless everything held (it wasn't there before: checked above)
work=$(mktemp -d)
done_well=no
trap 'rm -rf "$work"; [ "$done_well" = yes ] || rm -rf "$dest"' EXIT

# HTTPS only, TLS 1.2 or newer, and fail on any HTTP error rather than keep an error page. -q must come first: it keeps curl from
# reading ~/.curlrc.
fetch() {
  curl -q --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$2" "$1"
}

fetch "$url" "$work/awscli.zip"
fetch "$url.sig" "$work/awscli.zip.sig"

# 1. The signature. gpg gets a keyring of its own, in the work folder, holding only the key file, and the key it holds must be exactly
# the pinned one.
GNUPGHOME="$work/gnupg"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "$key_file"

# Every main key in that keyring (a "pub" record, and the "fpr" record after it): there must be one, and it must be the pinned one
keys=$(gpg --batch --with-colons --fingerprint | awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }')
[ "$keys" = "$AWS_FINGERPRINT" ] || { say "deploy/aws-cli-key.asc isn't only AWS's pinned key ($AWS_FINGERPRINT); it holds: $keys"; exit 1; }

# gpg says GOODSIG for a good signature, and VALIDSIG with the main key's fingerprint last: both must be there, with the pinned key
status=$(gpg --batch --status-fd 1 --verify "$work/awscli.zip.sig" "$work/awscli.zip" 2>/dev/null || true)
signer=$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $NF }')
if ! printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG ' || [ "$signer" != "$AWS_FINGERPRINT" ]; then
  say "the AWS CLI's signature isn't a good one by AWS's pinned key"
  exit 1
fi

# 2. The sha256
echo "$AWS_CLI_SHA256  $work/awscli.zip" | sha256sum --check --strict --quiet > /dev/null 2>&1 || { say "the AWS CLI's sha256 isn't the pinned one"; exit 1; }

# Only now is it unpacked, and its own installer run, into $dest
unzip -q "$work/awscli.zip" -d "$work/unpacked"
"$work/unpacked/aws/install" --install-dir "$dest/aws-cli" --bin-dir "$dest/bin" > "$work/install.log" 2>&1 \
  || { cat "$work/install.log" >&2; say "the AWS CLI's installer failed"; exit 1; }

# 3. The version it says it is: "aws-cli/<version> Python/..."
said=$("$dest/bin/aws" --version 2>&1 | head -n 1)
case "$said" in
  "aws-cli/$AWS_CLI_VERSION "*) ;;
  *) say "the AWS CLI says it is $said, not $AWS_CLI_VERSION"; exit 1 ;;
esac

done_well=yes
echo "get-aws-cli: AWS CLI $AWS_CLI_VERSION, signed by AWS's pinned key, sha256 as pinned, in $dest"
