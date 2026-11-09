#!/bin/sh
# The tests of deploy/get-aws-cli.sh, with no network and no AWS. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
#
#   sh deploy/test-get-aws-cli.sh     exits 0 if every case holds, 1 if any doesn't
#
# It needs gpg and zip (GitHub's Ubuntu runner has both).
#
# First the script as it is in the repository: while its pins say "not-pinned-yet", it must refuse before fetching anything. Then
# copies of it, with test pins, against a made-up release: a key made here for the test, a zip holding a stand-in installer, signed with
# that key, and a stand-in curl, first on PATH, that serves those files. So the real gpg checks real signatures, and nothing goes online.
# Each refusal must give its own reason, and leave no folder behind. Then broken copies, each with one check taken out, must each make
# some case fail.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="$here/get-aws-cli.sh"
work=$(mktemp -d)
# gpg's helpers for the test's keys are stopped first, so nothing holds the folder when it goes
trap 'GNUPGHOME="$work/keys" gpgconf --kill all > /dev/null 2>&1 || true; rm -rf "$work"' EXIT
command -v gpg > /dev/null && command -v zip > /dev/null || { echo 'test-get-aws-cli: needs gpg and zip'; exit 1; }

# Two keys made for the test: "aws", the one the copies pin, and "other", one they don't
GNUPGHOME="$work/keys"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'AVPx test, stands in for AWS <aws@example.invalid>' ed25519 sign never
gpg --batch --quiet --pinentry-mode loopback --passphrase '' --quick-gen-key 'AVPx test, some other key <other@example.invalid>' ed25519 sign never
fpr_of() { gpg --batch --with-colons --fingerprint "$1" | awk -F: '$1 == "fpr" { print $10; exit }'; }
AWS=$(fpr_of aws@example.invalid)
OTHER=$(fpr_of other@example.invalid)
gpg --batch --armor --export "$AWS" > "$work/aws.asc"
gpg --batch --armor --export "$OTHER" > "$work/other.asc"
cat "$work/aws.asc" "$work/other.asc" > "$work/both.asc"
unset GNUPGHOME

# A made-up release in $1, whose installer makes an aws that says it is version $2
release() {
  mkdir -p "$1/aws"
  printf '#!/bin/sh\n# the stand-in installer\nwhile [ "$#" -gt 0 ]; do case "$1" in --install-dir) i=$2; shift 2 ;; --bin-dir) b=$2; shift 2 ;; *) shift ;; esac; done\nmkdir -p "$i" "$b"\nprintf "#!/bin/sh\\necho aws-cli/%s Python/3.13 Linux/6 exe/x86_64\\n" > "$b/aws"\nchmod +x "$b/aws"\n' "$2" > "$1/aws/install"
  chmod +x "$1/aws/install"
  (cd "$1" && zip -q -r "$1.zip" aws)
}
release "$work/r999" 9.9.9
release "$work/r998" 9.9.8
sign() { GNUPGHOME="$work/keys" gpg --batch --quiet --yes --pinentry-mode loopback --passphrase '' --local-user "$1" --output "$3" --detach-sign "$2"; }
sha_of() { sha256sum "$1" | cut -d ' ' -f 1; }

# The stand-in curl: serves $FAKE_SERVE/<the name at the end of the address>, notes what was asked
mkdir -p "$work/fake"
printf '#!/bin/sh\nfor a in "$@"; do case "$prev" in --output) out=$a ;; esac; prev=$a; url=$a; done\necho "curl $url" >> "$FAKE_LOG"\ncp "$FAKE_SERVE/${url##*/}" "$out"\n' > "$work/fake/curl"
chmod +x "$work/fake/curl"

# A copy of the script $1 in a folder of its own, $c, with the pins $2 (version), $3 (sha256), $4 (fingerprint), the key file $5 next to
# it, and the stand-in curl first on PATH. Refuses to go on if the PATH line isn't there to change, so a copy can never go online.
copy() {
  c=$(mktemp -d "$work/copy.XXXXXX")
  sed -e "s/^AWS_CLI_VERSION='not-pinned-yet'\$/AWS_CLI_VERSION='$2'/" -e "s/^AWS_CLI_SHA256='not-pinned-yet'\$/AWS_CLI_SHA256='$3'/" \
    -e "s/^AWS_FINGERPRINT='not-pinned-yet'\$/AWS_FINGERPRINT='$4'/" -e "s|^PATH=/usr/bin:/bin\$|PATH=\"$work/fake:/usr/bin:/bin\"|" "$1" > "$c/get-aws-cli.sh"
  grep -q "^PATH=\"$work/fake:" "$c/get-aws-cli.sh" || { echo "test-get-aws-cli: the copy's PATH line wasn't changed; stopping, so nothing goes online"; exit 1; }
  if [ -n "$5" ]; then cp "$5" "$c/aws-cli-key.asc"; fi
}

# Runs the copy in $c, serving the folder $1; gives back 0 or 1, with what it said in $c/out
run() {
  rm -rf "$c/dest"
  : > "$c/log"
  if FAKE_SERVE="$1" FAKE_LOG="$c/log" sh "$c/get-aws-cli.sh" "$c/dest" > "$c/out" 2>&1; then return 0; else return 1; fi
}

# A folder to serve: the zip $1 under the release's own name for version $2, and its signature by the key $3 (or the file $4, if given)
serve() {
  s=$(mktemp -d "$work/serve.XXXXXX")
  cp "$1" "$s/awscli-exe-linux-x86_64-$2.zip"
  if [ -n "${4:-}" ]; then cp "$4" "$s/awscli-exe-linux-x86_64-$2.zip.sig"; else sign "$3" "$1" "$s/awscli-exe-linux-x86_64-$2.zip.sig"; fi
}

all_cases() {
  t=$1
  bad=0
  no() { bad=$((bad + 1)); [ "$quiet" = yes ] || { echo "FAIL  $1"; sed 's/^/    /' "$c/out" "$c/log" 2>/dev/null || true; }; }
  # Refused, with this reason in what it said, and no folder left behind
  refused() { ! run "$1" && grep -q "$2" "$c/out" && [ ! -e "$c/dest" ]; }

  # Not pinned: refused before anything is fetched
  copy "$t" not-pinned-yet not-pinned-yet not-pinned-yet "$work/aws.asc"
  serve "$work/r999.zip" 9.9.9 "$AWS"
  if refused "$s" "isn't pinned yet" && [ ! -s "$c/log" ]; then :; else no 'with its pins not filled in, it refuses before fetching anything'; fi
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$AWS" ''
  if refused "$s" "isn't pinned yet" && [ ! -s "$c/log" ]; then :; else no 'with no key file, it refuses before fetching anything'; fi
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$(printf '%s' "$AWS" | tr A-F a-f)" "$work/aws.asc"
  if refused "$s" "isn't pinned yet"; then :; else no 'a fingerprint not in its shape (small letters) is refused'; fi

  # The good one
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$AWS" "$work/aws.asc"
  serve "$work/r999.zip" 9.9.9 "$AWS"
  if run "$s" && [ "$("$c/dest/bin/aws" --version)" = 'aws-cli/9.9.9 Python/3.13 Linux/6 exe/x86_64' ] \
    && grep -q '^curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64-9.9.9.zip$' "$c/log" \
    && grep -q '^curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64-9.9.9.zip.sig$' "$c/log"; then :; else
    no 'the pinned release, signed by the pinned key, is fetched from AWS, checked, and installed'
  fi
  # ...and only into a folder that isn't there yet
  if ! FAKE_SERVE="$s" FAKE_LOG="$c/log" sh "$c/get-aws-cli.sh" "$c/dest" > "$c/out" 2>&1 && grep -q 'is there already' "$c/out" \
    && [ -x "$c/dest/bin/aws" ]; then :; else no 'a folder that is there already is refused, and left as it was'; fi

  # The zip changed after it was signed (its sha256 pinned as changed, so only the signature can tell)
  cp "$work/r999.zip" "$work/changed.zip" && printf x >> "$work/changed.zip"
  sign "$AWS" "$work/r999.zip" "$work/r999.sig"
  copy "$t" 9.9.9 "$(sha_of "$work/changed.zip")" "$AWS" "$work/aws.asc"
  serve "$work/changed.zip" 9.9.9 "$AWS" "$work/r999.sig"
  refused "$s" "signature isn't a good one" || no 'a zip changed after it was signed is refused'

  # Signed by another key, which the key file doesn't hold
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$AWS" "$work/aws.asc"
  serve "$work/r999.zip" 9.9.9 "$OTHER"
  refused "$s" "signature isn't a good one" || no 'a signature by another key is refused'

  # A key file holding another key besides the pinned one, signed by that other key
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$AWS" "$work/both.asc"
  serve "$work/r999.zip" 9.9.9 "$OTHER"
  refused "$s" "isn't only AWS's pinned key" || no 'a key file holding more than the pinned key is refused'

  # A key file holding only another key, and signed by it
  copy "$t" 9.9.9 "$(sha_of "$work/r999.zip")" "$AWS" "$work/other.asc"
  serve "$work/r999.zip" 9.9.9 "$OTHER"
  refused "$s" "isn't only AWS's pinned key" || no 'a key file holding a key other than the pinned one is refused'

  # Signed well, but not the pinned sha256
  copy "$t" 9.9.9 "$(sha_of "$work/r998.zip")" "$AWS" "$work/aws.asc"
  serve "$work/r999.zip" 9.9.9 "$AWS"
  refused "$s" "sha256 isn't the pinned one" || no 'a release that is not the pinned sha256 is refused'

  # Signed well, the pinned sha256, but it says it's another version
  copy "$t" 9.9.9 "$(sha_of "$work/r998.zip")" "$AWS" "$work/aws.asc"
  serve "$work/r998.zip" 9.9.9 "$AWS"
  refused "$s" "says it is aws-cli/9.9.8" || no 'an aws that says it is another version is refused, and not left behind'

  return "$bad"
}

failed=0
quiet=no
if all_cases "$script"; then echo 'get-aws-cli.sh: every case holds'; else echo "$? cases of get-aws-cli.sh don't hold"; failed=1; fi

# The script as it is in the repository: until card #17's pins are filled in, it must refuse, before fetching anything
if grep -q "^AWS_CLI_VERSION='not-pinned-yet'\$" "$script"; then
  if ! sh "$script" "$work/as-is" > "$work/as-is.out" 2>&1 && grep -q "isn't pinned yet" "$work/as-is.out" && [ ! -e "$work/as-is" ]; then
    echo 'get-aws-cli.sh, as it is: not pinned yet, so it refuses (card #17)'
  else
    echo 'FAIL  get-aws-cli.sh, as it is, refuses while not pinned'; failed=1
  fi
fi

quiet=yes
for edit in \
  's/^\[ "\$keys" = "\$AWS_FINGERPRINT" \] ||/true ||/' \
  's/^if ! printf .%s.n. "\$status" | grep -q .*$/if false; then/' \
  's/sha256sum --check --strict --quiet > \/dev\/null 2>&1 ||/true ||/' \
  's/^  "aws-cli\/\$AWS_CLI_VERSION "\*) ;;$/  *) ;;/' \
  's/^  || ! printf .%s. "\$AWS_FINGERPRINT".*$/  ; then/' \
  's/ || rm -rf "\$dest"/ || true/'; do
  sed "$edit" "$script" > "$work/broken.sh"
  if cmp -s "$work/broken.sh" "$script"; then echo "TAKE-OUT CAN'T RUN, its text isn't in get-aws-cli.sh: $edit"; failed=1; continue; fi
  if all_cases "$work/broken.sh"; then echo "TAKE-OUT NOT NOTICED: $edit"; failed=1; else echo "take-out noticed ($? cases): $edit"; fi
done

exit "$failed"
