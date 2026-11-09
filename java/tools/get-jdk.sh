#!/bin/sh
# Fetches the one JDK the server is built, tested and run with, and checks it is exactly that one before anything in it runs. Written
# 2026-11-08 by Melanikus for AVPx Dedicated Server.
#
#   sh java/tools/get-jdk.sh <folder>      the JDK ends up in <folder> (bin/java, bin/javac, ...), or the script fails and nothing is there
#
# Downloaded code is untrusted until it's checked (AVP Tao 1). So the JDK is used only once all three of these hold:
#   1. its signature is good, made by Adoptium's own key, the one whose fingerprint is pinned below: the key is fetched, but it's trusted
#      only if it is that key, so the check rests on the fingerprint written here, not on whoever served the key;
#   2. its sha256 is the one pinned below;
#   3. it says it is the version pinned below.
#
# The version, its address, its sha256 and Adoptium's fingerprint were looked up on 2026-11-08 from two places that agreed: the
# release's own .sha256.txt, and Adoptium's API (api.adoptium.net/v3/assets/release_name/eclipse/jdk-25.0.5+8); the fingerprint from
# adoptium.net/installation/gpg-verification. A new JDK changes all four lines below together, in one commit, looked up the same way.
set -eu

JDK_RELEASE='25.0.5+8'
JDK_URL='https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz'
JDK_SHA256='68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb'
ADOPTIUM_FINGERPRINT='3B04D753C9050D9A5D343F39843C48A565F8F04B'
ADOPTIUM_KEY_URL='https://packages.adoptium.net/artifactory/api/gpg/key/public'

dest="${1:?say where the JDK goes}"

if [ -e "$dest" ]; then
  echo "get-jdk: $dest is there already; this only fills a folder that isn't" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# NOTHING FROM THE USER'S HOME is used, so it runs the same as a user with no home folder at all (the deploy's avpx-build, ProtectHome):
# curl is told -q first, so it reads no ~/.curlrc, and gpg gets a home of its own in the work folder (below), never ~/.gnupg. java.yml's
# tests run this with a home that holds a .curlrc and a gpg.conf that would each break it, to prove neither is read.

# HTTPS only, TLS 1.2 or newer, and fail on any HTTP error rather than keep an error page. -q must come first: it's what keeps curl from
# reading ~/.curlrc.
fetch() {
  curl -q --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$2" "$1"
}

fetch "$JDK_URL" "$work/jdk.tar.gz"
fetch "$JDK_URL.sig" "$work/jdk.tar.gz.sig"
fetch "$ADOPTIUM_KEY_URL" "$work/adoptium.asc"

# 1. The signature. gpg gets a keyring of its own, holding only what was fetched, and the key it holds must be exactly the pinned one.
GNUPGHOME="$work/gnupg"
export GNUPGHOME
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "$work/adoptium.asc"

# Every main key in that keyring (a "pub" record, and the "fpr" record after it): there must be one, and it must be the pinned one
keys=$(gpg --batch --with-colons --fingerprint | awk -F: '$1 == "pub" { want = 1; next } $1 == "fpr" && want { print $10; want = 0 }')

if [ "$keys" != "$ADOPTIUM_FINGERPRINT" ]; then
  echo "get-jdk: the key fetched isn't only Adoptium's pinned one ($ADOPTIUM_FINGERPRINT); it holds: $keys" >&2
  exit 1
fi

# gpg says GOODSIG for a good signature, and VALIDSIG with the main key's fingerprint last: both must be there, with the pinned key
status=$(gpg --batch --status-fd 1 --verify "$work/jdk.tar.gz.sig" "$work/jdk.tar.gz" 2>/dev/null || true)
signer=$(printf '%s\n' "$status" | awk '$2 == "VALIDSIG" { print $NF }')

if ! printf '%s\n' "$status" | grep -q '^\[GNUPG:\] GOODSIG ' || [ "$signer" != "$ADOPTIUM_FINGERPRINT" ]; then
  echo "get-jdk: the JDK's signature isn't a good one by Adoptium's pinned key" >&2
  exit 1
fi

# 2. The sha256
echo "$JDK_SHA256  $work/jdk.tar.gz" | sha256sum --check --strict --quiet

# Only now is it unpacked
mkdir -p "$work/jdk"
tar -xzf "$work/jdk.tar.gz" -C "$work/jdk" --strip-components=1 --no-same-owner

# 3. The version it says it is
said=$("$work/jdk/bin/java" -version 2>&1 | head -n 1)

case "$said" in
  *"\"$JDK_RELEASE\""* | *"\"${JDK_RELEASE%+*}\""*) ;;
  *)
    echo "get-jdk: the JDK says it is $said, not $JDK_RELEASE" >&2
    exit 1
    ;;
esac

mv "$work/jdk" "$dest"
echo "get-jdk: Temurin $JDK_RELEASE, signed by Adoptium's pinned key, sha256 as pinned, in $dest"
