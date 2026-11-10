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
#
# FOR WHOEVER BUILDS THIS YEARS FROM NOW (the owner's "built to outlive us", 2026-11-09), what each pin is, and what to do when it fails:
#   - JDK_SHA256 is what pins the JDK: the SHA-256 of the exact file. Any copy of the file with this SHA-256 is this JDK, wherever it came
#     from. So if JDK_URL is gone (Adoptium moved its releases, or GitHub is gone), a copy from anywhere else will do: a mirror, an
#     archive (web.archive.org keeps many), or one someone kept. Put its address in JDK_URL, and its .sig beside it, or the signature
#     check fails. The SHA-256 still has to match, so a wrong file can't get through.
#   - ADOPTIUM_FINGERPRINT pins who made it: Adoptium's signing key, the one whose fingerprint this is, never just the key the address
#     happens to serve. If Adoptium ever signs with another key, this refuses until the fingerprint is looked up again from two places that
#     agree (their page above, and the key's own records). If the key is gone, and with it every copy of the .sig, then no copy of this JDK
#     can be checked for who made it any more: move to a newer JDK, signed by a key that can be checked, as below.
#   - JDK_RELEASE pins which one: java -version must say exactly this. Temurin 25 is a long-term release, with security updates for
#     years. When they end, or Temurin itself is gone, take another build of OpenJDK 25 or newer, from any maker who signs their releases.
#     Fill in its four lines the same way: from two places that agree, with its maker's key's fingerprint. The server uses only Java's
#     own standard library (its ML-KEM is the JDK's, JEP 496, from Java 24 on), and nothing else, so any full OpenJDK of that version builds
#     it. A different JDK makes different jar bytes, which is fine: GitHub and the machine both build with the one pinned here, and only
#     have to match each other.
#   - "The JDK is the newest Temurin 25" (java.yml) fails every quarter, when a security update comes out. That's the reminder to move
#     these four lines. It isn't a fault in the code.
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
# --retry 3: a server that's only busy for a moment (curl tries again on a timeout, or on HTTP 408, 429, 500, 502, 503 or 504, and on
# nothing else) gets three more tries, 10 s apart, before this fails. Java's check went red on 2026-11-09 for one 504 from the download
# server. Trying again changes nothing about what's trusted: whatever finally arrives must still pass the signature and sha256 checks
# below, or it's thrown away.
# A download that can't be had stops everything, saying so in the words every gate uses for a tool it can't reach (TAKING-OVER.md): so
# nothing ever goes on, or passes, for want of the JDK.
fetch() {
  if curl -q --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 10 --output "$2" "$1"; then
    return 0
  fi
  echo "get-jdk: $1 is unreachable: replace it with an equivalent, see TAKING-OVER.md (any copy with the SHA-256 pinned here is the same JDK: the notes at the top of this script)" >&2
  exit 1
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
