#!/bin/sh
# Builds the server and its tests with nothing but the JDK's own javac and jar, and runs the tests. Written 2026-11-08 by Melanikus for
# AVPx Dedicated Server.
#
#   JAVA_HOME=<the JDK> sh java/build.sh
#
# What it makes, in java/build/ (which it empties first):
#   avpx-server.jar   the server: java -jar avpx-server.jar (its settings are always /etc/avpx/settings.json)
#   avpx-smoke.jar    the smoke test: java -jar avpx-smoke.jar (tools/Smoke.java says how)
#   server/, test/    the compiled classes
#
# No Gradle, no Maven and nothing downloaded: every file it compiles is in this folder. JAVA_HOME must be the JDK the workflow pins
# (.github/workflows/java.yml: Temurin 25, checked by its signature and its sha256 before anything runs).
#
# Every warning javac knows of is switched on, and any warning fails the build. The sources must be ASCII (CODING-STANDARD.md rule 1):
# javac reads them as ASCII, and fails on any other byte.
set -eu

: "${JAVA_HOME:?set JAVA_HOME to the JDK the workflow pins}"
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

flags="--release 25 -encoding US-ASCII -proc:none -Xlint:all -Werror"

rm -rf build
mkdir -p build

# The server's own code, as a module that can use nothing but java.base (src/module-info.java)
find src -name '*.java' | LC_ALL=C sort > build/server-sources.txt
"$JAVA_HOME/bin/javac" $flags -d build/server @build/server-sources.txt

# The tests, compiled with the server's code (without its module file, so a test can reach what its package keeps to itself)
find src test -name '*.java' ! -name module-info.java | LC_ALL=C sort > build/test-sources.txt
"$JAVA_HOME/bin/javac" $flags -d build/test @build/test-sources.txt

# The tools (CheckStandard, Takeouts, Smoke): held to the same warnings, and compiled here so CodeQL reads them too. Smoke reads an
# installed server's settings with the server's own Settings, so the tools see the server's classes.
find tools -name '*.java' | LC_ALL=C sort > build/tools-sources.txt
"$JAVA_HOME/bin/javac" $flags -cp build/server -d build/tools @build/tools-sources.txt

# For the live tests (AVPX_LIVE=1), a certificate of their own, for 127.0.0.1 only, made fresh now by the JDK's own keytool and thrown away
# with build/. Its key store's password is random, made now, and kept in a file beside it, so no password is written in any code.
if [ "${AVPX_LIVE:-}" = "1" ]; then
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > build/test-tls.password
  "$JAVA_HOME/bin/keytool" -genkeypair -alias avpx-test -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
    -dname "CN=avpx test, O=AVPx Dedicated Server tests" -ext "SAN=ip:127.0.0.1" -validity 2 \
    -storetype PKCS12 -keystore build/test-tls.p12 -storepass:file build/test-tls.password -keypass:file build/test-tls.password \
    > /dev/null 2>&1
fi

"$JAVA_HOME/bin/java" -cp build/test avpx.AllTests

# Only then the jars, made so the same code always makes the same bytes, on any machine: every file's time is one fixed date, and jar is
# given the files one by one in one fixed order (sorted as bytes), never a folder to list, because a folder's listing order can differ
# from one filesystem to another. deploy/remote-deploy.sh builds the jars again on the server's machine, and puts them in place only if
# they're byte for byte the ones the checks built and tested.
jar_files() {
  (cd "$1" && find . -type f | LC_ALL=C sort | sed 's|^\./||') | while IFS= read -r f; do
    printf '%s\n%s\n%s\n' "-C" "$1" "$f"
  done
}

jar_files build/server > build/server-jar-files.txt
"$JAVA_HOME/bin/jar" --create --date=2026-11-08T00:00:00Z --file build/avpx-server.jar --main-class avpx.Main @build/server-jar-files.txt

# The smoke test, a jar of its own (java -jar avpx-smoke.jar): its classes, and the server's it reads installed settings with. It's what
# deploy's health check runs, and what anyone can run to test a server on their own machine.
mkdir -p build/smoke
cp -R build/server/avpx build/smoke/
mkdir -p build/smoke/avpx/tools
cp build/tools/avpx/tools/Smoke*.class build/smoke/avpx/tools/
# The known answers SmokeV2 pins version 2's code to before it trusts it to test a relay: in the jar, beside it, the very file built with
cp ../test-vectors/crypto-v2.json build/smoke/avpx/tools/
jar_files build/smoke > build/smoke-jar-files.txt
"$JAVA_HOME/bin/jar" --create --date=2026-11-08T00:00:00Z --file build/avpx-smoke.jar --main-class avpx.tools.Smoke @build/smoke-jar-files.txt
