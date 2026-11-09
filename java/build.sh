#!/bin/sh
# Builds the server and its tests with nothing but the JDK's own javac and jar, and runs the tests. Written 2026-11-08 by Melanikus for
# AVPx Dedicated Server.
#
#   JAVA_HOME=<the JDK> sh java/build.sh
#
# What it makes, in java/build/ (which it empties first):
#   avpx-server.jar   the server: java -jar avpx-server.jar <settings file>
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

# The tests, compiled with the server's code (without its module file, so a test can reach what its package keeps to itself), and run
find src test -name '*.java' ! -name module-info.java | LC_ALL=C sort > build/test-sources.txt
"$JAVA_HOME/bin/javac" $flags -d build/test @build/test-sources.txt
"$JAVA_HOME/bin/java" -cp build/test avpx.AllTests

# Only then the jar, with every file's time set to one fixed date, so the same code always makes the same bytes
"$JAVA_HOME/bin/jar" --create --date=2026-11-08T00:00:00Z --file build/avpx-server.jar --main-class avpx.Main -C build/server .
