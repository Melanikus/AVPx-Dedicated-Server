// AVPx Dedicated Server, as a Java module. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
// It names no other module it needs, so the only one it can use is java.base, Java's own core (networking, cryptography, collections,
// text). The compiler itself refuses anything else, so no code from outside Java can get into the server, not even another part of the
// JDK (CODING-STANDARD.md, rule 2). It gives nothing to other modules: it's a program, not a library.
module avpx.server {
}
