package avpx.v2;

import java.util.List;

// What a version 2 relay asks about approved players (CRYPTO.md section 6, server #24). Written 2026-11-09 by Melanikus for AVPx
// Dedicated Server. The server's own is the access store (avpx/access/AccessStore.java), which the owner's decisions change; the tests
// have their own.
//
// The relay's one thread carries every game, so neither call may wait for a disk or a lock someone else holds: the access store takes
// the owner's decisions on a thread of its own, and these only read what it has found.
public interface Approvals {
  // Whether this id (96 hex digits, small letters: a player's whole SHA-384, Identity.idHex) is an approved player's, as the owner's last
  // decision taken left the approved set. Never the 16-byte fingerprint: a machine compares the whole hash (CRYPTO.md section 8).
  boolean approved(String id);

  // The ids whose approval was taken back since the last time this was asked, each once. The relay asks once a turn, and ends those
  // players' sessions. By then, approved already says no for each of them.
  List<String> takeRevoked(long now);
}
