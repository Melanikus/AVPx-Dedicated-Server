package avpx.testing;

import avpx.v2.Approvals;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

// The approvals a test hands a version 2 relay: who's approved, as the test says, and revokes the test queues itself. Written 2026-11-09
// by Melanikus for AVPx Dedicated Server. Only for tests: the server's own is the access store (avpx/access/AccessStore.java).
public final class TestApprovals implements Approvals {
  private final Predicate<String> approved;
  private final List<String> revoked = new ArrayList<>();

  private TestApprovals(Predicate<String> approved) {
    this.approved = approved;
  }

  public static TestApprovals of(Predicate<String> approved) {
    return new TestApprovals(approved);
  }

  // A revoke, for the relay's next tick to take
  public void revoke(String fingerprint) {
    revoked.add(fingerprint);
  }

  @Override
  public boolean approved(String fingerprint) {
    return approved.test(fingerprint);
  }

  @Override
  public List<String> takeRevoked() {
    List<String> out = List.copyOf(revoked);
    revoked.clear();
    return out;
  }
}
