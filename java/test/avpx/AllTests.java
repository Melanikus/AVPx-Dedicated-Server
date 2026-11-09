package avpx;

import avpx.testing.Tests;

// Every test of the server, in one run. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
//
//   java -cp build/test avpx.AllTests      (build.sh does this)
//
// Each test file is named here, in the order they run. A test file that isn't named here would never run, so tools/CheckStandard.java
// refuses any file in test/ that ends in Test.java and isn't named here.
public final class AllTests {
  private AllTests() {
  }

  public static void main(String[] args) {
    Tests.file("ProtocolTest");
    avpx.relay.ProtocolTest.register();
    Tests.file("VectorsTest");
    avpx.relay.VectorsTest.register();
    Tests.file("LimitsTest");
    avpx.relay.LimitsTest.register();
    Tests.file("CoreTest");
    avpx.relay.CoreTest.register();
    Tests.file("JsonTest");
    avpx.list.JsonTest.register();
    Tests.file("StrictJsonTest");
    avpx.list.StrictJsonTest.register();
    Tests.file("ListTest");
    avpx.list.ListTest.register();
    System.exit(Tests.runAll());
  }
}
