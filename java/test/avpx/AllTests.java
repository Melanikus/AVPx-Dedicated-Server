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
    Tests.file("HttpTest");
    avpx.list.HttpTest.register();
    Tests.file("SettingsTest");
    avpx.SettingsTest.register();
    Tests.file("HkdfTest");
    avpx.crypto.HkdfTest.register();
    Tests.file("PrimitivesTest");
    avpx.crypto.PrimitivesTest.register();
    Tests.file("SymmetricKatTest");
    avpx.crypto.SymmetricKatTest.register();
    Tests.file("P384KatTest");
    avpx.crypto.P384KatTest.register();
    Tests.file("PostQuantumKatTest");
    avpx.crypto.PostQuantumKatTest.register();
    Tests.file("NoiseTest");
    avpx.v2.NoiseTest.register();
    Tests.file("FragmentsTest");
    avpx.v2.FragmentsTest.register();
    Tests.file("ReplayWindowTest");
    avpx.v2.ReplayWindowTest.register();
    Tests.file("ChannelTest");
    avpx.v2.ChannelTest.register();
    Tests.file("HandshakeATest");
    avpx.v2.HandshakeATest.register();
    Tests.file("CryptoV2VectorsTest");
    avpx.v2.CryptoV2VectorsTest.register();
    Tests.file("LiveTest");
    avpx.LiveTest.register();
    System.exit(Tests.runAll());
  }
}
