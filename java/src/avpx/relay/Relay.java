package avpx.relay;

import java.util.List;

// What RelaySockets.java needs of a relay: its ports, and packets in and out. Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
// Two relays have it: RelayCore.java speaks protocol version 1 (PROTOCOL.md), and avpx.v2.SealedRelay speaks version 2 (CRYPTO.md), in
// front of the same RelayCore for its games. A relay speaks one version only: version 2 is a new deployment, with no mixing and no
// asking which (CRYPTO.md, at its top).
public interface Relay {
  // The port hosts and joiners ask on
  int controlPort();

  // The relay's ports for joiners, in order
  List<Integer> relayPorts();

  // The biggest packet the relay takes: the sockets read one byte more, so they can tell a packet that was bigger
  int mostDatagramBytes();

  // A packet came to localPort from address:port at now (milliseconds): what to send, each from one of the relay's own ports
  List<RelayCore.Out> receive(int localPort, String address, int port, byte[] data, long now);

  // Called about once a second: ends what has run out, and gives back the lines to write, if any
  List<String> tick(long now);

  // The line of counts since the last one, made now (the sockets ask for one as the relay stops)
  String countsLine(long now);
}
