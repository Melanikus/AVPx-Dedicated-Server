package avpx;

import avpx.access.AccessStore;
import avpx.list.ListServer;
import avpx.list.Listings;
import avpx.relay.RandomBytes;
import avpx.relay.Relay;
import avpx.relay.RelayCore;
import avpx.relay.RelaySockets;
import avpx.v2.SealedRelay;
import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

// AVPx Dedicated Server: a relay, and the list if the settings say so, started together. Written 2026-11-08 by Melanikus for AVPx
// Dedicated Server, from main.js.
//
//   java -jar avpx-server.jar
//
// It reads its settings from SETTINGS, always that one file (Settings.java says what it holds), so nothing given to it when it starts
// can point it at any other file. Every machine runs the same code: a relay for its region, and, on the one machine whose settings have
// a "list", the list too. The list never asks the relay anything, even on the same machine: it checks each room's pass with the relay's
// key (Pass.java), just as it would for a relay in another country. The server stops when the machine asks it to (systemd's stop, or
// Ctrl+C): Java runs the stop below, which closes every port.
public final class Main {
  private Main() {
  }

  // Where the settings are, as deploy/README.md puts them: readable only by root and the server's own user
  static final Path SETTINGS = Path.of("/etc/avpx/settings.json");

  public static void main(String[] args) {
    int code = run(args);

    // 0 is the server stopped as asked; anything else, it didn't start, and systemd's log has the reason
    if (code != 0) {
      System.exit(code);
    }
  }

  static int run(String[] args) {
    // Java's TLS reads these once, the first time it's used, so they're set before anything else. The list's clients never renegotiate
    // a connection, so one asking to is refused; and a TLS session isn't resumed from a ticket, so each connection starts afresh.
    System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "true");
    System.setProperty("jdk.tls.server.enableSessionTicketExtension", "false");

    Log screen = Log.screenOnly();

    if (args.length != 0) {
      screen.line("use: java -jar avpx-server.jar (it takes nothing more: its settings are always " + SETTINGS + ")");
      return 2;
    }

    Settings settings;

    try {
      settings = Settings.read(SETTINGS);
    } catch (Settings.Refused e) {
      screen.line(e.getMessage());
      return 2;
    } catch (IOException e) {
      screen.line("settings: " + SETTINGS + " could not be read (" + e.getClass().getSimpleName() + ")");
      return 2;
    }

    Log log = new Log(settings.logFile().isEmpty() ? null : Path.of(settings.logFile()), Instant::now, Log.SCREEN);

    // The access store (AccessStore.java): who asked to play here, and what the owner decided. A store that can't be read, or holds
    // anything this server wouldn't write, stops the server here, with the reason: the relay never starts on an approved set nobody can
    // vouch for.
    AccessStore access = null;

    if (!settings.accessFolder().isEmpty()) {
      try {
        access = AccessStore.open(Path.of(settings.accessFolder()));
      } catch (AccessStore.Refused e) {
        log.line(e.getMessage() + ", so the server did not start");
        log.close();
        return 1;
      }
    }

    // The relay speaks one protocol: version 1 (PROTOCOL.md), or version 2 (CRYPTO.md: handshake A, then everything sealed, in front of
    // the same games). Version 2 takes approved players only, so it always has a store (Settings.java).
    Relay core;

    if (settings.protocol() == 2) {
      core = new SealedRelay(settings.controlPort(), settings.relayPorts(), settings.region(), settings.passKey(), settings.staticKeys(),
          access, RandomBytes.secure(), new SecureRandom(), new RelayCore.Limits(), new SealedRelay.Limits(), System.currentTimeMillis());
    } else {
      core = new RelayCore(settings.controlPort(), settings.relayPorts(), settings.region(), settings.passKey(), RandomBytes.secure(),
          new RelayCore.Limits(), System.currentTimeMillis());
    }

    Settings.ListSettings listSettings = settings.list();
    log.line("server: starting the " + settings.region() + " relay, version " + settings.protocol() + " of the relay's messages, "
        + settings.relayPorts().length + " relay ports"
        + (listSettings != null ? ", and the list for " + listSettings.relays().size() + " relays" : ", and no list"));

    ListServer list = null;
    AccessStore store = access;

    // If the list stops on an error nobody expected (avpx/Fatal.java), or the access store stops (AccessStore.start: its folder is no
    // longer the server's own and 0700, or a turn of the owner's decisions has hung), the relay is told to stop too, and run() gives 1,
    // for systemd to start the server again. Both start before the relay, so the relay is handed over once it exists, and checked for
    // one that failed in between.
    AtomicBoolean partFailed = new AtomicBoolean();
    AtomicReference<RelaySockets> relayToStop = new AtomicReference<>();
    Runnable whenPartFails = () -> {
      partFailed.set(true);
      RelaySockets toStop = relayToStop.get();

      if (toStop != null) {
        toStop.stopSoon();
      }
    };

    // The store's own thread: the owner's decisions about once a second, and its line of counts once a minute
    if (store != null) {
      store.start(log::line, System::currentTimeMillis, whenPartFails);
    }

    if (listSettings != null) {
      try {
        Listings listings = new Listings(listSettings.relays(), RandomBytes.secure(), System.currentTimeMillis());
        list = ListServer.start(listSettings, listings, store, log::line, System::currentTimeMillis, whenPartFails);
      } catch (ListServer.CertificateProblem e) {
        log.line("list: the certificate files could not be used (" + e.getMessage() + "), so the server did not start");
        stopTurns(store);
        log.close();
        return 1;
      } catch (IOException e) {
        log.line("list: the HTTPS port could not be used (" + e.getClass().getSimpleName() + "), so the server did not start");
        stopTurns(store);
        log.close();
        return 1;
      }
    }

    RelaySockets relay;

    try {
      relay = RelaySockets.start(settings.relayAddress(), core, log::line, System::currentTimeMillis);
    } catch (IOException e) {
      log.line(e.getMessage());

      if (list != null) {
        list.stop();
      }

      stopTurns(store);
      log.close();
      return 1;
    }

    relayToStop.set(relay);

    if (partFailed.get()) {
      relay.stopSoon();
    }

    ListServer started = list;
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      log.line("server: stopping");
      relay.stop();

      if (started != null) {
        started.stop();
      }

      stopTurns(store);
      log.close();
    }, "stop"));

    // The relay runs until the stop above ends it, or until it, the list or the store stops on something wrong: then the server ends with
    // 1, and systemd starts it afresh (deploy/avpx-java.service), rather than going on from a state nobody can vouch for
    relay.join();

    if (relay.failed() || partFailed.get()) {
      log.line("server: stopping, with 1, for systemd to start it again (the line before this says why)");
      stopTurns(store);
      return 1;
    }

    return 0;
  }

  // The access store's turns end, where there's a store
  private static void stopTurns(AccessStore store) {
    if (store != null) {
      store.stopTurns();
    }
  }
}
