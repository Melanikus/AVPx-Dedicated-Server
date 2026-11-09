package avpx;

import java.util.function.Consumer;

// What the server does when something it never expects goes wrong in one of the loops that run all the time: the relay's, and the list's
// timers. Written 2026-11-09 by Melanikus for AVPx Dedicated Server, for the independent review's V1-3.
//
// WHY IT STOPS THE WHOLE SERVER. The relay and the list keep tables (games, ports, listings) that each turn of their loops keeps right. An
// error nobody expected, part-way through a turn, may have left one half-changed: a port marked both free and in use, say. Going on from
// there could hand one player's port to another, so going on isn't safe. Doing nothing, as Java does by default, is worse: the relay's
// thread just ends, or a timer quietly never runs again, and the server looks up while it passes no games and tells nobody. So the turn's
// error is written down in one line, and the whole server stops with a failure, for systemd to start it afresh in a few seconds
// (deploy/avpx-java.service: Restart=on-failure, RestartSec=5, and no limit on how often). Every game in it ends; that's the price of
// never carrying on from a state nobody can vouch for.
//
// THE LINE says the error's kind and where it happened, never its words. An error's words can hold anything, an address among them, and
// the server writes no address anywhere (the user's ruling).
public final class Fatal {
  private Fatal() {
  }

  // Runs one turn of a loop. True if it went as expected. False if anything was thrown out of it, an Error as well as an exception, once
  // its line is written to log: the loop must then stop, and the server with it.
  public static boolean turn(String loop, Runnable body, Consumer<String> log) {
    try {
      body.run();
      return true;
    } catch (RuntimeException | Error e) {
      log.accept(loop + ": stopped by an error nobody expected, " + describe(e) + "; the server stops, for systemd to start it again");
      return false;
    }
  }

  // The error's kind and the line it came from, with none of its words
  static String describe(Throwable t) {
    StackTraceElement[] where = t.getStackTrace();
    String at = where.length > 0 ? " at " + where[0].getClassName() + "." + where[0].getMethodName() + ":" + where[0].getLineNumber() : "";
    return t.getClass().getName() + at;
  }
}
