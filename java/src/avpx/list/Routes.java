package avpx.list;

import avpx.list.Requests.Ending;
import avpx.list.Requests.Posted;
import avpx.list.Requests.Refusal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// What the list does with each request, with no network of its own: a request in, the answer out. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server, from list/routes.js.
//
// The list's five calls (PROTOCOL.md section 4):
//   GET    /v1/relays           the relays a game can use: 200 {relays}, never a key
//   POST   /v1/games            put a game on the list, with its relay's pass: 201 {owner}, 403 a pass not good, 409 listed already,
//                               503 the list is full
//   PUT    /v1/games            renew it, and change what it says, with its owner key and a fresh pass: 204, 403, 404 not listed
//   DELETE /v1/games            take it down, with its owner key: 204, 403, 404 not listed. The room stays until its host ends it.
//   GET    /v1/games?version=N  the games of that network version: 200 {games}, at most MOST_GAMES, the newest first
// Anything else is 404 (no such path) or 405 (no such call on it). Listings.java holds the games and checks the passes.
//
// The list never holds an address, and gives back nothing a request sent except what a host chose to list.
public final class Routes {
  private Routes() {
  }

  public static final int MOST_GAMES = 100;

  // How long a game is said to have been listed is at most a year, so a reader can hold that number to a limit too (a game listed for
  // longer still says a year)
  public static final long MOST_SECONDS = 31536000;

  // The most an answer to GET /v1/games can be: 100 games with every text field at its longest, every character one JSON writes as two
  // (" and \), and every number at its longest, come to 41,111 bytes. A game can refuse anything bigger. ListTest.java checks the worst
  // case fits.
  public static final int MOST_LIST_BYTES = 48 * 1024;

  // The most an answer to GET /v1/relays can be: 16 relays (Settings.java allows no more), each with the longest region and host name,
  // come to 1,868 bytes. ListTest.java checks that too.
  public static final int MOST_RELAYS_BYTES = 4 * 1024;

  // An answer: its status, and its body as JSON's objects (Json.write writes it), or null for none
  public record Answer(int status, Map<String, Object> body) {
  }

  private static Answer answer(int status, String field, Object value) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put(field, value);
    return new Answer(status, body);
  }

  private static Answer error(int status, String words) {
    return answer(status, "error", words);
  }

  // A request: its method, its path, its query (the text after the first ?, or ""), and its body's bytes, at now
  public static Answer handle(Listings listings, String method, String path, String query, byte[] body, long now) {
    try {
      if (path.equals("/v1/relays")) {
        if (!method.equals("GET")) {
          return error(405, "no such call on this path");
        }

        Requests.checkNoBody(body);

        if (!query.isEmpty()) {
          throw new Refusal(400, "GET /v1/relays has no query");
        }

        return answer(200, "relays", listings.relayList());
      }

      if (!path.equals("/v1/games")) {
        return error(404, "no such path");
      }

      if (method.equals("GET")) {
        Requests.checkNoBody(body);
        int version = Requests.parseListQuery(query);
        List<Object> games = new ArrayList<>();

        for (Listings.Shown shown : listings.games(version, now, MOST_GAMES)) {
          Requests.Listing g = shown.listing();
          Map<String, Object> game = new LinkedHashMap<>();
          game.put("region", g.region());
          game.put("code", g.code());
          game.put("name", g.name());
          game.put("level", g.level());
          game.put("mode", g.mode());
          game.put("gameStyle", g.gameStyle());
          game.put("levelNumber", g.levelNumber());
          game.put("coopLobby", g.coopLobby());
          game.put("players", g.players());
          game.put("maxPlayers", g.maxPlayers());
          game.put("version", g.version());
          game.put("hostMs", g.hostMs());
          game.put("seconds", Math.min(MOST_SECONDS, Math.max(0, Math.floorDiv(now - shown.listedAt(), 1000))));
          games.add(game);
        }

        return answer(200, "games", games);
      }

      if (!query.isEmpty()) {
        throw new Refusal(400, "only a GET has a query");
      }

      if (method.equals("POST")) {
        Posted posted = Requests.parseListing(body, false);
        return answer(201, "owner", listings.add(posted.pass(), posted.listing(), now));
      }

      if (method.equals("PUT")) {
        Posted posted = Requests.parseListing(body, true);
        listings.renew(posted.owner(), posted.pass(), posted.listing(), now);
        return new Answer(204, null);
      }

      if (method.equals("DELETE")) {
        Ending ending = Requests.parseEnding(body);
        listings.remove(ending.region(), ending.code(), ending.owner(), now);
        return new Answer(204, null);
      }

      return error(405, "no such call on this path");
    } catch (Refusal refusal) {
      return error(refusal.status(), refusal.getMessage());
    } catch (RuntimeException e) {
      // Nothing a request holds should get here; if something does, it gets a plain refusal and the server goes on
      return error(500, "the list could not answer that");
    }
  }
}
