package avpx.list;

import avpx.list.Requests.Ending;
import avpx.list.Requests.Posted;
import avpx.list.Requests.Refusal;
import avpx.relay.Pass;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

// What the list does with each request, with no network of its own: a request in, the answer out. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server, from list/routes.js.
//
// The list's seven calls (PROTOCOL.md section 4):
//   POST   /v1/access-requests  a player asks to play here, from the game's page: 200 {v, fp, state}; 400, 429, 503 with {v, error}.
//                               AccessRequests.java has its rules, and ListServer calls it, not this (handle says why); the access
//                               store keeps the requests and the owner's decisions
//   GET    /v1/relays           the relays a game can use: 200 {relays}, never a key
//   GET    /v1/relay-keys       with ?region= and a region: that version 2 relay's two static PUBLIC keys, 200 {region, p384, mlkem};
//                               with no query at all: the keys of the relay this same server runs (a servers.cfg line names no region).
//                               Any other query is 400; 404 for a region the list doesn't know, a version 1 relay, or no relay of its
//                               own. The game holds them to a fingerprint it already has before it sends that relay anything (CRYPTO.md
//                               sections 12.1 and 12.2)
//   POST   /v1/games            put a game on the list, with its relay's pass: 201 {owner}, 403 a pass not good, 409 listed already,
//                               503 the list is full
//   PUT    /v1/games            renew it, and change what it says, with its owner key and a fresh pass: 204, 403, 404 not listed
//   DELETE /v1/games            take it down, with its owner key: 204, 403, 404 not listed. The room stays until its host ends it.
//   GET    /v1/games?version=N  the games of that network version: 200 {games}, at most MOST_GAMES, the newest first. With &code= and
//                               8 code letters after it, only that code's games, one a region at most: a code someone typed
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
  // (" and \), every number at its longest, and a host's id (a version-2 game's, 96 hex digits), come to 51,511 bytes. A game can refuse
  // anything bigger. ListTest.java checks the worst case fits. (It was 46,011, under 48 KB, while a listing gave the 32-digit fingerprint.)
  public static final int MOST_LIST_BYTES = 56 * 1024;

  // The most an answer to GET /v1/relays can be: 16 relays (Settings.java allows no more), each with the longest region and host name,
  // come to 1,868 bytes. ListTest.java checks that too.
  public static final int MOST_RELAYS_BYTES = 4 * 1024;

  // The most an answer to GET /v1/relay-keys can be: the longest region (16 characters) and the two keys (194 and 3,136 hex digits) come
  // to 3,380 bytes. ListTest.java checks that too.
  public static final int MOST_RELAY_KEYS_BYTES = 4 * 1024;

  // GET /v1/relay-keys's one query, when it has one: "region=" and a region (Pass.isRegion says what one is), with nothing before or after
  private static final String REGION_QUERY = "region=";

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

  // A request: its method, its path, its query (the text after the first ?, or ""), and its body's bytes, at now. POST
  // /v1/access-requests never comes here: ListServer hands it to AccessRequests itself, outside the lock this is called under, so a
  // request being written to the disk keeps no other call waiting.
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

      if (path.equals("/v1/relay-keys")) {
        if (!method.equals("GET")) {
          return error(405, "no such call on this path");
        }

        Requests.checkNoBody(body);

        // No query: the relay this same server runs, the one at the address the game asked (CRYPTO.md section 12.2)
        if (query.isEmpty()) {
          Map<String, Object> own = listings.ownRelayKeys();
          return own == null ? error(404, "this server runs no version 2 relay") : new Answer(200, own);
        }

        String region = query.startsWith(REGION_QUERY) ? query.substring(REGION_QUERY.length()) : "";

        if (!Pass.isRegion(region)) {
          throw new Refusal(400, "GET /v1/relay-keys's query is nothing, or region= and a region, and nothing else");
        }

        Map<String, Object> keys = listings.relayKeys(region);

        if (keys == null) {
          return error(404, "the list has no version 2 relay in that region");
        }

        return new Answer(200, keys);
      }

      if (!path.equals("/v1/games")) {
        return error(404, "no such path");
      }

      if (method.equals("GET")) {
        Requests.checkNoBody(body);
        Requests.ListQuery asked = Requests.parseListQuery(query);
        List<Object> games = new ArrayList<>();

        for (Listings.Shown shown : listings.games(asked.version(), asked.code(), now, MOST_GAMES)) {
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

          // Only a version-2 game has one, so an older game's reader, which refuses a field it doesn't know, never sees one
          if (g.hostId() != null) {
            game.put("id", g.hostId());
          }

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
