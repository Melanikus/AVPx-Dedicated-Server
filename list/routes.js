'use strict';
// What the list does with each request, with no network of its own: a request in, the answer out. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server.
//
// The list's five calls (PROTOCOL.md section 4):
//   GET    /v1/relays           the relays a game can use: 200 {relays}, never a key
//   POST   /v1/games            put a game on the list, with its relay's pass: 201 {owner}, 403 a pass not good, 409 listed already,
//                               503 the list is full
//   PUT    /v1/games            renew it, and change what it says, with its owner key and a fresh pass: 204, 403, 404 not listed
//   DELETE /v1/games            take it down, with its owner key: 204, 403, 404 not listed. The room stays until its host ends it.
//   GET    /v1/games?version=N  the games of that network version: 200 {games}, at most kMostGames, the newest first
// Anything else is 404 (no such path) or 405 (no such call on it). listings.js holds the games and checks the passes.
//
// The list never holds an address, and gives back nothing a request sent except what a host chose to list.

const { Refusal, parseListing, parseEnding, parseListQuery, checkNoBody } = require('./requests');

const kMostGames = 100;

// How long a game is said to have been listed is at most a year, so a reader can hold that number to a limit too (a game listed for
// longer still says a year)
const kMostSeconds = 31536000;

// The most an answer to GET /v1/games can be: 100 games with every text field at its longest, every character one JSON writes as two
// (" and \), and every number at its longest, come to 41,111 bytes. A game can refuse anything bigger. test/list.test.js checks the worst
// case fits.
const kMostListBytes = 48 * 1024;

// The most an answer to GET /v1/relays can be: 16 relays (settings.js allows no more), each with the longest region and host name, come
// to 1,868 bytes. test/list.test.js checks that too.
const kMostRelaysBytes = 4 * 1024;

function answer(status, body = null) {
  return { status, body };
}

// A request: { method, path, query (the text after ?, or ''), body (Buffer) } at now. Gives back { status, body (an object, or null) }.
function handle(listings, { method, path, query, body }, now) {
  try {
    if (path === '/v1/relays') {
      if (method !== 'GET') {
        return answer(405, { error: 'no such call on this path' });
      }

      checkNoBody(body);

      if (query) {
        throw new Refusal(400, 'GET /v1/relays has no query');
      }

      return answer(200, { relays: listings.relayList() });
    }

    if (path !== '/v1/games') {
      return answer(404, { error: 'no such path' });
    }

    if (method === 'GET') {
      checkNoBody(body);
      const { version } = parseListQuery(query);

      return answer(200, {
        games: listings.games(version, now, kMostGames).map((g) => ({
          region: g.region,
          code: g.code,
          name: g.name,
          level: g.level,
          mode: g.mode,
          gameStyle: g.gameStyle,
          levelNumber: g.levelNumber,
          coopLobby: g.coopLobby,
          players: g.players,
          maxPlayers: g.maxPlayers,
          version: g.version,
          hostMs: g.hostMs,
          seconds: Math.min(kMostSeconds, Math.max(0, Math.floor((now - g.listedAt) / 1000))),
        })),
      });
    }

    if (query) {
      throw new Refusal(400, 'only a GET has a query');
    }

    if (method === 'POST') {
      const { pass, listing } = parseListing(body);
      return answer(201, { owner: listings.add(pass, listing, now) });
    }

    if (method === 'PUT') {
      const { owner, pass, listing } = parseListing(body, true);
      listings.renew(owner, pass, listing, now);
      return answer(204);
    }

    if (method === 'DELETE') {
      const { region, code, owner } = parseEnding(body);
      listings.remove(region, code, owner, now);
      return answer(204);
    }

    return answer(405, { error: 'no such call on this path' });
  } catch (e) {
    if (e instanceof Refusal) {
      return answer(e.status, { error: e.message });
    }

    // Nothing a request holds should get here; if something does, it gets a plain refusal and the server goes on
    return answer(500, { error: 'the list could not answer that' });
  }
}

module.exports = { handle, kMostGames, kMostSeconds, kMostListBytes, kMostRelaysBytes };
