'use strict';
// What the list does with each request, with no network of its own: a request in, the answer out. Written 2026-11-08 by Melanikus for
// AVPx Dedicated Server.
//
// The list's four calls (PROTOCOL.md section 4):
//   POST   /v1/games            put a room on the list, with the room's token: 201 {code}, 403 no such room, 409 listed already
//   PUT    /v1/games            change what the list says about it: 200, 403 no such room, 404 not listed
//   DELETE /v1/games            end the room, and so its list entry: 204, 403 no such room
//   GET    /v1/games?version=N  the games of that network version: 200 {games}, at most kMostGames, the newest first
// Anything else is 404 (no such path) or 405 (no such call on it). A room's entry lives on the room itself, so it ends with the room: its
// heartbeat is the room's own keepalive (relay/core.js).
//
// The list never holds an address, and gives back nothing a request sent except what a host chose to list.

const { Refusal, parseListing, parseEnding, parseListQuery } = require('./requests');

const kMostGames = 100;

// How long a game is said to have been listed is at most a year, so a reader can hold that number to a limit too (a room kept for longer
// still says a year)
const kMostSeconds = 31536000;

// The most an answer to GET /v1/games can be: 100 games with every text field at its longest and every character one JSON writes as two
// (" and \) come to 30,511 bytes. A game can refuse anything bigger. test/list.test.js checks the worst case fits.
const kMostListBytes = 32 * 1024;

function answer(status, body = null) {
  return { status, body };
}

// A request: { method, path, query (the text after ?, or ''), body (Buffer) } at now. Gives back { status, body (an object, or null) }.
function handle(relay, { method, path, query, body }, now) {
  try {
    if (path !== '/v1/games') {
      return answer(404, { error: 'no such path' });
    }

    if (method === 'GET') {
      if (body && body.length) {
        throw new Refusal(400, 'a GET has no body');
      }

      const { version } = parseListQuery(query);
      const games = [];

      for (const game of relay.liveGames()) {
        if (game.listing && game.listing.version === version) {
          games.push(game);
        }
      }

      // The newest first, and only so many
      games.sort((a, b) => b.listing.listedAt - a.listing.listedAt);
      return answer(200, {
        games: games.slice(0, kMostGames).map((g) => ({
          code: g.code.toString('latin1'),
          name: g.listing.name,
          level: g.listing.level,
          mode: g.listing.mode,
          players: g.listing.players,
          maxPlayers: g.listing.maxPlayers,
          version: g.listing.version,
          seconds: Math.min(kMostSeconds, Math.max(0, Math.floor((now - g.listing.listedAt) / 1000))),
        })),
      });
    }

    if (query) {
      throw new Refusal(400, 'only a GET has a query');
    }

    if (method === 'POST' || method === 'PUT') {
      const { token, listing } = parseListing(body);
      const game = relay.gameByToken(token);

      if (!game) {
        return answer(403, { error: 'no room has that token' });
      }

      if (method === 'POST') {
        if (game.listing) {
          return answer(409, { error: 'that room is listed already' });
        }

        game.listing = { ...listing, listedAt: now };
        return answer(201, { code: game.code.toString('latin1') });
      }

      if (!game.listing) {
        return answer(404, { error: 'that room is not listed' });
      }

      game.listing = { ...listing, listedAt: game.listing.listedAt };
      return answer(200, { code: game.code.toString('latin1') });
    }

    if (method === 'DELETE') {
      const { token } = parseEnding(body);
      const game = relay.gameByToken(token);

      if (!game) {
        return answer(403, { error: 'no room has that token' });
      }

      relay.endGame(game);
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

module.exports = { handle, kMostGames, kMostSeconds, kMostListBytes };
