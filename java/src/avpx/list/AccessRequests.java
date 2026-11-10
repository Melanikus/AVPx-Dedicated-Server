package avpx.list;

import avpx.access.AccessStore;
import avpx.crypto.MlKem;
import avpx.crypto.P384;
import avpx.v2.Identity;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

// POST /v1/access-requests: a player asks to play on this server, from the game's page, only when they press "Request access" (PROTOCOL.md
// section 4, agreed with Fourth and Third, 2026-11-09). Written 2026-11-09 by Melanikus for AVPx Dedicated Server.
//
//   in:   {"v":1,"name":"<the name they chose>","key":"<their identity's public halves, in base64>"}, at most 4,096 bytes, nothing else
//   out:  200 {"v":1,"fp":"<32 hex digits>","state":"waiting"|"approved"|"refused"|"revoked"}, at most 512 bytes
//         400 {"v":1,"error":"shape"|"name"|"key"}, 429 {"v":1,"error":"busy"}, 503 {"v":1,"error":"closed"}
//
// - THE BODY IS HOSTILE INPUT (AVP Tao 3): read by Json.java, then held to exactly these three fields. The key is exactly 2,220 base64
//   letters (1,665 bytes, a multiple of 3, so no = and no spare bits: one key has one text), checked before it's decoded; the bytes must
//   then be a P-384 key on the curve and an ML-KEM-1024 key that passes FIPS 203's check, as handshake A checks them. The name is held to
//   AccessStore.isName, and never "fixed".
// - The fingerprint and the id are worked out here, from the keys (Identity.java): a fingerprint the request gives would be taken from
//   nobody, so the body has none. The game checks the fp it gets back is its own, which catches two sides that hash differently. The store
//   keeps the whole id too, which is what the relay compares; a key whose fingerprint is another player's (the same first 16 bytes of
//   hash, another id) is refused as "key", so a fingerprint always names one player.
// - Asking again is safe, and how a player checks their state later: a fingerprint the store has only gets its state back, with the name
//   it first asked with. There's no way to ask about a fingerprint without its keys.
// - The answers are fixed words, never the request's own text, and the game shows its own words for each.
// - Limits (AccessLimits.java): every try, 1 a minute and 10 an hour from one address, asked by ListServer before the body is read; a
//   new request, 5 a day from one address and 10 from one network, asked through newAllowed only once the store would keep it. The
//   store holds at most 1,000 waiting. Logged as counts only.
// - Approval itself gives nothing until handshake A proves the player holds those keys (CRYPTO.md section 6). And with no pin on the list
//   yet (#175), the access code the game shows, read to the owner by another way, is what stops a key swapped on the way from ever being
//   approved: the owner's approve refuses unless exactly one waiting request matches the code they were told.
final class AccessRequests {
  private AccessRequests() {
  }

  static final String PATH = "/v1/access-requests";
  static final int MOST_BODY_BYTES = 4096;
  static final int MOST_ANSWER_BYTES = 512;
  private static final int KEY_LETTERS = 2220;
  private static final Pattern KEY = Pattern.compile("[A-Za-z0-9+/]{" + KEY_LETTERS + "}");
  private static final int DEPTH = 1;

  static Routes.Answer answer(int status, String field, String value) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("v", 1L);
    body.put(field, value);
    return new Routes.Answer(status, body);
  }

  // The answer for an address over its limit, in this call's own shape (the game's reader takes nothing else here)
  static Routes.Answer busy() {
    return answer(429, "error", "busy");
  }

  // newAllowed: whether the sender may make one more new request now (AccessLimits.allowsNew, under the list's lock), asked by the store
  static Routes.Answer handle(AccessStore store, String method, String query, byte[] body, long now, BooleanSupplier newAllowed) {
    if (!method.equals("POST")) {
      return answer(405, "error", "shape");
    }

    if (store == null) {
      return answer(503, "error", "closed");
    }

    Map<String, Object> request = null;

    if (query.isEmpty() && body != null && body.length > 0 && body.length <= MOST_BODY_BYTES) {
      try {
        request = Json.readObject(body, DEPTH);
      } catch (Json.Bad e) {
        request = null;
      }
    }

    if (request == null || request.size() != 3 || !Long.valueOf(1).equals(request.get("v")) || !(request.get("name") instanceof String name)
        || !(request.get("key") instanceof String key)) {
      return answer(400, "error", "shape");
    }

    if (!AccessStore.isName(name)) {
      return answer(400, "error", "name");
    }

    byte[] statics = KEY.matcher(key).matches() ? Base64.getDecoder().decode(key) : null;

    if (statics == null || statics.length != Identity.STATIC_BYTES) {
      return answer(400, "error", "key");
    }

    byte[] p384 = Arrays.copyOf(statics, P384.PUBLIC_BYTES);
    byte[] kem = Arrays.copyOfRange(statics, P384.PUBLIC_BYTES, Identity.STATIC_BYTES);

    if (P384.decode(p384) == null || MlKem.decode(kem) == null) {
      return answer(400, "error", "key");
    }

    // The fingerprint for people (the answer, the access code, the owner's decisions), and the whole id for what the relay compares
    String fingerprint = Identity.fingerprintHex(p384, kem);
    String id = Identity.idHex(p384, kem);
    AccessStore.Reply reply = store.request(fingerprint, id, name, now, newAllowed);

    return switch (reply) {
      case BUSY -> busy();
      case CLOSED -> answer(503, "error", "closed");
      // Another player's fingerprint, from other keys: the key is refused, so a fingerprint always names one player
      case NOT_THEIRS -> answer(400, "error", "key");
      default -> {
        Routes.Answer ok = answer(200, "fp", fingerprint);
        ok.body().put("state", reply.name().toLowerCase(java.util.Locale.ROOT));
        yield ok;
      }
    };
  }
}
