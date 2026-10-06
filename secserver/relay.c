#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include "net.h"
#include "wg.h"
#include "db.h"
#include "route_pool.h"
#include "relay_tunnel.h"
#include "logstamp.h"
#include <inttypes.h>
#include <sys/select.h>


#define ROUTE_EXPIRY_SECONDS 300
#define ROUTE_RESPONSE_TIMEOUT_SECONDS 10

int udp_sock = -1;
uint32_t server_ip;
uint32_t server_part_key;
uint32_t my_part_key;
uint8_t server_key[KEY_LEN];
static const uint8_t zero_key[KEY_LEN] = { 0 };
static uint64_t login_cookie;

/* --- DoS-hardening tunables (runtime-editable; also settable in relay.conf) ---
 * relay_log_verbose : gate the per-packet metadata logs (endpoints, partkeys,
 *   session_ids). Ungated they storm synchronous stdout under a flood — turning
 *   the "trivially dropped at one hash lookup" path into an I/O bottleneck — and
 *   leak endpoint<->identity correlation the relay is meant to stay blind to
 *   (THREAT_MODEL M-9). 0 = quiet (production); 1 = verbose.
 * msg1_rate_per_dest_ps : max NEW-call msg1 the relay forwards toward any one
 *   logged-in destination per second. Bounds the peer-path reflection/CPU-burn
 *   on a callee (J-4) and per-victim route churn (J-6) even under source
 *   spoofing — the target partkey is fixed. Legit use is ~a couple calls/day,
 *   so a handful/sec is invisible. The token state lives on the destination's
 *   own LOGIN route (no separate table).
 * route_login_reserve : slots kept back so a peer/activation route flood can
 *   never starve new LOGINs (J-6 blast-radius). Only login/server-control
 *   allocs may dip below this floor. */
int relay_log_verbose     = 0;
int msg1_rate_per_dest_ps = 5;
int route_login_reserve   = 1024;

#define RLOG(...) do { if (relay_log_verbose) printf(__VA_ARGS__); } while (0)

time_t next_login_attempt = 0;

static void print_key(const uint8_t *key, int length){
	while(length--)
		printf("%02x", *key++);
	printf("\n");
}

time_t get_current_time_seconds(){
    return time(NULL);
}

struct peer server_handshake;


int validate_public_key(const uint8_t *public_key, void *ctx){
  (void)ctx;
  // Check for all-zero public key
  bool all_zero = true;
  int i;
  for (i = 0; i < KEY_LEN; i++) {
    if (public_key[i] != 0) {
      all_zero = false;
      break;
    }
  }
  if (all_zero) {
    return 0; // Invalid key
  }

  // Additional checks can be added here if necessary

  return 1; // Valid key
}

// Read config file (client.conf) to set server_key, my_private, and server_ip
// Format: server_key=<hex>, my_private=<hex>, server_ip=<ip_address>
static int read_config(char *server_key_hex, char *my_private_hex, char *server_ip_str, char *my_ip_str, uint16_t *my_port) {
  FILE *fp = fopen("relay.conf", "r");
  char line[256];
  char key[32], value[128];

  // No built-in defaults for keys or addresses: they come from relay.conf,
  // never from the source. See relay.conf.example.
  server_key_hex[0] = '\0';
  my_private_hex[0] = '\0';
  server_ip_str[0] = '\0';
  my_ip_str[0] = '\0';
  *my_port = PUBLIC_PORT;

  if (!fp) {
      printf("relay.conf not found, the program will end\n");
      return -1;
  }

  while (fgets(line, sizeof(line), fp)) {
    // Skip comments and empty lines
    if (line[0] == '#' || line[0] == '\n') continue;

    // Parse key=value
    if (sscanf(line, "%31[^=]=%127s", key, value) == 2) {
      if (strcmp(key, "server_key") == 0) {
        strncpy(server_key_hex, value, 99);
        server_key_hex[99] = '\0';
      } else if (strcmp(key, "my_private") == 0) {
        strncpy(my_private_hex, value, 99);
        my_private_hex[99] = '\0';
      } else if (strcmp(key, "server_ip") == 0) {
        strncpy(server_ip_str, value, 99);
        server_ip_str[99] = '\0';
      } else if (strcmp(key, "my_ip") == 0) {
        strncpy(my_ip_str, value, 99);
        my_ip_str[99] = '\0';
      } else if (strcmp(key, "my_port") == 0) {
        int p = atoi(value);
        if (p > 0 && p <= 65535)
          *my_port = (uint16_t)p;
        else
          printf("relay.conf: invalid my_port=%s, using default %u\n", value, PUBLIC_PORT);
      } else if (strcmp(key, "log_verbose") == 0) {
        relay_log_verbose = atoi(value);
      } else if (strcmp(key, "msg1_rate_per_dest_ps") == 0) {
        int v = atoi(value);
        if (v > 0) msg1_rate_per_dest_ps = v;
      } else if (strcmp(key, "route_login_reserve") == 0) {
        int v = atoi(value);
        if (v >= 0) route_login_reserve = v;
      }
    }
  }
  fclose(fp);
  return 0;
}

/* Route storage lives in route_pool.c — a fixed pool with two intrusive hash
 * indexes (by session_id, and by part_key for logged-in users). The relay
 * holds pointers into the pool and writes data fields directly; see
 * route_pool.h for the API + the index-key ownership contract. */

/*
 route_ingress — find-or-create the A-side route for an inbound session,
 with the ENDPOINT-PIN invariant enforced in one place:

   a session_id's (a_ipv4, a_port) is set once, at creation, and never moves.
   A packet claiming an existing session from a different source is rejected
   (returns NULL), never re-stamped onto the new endpoint.

 This is sound because the device keeps session_id stable iff its ephemeral
 socket is stable (the session-lifecycle endpoint pass): a rekey reuses the
 socket, so it reuses the id; a re-establish uses a new socket, so a new id.
 A same-id-from-a-new-endpoint packet is therefore never legitimate — it's a
 route-squat / off-path spoof attempt, so we drop it (closes the M-7 /
 route-hijack angle for the ingress paths).

 On create the route is pinned to (rip,rport) with dest_key + route_type; b_*
 stays zero for the caller to fill (peer call) or msg2 to fill (login). NULL is
 returned on endpoint-pin rejection, the reserve floor (a non-high_prio alloc
 when free slots <= route_login_reserve), or a full pool (the latter logged
 inside route_pool_alloc). high_prio bypasses the reserve floor — login/
 server-control ingress passes true, peer-call/activation/lookup pass false.
 *created reports whether a fresh route was built.
*/
static struct route *route_ingress(uint64_t sid, uint32_t rip, uint16_t rport,
                                    uint32_t dest_key, uint8_t route_type,
                                    bool high_prio, bool *created){
  struct route *r = route_pool_get(sid);
  if (r){
    *created = false;
    if (r->a_ipv4 != rip || r->a_port != rport){
      RLOG("route_ingress: session %016" PRIx64 " endpoint moved to %s:%u — dropping (pin)\n",
             sid, ip2string(rip), rport);
      return NULL;
    }
    return r;
  }
  // Reserve headroom for LOGIN/server-control routes: a peer-call or activation
  // flood may draw the pool down to route_login_reserve but no further, so a new
  // login is always admissible (J-6 blast-radius floor).
  if (!high_prio && route_pool_free_count() <= route_login_reserve){
    RLOG("route_ingress: reserve floor (%d free <= %d) — dropping non-login %016" PRIx64 "\n",
         route_pool_free_count(), route_login_reserve, sid);
    return NULL;
  }
  r = route_pool_alloc(sid);          // NULL only when the pool is full (logs)
  if (!r)
    return NULL;
  r->a_ipv4     = rip;
  r->a_port     = rport;
  r->dest_key   = dest_key;
  r->route_type = route_type;
  *created = true;
  return r;
}

/*
 relay_reply_to_client — the one-shot server->client reply path shared by
 msg8 (contact response) and msg_activation_failed. Both are looked up by the
 echoed session_id, forwarded to the client's A-side endpoint, then dropped
 (the lookup was one-shot). Replies only ever originate from the server.
*/
static void relay_reply_to_client(uint64_t sid, const void *buf, int len, uint32_t rip){
  if (rip != server_ip)
    return;
  struct route *pr = route_pool_get(sid);
  if (!pr)
    return;
  udp_write(udp_sock, (void *)buf, len, pr->a_ipv4, pr->a_port);
  route_pool_free(pr);                // one-shot lookup — drop the route now
}

/*
 tunnel_to_server — wrap a client control datagram (msg1 login / msg5 activate /
 msg7 lookup) inside an msg4 on the relay's authenticated server session and
 send it up. The msg4 AEAD tag authenticates the forward as ours; the server
 unwraps and processes the inner packet. Returns 1 on send, 0 if the relay is
 not logged in or the frame won't fit. (See relay_tunnel.h for the framing.)
*/
static int tunnel_to_server(const uint8_t *inner, size_t inner_len){
  if (server_handshake.remote_index <= 0)
    return 0;
  uint8_t plain[MAX_PACKET_LEN];
  size_t plen = relay_tunnel_wrap(plain, sizeof(plain), inner, inner_len);
  if (!plen)
    return 0;
  uint8_t m4buf[MAX_PACKET_LEN];
  int n = tx_data((struct msg4 *)m4buf, &server_handshake, plain, plen);
  if (n <= 0)
    return 0;
  udp_write(udp_sock, m4buf, n, server_ip, PUBLIC_PORT);
  return 1;
}

/*
 forward_login_msg2 — a client-login msg2 that came back (tunneled) from the
 server. Promote the client's route to LOGIN (publish_login indexes it by the
 client's part_key so peers can call it) and forward the msg2 to the client.
 Same as the direct server-login branch of the msg2 handler, minus the source
 endpoint (the msg2 arrived wrapped, so the server side is the tunnel).
*/
static void forward_login_msg2(struct msg2 *m2, const uint8_t *org_pubkey){
  struct route *pr = route_pool_get(m2->session_id);
  if (!pr){
    RLOG("tunnel: login msg2 for unknown session %016" PRIx64 "; dropping\n",
           m2->session_id);
    return;
  }
  pr->expires_on = time(NULL) + ROUTE_EXPIRY_SECONDS;
  pr->b_ipv4 = server_ip;             // server reached via the tunnel; b_* vestigial for a login route
  pr->b_port = PUBLIC_PORT;
  route_pool_publish_login(pr, m2->sender_index);
  // Cache B's full pubkey (the server appended it to the login reply) so peer
  // calls to B can be cookie-challenged (J-4). Absent from an old server -> all
  // zero -> the cookie gate falls back to the plain forward.
  if (org_pubkey) memcpy(pr->org_pubkey, org_pubkey, ROUTE_PUBKEY_LEN);
  else            memset(pr->org_pubkey, 0, ROUTE_PUBKEY_LEN);
  udp_write(udp_sock, m2, sizeof(struct msg2), pr->a_ipv4, pr->a_port);
}

/*
 dispatch_server_reply — route an unwrapped tunnel reply to the right client.
 The inner datagram is a normal msg2 / msg8 / activation-failed carrying the
 client's session_id, so the existing route table resolves the destination.
*/
static void dispatch_server_reply(const uint8_t *inner, size_t ilen){
  switch (inner[0]){
    case MSG_RESPONSE_CONNECT:
      // The server appends B's 32-byte pubkey after the msg2 (J-4). Accept both
      // the plain msg2 (old server) and the msg2+pubkey form.
      if (ilen == sizeof(struct msg2))
        forward_login_msg2((struct msg2 *)inner, NULL);
      else if (ilen == sizeof(struct msg2) + ROUTE_PUBKEY_LEN)
        forward_login_msg2((struct msg2 *)inner, inner + sizeof(struct msg2));
      break;
    case MSG_CONTACT_RESPONSE:
      if (ilen == sizeof(struct msg_contact_response)){
        const struct msg_contact_response *m8 = (const struct msg_contact_response *)inner;
        relay_reply_to_client(m8->session_id, inner, (int)ilen, server_ip);
      }
      break;
    case MSG_ACTIVATION_FAILED:
      if (ilen == sizeof(struct msg_activation_failed)){
        const struct msg_activation_failed *mf = (const struct msg_activation_failed *)inner;
        relay_reply_to_client(mf->session_id, inner, (int)ilen, server_ip);
      }
      break;
  }
}

void on_msg1_to_server(struct msg1 *m1, uint32_t rip, uint16_t rport){
  uint8_t source_addr_port[6];
  
  memcpy(source_addr_port, &rip, 4);
  memcpy(source_addr_port +4, &rport, 2);

  if(m1->sender_index != server_part_key || server_handshake.remote_index <= 0){
    return;
  }
  //this is a login request, we need to check that the mac2 is correct or issue one.
  if (!memcmp(m1->mac2, zero_key, COOKIE_LEN)){
    //no mac2, we need to issue a cookie challenge
    struct msg3 m3;
    peer_create_cookie_reply(&m3, server_key, m1->mac1, m1->sender_index, m1->session_id, 
			source_addr_port, sizeof(source_addr_port));
    udp_write(udp_sock, &m3, sizeof(m3), rip, rport);
  } else {
    //mac2 is present, check it
    if (check_mac2((const uint8_t *)m1, sizeof(struct msg1)-COOKIE_LEN, source_addr_port, sizeof(source_addr_port), m1->mac2) == false){
      // Stale cookie, not a forgery -- same drift as the peer path above (our
      // secret rotates on our clock, the client's mac2 window runs on its own).
      // Re-challenge rather than drop, or the client re-sends the same stale
      // mac2 until its retry budget dies and login fails outright.
      struct msg3 m3;
      peer_create_cookie_reply(&m3, server_key, m1->mac1, m1->sender_index, m1->session_id,
                               source_addr_port, sizeof(source_addr_port));
      udp_write(udp_sock, &m3, sizeof(m3), rip, rport);
      RLOG("on_msg1_to_server: %08x stale mac2; re-challenged\n", (unsigned)m1->sender_index);
      return;
    }

    // login-pending: PEER is the neutral non-FREE type; org_key is learned
    // and the route promoted to LOGIN (publish_login) when the server's msg2
    // returns — until then it's session-id-only.
    bool created;
    struct route *r = route_ingress(m1->session_id, rip, rport,
                                    server_part_key, ROUTE_TYPE_PEER, true, &created);
    if (!r)
      return;
    r->expires_on = time(NULL) + ROUTE_RESPONSE_TIMEOUT_SECONDS;

    //relay it off to the server, tunneled inside our authenticated session.
    memset(m1->mac2, 0, COOKIE_LEN); //the relay validated the client's cookie; the server trusts the tunnel
    tunnel_to_server((uint8_t *)m1, sizeof(struct msg1));
  }
}

/*
 Peer A wants to call peer B. The relay's job:
 - look up B's login route (B previously logged in via this relay; that
   left a route whose org_key == B's partkey, set when the server's
   msg2 came back).
 - on a NEW session, allocate a route keyed by m1->session_id (the call
   session, distinct from B's login session), with a_* = A's endpoint
   and b_* = B's endpoint. Subsequent msg2 / msg4 traffic for this
   call session_id flows through this route; a rekey reuses it (below).
 - forward msg1 to B with mac2 cleared (B doesn't validate mac2; that's
   the relay's job). No cookie POW on this hop in v1 — see the note in
   the body for why the server-login cookie can't be reused here.
*/
void on_msg1_to_client(struct msg1 *m1, uint32_t rip, uint16_t rport){
  // Return-routability cookie on the peer path (THREAT_MODEL J-4): the cookie's
  // AEAD is keyed under the RESPONDER's static public -- B's pubkey for a peer
  // call -- which the relay now HOLDS, because the server appends it to B's
  // login reply and we cache it on the login route (bsr->org_pubkey). So we can
  // issue a cookie A's wg layer decrypts (its mac1 was computed against B's
  // pubkey, and so is the cookie), forcing a return-routability proof before we
  // forward or seed a route. See the gate in the new-call branch below.

  struct route *r = route_pool_get(m1->session_id);
  if (r) {
    // Existing call route: a rekey or a retransmitted msg1 on the same,
    // endpoint-pinned session. No need to re-resolve B's login route — just
    // refresh + forward to the b-side we already bound. This is the stable
    // session_id paying off: a mid-call rekey is a cheap re-forward, not a
    // new route (nor a phantom incoming call on B).
    if (r->a_ipv4 != rip || r->a_port != rport) {
      RLOG("on_msg1_to_client: session %016" PRIx64 " endpoint moved — dropping (pin)\n",
             m1->session_id);
      return;
    }
  } else {
    // New call: resolve B's login route (org_key == B's partkey, filled when
    // B's server-login msg2 came back) to learn B's endpoint.
    struct route *bsr = route_pool_resolve(m1->sender_index);
    if (!bsr) {
      RLOG("on_msg1_to_client: target %08x not logged in via this relay; dropping\n",
             (unsigned)m1->sender_index);
      return;
    }

    // --- J-4 return-routability cookie -------------------------------------
    // We know B's pubkey (the server appended it to B's login reply, cached on
    // the login route), so we can challenge the caller under it: A's existing wg
    // layer decrypts the cookie (keyed to B's pubkey, which is who A is calling)
    // and retries msg1 with a valid mac2. A SPOOFED source never receives the
    // cookie, so it never proves routability and its msg1 is never forwarded nor
    // route-seeded -- reflection eliminated, with NO per-caller state and nothing
    // learned about the anonymous initiator. Only a PROVEN (real-source) caller
    // reaches the throttle below, so the per-dest cap now bounds only real-source
    // floods, not genuine callers of B. Falls back to the plain forward if B's
    // pubkey is unknown (e.g. an older server that doesn't send it).
    if (memcmp(bsr->org_pubkey, zero_key, ROUTE_PUBKEY_LEN) != 0) {
      uint8_t src[6];
      memcpy(src, &rip, 4);
      memcpy(src + 4, &rport, 2);
      if (!memcmp(m1->mac2, zero_key, COOKIE_LEN)) {
        // No proof yet: challenge and stop. No route seeded, no token spent.
        struct msg3 m3;
        peer_create_cookie_reply(&m3, bsr->org_pubkey, m1->mac1,
                                 m1->sender_index, m1->session_id, src, sizeof src);
        udp_write(udp_sock, &m3, sizeof(m3), rip, rport);
        RLOG("on_msg1_to_client: dest %08x challenged with cookie\n", (unsigned)m1->sender_index);
        return;
      }
      if (!check_mac2((const uint8_t *)m1, sizeof(struct msg1) - COOKIE_LEN,
                      src, sizeof src, m1->mac2)) {
        // STALE, not hostile. Our cookie secret rotates every
        // COOKIE_SECRET_MAX_AGE (120 s), but the client keeps attaching mac2 for
        // its OWN 120 s from when it received the cookie (wg.c
        // peer_handshake_request_generate). The two windows drift, so an honest
        // client periodically presents a well-formed cookie we have already
        // rotated past. DROPPING that is fatal: the client's cookie still looks
        // fresh to itself, so every retry carries the SAME stale mac2 until its
        // budget expires and the handshake dies (the "challenged -> bad mac2 x3"
        // signature). Re-challenge instead -- WireGuard 5.4.7: under load an
        // INVALID mac2 gets a cookie reply, not a drop -- so the client refreshes
        // and its next retry validates. No new DoS surface: this is the same
        // 72-byte reply a zero-mac2 msg1 already draws, still smaller than the
        // 156-byte request, so there is no amplification.
        struct msg3 m3;
        peer_create_cookie_reply(&m3, bsr->org_pubkey, m1->mac1,
                                 m1->sender_index, m1->session_id, src, sizeof src);
        udp_write(udp_sock, &m3, sizeof(m3), rip, rport);
        RLOG("on_msg1_to_client: dest %08x stale mac2; re-challenged\n",
             (unsigned)m1->sender_index);
        return;
      }
      // Return-routability proven -> fall through to the throttle + forward.
    }

    // Per-destination msg1 throttle. State lives on B's LOGIN route (no separate
    // table): a fixed 1-second window caps how many NEW-call handshakes the
    // relay forwards toward B. A spoofed flood aimed at B's partkey can't push
    // past this (the target is fixed), so B's DH load stays under budget (J-4)
    // and per-victim route churn is bounded (J-6). Rekeys/retransmits on an
    // existing call session take the route_pool_get branch above and never
    // reach here, so only genuinely-new call attempts spend a token.
    {
      uint32_t now_s = (uint32_t)time(NULL);
      if (bsr->msg1_win != now_s){ bsr->msg1_win = now_s; bsr->msg1_count = 0; }
      if (bsr->msg1_count >= msg1_rate_per_dest_ps){
        RLOG("on_msg1_to_client: dest %08x over msg1 rate (%d/s); dropping\n",
             (unsigned)m1->sender_index, msg1_rate_per_dest_ps);
        return;
      }
      bsr->msg1_count++;
    }
    // Snapshot B's endpoint before route_pool_alloc — its sweep may invalidate
    // bsr (pointer-lifetime contract, route_pool.h).
    uint32_t b_ipv4 = bsr->a_ipv4;
    uint16_t b_port = bsr->a_port;
    bool created;
    r = route_ingress(m1->session_id, rip, rport,
                      m1->sender_index, ROUTE_TYPE_PEER, false, &created);
    if (!r)                              // pool full or reserve floor (logged inside)
      return;
    r->b_ipv4 = b_ipv4;                  // B's endpoint, from B's login route
    r->b_port = b_port;
    if (relay_log_verbose) route_pool_dump();
  }
  r->expires_on = time(NULL) + ROUTE_RESPONSE_TIMEOUT_SECONDS;

  // Forward to B with mac2 cleared.
  memset(m1->mac2, 0, COOKIE_LEN);
  udp_write(udp_sock, m1, sizeof(struct msg1), r->b_ipv4, r->b_port);
  RLOG("on_msg1_to_client: forwarded to %s:%u (call session=%016" PRIx64 ")\n",
         ip2string(r->b_ipv4), r->b_port, m1->session_id);
}

/*
 Activation request from a brand-new client to the server.
 - The client is not yet in the DB, so we cannot validate it.
 - mac2 holds the 16-byte activation code (NOT a DoS cookie), so we must
   not validate mac2 and must not strip it before forwarding.
 - We do not issue a cookie challenge; activation goes straight through.
 - We still bind a route by session_id so that the eventual msg2 (success)
   or msg_activation_failed (failure) from the server can be returned to
   the right client.
*/
void on_msg_activate_to_server(struct msg1 *m1, uint32_t rip, uint16_t rport){
  if (m1->sender_index != server_part_key || server_handshake.remote_index <= 0){
    return;
  }

  // dest_key == server_part_key; PEER is the neutral pending type (promoted to
  // LOGIN by its msg2 on activation success).
  bool created;
  struct route *r = route_ingress(m1->session_id, rip, rport,
                                  server_part_key, ROUTE_TYPE_PEER, false, &created);
  if (!r)
    return;
  r->expires_on = time(NULL) + ROUTE_RESPONSE_TIMEOUT_SECONDS;

  // Tunnel msg1 verbatim — mac2 carries the activation code; do NOT zero it.
  tunnel_to_server((uint8_t *)m1, sizeof(struct msg1));
}

/*
 Anonymous userid->pubkey lookup (msg7) from a client toward the server.
 Mirrors on_msg1_to_server exactly: cookie POW gating via msg3, then
 forward to server with mac2 zeroed. The relay does NOT need to inspect
 the encrypted payload — single-DH AEAD keys it under the server's static
 pub, which the relay doesn't hold.

 We DO require the relay's own login to the server to be up: msg7 is
 anonymous to the server, but the relay still wants to reach it via the
 same path it uses for msg1.
*/
void on_msg7_to_server(struct msg_contact_request *m7, uint32_t rip, uint16_t rport){
  uint8_t source_addr_port[6];
  memcpy(source_addr_port, &rip, 4);
  memcpy(source_addr_port +4, &rport, 2);

  if (m7->sender_index != server_part_key || server_handshake.remote_index <= 0){
    return;
  }

  if (!memcmp(m7->mac2, zero_key, COOKIE_LEN)){
    // No mac2 — issue a cookie challenge bound to (client endpoint, mac1,
    // session_id), exactly like on_msg1_to_server.
    struct msg3 m3;
    peer_create_cookie_reply(&m3, server_key, m7->mac1, m7->sender_index, m7->session_id,
        source_addr_port, sizeof(source_addr_port));
    udp_write(udp_sock, &m3, sizeof(m3), rip, rport);
    return;
  }

  if (!check_mac2((const uint8_t *)m7,
                  sizeof(struct msg_contact_request) - COOKIE_LEN,
                  source_addr_port, sizeof(source_addr_port), m7->mac2)){
    return;
  }

  bool created;
  struct route *r = route_ingress(m7->session_id, rip, rport,
                                  server_part_key, ROUTE_TYPE_QUERY, false, &created);
  if (!r)
    return;
  // Contact-query routes are one-shot; the msg8 reply frees the route
  // immediately. The TTL here only bounds the worst case (msg8 never
  // arrives) — keep it short so unanswered queries don't linger.
  r->expires_on = time(NULL) + 5;

  // Tunnel to server with mac2 zeroed — the server doesn't validate mac2 for
  // msg7 (peer_query_process doesn't touch it), and the tunnel authenticates
  // the forward.
  memset(m7->mac2, 0, COOKIE_LEN);
  tunnel_to_server((uint8_t *)m7, sizeof(struct msg_contact_request));
}

int main (int argc, char **argv){
	(void)argc;
	(void)argv;
	char server_key_hex[100];
	char my_private_hex[100];
	char server_ip_str[100];
	char my_ip_str[100];
	uint16_t my_port;

	uint8_t my_private[KEY_LEN];
  uint8_t my_public[KEY_LEN];
	struct msg1 m1;

	logstamp_install();   // timestamp every stdout/stderr line from here on

	// Read configuration
	if (read_config(server_key_hex, my_private_hex, server_ip_str, my_ip_str, &my_port) != 0)
		return 1;
	if (strlen(server_key_hex) != KEY_LEN * 2 || strlen(my_private_hex) != KEY_LEN * 2 ||
	    !server_ip_str[0] || !my_ip_str[0]) {
		fprintf(stderr, "relay: relay.conf needs server_key, my_private, server_ip and my_ip; "
		                "copy relay.conf.example\n");
		return 1;
	}

	server_ip = string2ip(server_ip_str);
	hex2bytes(my_private_hex, my_private, KEY_LEN * 2);
	hex2bytes(server_key_hex, server_key, KEY_LEN * 2);

	wireguard_init(my_private);
  wireguard_my_static_public(my_public);
  printf("client static public:");print_key(my_public, KEY_LEN);
  wireguard_ask_mac2(false);
	peer_init(&server_handshake);
	printf("server:");print_key(server_key, KEY_LEN);

  server_part_key = get_part_key(server_key);
  my_part_key = get_part_key(my_public);

  route_pool_init();

  //in a relay, the bind address selects the local interface.
  //my_ip=0.0.0.0 is allowed and means "listen on all local interfaces".
	udp_sock = udp_socket_open(my_ip_str, my_port);
	if (!strcmp(my_ip_str, "0.0.0.0"))
		printf("relay listening on all interfaces, port %u\n", my_port);
	else
		printf("relay listening on %s:%u\n", my_ip_str, my_port);
  uint32_t rip;
  uint16_t rport;
  uint8_t buffin[MAX_PACKET_LEN];
  uint8_t source_addr_port[6];
  int r;
  time_t t_next_sweep = 0;

  login_cookie = get_fresh_sessionid();

	while(1){
		// send handshake request
    if (next_login_attempt <= time(NULL)){
	    peer_handshake_request_generate(&server_handshake, MSG_REQUEST_CONNECT, server_key, login_cookie, &m1);
		  udp_write(udp_sock, &m1, sizeof(m1), server_ip, PUBLIC_PORT);
      next_login_attempt = get_current_time_seconds() + REKEY_TIMEOUT;
    }

    r = udp_read(udp_sock, buffin, sizeof(buffin), &rip, &rport);
    if (r <= 0)
      continue;


    memcpy(source_addr_port, &rip, 4);
    memcpy(source_addr_port +4, &rport, 2);

    switch (buffin[0]) {
    case MSG_REQUEST_CONNECT:
      if (r == sizeof(struct msg1) && server_handshake.remote_index > 0){
        struct msg1 *m1 = (struct msg1 *) buffin;
        //IF this is a user trying to login to the server, through the relay.
        if (m1->sender_index == server_part_key)
          on_msg1_to_server(m1, rip, rport);
        //ELSE this is a call to a logged in user.
        else
          on_msg1_to_client(m1, rip, rport);
      }
      break;
    case MSG_RESPONSE_CONNECT:
      //this message can be from the server, if so, we process it as part of the handshake.
      if (r == sizeof(struct msg2)){
        struct msg2 *m2 = (struct msg2 *) buffin;
        if (rip == server_ip && m2->receiver_index == server_part_key && m2->sender_index == my_part_key){
          int e = peer_response_process(&server_handshake, m2);
          if (!e){
            printf("The relay is online\n");
            printf("server public key:"); print_key(server_handshake.remote_static_public, KEY_LEN);
            //printf("sending key:"); print_key(server_handshake.sending_key, KEY_LEN);
            //printf("receiving key:"); print_key(server_handshake.receiving_key, KEY_LEN);
            next_login_attempt = get_current_time_seconds() + REKEY_AFTER_TIME;
          }
        } else {
          // Discriminate on the route's dest_key, NOT on `rip == server_ip`.
          // When the server and a peer share a host (common in dev/local
          // setups), source-IP comparison can't tell server-login msg2
          // from peer-call msg2. dest_key was stamped at route creation:
          // server_part_key for on_msg1_to_server, B's partkey for
          // on_msg1_to_client.
          struct route *pr = route_pool_get(m2->session_id);
          if (!pr){
            RLOG("msg2: no session %016" PRIx64 "; dropping\n",
                   m2->session_id);
            break;
          }
          pr->expires_on = time(NULL) + ROUTE_EXPIRY_SECONDS;

          if (pr->dest_key == server_part_key){
            // Server-login msg2 — first time we see B's (server's) endpoint.
            // Promote this route to LOGIN and publish the client's part_key
            // (m2->sender_index) into the part_key index so future peer calls
            // to this user can be resolved. publish_login also retires any
            // prior login holding the same part_key (one slot per user), and
            // because ONLY login routes enter that index, a peer-call route
            // can never shadow it — the old org_key-shadow bug is gone.
            pr->b_ipv4 = rip;
            pr->b_port = rport;
            route_pool_publish_login(pr, m2->sender_index);
            udp_write(udp_sock, m2, sizeof(struct msg2), pr->a_ipv4, pr->a_port);
          } else {
            // Peer-call msg2 — b_* was set in on_msg1_to_client; validate
            // the source endpoint matches before forwarding.
            if (pr->b_ipv4 != rip || pr->b_port != rport){
              RLOG("p2p msg2: source %s:%u doesn't match route's b-side; dropping\n",
                     ip2string(rip), rport);
              break;
            }
            RLOG("p2p msg2: relaying to caller at %s:%u\n",
                   ip2string(pr->a_ipv4), pr->a_port);
            udp_write(udp_sock, m2, sizeof(struct msg2), pr->a_ipv4, pr->a_port);
          }
        }
      }
      break;
    case MSG_REQUEST_ACTIVATE:
      if (r == sizeof(struct msg1)){
        struct msg1 *m1 = (struct msg1 *) buffin;
        on_msg_activate_to_server(m1, rip, rport);
      }
      break;
    case MSG_ACTIVATION_FAILED:
      if (r == sizeof(struct msg_activation_failed)){
        struct msg_activation_failed *mf = (struct msg_activation_failed *) buffin;
        relay_reply_to_client(mf->session_id, mf, sizeof(*mf), rip);
      }
      break;
    case MSG_COOKIE_REPLY:
      //we do some sanity check. we get cookies only from the server
      if (r == sizeof(struct msg3) && rip == server_ip){
        struct msg3 *m3 = (struct msg3 *) buffin;
        peer_cookie_process(&server_handshake, m3);
      }
      break;
    case MSG_DATA:
      // Peer-to-peer msg4. Route by session_id to whichever side of
      // the route the packet did NOT come from. The relay is fully
      // end-to-end-blind here: it neither decrypts nor inspects the
      // payload byte. Anything inside (voice samples, text, future
      // payload types) is the two peers' agreement, not the relay's.
      if (r >= (int)sizeof(struct msg4)){
        struct msg4 *m4 = (struct msg4 *) buffin;

        // A msg4 on the relay's OWN server session is a wrapped reply from the
        // server (a client's login msg2 / lookup msg8 / activation-failed).
        // Unwrap it and route the inner datagram to the client by its
        // session_id, exactly as if it had arrived from the server directly.
        if (rip == server_ip && m4->session_id == server_handshake.session_id){
          uint8_t plain[MAX_PACKET_LEN];
          int pl = rx_data(plain, &server_handshake, m4, r);
          if (pl > 0){
            const uint8_t *inner; size_t ilen;
            if (relay_tunnel_unwrap(plain, (size_t)pl, &inner, &ilen) && ilen >= 4)
              dispatch_server_reply(inner, ilen);
          }
          break;
        }

        struct route *pr = route_pool_get(m4->session_id);
        if (!pr){
          // No route for this session — could be a stale frame, an
          // un-handshaked attempt, or voice traffic for a route we
          // expired. Silently drop.
          break;
        }
        uint32_t dst_ip;
        uint16_t dst_port;
        if (rip == pr->a_ipv4 && rport == pr->a_port){
          dst_ip = pr->b_ipv4; dst_port = pr->b_port;
        } else if (rip == pr->b_ipv4 && rport == pr->b_port){
          dst_ip = pr->a_ipv4; dst_port = pr->a_port;
        } else {
          RLOG("msg4: source %s:%u not on route %016" PRIx64 "; dropping\n",
                 ip2string(rip), rport, m4->session_id);
          break;
        }
        pr->expires_on = time(NULL) + ROUTE_EXPIRY_SECONDS;
        udp_write(udp_sock, m4, r, dst_ip, dst_port);
      }
      break;
    case MSG_CONTACT_REQUEST:
      if (r == sizeof(struct msg_contact_request)){
        struct msg_contact_request *m7 = (struct msg_contact_request *) buffin;
        on_msg7_to_server(m7, rip, rport);
      }
      break;
    case MSG_CONTACT_RESPONSE:
      if (r == sizeof(struct msg_contact_response)){
        struct msg_contact_response *m8 = (struct msg_contact_response *) buffin;
        relay_reply_to_client(m8->session_id, m8, sizeof(*m8), rip);
      }
      break;
    } // end of the switch

    // Reclaim expired routes ~1/s instead of per-packet. Lazy-expire in
    // route_pool_get/resolve already prevents stale hits between sweeps, so
    // this is purely to free slots back to the pool.
    if (t_next_sweep <= time(NULL)){
      route_pool_sweep();
      t_next_sweep = time(NULL) + 1;
    }
    // No route_dump() on the per-packet path — it once fired per inbound UDP
    // packet (every voice frame at 25 fps). on_msg1_to_client dumps once when
    // a new call route is actually created.
  }
}

