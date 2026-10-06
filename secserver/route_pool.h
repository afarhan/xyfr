#ifndef ROUTE_POOL_H
#define ROUTE_POOL_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* B-pubkey length carried on a LOGIN route (== KEY_LEN; kept as a local literal
 * so this header stays free of the wg headers, per its minimal-deps design). */
#define ROUTE_PUBKEY_LEN 32

/*
 * route_pool — the relay's route table.
 *
 * A fixed pool of `struct route` with two intrusive hash indexes, addressed
 * only by session_id and part_key. No dynamic memory; ephemeral (rebuilds on
 * relay restart). Eviction is EXPIRED-ONLY — a live route is never sacrificed
 * for a new one; a full pool fails the alloc instead.
 *
 * Lookups return a pointer into the pool (like malloc/fopen) or NULL. Slots
 * are fixed-address, so the caller reads AND writes the caller-owned data
 * fields directly through the pointer (refresh = `r->expires_on = now+TTL`).
 *
 * THE ONE CONTRACT that keeps the two indexes consistent:
 *   the module owns the index-key fields; the caller owns the rest.
 *     - session_id            : set only by route_pool_alloc.
 *     - org_key + LOGIN type   : set only by route_pool_publish_login.
 *     - a_*, b_*, dest_key, expires_on : caller writes freely via the pointer.
 *   Writing an index-key field directly desyncs the indexes -- don't.
 *
 * Pointer lifetime: a returned `struct route *` is valid until the next
 * route_pool_alloc / route_pool_free / route_pool_sweep (which may reclaim
 * slots). The single-threaded relay uses it within one packet handler and
 * never caches it across udp_read/sweep.
 *
 * All entry points are single-threaded (the relay's one UDP loop).
 */

/* route_type — informational, plus it tags whether a route is searchable by
 * part_key. Only LOGIN routes live in the part_key index (set via
 * route_pool_publish_login); PEER/QUERY are session-id only. FREE is the
 * module's unused-slot marker. */
#define ROUTE_TYPE_FREE  0
#define ROUTE_TYPE_LOGIN 1   /* client<->server login — searchable by part_key */
#define ROUTE_TYPE_PEER  2   /* peer A<->B call        — session_id only        */
#define ROUTE_TYPE_QUERY 3   /* msg5 activate / msg7 contact — session_id only   */

/* Public route record. In-RAM only (never transmitted, never in EEPROM), so it is
 * naturally aligned — do NOT #pragma pack it. */
struct route {
  uint64_t session_id;  /* OWNED by module (route_pool_alloc)                  */
  uint32_t a_ipv4;      /* "A" = initiator / client side  — caller-writable    */
  uint16_t a_port;
  uint32_t b_ipv4;      /* "B" = responder / server side  — caller-writable    */
  uint16_t b_port;
  uint32_t dest_key;    /* responder part_key             — caller-writable    */
  uint32_t org_key;     /* OWNED by module (publish_login); LOGIN routes only  */
  time_t   expires_on;  /* caller-writable; refresh = `r->expires_on = now+TTL`*/
  uint8_t  route_type;  /* ROUTE_TYPE_*; LOGIN set by route_pool_publish_login */
  uint32_t msg1_win;    /* per-dest msg1 throttle: window (unix sec) — caller-writable */
  uint16_t msg1_count;  /* per-dest msg1 throttle: NEW-call count in msg1_win         */
  /* B's full static public key, delivered by the server alongside B's login
   * reply (THREAT_MODEL J-4). LOGIN routes only; all-zero = not (yet) known.
   * Lets the relay issue a return-routability cookie on peer calls to B without
   * a lookup and without learning anything about the anonymous caller. */
  uint8_t  org_pubkey[ROUTE_PUBKEY_LEN];
};

/* Zero the pool and both indexes. Call once at startup. */
void route_pool_init(void);

/* HOT: pointer to the live route for session_id, or NULL. Fail-closed +
 * lazy-expire (an expired match is freed and NULL returned). */
struct route *route_pool_get(uint64_t session_id);

/* HOT "who is this msg1 for?": pointer to the live LOGIN route whose org_key
 * == part_key, or NULL. Searches the LOGIN-only part_key index, so it can
 * never return a PEER/QUERY route. Lazy-expires. */
struct route *route_pool_resolve(uint32_t part_key);

/* Claim a free or expired slot, link it into the session index under
 * session_id, and return the (zeroed, default-TTL) route. Returns the existing
 * route if one already exists for session_id (idempotent). Returns NULL only
 * when every slot is LIVE (pool full) — never evicts a live route. */
struct route *route_pool_alloc(uint64_t session_id);

/* Promote a route to LOGIN: set r->org_key and route_type, and (re)link it
 * into the part_key index, retiring any prior login holding the same org_key
 * (one slot per logged-in user). */
void route_pool_publish_login(struct route *r, uint32_t org_key);

/* Remove a route now (unlink from both indexes, return its slot). One-shot
 * drop, e.g. after forwarding a contact response / activation failure. */
void route_pool_free(struct route *r);

/* Free every expired slot (both indexes kept consistent). Call ~1/s. Returns
 * the number freed. */
int  route_pool_sweep(void);

/* Slots currently free (capacity minus live routes). Lets the relay enforce a
 * reserve floor so a peer/activation flood can't starve high-priority (login)
 * allocs. */
int  route_pool_free_count(void);

/* Debug: print all live routes. */
void route_pool_dump(void);

#endif /* ROUTE_POOL_H */
