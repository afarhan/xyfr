#include "route_pool.h"
#include <stdio.h>
#include <string.h>

/*
 * Fixed pool + two intrusive hash chains. See route_pool.h for the API
 * contract. The data structure, in one breath:
 *
 *   - `slots[]` : the fixed pool. Each slot wraps a public `struct route`
 *     plus two chain links (slot indices) and two bookkeeping flags.
 *   - `bucket_session[]` : hash(session_id) -> head slot index; chained via
 *     `next_session`. Holds every live route.
 *   - `bucket_partkey[]` : hash(org_key) -> head slot index; chained via
 *     `next_partkey`. Holds ONLY published LOGIN routes — which is why
 *     route_pool_resolve() can never return a peer/query route.
 *   - `freelist[]` : a stack of unused slot indices. A slot enters the
 *     freelist ONLY via free (explicit or sweep-of-expired), so a live slot
 *     is never handed out by alloc — that is the expired-only eviction rule.
 */

#define ROUTE_POOL_SIZE          8192
#define ROUTE_NBUCKETS           16384      /* pow2 > 2*POOL => load factor ~0.5 */
#define ROUTE_MASK               (ROUTE_NBUCKETS - 1)
#define ROUTE_NIL                (-1)
#define ROUTE_ALLOC_DEFAULT_TTL  10         /* sane expiry until caller sets it  */

struct route_slot {
  struct route r;       /* MUST be first: we cast `struct route *` back to slot */
  int     next_session; /* chain in bucket_session[], or ROUTE_NIL              */
  int     next_partkey; /* chain in bucket_partkey[], or ROUTE_NIL              */
  uint8_t in_use;       /* slot allocated (linked in the session index)        */
  uint8_t in_partkey;   /* also linked in the part_key index (a LOGIN route)   */
};

static struct route_slot slots[ROUTE_POOL_SIZE];
static int bucket_session[ROUTE_NBUCKETS];
static int bucket_partkey[ROUTE_NBUCKETS];
static int freelist[ROUTE_POOL_SIZE];
static int free_count;

/* ---- hashing: MurmurHash3 finalizers (same mix as the old hash.c) ---- */
static uint64_t mix64(uint64_t x){
  x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
  x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
  x ^= x >> 33; return x;
}
static uint32_t mix32(uint32_t x){
  x ^= x >> 16; x *= 0x7feb352dU; x ^= x >> 15; return x;
}
static int bkt_session(uint64_t sid){ return (int)(mix64(sid) & ROUTE_MASK); }
static int bkt_partkey(uint32_t pk) { return (int)(mix32(pk)  & ROUTE_MASK); }

/* slot index from a public route pointer (route is the first slot member). */
static int slot_index(const struct route *r){
  return (int)((const struct route_slot *)r - slots);
}

/* ---- intrusive chain link/unlink ---- */
static void session_link(int idx){
  int b = bkt_session(slots[idx].r.session_id);
  slots[idx].next_session = bucket_session[b];
  bucket_session[b] = idx;
}
static void session_unlink(int idx){
  int b = bkt_session(slots[idx].r.session_id);
  int cur = bucket_session[b], prev = ROUTE_NIL;
  while (cur != ROUTE_NIL){
    if (cur == idx){
      if (prev == ROUTE_NIL) bucket_session[b] = slots[cur].next_session;
      else                   slots[prev].next_session = slots[cur].next_session;
      break;
    }
    prev = cur; cur = slots[cur].next_session;
  }
  slots[idx].next_session = ROUTE_NIL;
}
static void partkey_link(int idx){
  int b = bkt_partkey(slots[idx].r.org_key);
  slots[idx].next_partkey = bucket_partkey[b];
  bucket_partkey[b] = idx;
  slots[idx].in_partkey = 1;
}
static void partkey_unlink(int idx){
  if (!slots[idx].in_partkey) return;
  int b = bkt_partkey(slots[idx].r.org_key);
  int cur = bucket_partkey[b], prev = ROUTE_NIL;
  while (cur != ROUTE_NIL){
    if (cur == idx){
      if (prev == ROUTE_NIL) bucket_partkey[b] = slots[cur].next_partkey;
      else                   slots[prev].next_partkey = slots[cur].next_partkey;
      break;
    }
    prev = cur; cur = slots[cur].next_partkey;
  }
  slots[idx].next_partkey = ROUTE_NIL;
  slots[idx].in_partkey = 0;
}

/* reclaim a slot back to the freelist (both indexes kept consistent). */
static void free_idx(int idx){
  if (!slots[idx].in_use) return;
  partkey_unlink(idx);            /* no-op unless this is a LOGIN route */
  session_unlink(idx);
  memset(&slots[idx].r, 0, sizeof slots[idx].r);
  slots[idx].in_use = 0;
  freelist[free_count++] = idx;
}

/* ---- public API ---- */

void route_pool_init(void){
  memset(slots, 0, sizeof slots);
  for (int b = 0; b < ROUTE_NBUCKETS; b++){
    bucket_session[b] = ROUTE_NIL;
    bucket_partkey[b] = ROUTE_NIL;
  }
  free_count = 0;
  /* push high-to-low so the first allocs come from slot 0 upward (tidy dumps) */
  for (int i = ROUTE_POOL_SIZE - 1; i >= 0; i--){
    slots[i].next_session = ROUTE_NIL;
    slots[i].next_partkey = ROUTE_NIL;
    freelist[free_count++] = i;
  }
}

struct route *route_pool_get(uint64_t session_id){
  time_t now = time(NULL);
  int b = bkt_session(session_id);
  for (int cur = bucket_session[b]; cur != ROUTE_NIL; cur = slots[cur].next_session){
    if (slots[cur].r.session_id == session_id){
      if (slots[cur].r.expires_on <= now){ free_idx(cur); return NULL; } /* lazy-expire */
      return &slots[cur].r;
    }
  }
  return NULL;
}

struct route *route_pool_resolve(uint32_t part_key){
  time_t now = time(NULL);
  int b = bkt_partkey(part_key);
  for (int cur = bucket_partkey[b]; cur != ROUTE_NIL; cur = slots[cur].next_partkey){
    if (slots[cur].r.org_key == part_key){      /* chain holds only LOGIN routes */
      if (slots[cur].r.expires_on <= now){ free_idx(cur); return NULL; }
      return &slots[cur].r;
    }
  }
  return NULL;
}

struct route *route_pool_alloc(uint64_t session_id){
  struct route *existing = route_pool_get(session_id);
  if (existing) return existing;                /* idempotent: no duplicate sessions */

  if (free_count == 0){
    route_pool_sweep();                         /* reclaim expired — never live */
    if (free_count == 0){
      fprintf(stderr, "route_pool: FULL (%d slots all live) — dropping session %016llx\n",
              ROUTE_POOL_SIZE, (unsigned long long)session_id);
      return NULL;
    }
  }

  int idx = freelist[--free_count];
  struct route_slot *s = &slots[idx];
  memset(&s->r, 0, sizeof s->r);
  s->r.session_id = session_id;
  s->r.expires_on = time(NULL) + ROUTE_ALLOC_DEFAULT_TTL;
  s->r.route_type = ROUTE_TYPE_PEER;            /* neutral non-FREE default; caller refines */
  s->next_partkey = ROUTE_NIL;
  s->in_use = 1;
  s->in_partkey = 0;
  session_link(idx);
  return &s->r;
}

void route_pool_publish_login(struct route *r, uint32_t org_key){
  int idx = slot_index(r);

  /* If this slot was already published (re-publish on the same session),
   * detach it under its old org_key first. */
  if (slots[idx].in_partkey) partkey_unlink(idx);

  /* Retire any OTHER slot currently holding this org_key — a prior login for
   * the same user (one slot per logged-in user). At most one match. */
  int b = bkt_partkey(org_key);
  for (int cur = bucket_partkey[b]; cur != ROUTE_NIL; cur = slots[cur].next_partkey){
    if (slots[cur].r.org_key == org_key){ free_idx(cur); break; }
  }

  r->org_key    = org_key;
  r->route_type = ROUTE_TYPE_LOGIN;
  partkey_link(idx);
}

void route_pool_free(struct route *r){
  if (!r) return;
  free_idx(slot_index(r));
}

int route_pool_sweep(void){
  time_t now = time(NULL);
  int n = 0;
  for (int i = 0; i < ROUTE_POOL_SIZE; i++){
    if (slots[i].in_use && slots[i].r.expires_on <= now){ free_idx(i); n++; }
  }
  return n;
}

int route_pool_free_count(void){
  return free_count;
}

void route_pool_dump(void){
  time_t now = time(NULL);
  int live = ROUTE_POOL_SIZE - free_count;
  printf("\n=== route_pool: %d live / %d slots ===\n", live, ROUTE_POOL_SIZE);
  static const char *tname[] = { "FREE", "LOGIN", "PEER", "QUERY" };
  for (int i = 0; i < ROUTE_POOL_SIZE; i++){
    if (!slots[i].in_use) continue;
    struct route *r = &slots[i].r;
    uint8_t *a = (uint8_t *)&r->a_ipv4;
    uint8_t *bp = (uint8_t *)&r->b_ipv4;
    printf("[%d] %-5s session=%016llx dest=%08x org=%08x%s\n",
           i, r->route_type <= ROUTE_TYPE_QUERY ? tname[r->route_type] : "?",
           (unsigned long long)r->session_id, r->dest_key, r->org_key,
           slots[i].in_partkey ? " (indexed)" : "");
    printf("      A %u.%u.%u.%u:%u   B %u.%u.%u.%u:%u   ttl %lds\n",
           a[0], a[1], a[2], a[3], r->a_port, bp[0], bp[1], bp[2], bp[3], r->b_port,
           (long)(r->expires_on - now));
  }
  printf("=== end ===\n\n");
}

/* ------------------------------------------------------------------------- *
 *  Standalone unit test:  gcc -DROUTE_POOL_TEST route_pool.c -o /tmp/rpt
 * ------------------------------------------------------------------------- */
#ifdef ROUTE_POOL_TEST
#include <assert.h>

#define FAR (time(NULL) + 3600)   /* well in the future */

static struct route *mk(uint64_t sid, uint32_t dest, uint8_t type){
  struct route *r = route_pool_alloc(sid);
  assert(r);
  r->dest_key = dest;
  r->route_type = type;
  r->expires_on = FAR;
  return r;
}

int main(void){
  route_pool_init();

  /* 1. empty table */
  assert(route_pool_get(0x1234) == NULL);
  assert(route_pool_resolve(0xAAAA) == NULL);

  /* 2. alloc + get returns the SAME pointer (stable address) */
  struct route *r1 = mk(0x1111, 0x0000, ROUTE_TYPE_PEER);
  assert(route_pool_get(0x1111) == r1);

  /* 3. alloc is idempotent for an existing session */
  assert(route_pool_alloc(0x1111) == r1);

  /* 4. a PEER route is NOT resolvable by part_key (login-index isolation) */
  r1->dest_key = 0x1111;                 /* peer "dest" part_key */
  assert(route_pool_resolve(0x1111) == NULL);
  assert(route_pool_resolve(0x0000) == NULL);

  /* 5. publish_login makes a route resolvable; sets LOGIN type */
  struct route *r2 = mk(0x2222, 0x0000, ROUTE_TYPE_PEER);
  route_pool_publish_login(r2, 0xAAAA);
  assert(r2->route_type == ROUTE_TYPE_LOGIN);
  assert(route_pool_resolve(0xAAAA) == r2);
  assert(route_pool_resolve(0xAAAA)->session_id == 0x2222);

  /* 6. re-login on a NEW session for the same user retires the old one */
  struct route *r3 = mk(0x3333, 0x0000, ROUTE_TYPE_PEER);
  route_pool_publish_login(r3, 0xAAAA);
  assert(route_pool_resolve(0xAAAA) == r3);      /* now the new slot     */
  assert(route_pool_get(0x2222) == NULL);        /* old login retired    */

  /* 7. free unlinks from BOTH indexes */
  route_pool_free(r3);
  assert(route_pool_resolve(0xAAAA) == NULL);
  assert(route_pool_get(0x3333) == NULL);

  /* 8. lazy-expire on get */
  struct route *r4 = mk(0x4444, 0, ROUTE_TYPE_QUERY);
  r4->expires_on = time(NULL) - 1;               /* already expired */
  assert(route_pool_get(0x4444) == NULL);        /* expired => miss + freed */
  assert(route_pool_get(0x4444) == NULL);

  /* 9. many sessions exercise the collision chains, all retrievable */
  route_pool_init();
  for (uint64_t i = 1; i <= 4000; i++) mk(i, (uint32_t)i, ROUTE_TYPE_PEER);
  for (uint64_t i = 1; i <= 4000; i++){
    struct route *r = route_pool_get(i);
    assert(r && r->session_id == i);
  }

  /* 10. expired-only eviction: fill the pool with LIVE routes, next alloc
   *     FAILS (never evicts a live route); freeing/expiring one lets it in. */
  route_pool_init();
  for (uint64_t i = 1; i <= 8192; i++) mk(i, 0, ROUTE_TYPE_PEER);
  assert(route_pool_alloc(0xDEAD) == NULL);      /* full of live routes */
  struct route *victim = route_pool_get(42);
  assert(victim);
  victim->expires_on = time(NULL) - 1;           /* make ONE expired */
  struct route *r5 = route_pool_alloc(0xDEAD);   /* sweep reclaims it, alloc wins */
  assert(r5 && r5->session_id == 0xDEAD);
  assert(route_pool_get(42) == NULL);            /* the expired one is gone */
  /* a still-LIVE route was untouched */
  assert(route_pool_get(43) && route_pool_get(43)->session_id == 43);

  /* 11. sweep frees only expired, returns the count */
  route_pool_init();
  for (uint64_t i = 1; i <= 10; i++){
    struct route *r = mk(i, 0, ROUTE_TYPE_PEER);
    if (i % 2 == 0) r->expires_on = time(NULL) - 1;  /* expire evens */
  }
  assert(route_pool_sweep() == 5);
  for (uint64_t i = 1; i <= 10; i++)
    assert((route_pool_get(i) != NULL) == (i % 2 == 1));

  printf("route_pool: ALL TESTS PASSED\n");
  return 0;
}
#endif /* ROUTE_POOL_TEST */
