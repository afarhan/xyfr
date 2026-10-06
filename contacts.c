// contacts.c — the contacts API (contacts.h) over the filesystem: ONE CONTACT IS
// ONE FILE, of type FILE_TYPE_CONTACT, whose header body is the struct contact_record
// and whose log is that peer's message thread. So a contact and its history are
// one crypto-erase unit, which is what file_destroy means here.
//
// The filesystem is the authoritative store (flash is the source of truth; only a
// small directory sits in RAM). The volume_key it encrypts under comes from the
// keystore, which isn't unlocked until after a fresh device provisions — so the
// store is mounted lazily (ensure_store) the moment the key is available,
// independent of boot ordering.
//
// Writes run on core 0 (the store, the keystore and the filesystem are core-0
// owned). The UI core reads the list live via contact_by_index — see the
// cross-core note on it.

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>        // bool/true/false (plain C — this TU compiles as C, not C++)
#include "hal.h"            // hal_debug
#include "device_record.h"   // device_record — this file reads the device's own key
#include "config.h"
#include "contacts.h"       // struct contact_record + the contacts API
#include "filesystem.h"     // the backend: one contact is one file
#include "secure_store.h"   // CONTACTSBLOCK_BASE_SECTOR, store_unlocked
#include "keystore.h"       // ks_get_volume_key
#include "rawflash.h"       // RAWFLASH_DEV_INTERNAL
#include "wg.h"             // get_part_key, fill_random, crypto_zero, KEY_LEN
#include "netif.h"          // on_query_response — netif's resolution callback
#include "phone_state.h"    // WIFI_* + wifi_get_status (one copy, not a mirror)
#include "kernel.h"         // screen_invalidate

// The contact record IS the file header's body. 138 of 160 bytes today; growing
// struct contact_record past the cap is a compile error here, not a silent truncation.
_Static_assert(sizeof(struct contact_record) <= FILE_INODE_DATA,
               "struct contact_record must fit a file header body");

// ---- the lazy mount, shared by every tenant of the filesystem ----
// The volume_key is unavailable until the keystore is unlocked (a fresh device
// provisions during the first block_write, AFTER contacts_init runs). So every
// entry point ensures the store is up first; it comes up the moment the key
// exists and stays up. Until then, reads return empty and writes fail cleanly.
//
// It lives here rather than in filesystem.c because mounting needs the keystore,
// and filesystem.c deliberately includes nothing above rawflash/hal/wg. msg.c
// calls contacts_store_ready() for the same reason: one mount, not one per tenant
// — the contact inodes and the message logs are the same region.
static bool     s_store_up = false;
static uint32_t s_store_keygen;   // ks_key_generation() the mount was made under

static bool ensure_store(void) {
	// Re-mount if the volume key has been replaced since we mounted. Latching on
	// s_store_up alone leaves a re-provision (store_wipe + block_write) holding
	// the dead key: reads still work from the stale mount, but everything written
	// after is sealed under a key that no longer exists at the next boot.
	if (s_store_up && ks_key_generation() == s_store_keygen)
		return true;
	if (!store_unlocked())  // volume_key not derivable yet
		return false;
	uint8_t vk[KEY_LEN];
	if (!ks_get_volume_key(vk))
		return false;
	uint32_t total = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	if (total <= CONTACTSBLOCK_BASE_SECTOR)
		return false;
	s_store_keygen = ks_key_generation();
	s_store_up = file_storage_mount(RAWFLASH_DEV_INTERNAL, CONTACTSBLOCK_BASE_SECTOR,
	                                total - CONTACTSBLOCK_BASE_SECTOR, vk,
	                                store_current_epoch());
	crypto_zero(vk, sizeof vk);
	if (s_store_up)
		hal_debug(LOG_EVERYTHING, "contacts: store mounted (%d contacts)\n", contact_count());
	return s_store_up;
}

bool contacts_store_ready(void) {
	return ensure_store();
}

// How many contact files exist, and whether one does. Both are walks of the
// in-RAM directory via file_list -- no flash, no key. The walk is quadratic in
// the contact count. file_list ENUMERATES the whole directory -- groups and all
// -- and we pick out the contacts, which is why every one of these walks it and
// tests the type.
int contact_count(void) {
	int n = 0;
	uint64_t id;
	uint8_t type;
	for (int i = 0; file_list(i, &id, &type); i++)
		if (type == FILE_TYPE_CONTACT)
			n++;
	return n;
}

static bool contact_exists(uint32_t userid) {
	uint64_t id;
	uint8_t type;
	for (int i = 0; file_list(i, &id, &type); i++)
		if (type == FILE_TYPE_CONTACT && id == thread_file(userid, 0))
			return true;
	return false;
}

uint32_t contact_userid(const struct contact_record *pc) {
	return get_part_key(pc->key);
}

int contact_key_status(const struct contact_record *pc) {
	if (!pc)
		return CONTACT_KEY_PENDING;
	if (pc->status > CONTACT_KEY_VALID)
		return CONTACT_KEY_PENDING;
	return pc->status;
}

void contact_key_mark_failed(struct contact_record *pc) {
	if (!pc)
		return;
	pc->status = CONTACT_KEY_FAILED;
	memset(pc->key + 4, 0xFF, KEY_LEN - 4);
	pc->relay_ip4  = 0;
	pc->relay_port = 0;
}

void contact_create_pending(struct contact_record *out,
                            const char *name,
                            uint32_t partkey) {
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->flag = (uint8_t)(CONTACT_VERSION_CURRENT << CONTACT_VERSION_SHIFT);
	out->status = CONTACT_KEY_PENDING;
	if (name) {
		strncpy(out->name, name, MAX_NAME - 1);
		out->name[MAX_NAME - 1] = 0;
	}
	out->key[0] = (uint8_t)(partkey >> 24);
	out->key[1] = (uint8_t)(partkey >> 16);
	out->key[2] = (uint8_t)(partkey >>  8);
	out->key[3] = (uint8_t)(partkey      );
	// Only the partkey is known at add time; the remaining 28 bytes arrive with the
	// msg7 lookup reply, which rewrites the record through the normal save path.
	// Fill them 0xFF, not random, because that pattern is the unresolved marker
	// (contact_key_resolved). Random padding would have been indistinguishable from
	// a real key, which is why this needed a separate flag before.
	// contact_key_mark_failed() already used this same convention.
	memset(out->key + 4, 0xFF, KEY_LEN - 4);
	// The per-contact data key encrypts this record's body and every entry in the
	// peer's thread. It is minted once here and never rotated, because rotating it
	// would orphan the stored history; zeroing it (file_destroy) is the
	// crypto-erase.
	fill_random(out->contact_key, KEY_LEN);
}

// ---- contacts CRUD, over the filesystem ----

bool contacts_init(void) {
	ensure_store();   // may defer on a blank device until the keystore provisions
	return true;
}

void contacts_wipe_all(void) {
	if (ensure_store())
		file_storage_wipe();
}

bool contact_get(struct contact_record *pc, uint32_t userid) {
	if (!pc || !ensure_store())
		return false;
	struct file_header h;
	if (!file_header_read(thread_file(userid, 0), &h))
		return false;
	memcpy(pc, h.data, sizeof *pc);
	return true;
}

// Every contact mutation funnels through here: add, rename, a lookup writing the
// resolved key and endpoint, an endpoint refresh, a settings or flag edit. So
// this is the one place that raises the redraw, rather than each call site
// having to remember to.
bool contact_save(struct contact_record *pc) {
	if (!pc || !ensure_store())
		return false;
	struct file_header h;
	memset(&h, 0, sizeof h);
	h.file_id   = thread_file(contact_userid(pc), 0);
	h.file_type = FILE_TYPE_CONTACT;
	memcpy(h.data, pc, sizeof *pc);
	// Create mints this contact's data key; write reuses it. Rotating the key
	// would orphan the thread already written under it, which is why these are
	// different calls rather than one upsert.
	bool ok;
	if (contact_exists(contact_userid(pc)))
		ok = file_header_write(h.file_id, &h);
	else
		ok = file_create(&h);
	if (!ok)
		return false;
	screen_invalidate();
	return true;
}

// Record a contact's relay endpoint as observed on an authenticated inbound
// handshake (netif). Peer handshakes arrive via the relay, so this is the relay
// the peer is currently reachable through, and storing it means subsequent
// handshakes and data frames use the live endpoint without waiting for a lookup.
// No-op if the contact is unknown or the endpoint is unchanged, so the steady
// state — the same relay every time — costs no flash.
void contact_update_endpoint(uint32_t partkey, uint32_t ip4, uint16_t port) {
	struct contact_record c;
	if (!contact_get(&c, partkey))  // unknown peer: nothing to track
		return;
	if (c.relay_ip4 == ip4 && c.relay_port == port)  // unchanged
		return;
	c.relay_ip4  = ip4;
	c.relay_port = port;
	contact_save(&c);
}

bool contact_delete(uint32_t userid) {
	if (!ensure_store())
		return false;
	// A contact and a group are both ONE FILE, so deleting either is this call.
	// It scrubs the file's data key, which makes the record and its whole thread
	// permanently unreadable: one file is one crypto-erase unit.
	if (!file_destroy(thread_file(userid, 0)))
		return false;
	screen_invalidate();                  // the row is gone from the list
	return true;
}

bool contact_ls(int index, struct contact_record *pc, uint32_t *out_userid) {
	if (!pc || !ensure_store())
		return false;
	// `index` counts contacts, not directory slots, so skip the other types.
	uint64_t id;
	uint8_t type;
	int seen = 0;
	for (int i = 0; file_list(i, &id, &type); i++) {
		if (type != FILE_TYPE_CONTACT)
			continue;
		if (seen++ != index)
			continue;
		// The name carries the peer in its high half, which is the userid every
		// caller above this layer speaks.
		uint32_t userid = (uint32_t)(id >> 32);
		if (!contact_get(pc, userid))
			return false;
		if (out_userid)
			*out_userid = userid;
		return true;
	}
	return false;
}

// Iterate the contact list straight from storage, one contact per index
// (0,1,2,... until it returns false). This is what the UI renders from; there is
// no in-RAM cache copy to keep coherent.
//
// Cross-core note: this reads on the caller's core, and the UI core calls it
// directly. That is safe enough today — a read is an XIP memcpy plus an AEAD
// open, and a write parks the other core — so the worst case is a bounded,
// cosmetic flicker of one row during a concurrent write, never a deadlock. When
// the cores are formally separated the contact API itself should mediate
// core-safe access. (Same note in contacts.h.)
bool contact_by_index(int index, struct contact_record *pc) {
	return contact_ls(index, pc, NULL);
}

// =============================================================================
// Contact resolution.
//
// A device with no private key is mid-onboarding. This is the same test go_home()
// and the serial gate use, kept local rather than shared because it is two lines
// and exporting it would put a device-lifecycle question into a storage header.
static bool private_key_absent(void) {
	for (int i = 0; i < KEY_LEN; i++)
		if (device_record.my_private_key[i])
			return false;
	return true;
}

// Registration's half of the onboarding probe (registeration.cpp on device, a
// stub on the host). A platform extern, like net_login and wifi_get_status: the
// portable core names it, the platform provides it.
extern void registration_query_answer(const uint8_t key[32], int status);

// netif owns the mechanism (remote_query and on_query_response: one query in
// flight, the same retry machine as a handshake, on the anonymous socket). What
// lives here is the policy — which contact to ask about, and when — which is a
// walk over the contact store and so belongs with the store.
// =============================================================================

extern time_t get_current_time_seconds(void);   // ui.cpp / host shim (UTC epoch)

// True while netif is working on our query. Set when remote_query() accepts one,
// cleared by on_query_response — which netif calls for EVERY outcome including
// QUERY_TIMEOUT, so this cannot latch on a silent server.
static bool g_query_in_flight = false;

// Retry after a timeout: a single global backoff, because only one query is ever
// in flight. Doubles from min to max and retries FOREVER; any answer resets it.
// Exhaustion never marks a contact failed — that must mean "the server says no
// such user", never "we could not reach the server".
uint32_t lookup_retry_min_ms = 30u*1000u;       // first retry after a timeout
uint32_t lookup_retry_max_ms = 15u*60u*1000u;   // ceiling
static uint32_t g_retry_backoff_ms = 0;         // 0 = no failure outstanding

uint32_t lookup_pace_ms      = 1500;            // min spacing between queries
uint32_t lookup_offline_ms   = 5u*1000u;        // recheck while Wi-Fi/endpoint is down
uint32_t lookup_query_min_ms = 15u*60u*1000u;   // round-robin period, low end
uint32_t lookup_query_max_ms = 20u*60u*1000u;   // ... and high end

static uint32_t g_next_pump_ms  = 0;   // pacing floor between queries
static uint32_t g_next_query_ms = 0;   // when the next round-robin query is due
static uint32_t g_pending_uid   = 0;   // an explicit request awaiting its turn
static int      g_walk_idx      = 0;   // round-robin cursor over the contact table

static uint32_t random_in_range(uint32_t lo, uint32_t hi) {
	if (hi <= lo)
		return lo;
	return lo + (hal_rand() % (hi - lo + 1u));
}

// Resolve this contact as soon as the pump can. The only trigger API.
void contact_lookup_request(uint32_t partkey) {
	if (!partkey)
		return;
	g_pending_uid  = partkey;
	g_next_pump_ms = now_ms();
}

void contact_lookup_init(void) {
	g_query_in_flight = false;   // netif owns the query itself; this is just policy
	g_next_pump_ms  = 0;
	g_pending_uid   = 0;
	g_walk_idx      = 0;
	g_next_query_ms = now_ms() + random_in_range(lookup_query_min_ms, lookup_query_max_ms);
}


static struct missed_request *g_missed_requests;   // missed_slots entries, from contacts_init
static int missed_slots;

static struct missed_request *missed_request_find(uint32_t partkey) {
	for (int i = 0; i < missed_slots; i++)
		if (g_missed_requests[i].part_key == partkey)
			return &g_missed_requests[i];
	return NULL;
}

void contact_knock(const uint8_t *public_key) {
	uint32_t pk = get_part_key((uint8_t *)public_key);
	if (!pk)
		return;
	if (missed_request_find(pk))  // 1. already listed -> nothing to do
		return;
	if (!g_missed_requests) {
		g_missed_requests = kernel_alloc((size_t)kernel_cfg->missed_requests *
		                                 sizeof *g_missed_requests);
		if (!g_missed_requests)
			return;
		missed_slots = kernel_cfg->missed_requests;
	}

	// 2. Not present: take a slot (free, else LRU by last_update) and trigger the
	// query. The pump picks up MR_UNCONFIRMED rows itself, so there is no separate
	// queue and no "is the lookup free" test here.
	struct missed_request *m = NULL;
	for (int i = 0; i < missed_slots; i++)
		if (!g_missed_requests[i].part_key) {
			m = &g_missed_requests[i];
			break;
		}
	if (!m) {
		m = &g_missed_requests[0];
		for (int i = 1; i < missed_slots; i++)
			if ((int32_t)(g_missed_requests[i].last_update - m->last_update) < 0)
				m = &g_missed_requests[i];
	}
	memset(m, 0, sizeof(*m));
	m->part_key    = pk;
	memcpy(m->key, public_key, KEY_LEN);
	m->status      = MR_UNCONFIRMED;
	m->last_update = now_ms();
	m->seen_secs   = (uint32_t)get_current_time_seconds();   // wall clock, for the list
	g_next_pump_ms = now_ms();                   // verify on the next tick
	hal_debug(LOG_EVERYTHING, "knock: %08x recorded — verifying\n", (unsigned)pk);
}

int missed_request_count(void) {
	int n = 0;
	for (int i = 0; i < missed_slots; i++)
		if (g_missed_requests[i].part_key && g_missed_requests[i].status == MR_VALID)
			n++;
	return n;
}

bool missed_request_at(int idx, struct missed_request *out) {
	uint32_t prev = 0;
	bool have_prev = false;
	for (int rank = 0; rank <= idx; rank++) {
		struct missed_request *best = NULL;
		for (int i = 0; i < missed_slots; i++) {
			struct missed_request *m = &g_missed_requests[i];
			if (!m->part_key || m->status != MR_VALID)
				continue;
			if (have_prev && (int32_t)(m->last_update - prev) >= 0)
				continue;
			if (!best || (int32_t)(m->last_update - best->last_update) > 0)
				best = m;
		}
		if (!best)
			return false;
		if (rank == idx) {
			*out = *best;
			return true;
		}
		prev = best->last_update;
		have_prev = true;
	}
	return false;
}

void missed_request_clear(uint32_t partkey) {
	struct missed_request *m = missed_request_find(partkey);
	if (m)  // 3. slot freed once acted on
		memset(m, 0, sizeof(*m));
}


// The record is the flag: a contact needs a query exactly when its own stored
// bytes say so. There is no needs-lookup bit, no queue and no scheduler state,
// which is why a reboot needs no recovery logic — the flash still says what it
// said, so the walk finds the same work with nothing having had to survive.
//
// Two conditions, either one sufficient:
//   - the key tail is unresolved. contact_create_pending fills key[4..31] with
//     0xFF and contact_key_mark_failed does the same, so that pattern (or an
//     all-zero tail) means "we only ever had the partkey".
//   - the address is empty. Without the peer's ingress there is nowhere to send:
//     a relay routes only to clients logged in to IT. A resolved key with a
//     missing endpoint is still unreachable outbound, so it is still work.
bool contact_needs_lookup(const struct contact_record *pc) {
	if (!pc)
		return false;
	if (pc->relay_ip4 == 0)
		return true;
	bool all_ff = true, all_00 = true;
	for (int i = 4; i < KEY_LEN; i++) {
		if (pc->key[i] != 0xFF)
			all_ff = false;
		if (pc->key[i] != 0x00)
			all_00 = false;
	}
	return all_ff || all_00;
}

// The next partkey to query. An unconfirmed knock first (a peer is being refused
// until it resolves), then an explicit request, then — only when the timer says
// so — the next contact round-robin, which is both the periodic refresh and the
// cover traffic. It picks blind, resolved or not: querying only the interesting
// ones is exactly what would make the timing informative.
static bool pick_lookup_target(uint32_t *out_uid) {
	for (int i = 0; i < missed_slots; i++) {
		if (!g_missed_requests[i].part_key || g_missed_requests[i].status != MR_UNCONFIRMED)
			continue;
		*out_uid = g_missed_requests[i].part_key;
		return true;
	}
	if (g_pending_uid) {
		*out_uid = g_pending_uid;
		g_pending_uid = 0;              // one shot; re-triggered if it matters again
		return true;
	}
	int n = contact_count();
	if (n <= 0)
		return false;

	// A contact whose own record says it is unresolved outranks the timer, which
	// is what makes a reboot self-healing: without it, a contact added just before
	// a restart would wait out the whole cover interval before anyone asked about
	// it. One full pass, resuming at the cursor so no record can be starved.
	for (int step = 0; step < n; step++) {
		struct contact_record c;
		int idx = (g_walk_idx + step) % n;
		if (!contact_by_index(idx, &c))
			continue;
		if (!contact_needs_lookup(&c))
			continue;
		g_walk_idx = (idx + 1) % n;
		*out_uid = contact_userid(&c);
		return true;
	}

	if ((int32_t)(now_ms() - g_next_query_ms) < 0)
		return false;                   // nothing needs work, and cover isn't due
	g_next_query_ms = now_ms() + random_in_range(lookup_query_min_ms, lookup_query_max_ms);

	g_walk_idx %= n;
	struct contact_record c;
	if (!contact_by_index(g_walk_idx, &c))
		return false;
	g_walk_idx = (g_walk_idx + 1) % n;  // wrap around the table
	*out_uid = contact_userid(&c);
	return true;
}

void contact_query_pump(void) {
	// One at a time, always. Checked before picking, so a busy query never
	// consumes an explicit request or advances the round-robin cursor.
	if (g_query_in_flight)
		return;
	if ((int32_t)(now_ms() - g_next_pump_ms) < 0)
		return;

	// Preconditions: same gates as the login. We never transmitted, so recheck
	// soon — short enough that Wi-Fi coming back is caught promptly, and never
	// advancing any backoff, because none of this is the peer's fault.
	if (wifi_get_status() != WIFI_ONLINE) {
		g_next_pump_ms = now_ms() + lookup_offline_ms;
		return;
	}
	if (device_record.endpoints[1].ip4 == 0) {
		g_next_pump_ms = now_ms() + lookup_offline_ms;
		return;
	}

	uint32_t uid = 0;
	if (!pick_lookup_target(&uid)) {
		g_next_pump_ms = now_ms() + lookup_pace_ms;   // sleep one pace, never longer
		return;
	}

	// remote_query reads the partkey from key[0..3]; the other 28 bytes are what
	// the answer fills in, so they are deliberately not supplied here. Big-endian
	// byte by byte, matching get_part_key — never a (uint32_t *) cast.
	uint8_t key[KEY_LEN];
	memset(key, 0, sizeof key);
	key[0] = (uint8_t)(uid >> 24);
	key[1] = (uint8_t)(uid >> 16);
	key[2] = (uint8_t)(uid >>  8);
	key[3] = (uint8_t)(uid      );

	if (!remote_query(key)) {
		g_pending_uid  = uid;                         // put it back; nothing is lost
		g_next_pump_ms = now_ms() + lookup_pace_ms;
		return;
	}
	g_query_in_flight = true;
	g_next_pump_ms    = now_ms() + lookup_pace_ms;
	hal_debug(LOG_EVERYTHING, "lookup: querying %08x\n", (unsigned)uid);
}

// ---- the netif seam ----------------------------------------------------------
// netif addresses peers by full public key and keeps NO cache of where they
// live; the contact store is where that fact is kept, so these two are the whole
// interface between them. Both convert at the boundary: netif's address is an
// opaque blob, ours is the ip4+port tuple the record has always held.

// netif asking "where does this key live?", at link bring-up (never per frame).
// A contact with no endpoint is unreachable outbound — a relay routes only to
// clients logged in to IT, so there is nowhere to send — which is exactly why
// contact_needs_lookup counts a missing endpoint as work.
// A link carries the key it was BUILT with, so changing one leaves the live
// link handshaking under the old terms. Drop it and open it again: the new
// handshake happens now, and succeeds or fails where it can be seen, rather
// than deferring either to whenever somebody next sends.
//
// Both calls are needed and neither substitutes for the other.
// netif_open_route() returns early when a link exists, so alone it does
// nothing; netif_drop_route() alone would leave the next handshake until a
// send. ONLY when a route was already alive -- there is nothing to reset
// otherwise, and reopening one nobody was using would leave it idle on the
// anon socket, which has no NAT keepalive.
static void psk_changed(const struct contact_record *c) {
	if (!netif_route_alive(contact_userid(c)))
		return;
	netif_drop_route(c->key);
	netif_open_route(c->key);
	hal_debug(LOG_WARNING, "contacts: %08x key changed — handshaking again\n",
	          (unsigned)contact_userid(c));
}

// Whether this contact has a key at all. All-zero IS none, so this is the one
// question the UI can answer about it -- the key itself is one way and there is
// nothing to show.
bool contact_has_psk(uint32_t userid) {
	struct contact_record c;
	uint8_t zero[KEY_LEN];
	if (!contact_get(&c, userid))
		return false;
	memset(zero, 0, sizeof zero);
	return memcmp(c.psk, zero, KEY_LEN) != 0;
}

// Rounds of BLAKE2s between a passphrase and the key it becomes. Not free, and
// not meant to be: the phrase is short and human, so this is the cost per guess
// for anyone brute-forcing it against a captured handshake -- the one offline
// attack there is, since the stored key is already under the volume key and a
// guess cannot be checked against flash alone. ~0.3s on device, entered once.
uint32_t contact_psk_rounds = 4096;

// Turn a passphrase into this contact's pre-shared key. ONE WAY -- what is
// stored is the hash, so the phrase can never be read back, and both sides
// arrive at the same key by typing the same words.
//
// SALTED WITH THE PAIR, smaller partkey first so both sides compute the same
// salt. The salt is PUBLIC -- partkeys are visible in routing -- so it buys
// nothing against someone attacking this one pair; the rounds are what cost
// them per guess. What it buys is that a phrase reused across contacts does
// not produce the same key twice, so learning one contact's key reveals
// nothing about the others. A precomputed table also stops being reusable
// across pairs, which matters only to someone working through many at once.
//
// An empty phrase removes the key, which is what an all-zero one means.
bool contact_psk_set(uint32_t userid, const char *phrase) {
	struct contact_record c;
	if (!contact_get(&c, userid))
		return false;
	size_t n = 0;
	if (phrase)
		n = strlen(phrase);
	if (n > CONTACT_PSK_PHRASE_MAX)
		return false;
	if (n == 0) {
		memset(c.psk, 0, KEY_LEN);
		if (!contact_save(&c))
			return false;
		psk_changed(&c);
		return true;
	}

	uint8_t pub[KEY_LEN];
	curve25519(pub, device_record.my_private_key, basepoint);
	uint32_t mine = get_part_key(pub);
	uint32_t lo = mine, hi = userid;
	if (userid < mine) {
		lo = userid;
		hi = mine;
	}
	uint8_t salt[8];
	for (int i = 0; i < 4; i++) {
		salt[i]     = (uint8_t)(lo >> (24 - 8 * i));
		salt[4 + i] = (uint8_t)(hi >> (24 - 8 * i));
	}

	uint8_t key[KEY_LEN];
	blake2s(key, KEY_LEN, salt, sizeof salt, phrase, n);
	for (uint32_t i = 1; i < contact_psk_rounds; i++)
		blake2s(key, KEY_LEN, salt, sizeof salt, key, KEY_LEN);
	memcpy(c.psk, key, KEY_LEN);
	crypto_zero(key, sizeof key);
	if (!contact_save(&c))
		return false;
	psk_changed(&c);
	return true;
}

// The pre-shared key for this peer, if it has one. Byte-exact on all 32 for the
// same reason the address is: a partkey collision must not hand a link somebody
// else's secret. False means no PSK, which is the ordinary case and is what
// WireGuard calls an all-zero one.
bool contact_resolve_psk(const uint8_t peer_key[32], uint8_t psk[32]) {
	struct contact_record c;
	if (!contact_get(&c, get_part_key((uint8_t *)peer_key)))
		return false;
	if (memcmp(c.key, peer_key, KEY_LEN) != 0)
		return false;
	uint8_t zero[KEY_LEN];
	memset(zero, 0, sizeof zero);
	if (memcmp(c.psk, zero, KEY_LEN) == 0)
		return false;                 // all-zero IS unset
	memcpy(psk, c.psk, KEY_LEN);
	return true;
}

bool contact_resolve_addr(const uint8_t peer_key[32], uint8_t *addr, int *addr_len) {
	struct contact_record c;
	if (!contact_get(&c, get_part_key((uint8_t *)peer_key)))
		return false;
	// Byte-exact on all 32. The directory is keyed by partkey and a 4-byte
	// collision is an explicit threat in this system — matching a prefix here
	// would hand someone else's address to a link claiming this identity.
	if (memcmp(c.key, peer_key, KEY_LEN) != 0)
		return false;
	if (c.relay_ip4 == 0)
		return false;                 // unresolved: query first
	netif_addr_from_ip4(addr, addr_len, c.relay_ip4, c.relay_port);
	return true;
}

// netif handing back a settled query. Storing it is our job: netif keeps no
// cache, so an answer we do not write down is an answer lost, and the next send
// simply queries again.
void on_query_response(const uint8_t key[32], const uint8_t *addr, int addr_len,
                       int status) {
	uint32_t userid = get_part_key((uint8_t *)key);
	g_query_in_flight = false;        // netif calls us for EVERY outcome, timeout included

	// No private key means onboarding, and the answer is not ours. A device with
	// no identity has no contacts to resolve and is not logged in, so the only
	// query that can be in flight is registration asking whether a freshly
	// generated partkey is already taken. Branching on device state costs netif
	// no second callback: there is exactly one asker at a time either way.
	if (private_key_absent()) {
		registration_query_answer(key, status);
		return;
	}

	struct contact_record c;
	if (!contact_get(&c, userid)) {
		// Not a contact — so this is a knock awaiting verification. The verdict is
		// recorded on its row: VALID makes it visible to the user, INVALID keeps
		// the row so repeat knocks from that key cost no further lookups.
		struct missed_request *m = missed_request_find(userid);
		if (!m) {
			hal_debug(LOG_WARNING, "contacts: query settled for %08x, no such contact\n",
				(unsigned)userid);
			return;
		}
		// Byte-exact on all 32 against the key that actually knocked, so a
		// partkey-collision impostor cannot post a request in the owner's name.
		bool ok = (status == QUERY_FOUND) && (memcmp(key, m->key, KEY_LEN) == 0);
		m->status = MR_INVALID;
		const char *verdict = "not a user (hidden)";
		if (ok) {
			m->status = MR_VALID;
			verdict   = "REGISTERED (shown)";
		}
		m->last_update = now_ms();
		hal_debug(LOG_EVERYTHING, "knock: %08x -> %s\n", (unsigned)userid, verdict);
		return;
	}
	if (status == QUERY_NOUSER) {
		// A verdict about them: the server says this user is not registered.
		g_retry_backoff_ms = 0;         // we were answered; the network is fine
		contact_key_mark_failed(&c);
		contact_save(&c);
		hal_debug(LOG_WARNING, "contacts: %08x — no such user\n", (unsigned)userid);
		return;
	}
	if (status != QUERY_FOUND) {
		// A timeout is a statement about us, so the record is left exactly as it
		// was — but the request is not dropped. Re-arm the same partkey behind a
		// doubling global backoff; without it, an explicit add that times out
		// would wait for the whole round-robin period.
		if (!g_retry_backoff_ms)
			g_retry_backoff_ms = lookup_retry_min_ms;
		else if (g_retry_backoff_ms * 2 > lookup_retry_max_ms)
			g_retry_backoff_ms = lookup_retry_max_ms;
		else
			g_retry_backoff_ms = g_retry_backoff_ms * 2;
		g_pending_uid  = userid;
		g_next_pump_ms = now_ms() + g_retry_backoff_ms;
		hal_debug(LOG_WARNING, "lookup: %08x timed out, retry in %us\n",
			(unsigned)userid, (unsigned)(g_retry_backoff_ms / 1000u));
		return;
	}
	g_retry_backoff_ms = 0;   // an answer of any kind resets the backoff

	// Guard a misrouted answer: the returned key's first 4 bytes must be the
	// partkey we asked about.
	if (get_part_key((uint8_t *)key) != userid) {
		hal_debug(LOG_WARNING, "contacts: %08x partkey-mismatch in response\n",
			(unsigned)userid);
		return;
	}
	uint32_t ip4 = 0;
	uint16_t port = 0;
	if (!netif_addr_to_ip4(addr, addr_len, &ip4, &port)) {
		hal_debug(LOG_ERROR, "contacts: %08x resolved with no usable address\n",
			(unsigned)userid);
		return;
	}
	memcpy(c.key, key, KEY_LEN);      // the 28 bytes we did not have
	c.status     = CONTACT_KEY_VALID;
	c.relay_ip4  = ip4;
	c.relay_port = port;
	contact_save(&c);                 // and that repaints the UI
	hal_debug(LOG_WARNING, "contacts: %08x resolved -> %u.%u.%u.%u:%u\n",
		(unsigned)userid,
		(unsigned)(ip4 & 0xff), (unsigned)((ip4 >> 8) & 0xff),
		(unsigned)((ip4 >> 16) & 0xff), (unsigned)((ip4 >> 24) & 0xff),
		(unsigned)port);
}

// ---- msg7/msg8 format helpers (see contacts.h) ------------------------------
// These serve one caller: registeration.cpp, which runs its own msg7 to check a
// partkey is free before spending an activation code. That query is
// pre-identity — it happens before we have a private key, so it cannot ride
// netif's link — which is why it is not part of remote_query(). Folding it in is
// a job for the activation cutover, alongside netif's missing raw hook for
// msg5/6.
void query_init(struct query *q) {
	memset(&q->peer, 0, sizeof(q->peer));
	memcpy(q->peer.remote_static_public, device_record.server_static_public, KEY_LEN);
}

void query_build(struct query *q, struct msg_contact_request *out, uint32_t partkey) {
	uint8_t pk_be[QUERY_REQUEST_PAYLOAD_LEN];
	pk_be[0] = (uint8_t)(partkey >> 24);
	pk_be[1] = (uint8_t)(partkey >> 16);
	pk_be[2] = (uint8_t)(partkey >>  8);
	pk_be[3] = (uint8_t)(partkey      );
	q->partkey = partkey;
	peer_query_generate(q, MSG_CONTACT_REQUEST, get_fresh_sessionid(),
	                    get_part_key(q->peer.remote_static_public),
	                    pk_be, sizeof(pk_be), out);
}

bool query_parse(struct query *q, const uint8_t *data, uint16_t length,
                 uint8_t *out_status, uint8_t out_key[KEY_LEN],
                 uint32_t *out_relay_ip4, uint16_t *out_relay_port) {
	if (length < sizeof(struct msg_contact_response) || data[0] != MSG_CONTACT_RESPONSE) {
		hal_debug(LOG_ERROR, "query: bad type/length (mt=%u len=%u)\n",
			(unsigned)data[0], (unsigned)length);
		return false;
	}
	uint8_t payload[QUERY_RESPONSE_PAYLOAD_LEN];
	size_t  payload_len = 0;
	if (peer_query_process(q, (uint8_t *)data, length, NULL, 0,
	                       payload, &payload_len) != REQUEST_SUCCESS) {
		hal_debug(LOG_WARNING, "query: peer_query_process failed (ignored)\n");
		return false;
	}
	if (payload_len < QUERY_RESPONSE_PAYLOAD_LEN) {
		hal_debug(LOG_WARNING, "query: short payload %u\n", (unsigned)payload_len);
		return false;
	}
	if (out_status)
		*out_status = payload[0];
	if (out_key)
		memcpy(out_key, payload + 1, KEY_LEN);
	// Trailing 6 bytes: relay_ip4 (octet 0 in the low byte) then relay_port as a
	// big-endian u16, matching struct server_endpoint in device_record.h.
	if (out_relay_ip4)
		memcpy(out_relay_ip4, payload + 1 + KEY_LEN, sizeof(uint32_t));
	if (out_relay_port)
		*out_relay_port = ((uint16_t)payload[1 + KEY_LEN + 4] << 8) |
		                   (uint16_t)payload[1 + KEY_LEN + 5];
	return true;
}

// contacts is not in the packet path. A peer that may not talk to us has no wg
// session, so admission was settled at the handshake (policy.c admit_handshake)
// before any packet could decrypt, and kernel.c decides which app a packet
// reaches. What is left here is the store an app queries to learn who a peer is.

