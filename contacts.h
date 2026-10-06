#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "filesystem.h"        // MAX_INODES, and a contact is one of its files
#include "wg.h"                // KEY_LEN

#define MAX_NAME 30       // a contact's display name, including the NUL

// A THREAD'S FILE NAME: the peer in the high half, the channel id in the low.
// Channel 0 is the 1:1 thread with that peer, so a contact's file and each of
// that peer's channels are separate files under one rule. The filesystem never
// looks inside it -- to it the name is one unique 64-bit number.
//
// 16 bits, matching the id the chunk header carries (app_channel.c), so the
// name on the network and the name on flash are the same number. The low half
// has 32, and the top 16 stay unallocated.
static inline uint64_t thread_file(uint32_t partkey, uint16_t channel_id) {
	return ((uint64_t)partkey << 32) | channel_id;
}

#pragma pack(1)
#define CONTACT_VERSION_SHIFT 6
#define CONTACT_VERSION_MASK  0xC0
#define CONTACT_FLAG_MASK     0x3F
#define CONTACT_VERSION_CURRENT 3

// ---- the contact at rest ----------------------------------------------------
// The plaintext body of one contact FILE's inode, zero-padded to
// FILE_INODE_DATA and encrypted under that file's own key. ~138 B, v3.
//
// `flag` bits [7:6] are the on-disk format version and [5:0] are app flags.
// Reordering or resizing any field changes the record — bump the version.
struct contact_record {
	uint8_t  flag;            // [7:6] version (=3), [5:0] app flags
	uint8_t  status;          // CONTACT_KEY_PENDING / FAILED / VALID
	char     name[MAX_NAME];  // null-terminated, up to MAX_NAME-1 displayable
	uint8_t  key[KEY_LEN];    // first 4 bytes always = partkey; tail per status
	uint32_t relay_ip4;       // B's relay (octet 0 in low byte); 0 unless VALID
	uint16_t relay_port;      // 0 unless VALID
	uint8_t  contact_key[KEY_LEN]; // logbook payload DEK (per-contact crypto-erase unit)
	uint8_t  psk[KEY_LEN];         // wireguard pre-shared key; all-zero = unset
	uint32_t settings;             // per-contact bitmap: CONTACT_STAR/BURNER/BLOCKED (+room to grow)
};

// contact_record.settings bits (set from the contact menu). Star: rings/pings even in
// Busy presence. Burner: wiped by the duress PIN (Phase 2). Blocked: handshakes
// always refused at the accept gate (policy.c).
#define CONTACT_STAR    0x00000001u
#define CONTACT_BURNER  0x00000002u
#define CONTACT_BLOCKED 0x00000004u
// Key-verification (THREAT_MODEL §9.5): a VALID contact whose full key the USER
// has confirmed out-of-band is CONTACT_VERIFIED. Three UI states: PENDING (still
// resolving) -> VALID+unverified (usable, orange) -> VALID+VERIFIED (green). The
// first msg/call/PTT/terminal to an unverified contact gates on a Yes/No/Proceed
// screen showing the full key. Defends the compromised-directory case, which the
// wg handshake alone can't (a 32-bit partkey collision is grindable).
#define CONTACT_VERIFIED 0x00000008u
// PTT plays on arrival with no ring and no accept, so anyone able to send it
// could talk into the room. It is therefore off by default and granted per
// contact: policy.c refuses DATA_PTT from a contact without this bit.
#define CONTACT_ALLOW_PTT 0x00000010u

#pragma pack()



// (The old per-contact "logbook"/log_record API was RETIRED in the storage
// cutover and is now removed — message + call history lives in logbook.c
// (logbook_*), a single device-level log, not a per-contact one.)

bool contacts_init(void);

// The filesystem mount, shared by every tenant: contact inodes and message logs
// are the same region, so there is ONE mount and it lives here because it needs
// the keystore. msg.c calls this before touching a log.
bool contacts_store_ready(void);

// How many contact files exist.
int contact_count(void);
void contacts_wipe_all(void);   // empties the contact table + persists
bool contact_get(struct contact_record *pc, uint32_t userid);
bool contact_save(struct contact_record *pc);
// Update a contact's relay endpoint from an authenticated inbound handshake;
// no-op if unknown or unchanged. Called on core 0 (session.c).
void contact_update_endpoint(uint32_t partkey, uint32_t ip4, uint16_t port);
bool contact_delete(uint32_t userid);
bool contact_ls(int index, struct contact_record *pc, uint32_t *out_userid);

// Iterate the contact list straight from storage: copy contact `index` (0,1,2,...)
// into *pc; returns false once past the end. This is the UI's list source (no
// in-RAM cache). CROSS-CORE NOTE: reads the ring on the caller's core — the UI
// core calls it directly. Safe enough today (XIP reads + AEAD; a concurrent ring
// write parks the reader, so worst case is a bounded cosmetic flicker, never a
// deadlock). When the cores are formally separated, the contact API should
// mediate core-safe access; for now the caller's core is its own responsibility.
bool contact_by_index(int index, struct contact_record *pc);

// Userid is the first 4 bytes of pc->key packed big-endian — same derivation
// as wg's get_part_key. Exposed here so callers don't have to pull in wg.h.
uint32_t contact_userid(const struct contact_record *pc);

// THE netif SEAM (netif.h). contact_resolve_addr is the netif_resolve_cb the
// platform passes to frame_init; on_query_response is declared by netif.h and
// defined in contacts.c. Both live here because netif keeps no cache and the
// contact record is where a peer's address is kept.
bool contact_resolve_addr(const uint8_t peer_key[32], uint8_t *addr, int *addr_len);

// The pre-shared key for this peer, or false when it has none.
bool contact_resolve_psk(const uint8_t peer_key[32], uint8_t psk[32]);

// Longest passphrase a secure key may be made from.
#define CONTACT_PSK_PHRASE_MAX 50

// Set this contact's pre-shared key from a passphrase, or remove it with an
// empty one. ONE WAY: the phrase is not stored and cannot be read back, so both
// sides type the same words rather than copying a key about.
bool contact_psk_set(uint32_t userid, const char *phrase);

// Whether one is set. The key is one way, so this is all that can be asked.
bool contact_has_psk(uint32_t userid);
extern uint32_t contact_psk_rounds;

// Does this contact still need resolving? THE RECORD IS THE FLAG — an unresolved
// key tail (all 0xFF/0x00 past the partkey) or an empty endpoint. No stored bit,
// so a reboot needs no recovery logic.
bool contact_needs_lookup(const struct contact_record *pc);

// Status of the full public key associated with a contact. Persisted
// in pc->status. The key tail (key[4..31]) is interpreted per status:
//   PENDING : key[0..3] = partkey; key[4..31] = random padding (NOT
//             zeros — random so any accidental key derivation before
//             lookup completes isn't guessable).
//   FAILED  : key[0..3] = partkey; key[4..31] = 0xFF sentinel.
//   VALID   : key[0..31] = real Curve25519 pubkey.
#define CONTACT_KEY_PENDING 0
#define CONTACT_KEY_FAILED  1
#define CONTACT_KEY_VALID   2

int contact_key_status(const struct contact_record *pc);
void contact_key_mark_failed(struct contact_record *pc);

// Build a fresh PENDING contact: zero the struct, stamp version + status,
// copy name (truncated to MAX_NAME-1), write partkey into key[0..3]
// big-endian, and fill key[4..31] with random bytes. Caller still needs
// to contact_save(out) to persist.
void contact_create_pending(struct contact_record *out,
                            const char *name,
                            uint32_t partkey);

void test_contacts(void);

// ---- anonymous msg7 partkey query (contact_lookup.c) ------------------------
// The transmitted half of a userid->pubkey lookup, shared by the contact-lookup
// and registration's collision probe (registeration.cpp) so the msg7 build and
// the msg8 decode exist once. Each caller keeps its own struct query + request
// slot + policy; only the packet handling is common.
struct query;                     // wg.h
struct msg_contact_request;       // wg.h

// Prepare `q` for a fresh series of queries: zero the peer state and install the
// server's static public key from `block`. Call once per probe, not per retry.
void query_init(struct query *q);

// Build an anonymous msg7 for `partkey` into *out. Fresh ephemeral keypair and
// fresh session_id every call, so this doubles as the request-layer regenerate
// hook (each retry must carry a new ephemeral, and mac2 picks up any cookie that
// arrived since).
void query_build(struct query *q, struct msg_contact_request *out, uint32_t partkey);

// Decode an msg8 reply. False = not a usable reply yet; the caller should leave
// its request slot ACTIVE so request_poll keeps retrying. True fills *out_status
// (0 = registered) and, when registered, the key + relay endpoint. Any of the
// out pointers may be NULL.
bool query_parse(struct query *q, const uint8_t *data, uint16_t length,
                 uint8_t *out_status, uint8_t out_key[KEY_LEN],
                 uint32_t *out_relay_ip4, uint16_t *out_relay_port);

// ---- contact lookup (contact_lookup.c) ----
// Resolves a contact's full pubkey + endpoint from the server (userid -> key via
// msg7/msg8) and refreshes every contact on a round-robin sweep. Polled from
// loop() on core 0; the host stubs these.
void contact_lookup_init(void);
void contact_query_pump(void);
// Jump the refresh round-robin to `partkey` so a freshly-added contact resolves
// on the next pump tick instead of waiting a whole sweep.
// Resolve this contact as soon as the pump can (next tick). Fired when a contact
// is ADDED, when an outbound handshake to it times out (its endpoint may be
// stale), and by the chat-open path. Named for WHEN it acts; it replaced
// contact_lookup_focus(), whose "focus" was a UI term and which was the ONLY
// thing that could wake a pump that otherwise slept 20-40 minutes.
void contact_lookup_request(uint32_t partkey);

// ---- missed requests: the knock list (contact_lookup.c) ---------------------
// A handshake from a key that is NOT a contact is always REFUSED — a stranger
// never gets a session, so nothing they send can ever reach the logbook. What
// survives the refusal is the knock, held HERE and NOT in the contact ring (the
// ring must never fill with spam ids). This is the "give me a missed call, I'll
// add you" flow: the user reviews the list and Adds / Ignores / Blocks.
//
// The table doubles as the verification cache, so there is no second structure.
// A knock is only SHOWN once the server confirms the key is a registered user:
// a keypair is free, but a registration costs an activation code, so gating the
// ROW on registration is what makes a slot here cost real money. Without it an
// attacker mints a fresh key per knock and churns the list faster than it can
// be read.

#define MR_UNCONFIRMED 0   // recorded; server check pending. Not shown.
#define MR_VALID       1   // confirmed registered user. Shown to the user.
#define MR_INVALID     2   // server says no such user. Hidden, but KEPT so repeat
                           //   knocks from that key cost no further lookups.

struct missed_request {
	uint32_t part_key;        // 0 = free slot
	uint8_t  key[KEY_LEN];    // full wg static public — what "Add as contact" needs
	uint8_t  status;          // MR_*
	uint32_t last_update;     // now_ms of the last knock/verdict; the LRU key
	uint32_t seen_secs;       // wall-clock (UTC epoch) of the first knock, for display
};

// Record a refused handshake (policy.c admit_handshake). Partkey already in the
// table => nothing to do, so repeat knocks from one key collapse onto one row.
// Otherwise take a slot (free, else LRU on last_update) and trigger the lookup.
void contact_knock(const uint8_t *public_key);

// Count of MR_VALID rows — the home screen's "Requests from (N) users".
int  missed_request_count(void);
// i-th MR_VALID row, newest first. False past the end.
bool missed_request_at(int i, struct missed_request *out);
// Free the slot once the user has acted (Add / Ignore / Block).
void missed_request_clear(uint32_t partkey);

// The identity-anonymous ephemeral UDP socket lookups leave on (net_open(0), a
// FRESH source port distinct from the login socket) so a relay/observer can't tie
// lookup traffic to our login identity (THREAT_MODEL 10.4). NULL until the first
// lookup opens it; the kernel's udp_read drains it each tick (dispatch is by
// session_id, so the arrival socket is irrelevant to routing). Host stub -> NULL.
// Declared with the bare struct tag so contacts.h needn't pull in hal.h.
// (contact_lookup_socket is GONE — netif owns the anonymous socket and drains it.)


#ifdef __cplusplus
}
#endif
