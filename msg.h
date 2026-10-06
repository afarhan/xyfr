#pragma once

// msg.h — the messaging system, the first application on the stream transport.
//
// Every message rides one stream, streamed to and from the logbook a chunk at a
// time; the whole message is never held in RAM. The log is the queue: an
// outbound message is an ENTRY_MSG_OUT record and delivery is its DELIVERED bit, set
// when the transport acks the last chunk.
// Core 0.

#include <stdint.h>
#include <stdbool.h>
#include "filesystem.h"     // enum entry_kind — a message is one kind of entry


// Status bits on a logged message, ACTIVE LOW like every filesystem flag: the
// bit is SET while the thing has not happened, and marking clears it.
#define MSG_ST_DELIVERED  0x02u
#define MSG_ST_READ       0x08u

// One logged message, as every screen reads it: the filesystem's entry info with
// the FILE_META bytes decoded. record_id is the entry id — the handle to pass
// back to msg_read/msg_delete — and contact_id is the peer, because a thread IS
// that contact's log.
struct msg_record {
	uint32_t record_id;
	uint32_t contact_id;
	uint32_t timestamp;
	uint16_t payload_len;      // BYTES STORED, head included — see msg_body_len
	uint8_t  kind;              // enum entry_kind, always a message one here
	uint8_t  status;
};

#define msg_is_delivered(r)  (!((r).status & MSG_ST_DELIVERED))
#define msg_is_read(r)       (!((r).status & MSG_ST_READ))
#define msg_is_deleted(r)    (!((r).status & FILE_DELETED))


#ifdef __cplusplus
extern "C" {
#endif

// Size the in-flight pool and install the reachability hook. From kernel_init.
void msg_register(void);

int  msg_ensure_log(void);        // mount the logbook if it is not already; 1 if up

// THE way to send a message. Appends an ENTRY_MSG_OUT record for `partkey` and tries
// to send it at once; the lap retries until it is acked or ages past
// msg_expiry_secs. 0 on success, -1 on failure.
int  msg_post(uint32_t partkey, const char *text);

// Core-0 pump: advances the pending lap one hop per msg_hop_interval_ms.

// Try this thread's oldest pending message now, instead of waiting for the lap.
// Call it when waiting has become pointless: the peer completed a handshake and
// is demonstrably reachable, or the user pressed Retry. Does nothing if a send
// to that peer is already under way, or if the thread has nothing pending.
void msg_attempt_delivery(uint32_t partkey);

// A fresh login (offline -> online): let the lap hop at once rather than wait
// out an interval that started while we were offline.
void msg_login_prod(void);

// Crypto-erase every stored record for one peer (the chat's "Delete all Texts").
// Returns the count destroyed, or -1 if the log is not mounted.
int  msg_delete_thread(uint32_t partkey);

// ---- reading a thread -------------------------------------------------------
// The log is the model: every one of these reads flash on demand, and none of
// them caches. A thread is a contact's log, so all of them take the partkey.

// The newest `max` messages, newest at index 0. Returns how many were filled.
int msg_recent(uint32_t partkey, struct msg_record out[], int max);

// The pager: the newest `max` messages OLDER than `before_entry`, newest at
// index 0. Pass the oldest record_id you already hold. Returns how many.
int msg_recent_before(uint32_t partkey, uint32_t before_entry,
                      struct msg_record out[], int max);

// The newest message of a thread. false if the thread is empty.
bool msg_head(uint32_t partkey, struct msg_record *out);

// One message's metadata by its entry id.
bool msg_get(uint32_t partkey, uint32_t entry, struct msg_record *out);

// Read a message's text. `at` is an offset into the TEXT: msg.c keeps framing
// of its own in front of it, and stripping that is this call's job, so byte 0
// is the first byte the user typed. Returns bytes read, -1 on error.
int msg_read(uint32_t partkey, uint32_t entry,
             uint32_t at, void *buf, int max);

// How many bytes of text there are, which is NOT msg_record.payload_len — that
// counts the framing too. Costs a read, so call it only when a total is needed
// up front; otherwise read with msg_read until it returns short. -1 on error.
int msg_body_len(uint32_t partkey, uint32_t entry);

// Any unread inbound message in this thread? A scan, not an index — storage
// keeps no unread counter.
bool msg_thread_unread(uint32_t partkey);

// Clear the unread bit on every inbound message of a thread.
void msg_mark_read(uint32_t partkey);

// Delete ONE message: scrubs its payload in place, keeps the contact and its
// data key, so the thread carries on. (Deleting the CONTACT is what destroys a
// thread wholesale — see contact_delete.)
bool msg_delete_one(uint32_t partkey, uint32_t entry);


// Everything that happens to MSG arrives here (kernel.h notifications).

// The bench surface, msg_debug.c. Console verbs only — no screen and no pump
// calls either of these.
void msg_list(uint32_t partkey);
int  msg_post_to_key(const uint8_t key[32], const char *text);

// The delivery cache as it stands: one line per thread with something pending.
// Read-only.
void msg_cache_dump(void);

extern int      msg_accept;             // test toggle: 0 ⇒ do not take inbound messages
extern uint32_t msg_expiry_secs;        // stop retrying past this (default 86400 = 24 h)
extern uint32_t msg_hop_interval_ms;    // one lap hop per this long (default 10 s)

#ifdef __cplusplus
}
#endif
