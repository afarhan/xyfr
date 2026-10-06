// msg.c — the messaging system: stores messages, transmits the pending ones,
// and files what arrives. It holds no part of the messaging UI — that is
// app_chat.c.
// Named msg, not text: `text` in this tree belongs to the GUI.
//
// The division: filesystem.c is the database, stream.c is
// reliable delivery, and this file is the policy — what counts as pending, and
// which message to transmit next.
//
// The log is the queue. An outbound message is an ENTRY_MSG_OUT record and its
// delivery state is the record's DELIVERED bit, so there is no separate queue.
// Delivery is the transport's ack of the last chunk, which is honest only
// because the receiver appends to flash before stream.c acks. Nothing here holds
// a retry timer: a failed transmission leaves the record pending and the next
// lap meets it again.
//
// A message is any size up to FILE_ENTRY_MAX. It is sent in as many stream_write
// calls as it takes, each bounded by stream_can_write, and total_length in the
// head tells the receiver where the message ends.
//
// No buffer holds a whole message. transmit_record reads the entry from
// slot->sent and advances it by what stream_write accepted. On the other side
// every stream_read is appended with file_entry_write, which takes exactly
// FILE_CHUNK bytes until an entry's last write, so struct assembly keeps the
// remainder in tail until the next stream_read completes a chunk. msg_post
// writes the head and the caller's text into the entry directly.
//
// Core 0 only. Portable C (device + host CLI).

#include "hal.h"
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include "kernel.h"         // NOTIFY_* — everything reaches MSG through app_main
#include "stream.h"
#include "netif.h"          // net_time — netif owns the NTP client, so its answer is THE answer
#include "contacts.h"
#include "filesystem.h"
#include "secure_store.h"
#include "keystore.h"
#include "rawflash.h"
#include "wg.h"             // KEY_LEN, get_part_key, crypto_zero
#include "device_record.h"   // device_record.my_private_key
#include "config.h"
#include "msg.h"

// ---- structs ---------------------------------------------------------------
//
// A message is a HEAD followed by the TEXT, and the same bytes are transmitted
// and stored. Neither end re-frames, and a retry rebuilds nothing.
//
// HOW LARGE A MESSAGE MAY BE IS FILE_ENTRY_MAX, named where it is used. This
// file keeps no size of its own: a second name for the store's cap is a second
// place for it to go wrong, and it did — one held the stream's segment size for
// three days and a message was a tenth of what it should have been.

// THE HEAD, in front of every message, transmitted and stored. PRIVATE to this
// file: msg_read() hands back the text alone.
#define MSG_HEADER_MAGIC   0x01A1u   // and the version: one value per format
#define MSG_CONTENT_TEXT   0

#pragma pack(push, 1)
struct msg_header {
	uint16_t magic;
	uint8_t  content_type;
	uint8_t  reserved0;
	uint16_t header_length;      // the text's offset
	uint16_t reserved1;
	uint32_t total_length;       // head + text: where the message ENDS
	uint32_t sender_timestamp;   // 0 = not stated
};
#pragma pack(pop)
_Static_assert(sizeof(struct msg_header) == 16, "the head is 16 bytes");
_Static_assert(sizeof(struct msg_header) % 4 == 0, "32-bit aligned");

// reserved0/reserved1 are written 0 and never read; a later format claims them
// by bumping the magic.
#define MSG_STAGE_BYTES 1024   // staging between flash and the stream, not a protocol size

// The meta slot is struct file_entry_meta and belongs to filesystem.h. msg.c
// writes only its kind: the three app bytes stay zero, because the slot rides
// the entry framing under the VOLUME key and so SURVIVES file_destroy. Nothing
// about a message's content may live there, or a crypto-erased thread stays
// legible. Delivered and read are status bits instead, being mutable in place.

// One thread's outbound state: which message is next, when it may be tried, and
// whether its bytes are with the stream right now. in_flight is the whole of the
// transmission state, because a message goes out in ONE write — so "handed over"
// and "handed over in full" are the same fact, and there is no byte cursor to
// keep. Everything else here is derived from the log and is rebuilt from it.
struct delivery_slot {
	uint32_t partkey;          // meaningful only while record_id != 0
	uint32_t record_id;        // 0 = slot free / nothing pending for this contact
	bool     in_flight;        // every byte is with the stream, awaiting the ack
	uint32_t sent;             // bytes of this record already handed over
	uint32_t next_attempt_ms;  // lap skips this slot until then
	uint32_t backoff_ms;       // doubles per failed attempt, min..max
};

// ---- all of this file's state, so its cost is visible in one place ----------
// The delivery cache: one entry per contact, because a broadcast can leave one
// message pending for every one. It is the answer to "which message next, and
// when?", and it must outlive every failed attempt — which is why the retry
// pacing lives here and not with the bytes in transmission.
static struct delivery_slot *delivery_cache;   // delivery_slots entries, from msg_register
static int delivery_slots;
static int delivery_pick_at;                         // round-robin fairness across contacts

// When the lap may take its next hop. RAM-only on purpose: after a reboot every
// in-flight transmission died with the RAM that tracked it, so the first hop
// should come at once rather than wait out a deadline saved before the reboot.
static uint32_t lap_next_ms;

// Whether the delivery cache has been built for the mount currently up.
static bool delivery_cache_built = false;

extern int kernel_online(void);

int msg_accept = 1;       // test toggle: 0 ⇒ reject inbound (sender sees it undelivered)

uint32_t msg_expiry_secs      = 86400;   // past this a message falls silent, for good
uint32_t msg_hop_interval_ms  = 10000;   // one lap hop per this long
uint32_t msg_retry_min_ms     = 300000;  // first retry after a failed attempt (5 min)
uint32_t msg_retry_max_ms     = 900000;  // backoff cap (mirrors the lookup pump's pacing)

// Forward declarations for the delivery cache, whose users appear above it.
static struct delivery_slot *deliver_slot(uint32_t partkey);
static void     delivery_cache_set(uint32_t partkey, uint32_t record_id);
static uint32_t oldest_pending_for(uint32_t partkey);
static uint32_t next_pending_after(uint32_t partkey, uint32_t after);
static void     delivery_cache_rebuild(void);
static void     delivery_attempt_failed(uint32_t partkey);
static void     msg_pump(void);
static int      msg_app_main(int notification, uint32_t param);

// ---- a message is an entry in its contact's file ------------------------------
// One contact is one file and that contact's thread is its log, so a message
// needs no key of its own and no thread index: file_id is the peer.

// Fill a head for a message we are about to store. The stamp is the SENDING
// peer's clock, so an inbound message that did not state one gets 0 rather than
// our own — "when it arrived" is already the entry's own timestamp, and writing
// it here twice would make a guess look like a statement.
static void head_fill(struct msg_header *out, uint32_t sender_timestamp,
                      uint32_t total_length) {
	memset(out, 0, sizeof *out);
	out->magic            = MSG_HEADER_MAGIC;
	out->header_length    = sizeof *out;
	out->total_length     = total_length;
	out->sender_timestamp = sender_timestamp;
	out->content_type     = MSG_CONTENT_TEXT;
}

// Does this begin with a header, and how long is it? 0 means no. `len` bounds
// header_length, so pass the whole message. A future format may make the header
// longer, hence the range rather than an equality.
static uint16_t head_in_buffer(const void *buf, int len) {
	struct msg_header head;
	if (len < (int)sizeof head)
		return 0;
	memcpy(&head, buf, sizeof head);
	if (head.magic != MSG_HEADER_MAGIC)
		return 0;
	if (head.header_length < sizeof head || head.header_length > (uint16_t)len)
		return 0;
	return head.header_length;
}

// The same question of a stored entry. 0 means it is not readable as a message
// — a call record, whose payload is empty, or a corrupt one.
static uint16_t head_len(uint64_t file_id, uint32_t entry, uint16_t stored_len) {
	struct msg_header head;
	if (stored_len < sizeof head)
		return 0;
	if (file_entry_read(file_id, entry, 0, &head, (int)sizeof head)
	    != (int)sizeof head)
		return 0;
	return head_in_buffer(&head, (int)stored_len);
}

// Store one whole message — head and text, as they are transmitted. Returns the
// entry id, or FILE_NONE; a failure part-way leaves the entry unsealed, which
// the scan skips and the peer retries.
// A chunk can span the end of head and the start of text, so it is filled from both.
static uint32_t store_message_parts(uint64_t file_id,
                                    const void *head, size_t headlen,
                                    const char *text, size_t textlen,
                                    uint8_t kind) {
	size_t total = headlen + textlen;
	if (total > FILE_ENTRY_MAX) {
		hal_debug(LOG_ERROR, "msg: %u bytes is past FILE_ENTRY_MAX\n", (unsigned)total);
		return FILE_NONE;
	}
	struct file_entry_meta meta = { kind, { 0, 0, 0 } };
	uint32_t id = file_entry_create(file_id, (uint16_t)total, 0,
	                                (const uint8_t *)&meta);
	if (id == FILE_NONE) {
		hal_debug(LOG_ERROR, "msg: entry_create failed\n");
		return FILE_NONE;
	}
	uint8_t chunk[FILE_CHUNK];
	size_t done = 0;
	while (done < total) {
		size_t take = FILE_CHUNK;
		if (total - done < take)
			take = total - done;
		for (size_t i = 0; i < take; i++) {
			size_t at = done + i;
			if (at < headlen)
				chunk[i] = ((const uint8_t *)head)[at];
			else
				chunk[i] = (uint8_t)text[at - headlen];
		}
		if (file_entry_write(file_id, id, chunk, (int)take) != (int)take) {
			hal_debug(LOG_ERROR, "msg: entry_write failed at %u\n", (unsigned)done);
			return FILE_NONE;
		}
		done += take;
	}
	if (!file_entry_commit(file_id, id)) {
		hal_debug(LOG_ERROR, "msg: entry_commit failed\n");
		return FILE_NONE;
	}
	return id;
}


// MUST NOT open the payload: delivery_cache_rebuild and the unread scan walk the
// whole store through here. So payload_len is the STORED length; the text length
// costs a read and lives in msg_body_len().
static void msg_record_from_entry(uint32_t entry, const struct file_entry_info *info,
                                  struct msg_record *out) {
	struct file_entry_meta meta;
	memcpy(&meta, info->meta, FILE_META);
	out->record_id   = entry;
	out->contact_id  = (uint32_t)(info->file_id >> 32);
	out->timestamp   = info->timestamp;
	out->payload_len = info->length;
	out->kind        = meta.kind;
	out->status      = info->flags;
}

static bool msg_stat(uint32_t contact_id, uint32_t entry,
                     struct msg_record *out) {
	struct file_entry_info info;
	if (!file_entry_stat(thread_file(contact_id, 0), entry, &info))
		return false;
	msg_record_from_entry(entry, &info, out);
	return true;
}

// One thread changed: repaint whatever is showing it. Both halves are needed —
// screen_invalidate() rebuilds the legacy home list, which names no peer, and
// the post is what the chat screens listen for. Every place that lands a change
// in the log calls this, so neither half can be forgotten at one site.
static void thread_changed(uint32_t partkey) {
	screen_invalidate();
	kernel_post(NOTIFY_MSG_UPDATE, partkey);
}

// Walk every message of every contact, oldest first. Framing only, so it opens
// no contact and decrypts no payload. FILE_NONE ends the walk.
static uint32_t msg_walk(uint32_t cursor, struct msg_record *out) {
	struct file_entry_info info;
	uint32_t id = file_entry_scan_all(cursor, &info);
	if (id != FILE_NONE)
		msg_record_from_entry(id, &info, out);
	return id;
}

// Bound once, at registration: MSG owns PORT_MSG for the life of the device and
// never hands it back. Every stream call below names this handle, which is why
// none of them can name another app's port.
static stream_handle msg_stream;

// A message thread IS the log of that contact's file, so there is nothing to
// mount here: contacts.c owns the one mount (it needs the keystore, which this
// layer has no business knowing about). All this reports is whether that mount
// is up.
//
// IT DOES NOT SYNC THE CACHE. A screen asking whether the store is readable must
// not pay for a walk of it — home's first render called this and wore the whole
// rebuild, which is what held the UI down for 43 seconds at boot. msg_pump syncs
// it when the device is online. Losing the mount clears the flag, so the next
// one syncs again.
static bool ensure_log_ready(void) {
	if (!contacts_store_ready()) {
		delivery_cache_built = false;
		return false;
	}
	return true;
}

int msg_ensure_log(void) {
	if (!ensure_log_ready())
		return 0;
	return 1;
}

// ============================================================
//  Transmitting
// ============================================================

// One stream serves a peer for all of PORT_MSG, so only one of that peer's
// threads may have bytes out at a time. Walked rather than indexed because it is
// asked once per lap hop, never per tick.
static bool peer_is_transmitting(uint32_t partkey) {
	for (int i = 0; i < delivery_slots; i++) {
		if (delivery_cache[i].in_flight && delivery_cache[i].partkey == partkey)
			return true;
	}
	return false;
}

// Hand this thread's pending record to the stream, whole. THE FIRST WRITE TO A
// PEER IS THE STREAM — stream.c creates the slot and netif opens the link — so
// this is also what starts the handshake, and there is nothing to open first.
// Reads the entry from offset 0, not msg_read, so the head goes out with the
// text. Returns false when stream_write accepted nothing.
static bool transmit_record(struct delivery_slot *slot, const struct msg_record *record) {
	(void)record;
	if (slot->in_flight)
		return false;
	uint64_t file = thread_file(slot->partkey, 0);
	struct file_entry_info info;
	if (!file_entry_stat(file, slot->record_id, &info))
		return false;
	uint8_t stage[MSG_STAGE_BYTES];
	uint32_t before = slot->sent;
	while (slot->sent < info.length) {
		int room = stream_can_write(msg_stream, slot->partkey);
		if (room <= 0)
			break;
		uint32_t take = info.length - slot->sent;
		if (take > (uint32_t)room)
			take = (uint32_t)room;
		if (take > sizeof stage)
			take = sizeof stage;
		int got = file_entry_read(file, slot->record_id, (int)slot->sent,
		                          stage, (int)take);
		if (got != (int)take)
			return false;
		int wrote = stream_write(msg_stream, slot->partkey, stage, got);
		if (wrote <= 0)
			break;
		slot->sent += (uint32_t)wrote;
	}
	if (slot->sent >= info.length)
		slot->in_flight = true;
	if (slot->sent == before)
		return false;
	hal_debug(LOG_EVERYTHING, "msg: transmitting record %u to %08x (%u/%u bytes)\n",
	          (unsigned)slot->record_id, (unsigned)slot->partkey,
	          (unsigned)slot->sent, (unsigned)info.length);
	return true;
}

// Is a transmission under way on this slot? `sent` is the bytes already handed
// to the stream and it is cleared the moment one ends, so both fields describe a
// live transmission and neither outlives it.
static bool slot_is_transmitting(const struct delivery_slot *slot) {
	if (slot->record_id == 0)
		return false;
	if (slot->in_flight)
		return true;
	return slot->sent > 0;
}

// One tick of one thread that has bytes out. stream.c is stop-and-wait, so
// can_write turning positive again IS the peer's acknowledgement, and the peer
// only acknowledges what it has appended to flash — which is what makes
// "delivered" mean delivered. Nothing subscribes to an event here.
static void advance_transmission(struct delivery_slot *slot) {
	// A vanished stream acknowledged nothing. can_write() answers "yes" when
	// there is no slot at all, because a write would create one, so without this
	// the test below would read a reaped stream as the peer having taken the body
	// and mark a message delivered that nobody received.
	//
	// `sent` GOES WITH in_flight. The transmission is over, so leaving the byte
	// count behind leaves the slot looking like it is still transmitting: the
	// pump picks it again on the very next tick, finds no stream, and charges
	// another failure. That doubled the backoff every tick and pinned it at
	// msg_retry_max_ms within a second of a peer going away — 427,459 failures
	// on one host client, 384 of them inside one second.
	if (!stream_exists(msg_stream, slot->partkey)) {
		slot->in_flight = false;
		slot->sent      = 0;
		delivery_attempt_failed(slot->partkey);
		return;
	}
	if (stream_can_write(msg_stream, slot->partkey) <= 0)
		return;                             // still outstanding; come back next tick

	// in_flight is set only once slot->sent covers the whole entry. Before that,
	// this ack belongs to an earlier stream_write, so send the rest.
	if (!slot->in_flight) {
		struct msg_record more;
		if (msg_stat(slot->partkey, slot->record_id, &more))
			transmit_record(slot, &more);
		return;
	}

	if (file_entry_flag_clear(thread_file(slot->partkey, 0),
	                          slot->record_id, MSG_ST_DELIVERED)) {
		thread_changed(slot->partkey);
	}
	hal_debug(LOG_EVERYTHING, "msg: record %u delivered to %08x\n",
	          (unsigned)slot->record_id, (unsigned)slot->partkey);
	// Chaining stays inside the thread that just delivered: the next pending
	// message for THIS peer, not whatever is oldest overall. It goes at once,
	// delivery being proof the route works — chained per-thread delivery at
	// stream speed is what moves a broadcast, while the lap is only the retry
	// path. No next one leaves the slot at 0, which frees it.
	uint32_t next_id = next_pending_after(slot->partkey, slot->record_id);
	slot->in_flight = false;
	delivery_cache_set(slot->partkey, next_id);
	if (next_id) {
		struct msg_record next_record;
		if (msg_stat(slot->partkey, next_id, &next_record))
			transmit_record(slot, &next_record);
	}
}

int msg_post(uint32_t partkey, const char *text) {
	if (!ensure_log_ready() || !text) {
		hal_debug(LOG_ERROR, "msg: no store to write to\n");
		return -1;
	}
	struct contact_record contact;
	if (!contact_get(&contact, partkey)) {
		hal_debug(LOG_ERROR, "msg: %08x is not a contact\n", (unsigned)partkey);
		return -1;
	}

	// The head is stored in front of the text, so the two together are one entry
	// and FILE_ENTRY_MAX is the whole of the limit.
	size_t len = strlen(text);
	if (len == 0 || len + sizeof(struct msg_header) > FILE_ENTRY_MAX) {
		hal_debug(LOG_ERROR, "msg: %u bytes is not a message\n", (unsigned)len);
		return -1;
	}

	// net_time(), not get_current_time_seconds(): before the first NTP sync that
	// shim returns a made-up date, and 0 already means "not stated".
	struct msg_header head;
	head_fill(&head, (uint32_t)net_time(), (uint32_t)(sizeof head + len));
	uint32_t id = store_message_parts(thread_file(partkey, 0), &head, sizeof head,
	                                  text, len, ENTRY_MSG_OUT);
	if (id == FILE_NONE) {
		hal_debug(LOG_ERROR, "msg: the store refused %u bytes for %08x\n",
		          (unsigned)(sizeof head + len), (unsigned)partkey);
		return -1;
	}
	thread_changed(partkey);
	struct delivery_slot *slot = deliver_slot(partkey);
	if (!slot) {
		delivery_cache_set(partkey, id);  // the first pending for this thread
		slot = deliver_slot(partkey);
	}
	hal_debug(LOG_EVERYTHING, "msg: queued %u bytes for %08x\n",
	          (unsigned)len, (unsigned)partkey);
	// Try now, online or not: the write is what starts the handshake. Through
	// msg_attempt_delivery because it RESETS THE BACKOFF — a message typed now
	// must not wait out one an older message earned. It sends the thread's oldest
	// pending record, not this one, so the thread stays in order.
	msg_attempt_delivery(partkey);
	return 0;
}

// ============================================================
//  Receiving
// ============================================================
// One peer, one thread: an arriving message is filed under the partkey the
// stream authenticated. Nothing in the message selects a destination.

struct assembly {
	uint32_t userid;
	uint32_t record_id;
	uint32_t expected;
	uint32_t written;
	uint32_t touched_ms;
	uint16_t tail_len;
	uint8_t  tail[FILE_CHUNK];
};
#define MSG_ASSEMBLY_SLOTS 4
static struct assembly assembly_slots[MSG_ASSEMBLY_SLOTS];

static struct assembly *assembly_find(uint32_t userid) {
	for (int i = 0; i < MSG_ASSEMBLY_SLOTS; i++) {
		if (assembly_slots[i].record_id != FILE_NONE &&
		    assembly_slots[i].userid == userid)
			return &assembly_slots[i];
	}
	return NULL;
}

static void assembly_free(struct assembly *a) {
	memset(a, 0, sizeof *a);
	a->record_id = FILE_NONE;
}

// A free slot, or the one with the oldest touched_ms. Reusing a slot leaves its
// entry uncommitted, which filesystem.c reads as torn.
static struct assembly *assembly_take(uint32_t userid) {
	struct assembly *oldest = &assembly_slots[0];
	for (int i = 0; i < MSG_ASSEMBLY_SLOTS; i++) {
		if (assembly_slots[i].record_id == FILE_NONE) {
			oldest = &assembly_slots[i];
			break;
		}
		if ((int32_t)(assembly_slots[i].touched_ms - oldest->touched_ms) < 0)
			oldest = &assembly_slots[i];
	}
	assembly_free(oldest);
	oldest->userid = userid;
	return oldest;
}

// A peer that stops mid-message and never comes back would hold its slot for
// ever, and four such peers would leave nothing for anyone else. The stream that
// was feeding it is reaped after stream_idle_ms, so an assembly quiet for longer
// than that has nothing left to feed it either.
uint32_t msg_assembly_idle_ms = 60000;

static void assembly_expire(void) {
	uint32_t now = now_ms();
	for (int i = 0; i < MSG_ASSEMBLY_SLOTS; i++) {
		struct assembly *a = &assembly_slots[i];
		if (a->record_id == FILE_NONE)
			continue;
		if ((uint32_t)(now - a->touched_ms) < msg_assembly_idle_ms)
			continue;
		hal_debug(LOG_WARNING, "msg: %08x went quiet at %u of %u — part dropped\n",
		          (unsigned)a->userid, (unsigned)a->written, (unsigned)a->expected);
		assembly_free(a);
	}
}

static bool assembly_append(struct assembly *a, uint64_t file,
                            const uint8_t *data, uint32_t len) {
	uint32_t at = 0;
	while (at < len) {
		uint32_t room = FILE_CHUNK - a->tail_len;
		uint32_t take = len - at;
		if (take > room)
			take = room;
		memcpy(a->tail + a->tail_len, data + at, take);
		a->tail_len += (uint16_t)take;
		at          += take;
		bool chunk_full = (a->tail_len == FILE_CHUNK);
		bool is_the_end = (a->written + a->tail_len == a->expected);
		if (!chunk_full && !is_the_end)
			return true;
		if (file_entry_write(file, a->record_id, a->tail, (int)a->tail_len)
		    != (int)a->tail_len)
			return false;
		a->written += a->tail_len;
		a->tail_len = 0;
	}
	return true;
}

static void store_arriving_bytes(uint32_t userid) {
	// stream_read whenever the stream offers, not only when the peer is a
	// contact: the notification repeats until the bytes are read.
	uint8_t arrived[MSG_STAGE_BYTES];
	if (!msg_accept)
		return;                       // leave it unread; the peer keeps it pending
	if (!ensure_log_ready())
		return;
	if (!file_entry_fits(FILE_ENTRY_MAX))
		return;                       // leave it unread; reading is what acks
	int len = stream_read(msg_stream, userid, arrived, sizeof arrived);
	if (len <= 0)
		return;

	uint64_t file = thread_file(userid, 0);
	struct assembly *a = assembly_find(userid);

	// A MESSAGE THAT STARTS AGAIN ABANDONS THE ONE BEFORE IT. The sender restarts
	// from byte 0 whenever its link died mid-transfer, and stream.c resets its
	// receive state for that (seq 0 carrying payload) without telling anyone. An
	// assembly left over from the first attempt then takes the retry's bytes as a
	// continuation of it: 3072 bytes in, one arrived at offset 9840 of a
	// 10016-byte entry and the write ran off the end, after which every remaining
	// segment had no assembly and no head of its own and was dropped. One
	// interrupted message poisoned every attempt after it.
	//
	// The head is the message boundary -- it is in front of every message, which
	// is what the no-assembly branch below already relies on -- so a head arriving
	// mid-assembly means the peer started over.
	if (a && head_in_buffer(arrived, len) != 0) {
		hal_debug(LOG_WARNING, "msg: %08x restarted at %u of %u — dropping the part\n",
		          (unsigned)userid, (unsigned)a->written, (unsigned)a->expected);
		assembly_free(a);
		a = NULL;
	}

	if (!a) {
		// Read and dropped: reading is what stops the notification repeating.
		if (head_in_buffer(arrived, len) == 0) {
			hal_debug(LOG_WARNING, "msg: no header from %08x — dropped\n", (unsigned)userid);
			return;
		}
		struct msg_header head;
		memcpy(&head, arrived, sizeof head);
		// Flash is reserved on the peer's claim, so check it first.
		if (head.total_length < head.header_length ||
		    head.total_length > FILE_ENTRY_MAX ||
		    (uint32_t)len > head.total_length) {
			hal_debug(LOG_WARNING, "msg: %08x claimed %u bytes — refused\n",
			          (unsigned)userid, (unsigned)head.total_length);
			return;
		}

		// The thread is the peer the stream authenticated, and only that one.
		struct file_entry_meta meta = { ENTRY_MSG_IN, { 0, 0, 0 } };
		uint32_t id = file_entry_create(file, (uint16_t)head.total_length, 0,
		                                (const uint8_t *)&meta);
		if (id == FILE_NONE) {
			// No file means no payload key; the sender keeps the record pending.
			hal_debug(LOG_WARNING, "msg: cannot store from %08x — no such thread\n",
			          (unsigned)userid);
			return;
		}
		a = assembly_take(userid);
		a->record_id = id;
		a->expected  = head.total_length;
	}

	a->touched_ms = now_ms();
	if (!assembly_append(a, file, arrived, (uint32_t)len)) {
		hal_debug(LOG_ERROR, "msg: write failed from %08x at %u\n",
		          (unsigned)userid, (unsigned)a->written);
		assembly_free(a);
		return;
	}
	if (a->written < a->expected)
		return;

	// Sealed before stream.c acks: anything acked must already be durable.
	if (!file_entry_commit(file, a->record_id)) {
		hal_debug(LOG_ERROR, "msg: commit failed from %08x\n", (unsigned)userid);
		assembly_free(a);
		return;
	}
	hal_debug(LOG_EVERYTHING, "msg: stored %u bytes from %08x\n",
	          (unsigned)a->written, (unsigned)userid);
	assembly_free(a);
	thread_changed(userid);
}

// ============================================================
//  The delivery cache — "which message should I retry next?"
// ============================================================
// One RAM slot per contact with something pending: the LEAST RECENT undelivered
// outbound record (within the expiry window) and its retry pacing. The log
// stays the truth; this is only an index over it, rebuilt at mount and
// periodically, repaired in place whenever it is found stale. Core 0 only, so
// every mutation below runs to completion before anything else reads it.

static bool message_is_pending(const struct msg_record *record, uint32_t cutoff);

// kernel_time_now() and NOT now_seconds(): a record's stamp was minted through
// the same clock, and a raw wall clock is months behind it until NTP lands — so
// a boot compared entries carrying real time against a cutoff in 2026-05-01.
static uint32_t expiry_cutoff(void) {
	uint32_t now = kernel_time_now();
	if (now > msg_expiry_secs)
		return now - msg_expiry_secs;
	return 0;
}

// A slot is one thread's next retry, and a thread is one contact.
static struct delivery_slot *deliver_slot(uint32_t partkey) {
	for (int i = 0; i < delivery_slots; i++) {
		if (delivery_cache[i].record_id &&
		    delivery_cache[i].partkey == partkey)
			return &delivery_cache[i];
	}
	return NULL;
}

// Try this contact again at the next opportunity, from the shortest backoff.
// Used wherever something has happened that makes waiting pointless: a new
// message queued, a delivery landed, or the peer proving it is reachable.
static void reset_retry_pacing(struct delivery_slot *slot) {
	slot->next_attempt_ms = now_ms();
	slot->backoff_ms      = msg_retry_min_ms;
}

// Point this contact's slot at `record_id` (0 clears it). Every call is an event
// worth acting on promptly, so the retry pacing resets too.
static void delivery_cache_set(uint32_t partkey, uint32_t record_id) {
	struct delivery_slot *slot = deliver_slot(partkey);
	if (!slot && record_id) {
		for (int i = 0; i < delivery_slots; i++) {
			if (delivery_cache[i].record_id == 0) {
				slot = &delivery_cache[i];
				break;
			}
		}
		if (!slot) {
			// Full: this contact waits for the periodic rebuild. Logged,
			// because a silently dropped slot looks like a stalled lap.
			hal_debug(LOG_WARNING, "msg: delivery cache full, %08x deferred\n",
			          (unsigned)partkey);
			return;
		}
	}
	if (!slot)
		return;
	uint32_t was = slot->record_id;
	slot->partkey   = partkey;
	slot->record_id = record_id;
	slot->sent      = 0;
	// in_flight describes the record the slot is pointing AT, so pointing it
	// somewhere else ends it. Bytes already with the stream still go, and the
	// peer may still store them; what this prevents is their acknowledgement
	// landing on whatever record the slot now names. The abandoned one keeps its
	// pending bit and is offered again.
	slot->in_flight = false;
	reset_retry_pacing(slot);
	if (was != record_id) {
		hal_debug(LOG_EVERYTHING, "msg: slot %08x record %u -> %u\n",
		          (unsigned)partkey, (unsigned)was, (unsigned)record_id);
	}
}

// This thread's oldest pending record inside the expiry window, and the repair
// for a stale slot. Walks the THREAD back from its newest entry, keeps the last
// pending one it sees, and stops at the cutoff. Stamps rise with the append
// order, so everything behind that point is older still and none of it can be
// pending — the cost is this contact's recent history, not the size of the log.
static uint32_t oldest_pending_for(uint32_t partkey) {
	uint32_t cutoff = expiry_cutoff();
	uint64_t file_id = thread_file(partkey, 0);
	uint32_t oldest = 0;
	uint32_t id = file_log_newest(file_id);
	while (id != FILE_NONE) {
		struct msg_record record;
		if (!msg_stat(partkey, id, &record))
			break;
		if (record.timestamp < cutoff)
			break;
		if (message_is_pending(&record, cutoff))
			oldest = id;
		id = file_log_older(file_id, id);
	}
	return oldest;
}

// The next pending record after `after` in this thread. A delivery ADVANCES the
// cursor from where it is, rather than deriving the answer again from one end
// of the log.
static uint32_t next_pending_after(uint32_t partkey, uint32_t after) {
	uint32_t cutoff = expiry_cutoff();
	uint64_t file_id = thread_file(partkey, 0);
	uint32_t id = file_log_newer(file_id, after);
	while (id != FILE_NONE) {
		struct msg_record record;
		if (!msg_stat(partkey, id, &record))
			return 0;
		if (message_is_pending(&record, cutoff))
			return id;
		id = file_log_newer(file_id, id);
	}
	return 0;
}

// Sync the cache to what is on flash. ONCE, when the device first comes online
// on this mount — nothing is delivered offline, and the cutoff wants a clock a
// boot may not have yet.
//
// ONE SLOT PER THREAD, so it is built thread by thread: each contact is asked
// for its oldest pending record, and that walk stops at the cutoff. Walking the
// whole log instead cost 43 seconds of a boot with the store 31% full, because
// the sweep it used restarts at the oldest entry on every step.
//
// IT WIPES in_flight ALONG WITH EVERYTHING ELSE, so it runs before anything has
// bytes out: on this path the link has just come up and no message has been
// offered.
static void delivery_cache_rebuild(void) {
	memset(delivery_cache, 0, (size_t)delivery_slots * sizeof *delivery_cache);
	int threads = 0;
	struct contact_record contact;
	for (int i = 0; contact_by_index(i, &contact); i++) {
		uint32_t partkey = contact_userid(&contact);
		uint32_t id = oldest_pending_for(partkey);
		if (id == 0)
			continue;
		delivery_cache_set(partkey, id);
		threads++;
	}
	hal_debug(LOG_EVERYTHING, "msg: cache synced, %d threads pending, cutoff %u\n",
	          threads, (unsigned)expiry_cutoff());
}

// An attempt on this thread ended without the delivered bit: back off, doubling
// to the cap. PEER_UP resets the pacing via delivery_cache_set.
static void delivery_attempt_failed(uint32_t partkey) {
	struct delivery_slot *slot = deliver_slot(partkey);
	if (!slot)
		return;
	uint32_t waited = slot->backoff_ms;
	slot->next_attempt_ms = now_ms() + slot->backoff_ms;
	slot->backoff_ms *= 2;
	if (slot->backoff_ms > msg_retry_max_ms)
		slot->backoff_ms = msg_retry_max_ms;
	// Only when the wait actually grew. A slot held at the cap says the same
	// thing every time, and a line that repeats is worse than no line: Debug
	// drops output when the TX buffer fills, so a flood takes the diagnostics
	// around it with it. That is how a heartbeat came to be missing from a log
	// while the core it reports on was running perfectly well.
	if (slot->backoff_ms != waited) {
		hal_debug(LOG_WARNING, "msg: slot %08x record %u failed, retry in %u ms\n",
		          (unsigned)partkey, (unsigned)slot->record_id, (unsigned)waited);
	}
}

// ============================================================
//  The lap — retrying what has not been delivered
// ============================================================
// One attempt every msg_hop_interval_ms, and no more: the lap is the retry path,
// not the fast path. It reads the delivery cache round-robin and never walks the
// log, because the cache already holds the answer to "which message next?".
// A contact still inside its backoff is skipped and keeps its turn.
//
// Expiry needs no sweep. message_is_pending() compares each record against a
// cutoff computed from the clock, so a message falls silent by no longer
// matching, and nothing has to go and mark it.

static bool message_is_pending(const struct msg_record *record, uint32_t cutoff) {
	if (record->kind != ENTRY_MSG_OUT)
		return false;
	if (msg_is_delivered(*record))
		return false;
	if (record->timestamp < cutoff)
		return false;             // fallen silent: past msg_expiry_secs
	return true;
}

static void advance_pending_lap(void) {
	// One attempt per hop, picked from the delivery cache round-robin — never a
	// log walk (the cache IS the answer to "which message next?"). A slot
	// still inside its retry backoff is skipped; a stale slot (deleted or
	// already-delivered record) is repaired in place and tried on the next hop.
	uint32_t now = now_ms();
	for (int step = 0; step < delivery_slots; step++) {
		int i = (delivery_pick_at + step) % delivery_slots;
		struct delivery_slot *slot = &delivery_cache[i];
		if (slot->record_id == 0)
			continue;
		if ((int32_t)(now - slot->next_attempt_ms) < 0)
			continue;
		delivery_pick_at = (i + 1) % delivery_slots;
		if (peer_is_transmitting(slot->partkey))
			return;               // that peer is busy; the slot keeps its turn
		struct msg_record record;
		bool valid = msg_stat(slot->partkey, slot->record_id, &record) &&
		             record.contact_id == slot->partkey &&
		             message_is_pending(&record, expiry_cutoff());
		if (!valid) {
			// Stale (chat-UI delete, expiry, external change): repair from this
			// thread alone and let the next hop try the repaired target.
			hal_debug(LOG_WARNING, "msg: slot %08x record %u stale, repairing\n",
			          (unsigned)slot->partkey, (unsigned)slot->record_id);
			slot->record_id = oldest_pending_for(slot->partkey);
			slot->sent      = 0;
			return;
		}
		if (!transmit_record(slot, &record))
			delivery_attempt_failed(slot->partkey);
		return;
	}
}

static void msg_pump(void) {
	if (!ensure_log_ready())
		return;
	assembly_expire();
	// Every thread with bytes out moves as fast as its stream allows, on every
	// tick, and is not gated on being online: a transmission already under way
	// should finish the instant its link returns rather than on the next hop.
	for (int i = 0; i < delivery_slots; i++) {
		if (slot_is_transmitting(&delivery_cache[i]))
			advance_transmission(&delivery_cache[i]);
	}
	// The lap only starts work, so there is nothing for it to do offline.
	if (!kernel_online()) {
		static uint32_t offline_log_ms;
		uint32_t t = now_ms();
		if ((uint32_t)(t - offline_log_ms) >= 10000) {
			offline_log_ms = t;
			hal_debug(LOG_EVERYTHING, "msg: lap paused (offline)\n");
		}
		return;
	}
	// Online, and the cache not yet synced on this mount: do it here and once.
	// THERE IS NO PERIODIC REBUILD — every drift source reports itself. A queued
	// message fills its own slot, a delivery advances its own cursor, both
	// deletes repair the slot they touched, and the lap re-tests each slot
	// against the live cutoff on every hop. A ten-minute sweep of the whole
	// store repaired nothing and froze the device for as long as a boot did.
	if (!delivery_cache_built) {
		delivery_cache_built = true;
		delivery_cache_rebuild();
	}
	uint32_t now = now_ms();
	if ((int32_t)(now - lap_next_ms) < 0)
		return;
	lap_next_ms = now + msg_hop_interval_ms;
	advance_pending_lap();
}

// The cache as it stands. Read-only, and the one place its whole state is
// visible at once — every other line reports a single transition, which shows
// what changed and never what is sitting there.
void msg_cache_dump(void) {
	uint32_t now = now_ms();
	hal_debug(LOG_CRITICAL, "msg cache: synced=%d cutoff=%u now=%u\n",
	          (int)delivery_cache_built, (unsigned)expiry_cutoff(),
	          (unsigned)kernel_time_now());
	int shown = 0;
	for (int i = 0; i < delivery_slots; i++) {
		struct delivery_slot *slot = &delivery_cache[i];
		if (slot->record_id == 0)
			continue;
		int32_t due = (int32_t)(slot->next_attempt_ms - now);
		if (due < 0)
			due = 0;
		const char *state = "waiting";
		if (slot->in_flight)
			state = "IN FLIGHT";
		hal_debug(LOG_CRITICAL, "  %08x record %u %s, sent %u, due in %d ms, backoff %u ms\n",
		          (unsigned)slot->partkey, (unsigned)slot->record_id, state,
		          (unsigned)slot->sent, (int)due, (unsigned)slot->backoff_ms);
		shown++;
	}
	hal_debug(LOG_CRITICAL, "msg cache: %d of %d slots\n", shown, delivery_slots);
}

// Send this contact's oldest pending message at once, without waiting for the lap.
// Two things ask for that and they mean the same thing here: the peer just
// completed a handshake, so it is demonstrably reachable, or the user pressed
// Retry. Does nothing if a transmission to that peer is already under way, or if
// the contact has nothing pending.
void msg_attempt_delivery(uint32_t partkey) {
	if (!ensure_log_ready() || peer_is_transmitting(partkey))
		return;
	struct delivery_slot *slot = deliver_slot(partkey);
	if (!slot)
		return;
	reset_retry_pacing(slot);   // an accumulated backoff must not delay this
	struct msg_record record;
	if (msg_stat(slot->partkey, slot->record_id, &record) &&
	    message_is_pending(&record, expiry_cutoff()))
		transmit_record(slot, &record);
}

// A fresh login: let the lap hop immediately instead of waiting out the
// interval that started while we were offline.
void msg_login_prod(void) {
	lap_next_ms = now_ms();
}


// ============================================================
//  The app
// ============================================================

static int msg_app_main(int notification, uint32_t param) {
	switch (notification) {
	case NOTIFY_STREAM_DATA:
		store_arriving_bytes(param);
		return 1;
	case NOTIFY_STREAM_DELIVERED: {
		// The peer acknowledged, so the delivery can be recorded and the next
		// message go at once rather than waiting for the next tick.
		// advance_transmission still asks can_write() itself, so this is a nudge,
		// never a second source of truth. The peer names the thread only through
		// its slot, one being in flight at a time.
		for (int i = 0; i < delivery_slots; i++) {
			if (slot_is_transmitting(&delivery_cache[i]) &&
			    delivery_cache[i].partkey == param) {
				advance_transmission(&delivery_cache[i]);
				break;
			}
		}
		return 1;
	}
	case NOTIFY_PEER_UP:
		msg_attempt_delivery(param);
		return 1;
	case APP_PUMP:
		msg_pump();
		return 1;
	}
	return 0;
}

void msg_register(void) {
	// One slot per file, because a broadcast can leave a message pending for
	// every contact at once.
	if (!delivery_cache) {
		delivery_cache = kernel_alloc((size_t)kernel_cfg->max_files * sizeof *delivery_cache);
		if (!delivery_cache) {
			hal_debug(LOG_CRITICAL, "msg: no delivery cache — nothing will be sent\n");
			return;
		}
		delivery_slots = kernel_cfg->max_files;
	}
	// stream.c caps how many peers can have bytes out at once, so nothing here
	// mirrors that number. Zero streams means nothing can ever be transmitted,
	// which is worth saying rather than letting posted messages sit in the log.
	if (stream_slot_count() == 0)
		hal_debug(LOG_ERROR, "msg: no streams — msg_register ran before stream_init\n");
	// The kernel takes the port and remembers the handler, so stream events
	// arrive here whether or not a chat screen is anywhere on the stack.
	msg_stream = kernel_listen_stream(PORT_MSG, msg_app_main);
	if (!msg_stream)
		hal_debug(LOG_ERROR, "msg: PORT_MSG already bound — MSG has no stream\n");
}

// ---- reading a thread -------------------------------------------------------
// Walks the contact's own log newest-first. There is no index and no cache: the
// entries on flash are the model, and a render is the refresh.

static int recent_from(uint32_t partkey, uint32_t start,
                       struct msg_record out[], int max) {
	if (!ensure_log_ready() || !out || max <= 0)
		return 0;
	int n = 0;
	uint32_t id = start;
	while (id != FILE_NONE && n < max) {
		struct msg_record record;
		if (msg_stat(partkey, id, &record) && !msg_is_deleted(record))
			out[n++] = record;
		id = file_log_older(thread_file(partkey, 0), id);
	}
	return n;
}

int msg_recent(uint32_t partkey, struct msg_record out[], int max) {
	if (!ensure_log_ready())
		return 0;
	return recent_from(partkey, file_log_newest(thread_file(partkey, 0)), out, max);
}

int msg_recent_before(uint32_t partkey, uint32_t before_entry,
                      struct msg_record out[], int max) {
	if (!ensure_log_ready() || before_entry == FILE_NONE)
		return 0;
	return recent_from(partkey,
	                   file_log_older(thread_file(partkey, 0), before_entry), out, max);
}

bool msg_head(uint32_t partkey, struct msg_record *out) {
	if (!ensure_log_ready() || !out)
		return false;
	return recent_from(partkey, file_log_newest(thread_file(partkey, 0)), out, 1) == 1;
}

bool msg_get(uint32_t partkey, uint32_t entry, struct msg_record *out) {
	if (!ensure_log_ready() || !out)
		return false;
	return msg_stat(partkey, entry, out);
}

// How many bytes of TEXT this message has: the stored length less its head.
// Costs one payload read, so only a screen that must know a total up front
// should call it — a screen that just wants text asks msg_read for as much as
// it can show and stops when the read comes back short.
int msg_body_len(uint32_t partkey, uint32_t entry) {
	if (!ensure_log_ready())
		return -1;
	struct file_entry_info info;
	if (!file_entry_stat(thread_file(partkey, 0), entry, &info))
		return -1;
	return (int)info.length - (int)head_len(thread_file(partkey, 0), entry, info.length);
}

// `at` is an offset into the BODY, so the head is stripped here and nowhere
// else. That is what keeps struct msg_header private to this file: every screen
// asks for byte 0 and gets the first byte of the message.
int msg_read(uint32_t partkey, uint32_t entry,
             uint32_t at, void *buf, int max) {
	if (!ensure_log_ready())
		return -1;
	struct file_entry_info info;
	if (!file_entry_stat(thread_file(partkey, 0), entry, &info))
		return -1;
	uint16_t head = head_len(thread_file(partkey, 0), entry, info.length);
	return file_entry_read(thread_file(partkey, 0), entry, head + at, buf, max);
}

// A scan, not an index. Storage keeps no unread counter, so this walks the
// thread newest-first and stops at the first unread inbound. That is the newest
// entry either way, so both a read and an unread thread cost one entry.
bool msg_thread_unread(uint32_t partkey) {
	if (!ensure_log_ready())
		return false;
	uint32_t id = file_log_newest(thread_file(partkey, 0));
	while (id != FILE_NONE) {
		struct msg_record record;
		if (msg_stat(partkey, id, &record) && !msg_is_deleted(record) &&
		    record.kind == ENTRY_MSG_IN && !msg_is_read(record))
			return true;
		id = file_log_older(thread_file(partkey, 0), id);
	}
	return false;
}

void msg_mark_read(uint32_t partkey) {
	if (!ensure_log_ready())
		return;
	uint32_t id = file_log_newest(thread_file(partkey, 0));
	bool touched = false;
	while (id != FILE_NONE) {
		struct msg_record record;
		if (msg_stat(partkey, id, &record) &&
		    record.kind == ENTRY_MSG_IN && !msg_is_read(record)) {
			file_entry_flag_clear(thread_file(partkey, 0), id, MSG_ST_READ);
			touched = true;
		}
		id = file_log_older(thread_file(partkey, 0), id);
	}
	if (touched) {
		file_storage_flush();
		// screen_invalidate() alone rather than thread_changed(): the only caller
		// is the chat screen's own APP_FOREGROUND, which repaints itself straight
		// afterwards, so posting NOTIFY_MSG_UPDATE would only make it repaint
		// twice. Home still needs telling, and that is what this call does.
		screen_invalidate();
	}
}

bool msg_delete_one(uint32_t partkey, uint32_t entry) {
	if (!ensure_log_ready())
		return false;
	if (!file_entry_flag_clear(thread_file(partkey, 0), entry, FILE_DELETED))
		return false;
	file_storage_flush();
	if (deliver_slot(partkey))
		delivery_cache_set(partkey, oldest_pending_for(partkey));
	thread_changed(partkey);
	return true;
}

// ============================================================
//  Deleting
// ============================================================
int msg_delete_thread(uint32_t partkey) {
	if (!ensure_log_ready())
		return -1;
	int n = 0;
	struct msg_record record;
	uint32_t id = msg_walk(0, &record);
	while (id) {
		uint32_t this_id = id;
		bool mine = record.contact_id == partkey;
		id = msg_walk(this_id, &record);
		if (mine && file_entry_flag_clear(thread_file(partkey, 0), this_id, FILE_DELETED))
			n++;
	}
	file_storage_flush();
	delivery_cache_set(partkey, 0);   // the thread is gone; so is its slot
	thread_changed(partkey);
	return n;
}
