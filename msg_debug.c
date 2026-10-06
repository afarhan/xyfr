// msg_debug.c — the bench surface for the messaging system: dump a stored
// thread, and send to a peer named by its raw public key.
//
// It is kept out of msg.c deliberately: nothing here is reached from a screen or
// a pump, only from the serial and cmdq test verbs (`msg-list`, `msg-key`,
// `msg-bulk`), and between them these two functions use just two of the engine's
// public calls, msg_ensure_log() and msg_post().
//
// Core 0. Portable C.

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "hal.h"
#include "msg.h"
#include "contacts.h"
#include "device_record.h"
#include "stream.h"
#include "wg.h"

// One page of a thread, from the same place the engine takes it: a dump reads a
// page at a time for the same reason the engine writes one.
#define MSG_CHUNK FILE_CHUNK

void msg_list(uint32_t partkey) {
	if (!msg_ensure_log()) {
		hal_debug(LOG_WARNING, "msg: log not ready\n");
		return;
	}
	struct contact_record ct;
	char name[9];
	if (contact_get(&ct, partkey))
		snprintf(name, sizeof name, "%.8s", ct.name);
	else
		snprintf(name, sizeof name, "%08x", (unsigned)partkey);

	struct msg_record recs[32];
	int n = msg_recent(partkey, recs, 32);
	hal_debug(LOG_WARNING, "msg: %d stored for %08x (%s):\n", n, (unsigned)partkey, name);
	uint8_t buf[MSG_CHUNK];   // debug dump: the first page only (long messages truncate here)
	for (int i = n - 1; i >= 0; i--) {
		struct msg_record m = recs[i];
		// From the body, not from 0: a group message's payload begins with the
		// envelope's fields, and dumping those would print binary at the reader.
		int got = msg_read(m.contact_id, m.record_id, 0, buf, sizeof buf);
		if (got < 0)
			continue;
		const char *label = "IN            ";
		if (m.kind == ENTRY_MSG_OUT) {
			label = "OUT[pending]  ";
			if (msg_is_delivered(m))
				label = "OUT[delivered]";
		}
		// Age is printed because an undelivered ENTRY_MSG_OUT stops being retried once
		// it is older than msg_expiry_secs, so "pending" alone does not say
		// whether the lap is still spending handshakes on it. A negative age means
		// the clock is behind the record: before NTP lands now_seconds() reads
		// about 95 days stale, so both the age and the cutoff drawn from the same
		// clock are meaningless, and saying so beats printing a misleading number.
		uint32_t nowsec = (uint32_t)now_seconds();
		long age = (long)nowsec - (long)m.timestamp;
		const char *note = "";
		if (age < 0)
			note = " (clock not yet set)";
		else if (m.kind == ENTRY_MSG_OUT && !msg_is_delivered(m)
		         && age > (long)msg_expiry_secs)
			note = " (EXPIRED, no longer retried)";
		// Stored against text, so a dump shows the framing is there: they differ
		// by its length, and equal means an entry written before it existed —
		// the one thing a text-only dump cannot show.
		int text = msg_body_len(m.contact_id, m.record_id);
		hal_debug(LOG_WARNING, "  %s age=%lds stored=%u text=%d%s %.*s\n",
		          label, age, (unsigned)m.payload_len, text,
		          note, got, (const char *)buf);
	}
}

// Send to a peer identified by its full 32-byte public key, adding it to the
// address book if it is not there yet. The ordinary send path takes a partkey
// and needs the contact to exist already; this is the bench's way in when the
// operator has the raw key and nothing else.
int msg_post_to_key(const uint8_t key[KEY_LEN], const char *text) {
	uint32_t partkey = get_part_key((uint8_t *)key);
	struct contact_record contact;
	if (!contact_get(&contact, partkey)) {
		// No name to give it yet, so it is named by what we do know. "unnamed"
		// would be the same string for everyone, making a list of them useless.
		char name[9];
		snprintf(name, sizeof name, "%08x", (unsigned)partkey);
		contact_create_pending(&contact, name, partkey);
	}
	// Holding the real 32 bytes is what VALID means, so no msg7 lookup is needed
	// to reach this peer — only its relay endpoint still has to be resolved.
	if (memcmp(contact.key, key, KEY_LEN) != 0 || contact.status != CONTACT_KEY_VALID) {
		memcpy(contact.key, key, KEY_LEN);
		contact.status = CONTACT_KEY_VALID;
		if (!contact_save(&contact))
			return -1;
	}
	return msg_post(partkey, text);
}
