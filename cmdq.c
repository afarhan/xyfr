// cmdq.c — the UI-to-core command ferry: a byte ring of NUL-framed text
// commands, and the table that turns each one into a call. The verb table below
// is the specification of the command language.
//
// Core 0 drains it. Portable C.

#include "hal.h"
#include <string.h>
#include <stdio.h>     // snprintf — the fallback names for an unnamed knock
#include <stdlib.h>    // atoi, strtoul
#include "cmdq.h"
#include "netif.h"        // frame_write — the netif-open test verb
#include "contacts.h"
#include "device_record.h"
#include "call.h"
#include "wg.h"       // get_part_key
#include "msg.h"
#include "filesystem.h"   // file_list, FILE_TYPE_CHANNEL
#include "channel_log.h"
#include "kernel.h"  // screen_invalidate

// ---- structs -----------------------------------------------------------------

// What must follow a verb, which is the whole of the matching rule.
enum verb_arg {
	ARG_NONE,        // the line is exactly the verb        "call-answer"
	ARG_REQ,         // verb, a space, then the payload     "contact-add 1a2b3c4d Bob"
	ARG_OPT          // either of those
};

// One row of the command language. The handler is passed the ARGUMENT — whatever
// follows the verb and its space, or "" when there is none — so renaming a verb
// cannot shift any offset a handler reads from.
struct verb_row {
	const char   *verb;
	uint8_t       arg;         // enum verb_arg
	void        (*handler)(const char *arg);
};

struct ByteQueue cmdq_ui_to_fs;

// Core-0 -> UI repaint flag (see cmdq.h). 0 = no pending event.
volatile uint8_t home_needs_refresh = 0;

void cmdq_init(struct ByteQueue *q) {
	q->head  = 0;
	q->tail  = 0;
	q->count = 0;
}

static int q_free(const struct ByteQueue *q) {
	return CMDQ_SIZE - q->count;
}

static void q_push_byte(struct ByteQueue *q, uint8_t b) {
	q->data[q->head++] = b;
	if (q->head == CMDQ_SIZE)
		q->head = 0;
	q->count++;
}

static uint8_t q_pop_byte(struct ByteQueue *q) {
	uint8_t b = q->data[q->tail++];
	if (q->tail == CMDQ_SIZE)
		q->tail = 0;
	q->count--;
	return b;
}

bool cmdq_post(struct ByteQueue *q, const char *line) {
	if (!q || !line)
		return false;
	size_t n = strlen(line);
	// Drop any trailing newlines the caller appended; the command is framed by
	// CMDQ_SEP. Newlines inside the line — a multi-line message body — are kept.
	while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
		n--;
	size_t total = n + 1;   // + CMDQ_SEP
	if ((int)total > q_free(q))
		return false;
	for (size_t i = 0; i < n; i++)
		q_push_byte(q, (uint8_t)line[i]);
	q_push_byte(q, CMDQ_SEP);
	return true;
}

// Returns count of bytes from tail up to and including the next CMDQ_SEP, or
// 0 if no complete command is buffered.
static int q_peek_line_len(const struct ByteQueue *q) {
	int idx = q->tail;
	int seen = 0;
	while (seen < q->count) {
		if (q->data[idx] == CMDQ_SEP)
			return seen + 1;
		idx++;
		if (idx == CMDQ_SIZE)
			idx = 0;
		seen++;
	}
	return 0;
}

int cmdq_pop_line(struct ByteQueue *q, char *out, size_t out_max) {
	if (!q || !out || out_max == 0)
		return 0;
	int line_len = q_peek_line_len(q);
	if (line_len == 0)
		return 0;
	if ((size_t)line_len > out_max) {
		// Command wouldn't fit in caller's buffer; discard it so the queue
		// can resync on the next CMDQ_SEP.
		for (int i = 0; i < line_len; i++)
			(void)q_pop_byte(q);
		return -1;
	}
	int copied = 0;
	for (int i = 0; i < line_len; i++) {
		uint8_t b = q_pop_byte(q);
		if (b == CMDQ_SEP)
			break;
		out[copied++] = (char)b;
	}
	out[copied] = 0;
	return copied;
}

// ---- parsers ----

static int hex_nibble(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F')
		return 10 + (c - 'A');
	return -1;
}

static bool parse_hex_bytes(const char *s, size_t hex_chars,
                            uint8_t *out, size_t out_bytes) {
	if (hex_chars != out_bytes * 2)
		return false;
	for (size_t i = 0; i < out_bytes; i++) {
		int hi = hex_nibble(s[2 * i]);
		int lo = hex_nibble(s[2 * i + 1]);
		if (hi < 0 || lo < 0)
			return false;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return true;
}

static bool parse_userid_hex(const char *s, uint32_t *out) {
	uint8_t b[4];
	if (!parse_hex_bytes(s, 8, b, 4))
		return false;
	*out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
	       ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
	return true;
}

// ---- dispatch ----

static void dispatch_contact_del(const char *arg) {
	const char *uid_str = arg;
	uint32_t uid;
	if (strlen(uid_str) < 8 || !parse_userid_hex(uid_str, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-del bad userid: [%s]\n", arg);
		return;
	}
	if (!contact_delete(uid))
		hal_debug(LOG_ERROR, "cmdq: contact-del %08x failed\n", (unsigned)uid);
}

static void dispatch_contact_add(const char *arg) {
	// "contact-add <8hex-uid> <name>" adds or updates; the UI's Edit path reuses
	// this verb to rename. A new contact is created pending, holding only the
	// userid in the first four key bytes, and the msg7 lookup later rewrites it
	// with the real public key. An existing contact has only its name updated, so
	// a rename never knocks a resolved contact back to pending.
	const char *uid_str = arg;
	if (strlen(uid_str) < 8 + 2 || uid_str[8] != ' ') {
		hal_debug(LOG_ERROR, "cmdq: contact-add malformed: [%s]\n", arg);
		return;
	}
	const char *name = uid_str + 9;

	uint32_t uid;
	if (!parse_userid_hex(uid_str, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-add bad userid: [%s]\n", arg);
		return;
	}

	struct contact_record c;
	bool is_new = !contact_get(&c, uid);
	if (is_new) {
		contact_create_pending(&c, name, uid);
	} else {
		strncpy(c.name, name, MAX_NAME - 1);   // existing: rename only, keep key/status/endpoint
		c.name[MAX_NAME - 1] = 0;
	}

	if (!contact_save(&c))
		hal_debug(LOG_ERROR, "cmdq: contact-add %08x \"%s\" save failed\n",
		              (unsigned)uid, c.name);
	else if (is_new)
		contact_lookup_request(uid);   // resolve a freshly-added contact on the next pump tick
}

// "contact-psk <8hex-uid> [phrase]" — the per-contact secure key, made from a
// passphrase, or nothing at all to remove it. The bench form of the contact
// menu's Secure key.
static void dispatch_contact_psk(const char *arg) {
	uint32_t uid;
	if (strlen(arg) < 8 || !parse_userid_hex(arg, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-psk bad userid: [%s]\n", arg);
		return;
	}
	const char *p = arg + 8;
	while (*p == ' ')
		p++;
	if (!contact_psk_set(uid, p)) {
		hal_debug(LOG_ERROR, "cmdq: contact-psk %08x failed\n", (unsigned)uid);
		return;
	}
	if (*p == 0)
		hal_debug(LOG_WARNING, "psk %08x cleared\n", (unsigned)uid);
	else
		hal_debug(LOG_WARNING, "psk %08x set\n", (unsigned)uid);
}

// "contact-find <8hex-uid>" — the contact menu's "Find..." action, and the query
// half of every "Retry". Re-asks the server for this contact's full key and
// relay endpoint. Nothing re-queries automatically on a failed handshake: an
// unanswered msg1 cannot tell "peer offline" from "peer moved relay", so it is
// the user's call, made when they retry something that just failed.
static void dispatch_contact_find(const char *arg) {
	uint32_t uid;
	if (!parse_userid_hex(arg, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-find bad userid: [%s]\n", arg);
		return;
	}
	contact_lookup_request(uid);
	hal_debug(LOG_EVERYTHING, "cmdq: contact-find %08x — querying\n", (unsigned)uid);
}

// "msg-retry <8hex-uid>" — the "Retry" action on a pending message. Re-queries
// the endpoint and asks the messaging engine to offer this contact's oldest
// pending message again, clearing any accumulated backoff. Fire and forget: the
// message goes out on this attempt or a later one, to whatever endpoint the
// query resolves.
static void dispatch_msg_retry(const char *arg) {
	uint32_t uid;
	if (!parse_userid_hex(arg, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: msg-retry bad userid: [%s]\n", arg);
		return;
	}
	contact_lookup_request(uid);
	msg_attempt_delivery(uid);
	hal_debug(LOG_EVERYTHING, "cmdq: msg-retry %08x — re-query + offer it again\n",
	          (unsigned)uid);
}

// "contact-flag <8hex-uid> <hexmask> <op>" — set, clear or toggle bits in
// contact.settings (Star/Burner/Blocked; device_record.h). op: s=set, c=clear,
// t=toggle. Load, modify, save: contact_save rewrites the whole record, so key,
// status, endpoint and name ride through unchanged, and compare-before-write
// skips a toggle that changes nothing.
static void dispatch_contact_flag(const char *arg) {
	const char *uid_str = arg;
	uint32_t uid;
	if (strlen(uid_str) < 8 + 2 || uid_str[8] != ' ' || !parse_userid_hex(uid_str, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-flag malformed: [%s]\n", arg);
		return;
	}
	const char *rest = uid_str + 9;
	while (*rest == ' ')
		rest++;
	char *end = NULL;
	unsigned long mask = strtoul(rest, &end, 16);
	if (end == rest) {
		hal_debug(LOG_ERROR, "cmdq: contact-flag bad mask: [%s]\n", arg);
		return;
	}
	while (*end == ' ')
		end++;
	char op = *end;

	struct contact_record c;
	if (!contact_get(&c, uid)) {
		hal_debug(LOG_ERROR, "cmdq: contact-flag %08x — no contact\n", (unsigned)uid);
		return;
	}
	uint32_t before = c.settings;
	switch (op) {
	case 's':
		c.settings |= (uint32_t)mask;
		break;
	case 'c':
		c.settings &= ~(uint32_t)mask;
		break;
	case 't':
		c.settings ^= (uint32_t)mask;
		break;
	default:
		hal_debug(LOG_ERROR, "cmdq: contact-flag bad op '%c'\n", op);
		return;
	}
	if (c.settings != before && !contact_save(&c))
		hal_debug(LOG_ERROR, "cmdq: contact-flag %08x save failed\n", (unsigned)uid);
}

// "msg <8hex-userid> <text>" — send a message to the contact with that userid.
// Appends an MSG_OUT record to the log and fires delivery. Group 0 is the
// ordinary one-to-one thread, which is the whole difference from "msg-group".
static void dispatch_msg(const char *arg) {
	const char *p = arg;
	if (strlen(p) < 8 + 1 || p[8] != ' ') {
		hal_debug(LOG_ERROR, "cmdq: msg malformed: [%s]\n", arg);
		return;
	}
	uint32_t uid;
	if (!parse_userid_hex(p, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: msg bad userid: [%s]\n", arg);
		return;
	}
	msg_post(uid, p + 9);
}

// "msg-key <64hex-pubkey> <text>" — send a message to a peer by its full public
// key, needing no lookup because we already hold the real key. The counterpart
// of "call-key"; the host CLI's `msg <key> <text>` mode posts it. It saves the
// peer as a resolved contact, then sends.
static void dispatch_msg_key(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t key[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, key, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: msg-key bad pubkey: [%s]\n", arg);
		return;
	}
	const char *text = p + KEY_LEN * 2;
	while (*text == ' ')
		text++;
	msg_post_to_key(key, text);
}

// ---- knock (missed-request) actions, from the Requests list -----------------
// The knock table holds the peer's full key, so these add a contact outright as
// CONTACT_KEY_VALID with no lookup round trip. Each clears the knock slot.
//
// "knock-allow <64hex-pubkey> <name>" — Allow: save as a usable contact under <name>.
static void dispatch_knock_allow(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t key[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, key, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: knock-allow bad pubkey: [%s]\n", arg);
		return;
	}
	const char *name = p + KEY_LEN * 2;
	while (*name == ' ')
		name++;
	uint32_t uid = get_part_key(key);
	char fallback[9];
	if (!*name) {                       // no name given: the userid becomes the name
		snprintf(fallback, sizeof fallback, "%08x", (unsigned)uid);
		name = fallback;
	}
	struct contact_record c;
	if (!contact_get(&c, uid))
		contact_create_pending(&c, name, uid);
	else
		snprintf(c.name, sizeof c.name, "%s", name);
	memcpy(c.key, key, KEY_LEN);
	c.status    = CONTACT_KEY_VALID;    // full key in hand: usable immediately
	c.settings &= ~CONTACT_BLOCKED;     // allowing overrides a previous block
	if (!contact_save(&c)) {
		hal_debug(LOG_ERROR, "cmdq: knock-allow save %08x failed\n", (unsigned)uid);
		return;
	}
	missed_request_clear(uid);
	hal_debug(LOG_EVERYTHING, "cmdq: knock-allow %08x allowed as [%s]\n", (unsigned)uid, name);
}

// "knock-block <64hex-pubkey>" — Block: take a contact slot flagged
// CONTACT_BLOCKED, so admit_handshake refuses this key outright and it never
// knocks again.
static void dispatch_knock_block(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t key[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, key, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: knock-block bad pubkey: [%s]\n", arg);
		return;
	}
	uint32_t uid = get_part_key(key);
	char name[9];
	snprintf(name, sizeof name, "%08x", (unsigned)uid);
	struct contact_record c;
	if (!contact_get(&c, uid))
		contact_create_pending(&c, name, uid);
	memcpy(c.key, key, KEY_LEN);
	c.status    = CONTACT_KEY_VALID;
	c.settings |= CONTACT_BLOCKED;
	if (!contact_save(&c)) {
		hal_debug(LOG_ERROR, "cmdq: knock-block save %08x failed\n", (unsigned)uid);
		return;
	}
	missed_request_clear(uid);
	hal_debug(LOG_WARNING, "cmdq: knock-block %08x BLOCKED\n", (unsigned)uid);
}

// "knock-ignore <8hex-userid>" — Ignore: drop the knock and record nothing, so
// the same key may knock again later.
static void dispatch_knock_ignore(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint32_t uid;
	if (!parse_userid_hex(p, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: knock-ignore bad userid: [%s]\n", arg);
		return;
	}
	missed_request_clear(uid);
	hal_debug(LOG_EVERYTHING, "cmdq: knock-ignore %08x ignored\n", (unsigned)uid);
}

// "msg-bulk <64hex-pubkey> <size>" — a bench verb: send a generated <size>-byte
// message by raw key, to exercise large-message streaming past the cmdq line cap.
static void dispatch_msg_bulk(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t key[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, key, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: msg-bulk bad pubkey\n");
		return;
	}
	const char *ns = p + KEY_LEN * 2;
	while (*ns == ' ')
		ns++;
	int size = atoi(ns);
	if (size < 1)
		size = 1;
	if (size > 10000)
		size = 10000;
	// The shared scratch arena rather than a 10 KB static: msg_post_to_key
	// consumes the text before it returns, writing it straight to storage, so the
	// buffer is big, transient, foreground and single-holder — the arena's
	// contract exactly.
	char *big = (char *)hal_malloc((size_t)size + 1);
	if (!big) {
		hal_debug(LOG_ERROR, "cmdq: msg-bulk scratch arena busy\n");
		return;
	}
	for (int i = 0; i < size; i++)
		big[i] = (char)('A' + (i % 26));
	big[size] = 0;
	hal_debug(LOG_WARNING, "cmdq: msg-bulk generating %d-byte message\n", size);
	msg_post_to_key(key, big);
	hal_free(big);
}

// "msg-delete-all <8hex-userid>" — the chat menu's "Delete all Texts". Marks
// every entry in the contact's thread deleted, keeping the contact and its data
// key. Irreversible. It then invalidates the screen so the UI repaints home and
// any open chat without polling for it.
static void dispatch_msg_delete_all(const char *arg) {
	uint32_t uid;
	if (strlen(arg) < 8 || !parse_userid_hex(arg, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: msg-delete-all bad userid: [%s]\n", arg);
		return;
	}
	int n = msg_delete_thread(uid);
	if (n < 0)
		return;
	screen_invalidate();   // the home row changes too (unread dot / preview / order)
}

// ---- channels ----------------------------------------------------------------

// "channel-new <name>" — host a channel. The id is ours to allocate.
static void dispatch_channel_new(const char *arg) {
	uint8_t id = channel_new(arg);
	if (!id) {
		hal_debug(LOG_ERROR, "cmdq: channel-new failed\n");
		return;
	}
	hal_debug(LOG_WARNING, "channel %u created: %s\n", (unsigned)id, arg);
}

// "channel-post <id> <text>" — append a line to one of ours, as ourselves.
static void dispatch_channel_post(const char *arg) {
	unsigned id = 0;
	int digits = 0;
	while (*arg >= '0' && *arg <= '9' && digits < 3) {
		id = id * 10 + (unsigned)(*arg - '0');
		arg++;
		digits++;
	}
	if (digits == 0 || id == 0 || id > CHANNEL_ID_MAX || *arg != ' ') {
		hal_debug(LOG_ERROR, "usage: channel-post <id> <text>\n");
		return;
	}
	arg++;
	uint32_t me = channel_my_partkey();
	if (channel_append(me, (uint16_t)id, me, arg, (int)strlen(arg)) == FILE_NONE)
		hal_debug(LOG_ERROR, "cmdq: channel-post failed\n");
}

// The seed lines: short, long and everything between, so wrapping, paging and
// the one-segment limit all get exercised by a single command.
static const char *const seed_lines[] = {
	"hi",
	"anyone around?",
	"I have been reading through the storage layer this morning and the thing that keeps surprising me is how much of it is arithmetic rather than cryptography.",
	"ok",
	"The append point is the first still-erased page, so a torn write resumes with nothing held in RAM.",
	"that took me a while to believe",
	"yes",
	"Compaction copies one destination sector at a time, which is what makes bytes-written never exceed bytes-read.",
	"neat",
	"A flag is active low because erased NOR is 0xFF and a program only clears bits, so clearing one in place needs no erase at all.",
	"so a delete is a single bit",
	"exactly that",
	"The part I still find striking is that the inode's first thirty-two bytes are cleartext, which means a mount can rebuild the whole directory before it holds any key, and a wrong volume key shows up as a named file that will not open rather than as a store that looks empty.",
	"that is a good failure mode",
	"much better than silence",
	"Every entry carries its own epoch, so a read uses the epoch the entry was written under and a remount never has to rewrite anything.",
	"right",
	"One more: the log is the queue. There is no separate outbox, the pending set is just the records whose delivered bit is still set.",
	"and the sweep is a lap with a cutoff",
	"that is the whole of it",
};

// "channel-seed <id>" — write the test lines into one of our channels.
static void dispatch_channel_seed(const char *arg) {
	unsigned id = (unsigned)atoi(arg);
	if (id == 0 || id > CHANNEL_ID_MAX) {
		hal_debug(LOG_ERROR, "usage: channel-seed <id>\n");
		return;
	}
	uint32_t me = channel_my_partkey();
	int n = (int)(sizeof seed_lines / sizeof seed_lines[0]);
	int wrote = 0;
	for (int i = 0; i < n; i++) {
		if (channel_append(me, (uint16_t)id, me, seed_lines[i],
		                   (int)strlen(seed_lines[i])) != FILE_NONE)
			wrote++;
	}
	hal_debug(LOG_WARNING, "channel %u seeded: %d of %d lines\n",
	          (unsigned)id, wrote, n);
}

// "channel-open <8hex host> <id>" — open the session screen on that channel.
static void dispatch_channel_open(const char *arg) {
	unsigned host = 0, id = 0;
	if (sscanf(arg, "%x %u", &host, &id) != 2 || id == 0 || id > CHANNEL_ID_MAX) {
		hal_debug(LOG_ERROR, "usage: channel-open <8hex host> <id>\n");
		return;
	}
	channel_open((uint16_t)id);
	screen_push(APP_CHANNEL, (uint32_t)host);
}

// "channel-add <8hex host> <id> <name>" — create a channel at a CHOSEN id.
// Ours when the host is our own partkey, joined when it is somebody else's:
// the same file either way, which is why one verb covers both.
static void dispatch_channel_add(const char *arg) {
	unsigned host = 0, id = 0;
	int at = 0;
	if (sscanf(arg, "%x %u %n", &host, &id, &at) < 2 || id == 0 || id > CHANNEL_ID_MAX) {
		hal_debug(LOG_ERROR, "usage: channel-add <8hex host> <id> <name>\n");
		return;
	}
	const char *name = arg + at;
	if (!channel_create((uint32_t)host, (uint16_t)id, name)) {
		hal_debug(LOG_ERROR, "cmdq: channel-add failed\n");
		return;
	}
	hal_debug(LOG_WARNING, "channel %u under %08x: %s\n", id, host, name);
}

// "channel-say <text>" — send a line to the channel currently on screen, the
// same path the composer takes on Enter. A bench verb: it exists so the send
// can be exercised without a keyboard.
static void dispatch_channel_say(const char *arg) {
	if (!channel_screen_say(arg))
		hal_debug(LOG_ERROR, "cmdq: no channel screen open\n");
}

// "channel-list" — every channel this device holds, hosted or joined.
static void dispatch_channel_list(const char *arg) {
	(void)arg;
	uint32_t me = channel_my_partkey();
	uint32_t host;
	uint16_t id;
	int n = 0;
	for (int i = 0; channel_by_index(i, &host, &id); i++) {
		struct channel_record record;
		if (!channel_get(host, id, &record))
			continue;
		const char *role = "member";
		if (host == me)
			role = "HOST";
		hal_debug(LOG_WARNING, "  channel %u under %08x  %-6s  %s\n",
		          (unsigned)id, (unsigned)host, role, record.name);
		n++;
	}
	hal_debug(LOG_WARNING, "%d channel(s)\n", n);
}

// "channel-dump <id> [8hex host]" — every line, oldest first, with its cursor.
static void dispatch_channel_dump(const char *arg) {
	unsigned id = 0;
	uint32_t host = channel_my_partkey();
	unsigned h = 0;
	if (sscanf(arg, "%u %x", &id, &h) == 2)
		host = (uint32_t)h;
	else if (sscanf(arg, "%u", &id) != 1)
		id = 0;
	if (id == 0 || id > CHANNEL_ID_MAX) {
		hal_debug(LOG_ERROR, "usage: channel-dump <1-255> [8hex host]\n");
		return;
	}
	// Walk to the oldest, then forward, so the dump reads in the order written.
	uint32_t entry = channel_newest(host, (uint16_t)id);
	uint32_t oldest = entry;
	while (entry != FILE_NONE) {
		oldest = entry;
		entry = channel_older(host, (uint16_t)id, entry);
	}
	int n = 0;
	char text[CHANNEL_TEXT_MAX + 1];
	for (entry = oldest; entry != FILE_NONE;
	     entry = channel_newer(host, (uint16_t)id, entry)) {
		uint32_t author = 0, stamp = 0;
		int len = channel_line_read(host, (uint16_t)id, entry, &author, &stamp,
		                            text, (int)sizeof text);
		if (len < 0)
			continue;
		hal_debug(LOG_WARNING, "  [%u] %08x t=%u (%d) %s\n",
		          (unsigned)entry, (unsigned)author, (unsigned)stamp, len, text);
		n++;
	}
	hal_debug(LOG_WARNING, "%d line(s) in channel %u under %08x\n",
	          n, (unsigned)id, (unsigned)host);
}

// "thread-del <8hex-uid> [channel]" — destroy a file and everything in it. A
// contact and a group are the same file, so this is the same call for both:
// no group id, or 0, is the contact.
static void dispatch_thread_del(const char *arg) {
	uint32_t uid;
	if (!parse_userid_hex(arg, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: thread-del bad userid: [%s]\n", arg);
		return;
	}
	unsigned gid = 0;
	const char *p = arg + 8;
	if (*p == ' ') {
		p++;
		while (*p >= '0' && *p <= '9')
			gid = gid * 10 + (unsigned)(*p++ - '0');
	}
	if (gid > CHANNEL_ID_MAX) {
		hal_debug(LOG_ERROR, "cmdq: thread-del channel id must be 0..65535\n");
		return;
	}
	if (!file_destroy(thread_file(uid, (uint16_t)gid))) {
		hal_debug(LOG_ERROR, "cmdq: thread-del %08x g=%u failed\n", (unsigned)uid, gid);
		return;
	}
	screen_invalidate();
	hal_debug(LOG_WARNING, "thread %08x g=%u destroyed\n", (unsigned)uid, gid);
}

// "msg-list <8hex-userid>" — dump a contact's stored message log, for inspection.
static void dispatch_msg_list(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint32_t uid;
	if (!parse_userid_hex(p, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: msg-list bad userid: [%s]\n", arg);
		return;
	}
	msg_list(uid);
}

// "call <8hex-userid>" — originate a call to the contact with that userid. The
// contact is loaded here so the key status can be checked before a call slot is
// spent: a contact whose key is still unresolved cannot be reached.
static void dispatch_call(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;

	uint32_t uid;
	if (!parse_userid_hex(p, &uid)) {
		hal_debug(LOG_ERROR, "cmdq: call bad userid: [%s]\n", arg);
		return;
	}

	struct contact_record c;
	if (!contact_get(&c, uid)) {
		hal_debug(LOG_WARNING, "cmdq: call no contact for %08x\n", (unsigned)uid);
		return;
	}
	if (contact_key_status(&c) != CONTACT_KEY_VALID) {
		hal_debug(LOG_WARNING, "cmdq: call %08x key not VALID (status=%d); deferring\n",
			(unsigned)uid, contact_key_status(&c));
		return;
	}
	call_handle rc = call_originate(uid);
	if (rc < 0)
		hal_debug(LOG_WARNING, "cmdq: call %08x call_originate rc=%d\n", (unsigned)uid, rc);
}

// "call-key <64hex-pubkey>" — originate a call to a peer by its raw wg static
// public key, with no contact required. The device UI uses "call <userid>" and a
// saved contact; this verb is for the host CLI test shell and any other caller
// that already holds the full key.
static void dispatch_call_key(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t pub[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, pub, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: call-key bad pubkey: [%s]\n", arg);
		return;
	}
	call_handle rc = call_originate(get_part_key(pub));
	if (rc < 0)
		hal_debug(LOG_WARNING, "cmdq: call-key call_originate rc=%d\n", rc);
}

// "netif-open <64hex-pubkey>" — a bench verb that makes netif originate a peer
// link. Firing it at both ends inside the handshake window is how the
// crossing-handshake tie-break is provoked deliberately. The one-byte payload is
// dropped: frame_write returns FRAME_PENDING and starts bring-up, which is the
// whole point.
static void dispatch_netif_open(const char *arg) {
	const char *p = arg;
	while (*p == ' ')
		p++;
	uint8_t pub[KEY_LEN];
	if (strlen(p) < KEY_LEN * 2 || !parse_hex_bytes(p, KEY_LEN * 2, pub, KEY_LEN)) {
		hal_debug(LOG_ERROR, "cmdq: netif-open bad pubkey: [%s]\n", arg);
		return;
	}
	uint8_t probe = 0;
	int st = frame_write(pub, &probe, 1);
	const char *outcome = "FAILED";
	if (st == FRAME_SENT)
		outcome = "SENT";
	else if (st == FRAME_PENDING)
		outcome = "PENDING (bringing up)";
	hal_debug(LOG_WARNING, "cmdq: netif-open %08x -> %s\n",
		(unsigned)get_part_key(pub), outcome);
}

// The one call a UI button acts on: whichever holds the audio, or failing that
// the one ringing — which is the inbound case, before Answer. Several calls can
// exist at once, but the screen only ever shows one, so the first match is the
// one the user is looking at.
static call_handle call_the_button_acts_on(void) {
	call_handle call = call_holding_audio();
	if (call)
		return call;
	return call_ringing();
}

// "call-answer" — the user pressed Answer. A no-op if the chosen call is no
// longer ringing, which happens when it timed out between the keypress and this
// drain; the screen re-renders off whatever state results.
static void dispatch_call_answer(const char *arg) {
	(void)arg;
	call_answer(call_the_button_acts_on());
}

// "call-refuse" and "call-hangup" both land here. They are the same operation on
// the network: distinguishing them in what is transmitted would only leak the
// local UI choice to the peer.
static void dispatch_call_end(const char *arg) {
	(void)arg;
	call_hangup(call_the_button_acts_on());
}

// "msg-accept <0|1>" — a bench toggle: 0 rejects inbound messages, so the sender
// sees them stay undelivered.
static void dispatch_msg_accept(const char *arg) {
	msg_accept = (arg[0] != '0');
	hal_debug(LOG_WARNING, "msg: accept = %d\n", msg_accept);
}

// Simulated inbound loss, so a soak can run over a link that is bad on purpose.
// The device has had this over serial since the loss counter went in; the host
// CLI held the same variable with no way to set it, which meant a run could only
// ever degrade four of its six actors.
static void dispatch_loss(const char *arg) {
	int pct = atoi(arg);
	if (pct < 0)
		pct = 0;
	if (pct > 100)
		pct = 100;
	net_loss_pct = pct;
	hal_debug(LOG_WARNING, "loss: inbound now %d%%\n", net_loss_pct);
}

// The verb table: the command language in one place.
//
// The space required after an ARG_REQ verb is what keeps same-prefix verbs
// apart, so the table needs no length ordering. "call" cannot swallow
// "call-key 0a1b..." because the character after the verb is '-' rather than a
// space, and it cannot swallow "call-answer" because that is an exact-match row.
// A verb that is a prefix of another is safe as long as the longer one continues
// with something other than a space.
static const struct verb_row verb_table[] = {
	// contacts
	{ "contact-add",    ARG_REQ,  dispatch_contact_add     },  // <uid> <name>, also renames
	{ "contact-del",    ARG_REQ,  dispatch_contact_del     },  // <uid>
	{ "contact-flag",   ARG_REQ,  dispatch_contact_flag    },  // <uid> <hexmask> s|c|t
	{ "contact-find",   ARG_REQ,  dispatch_contact_find    },  // <uid>, re-query key+endpoint
	{ "contact-psk",    ARG_REQ,  dispatch_contact_psk     },  // <uid> [phrase], empty clears
	{ "msg-retry",      ARG_REQ,  dispatch_msg_retry       },  // <uid>, re-query + offer again
	// calls
	{ "call",           ARG_REQ,  dispatch_call            },  // <uid>
	{ "call-key",       ARG_REQ,  dispatch_call_key        },  // <64hex-pubkey>
	{ "netif-open",     ARG_REQ,  dispatch_netif_open      },  // <64hex-pubkey>, bench verb
	{ "call-answer",    ARG_NONE, dispatch_call_answer     },
	{ "call-refuse",    ARG_NONE, dispatch_call_end        },  // the same as hangup, transmitted
	{ "call-hangup",    ARG_NONE, dispatch_call_end        },
	// messages
	{ "msg",            ARG_REQ,  dispatch_msg             },  // <uid> <text>
	{ "msg-key",        ARG_REQ,  dispatch_msg_key         },  // <64hex-pubkey> <text>
	{ "msg-list",       ARG_REQ,  dispatch_msg_list        },  // <uid>, dump a thread
	{ "msg-delete-all", ARG_REQ,  dispatch_msg_delete_all  },  // <uid>, delete the whole thread
	{ "msg-bulk",       ARG_REQ,  dispatch_msg_bulk        },  // <64hex-pubkey> <size>, bench verb
	// knock (admission decisions on an unknown caller)
	{ "knock-allow",    ARG_REQ,  dispatch_knock_allow     },  // <64hex-pubkey> <name>
	{ "knock-block",    ARG_REQ,  dispatch_knock_block     },  // <64hex-pubkey>
	{ "knock-ignore",   ARG_REQ,  dispatch_knock_ignore    },  // <uid>
	// the messaging bench surface
	{ "msg-accept",     ARG_REQ,  dispatch_msg_accept      },  // 0|1, inbound accept toggle
	{ "loss",           ARG_REQ,  dispatch_loss            },  // <0..100> simulated inbound loss
	// channels
	{ "channel-new",    ARG_REQ,  dispatch_channel_new     },  // <name>, we host it
	{ "channel-post",   ARG_REQ,  dispatch_channel_post    },  // <id> <text>
	{ "channel-seed",   ARG_REQ,  dispatch_channel_seed    },  // <id>, the 20 test lines
	{ "channel-add",    ARG_REQ,  dispatch_channel_add     },  // <8hex host> <id> <name>
	{ "channel-say",    ARG_REQ,  dispatch_channel_say     },  // <text>, to the open channel
	{ "channel-list",   ARG_NONE, dispatch_channel_list    },
	{ "channel-open",   ARG_REQ,  dispatch_channel_open    },  // <8hex host> <id>
	{ "channel-dump",   ARG_REQ,  dispatch_channel_dump    },  // <id> [8hex host]
	{ "thread-del",     ARG_REQ,  dispatch_thread_del      },  // <uid> [gid], destroys its messages too
};

static void dispatch_line(const char *line) {
	for (unsigned i = 0; i < sizeof verb_table / sizeof verb_table[0]; i++) {
		const char *verb = verb_table[i].verb;
		size_t verb_len = strlen(verb);
		if (strncmp(line, verb, verb_len) != 0)
			continue;
		char after = line[verb_len];
		if (verb_table[i].arg == ARG_NONE && after != 0)
			continue;
		if (verb_table[i].arg == ARG_REQ && after != ' ')
			continue;
		if (verb_table[i].arg == ARG_OPT && after != ' ' && after != 0)
			continue;
		const char *argument = "";
		if (after == ' ')
			argument = line + verb_len + 1;
		verb_table[i].handler(argument);
		return;
	}
	hal_debug(LOG_WARNING, "cmdq: unknown verb: [%s]\n", line);
}

void cmdq_dispatch(void) {
	char line[CMD_MAX_LINE];
	for (;;) {
		int n = cmdq_pop_line(&cmdq_ui_to_fs, line, sizeof(line));
		if (n == 0)
			return;
		if (n < 0) {
			hal_debug(LOG_WARNING, "cmdq: oversize line discarded\n");
			continue;
		}
		dispatch_line(line);
	}
}
