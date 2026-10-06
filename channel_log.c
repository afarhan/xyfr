// channel_log.c — the channel store: one file per channel, one entry per line.
//
// This file knows nothing about how a line travels. It creates channels,
// appends lines and reads them back by cursor; app_channel.c turns that into a
// session and filesystem.c does the storing. channel_log.h says what a channel is.
//
// Portable C, core 0.

#include "hal.h"
#include <string.h>
#include <stdio.h>
#include "channel_log.h"
#include "contacts.h"       // thread_file, contacts_store_ready — one mount for the region
#include "filesystem.h"
#include "wg.h"             // KEY_LEN, get_part_key
#include "device_record.h"  // device_record.my_private_key
#include "hal.h"            // hal_rand — the epoch is random, not a counter

_Static_assert(sizeof(struct channel_record) <= FILE_INODE_DATA,
               "a channel record must fit the inode body");

// contacts.c owns the one mount: channel files and contact files are the same
// region under the same volume key.
static bool store_ready(void) {
	return contacts_store_ready();
}

// Deriving this is a Curve25519 scalar multiplication, and author_name asks for
// it once per rendered line. The private key does change while running -- the
// `key` verb, activation through netif_setkey, a restore -- so it cannot be
// taken once at boot. Keeping the key it was derived FROM as the cache key
// means there is no invalidation call anywhere for somebody to forget.
uint32_t channel_my_partkey(void) {
	static uint8_t  seen_private[KEY_LEN];
	static uint32_t cached;
	static bool     have_cached;      // an all-zero key is a real input, not an empty cache
	if (!have_cached ||
	    memcmp(seen_private, device_record.my_private_key, KEY_LEN) != 0) {
		uint8_t pub[KEY_LEN];
		curve25519(pub, device_record.my_private_key, basepoint);
		cached = get_part_key(pub);
		memcpy(seen_private, device_record.my_private_key, KEY_LEN);
		have_cached = true;
	}
	return cached;
}

// Random, and never zero: zero is how a caller says "no such channel".
static uint32_t mint_epoch(void) {
	uint32_t e = 0;
	while (e == 0)
		e = hal_rand();
	return e;
}

// Wrong version means a record this build cannot read, which is not the same as
// no channel, so it fails rather than guessing.
static bool record_read(uint32_t host, uint16_t channel_id,
                        struct channel_record *out) {
	struct file_header header;
	if (channel_id == 0)
		return false;              // that name belongs to a contact
	if (!file_header_read(thread_file(host, channel_id), &header))
		return false;
	memcpy(out, header.data, sizeof *out);
	if (((out->flag & CHANNEL_VERSION_MASK) >> CHANNEL_VERSION_SHIFT) != CHANNEL_VERSION_CURRENT)
		return false;
	return true;
}

bool channel_create(uint32_t host, uint16_t channel_id, const char *name) {
	struct file_header header;
	if (!store_ready() || channel_id == 0)
		return false;
	if (file_header_read(thread_file(host, channel_id), &header))
		return true;               // already held; its name may be newer than this one

	struct channel_record record;
	memset(&record, 0, sizeof record);
	record.flag       = CHANNEL_VERSION_CURRENT << CHANNEL_VERSION_SHIFT;
	record.channel_id = channel_id;
	record.epoch      = mint_epoch();
	if (name)
		snprintf(record.name, sizeof record.name, "%s", name);

	memset(&header, 0, sizeof header);
	header.file_id   = thread_file(host, channel_id);
	header.file_type = FILE_TYPE_CHANNEL;
	memcpy(header.data, &record, sizeof record);
	return file_create(&header);
}

uint16_t channel_new(const char *name) {
	if (!store_ready() || !name || !name[0])
		return 0;
	uint32_t me = channel_my_partkey();
	for (uint32_t id = 1; id <= CHANNEL_ID_MAX; id++) {
		struct file_header probe;
		if (file_header_read(thread_file(me, (uint16_t)id), &probe))
			continue;
		if (!channel_create(me, (uint16_t)id, name))
			return 0;
		hal_debug(LOG_EVERYTHING, "channel: %u created under %08x (%s)\n",
		          (unsigned)id, (unsigned)me, name);
		return (uint16_t)id;
	}
	hal_debug(LOG_WARNING, "channel: no free id under %08x\n", (unsigned)me);
	return 0;
}

bool channel_get(uint32_t host, uint16_t channel_id, struct channel_record *out) {
	if (!store_ready() || !out)
		return false;
	return record_read(host, channel_id, out);
}

bool channel_rename(uint32_t host, uint16_t channel_id, const char *name) {
	struct channel_record record;
	struct file_header header;
	if (!store_ready() || !name)
		return false;
	if (!record_read(host, channel_id, &record))
		return false;
	snprintf(record.name, sizeof record.name, "%s", name);
	memset(&header, 0, sizeof header);
	header.file_id   = thread_file(host, channel_id);
	header.file_type = FILE_TYPE_CHANNEL;
	memcpy(header.data, &record, sizeof record);
	return file_header_write(header.file_id, &header);
}

uint32_t channel_epoch(uint32_t host, uint16_t channel_id) {
	struct channel_record record;
	if (!store_ready() || !record_read(host, channel_id, &record))
		return 0;
	return record.epoch;
}

// A member holding an offset counted in the old numbering will see this change
// and start again from the tail. That is the whole purpose: nothing here has to
// find those members or tell them anything.
bool channel_new_epoch(uint32_t host, uint16_t channel_id) {
	struct channel_record record;
	struct file_header header;
	if (!store_ready() || !record_read(host, channel_id, &record))
		return false;
	record.epoch = mint_epoch();
	memset(&header, 0, sizeof header);
	header.file_id   = thread_file(host, channel_id);
	header.file_type = FILE_TYPE_CHANNEL;
	memcpy(header.data, &record, sizeof record);
	return file_header_write(header.file_id, &header);
}

// Compaction moves entries, so every entry id it leaves behind names a
// different place -- and a member's cursor IS an entry id. Minting a fresh
// epoch on every channel we host is what tells those members to start again;
// one we have only joined holds no log here, so it has nothing to renumber.
int channel_epochs_renew(void) {
	int done = 0;
	uint32_t me = channel_my_partkey();
	uint32_t host;
	uint16_t id;
	for (int i = 0; channel_by_index(i, &host, &id); i++) {
		if (host != me)
			continue;
		if (channel_new_epoch(host, id))
			done++;
	}
	return done;
}

// Empty a channel we hold: destroy the file and make it again under the same
// name. Destroying scrubs the data key, so the log goes with it, and the fresh
// file mints a fresh epoch -- which is exactly what tells every member holding
// an offset that the numbering it was counted in is gone.
bool channel_reset(uint32_t host, uint16_t channel_id) {
	struct channel_record record;
	char name[CHANNEL_NAME_MAX];
	if (!store_ready() || !record_read(host, channel_id, &record))
		return false;
	snprintf(name, sizeof name, "%s", record.name);
	if (!file_destroy(thread_file(host, channel_id)))
		return false;
	return channel_create(host, channel_id, name);
}

// Give a channel a different id. The id IS the low half of the file's name, so
// this is a move, and there is no move: a file's log is reached through the
// name it was written under. Refused while the log holds anything, which leaves
// the case that matters -- a channel joined under the wrong number, before
// anything has arrived in it.
bool channel_renumber(uint32_t host, uint16_t from_id, uint16_t to_id) {
	struct channel_record record;
	char name[CHANNEL_NAME_MAX];
	if (!store_ready() || to_id == 0 || from_id == 0)
		return false;
	if (to_id == from_id)
		return true;
	if (!record_read(host, from_id, &record))
		return false;
	if (file_log_newest(thread_file(host, from_id)) != FILE_NONE) {
		hal_debug(LOG_ERROR, "channel: %u under %08x has messages; id kept\n",
		          (unsigned)from_id, (unsigned)host);
		return false;
	}
	struct file_header probe;
	if (file_header_read(thread_file(host, to_id), &probe)) {
		hal_debug(LOG_ERROR, "channel: %u under %08x already exists\n",
		          (unsigned)to_id, (unsigned)host);
		return false;
	}
	snprintf(name, sizeof name, "%s", record.name);
	if (!channel_create(host, to_id, name))
		return false;
	return file_destroy(thread_file(host, from_id));
}

// ---- the member list --------------------------------------------------------
//
// A record write per change, which is one inode page: membership changes when a
// person is added, not when a message arrives, so there is nothing to batch.

static bool record_write(uint32_t host, uint16_t channel_id,
                         const struct channel_record *record) {
	struct file_header header;
	memset(&header, 0, sizeof header);
	header.file_id   = thread_file(host, channel_id);
	header.file_type = FILE_TYPE_CHANNEL;
	memcpy(header.data, record, sizeof *record);
	return file_header_write(header.file_id, &header);
}

bool channel_admits(uint32_t host, uint16_t channel_id, uint32_t contact_id) {
	struct channel_record record;
	if (!store_ready() || !record_read(host, channel_id, &record))
		return false;
	if (record.members > CHANNEL_MEMBERS_MAX)
		return false;                   // a record we cannot trust admits nobody
	for (int i = 0; i < record.members; i++) {
		if (record.member[i] == contact_id)
			return true;
	}
	return false;
}

bool channel_admit(uint32_t host, uint16_t channel_id, uint32_t contact_id) {
	struct channel_record record;
	if (!store_ready() || contact_id == 0 || !record_read(host, channel_id, &record))
		return false;
	if (record.members > CHANNEL_MEMBERS_MAX)
		return false;
	for (int i = 0; i < record.members; i++) {
		if (record.member[i] == contact_id)
			return true;                // already in; nothing to write
	}
	if (record.members == CHANNEL_MEMBERS_MAX) {
		hal_debug(LOG_ERROR, "channel: %u under %08x holds its %d members\n",
		          (unsigned)channel_id, (unsigned)host, CHANNEL_MEMBERS_MAX);
		return false;
	}
	record.member[record.members++] = contact_id;
	return record_write(host, channel_id, &record);
}

bool channel_expel(uint32_t host, uint16_t channel_id, uint32_t contact_id) {
	struct channel_record record;
	if (!store_ready() || !record_read(host, channel_id, &record))
		return false;
	if (record.members > CHANNEL_MEMBERS_MAX)
		return false;
	for (int i = 0; i < record.members; i++) {
		if (record.member[i] != contact_id)
			continue;
		// The order says nothing, so the last one fills the hole.
		record.member[i] = record.member[record.members - 1];
		record.member[record.members - 1] = 0;
		record.members--;
		return record_write(host, channel_id, &record);
	}
	return true;                        // not in it, which is what was wanted
}

int channel_member_count(uint32_t host, uint16_t channel_id) {
	struct channel_record record;
	if (!store_ready() || !record_read(host, channel_id, &record))
		return 0;
	if (record.members > CHANNEL_MEMBERS_MAX)
		return 0;
	return record.members;
}

bool channel_member_at(uint32_t host, uint16_t channel_id, int index, uint32_t *out) {
	struct channel_record record;
	if (!store_ready() || index < 0 || !record_read(host, channel_id, &record))
		return false;
	if (record.members > CHANNEL_MEMBERS_MAX || index >= record.members)
		return false;
	if (out)
		*out = record.member[index];
	return true;
}

// Destroying scrubs the file's own key, so the log goes with it.
bool channel_destroy(uint32_t host, uint16_t channel_id) {
	if (!store_ready() || channel_id == 0)
		return false;
	return file_destroy(thread_file(host, channel_id));
}

bool channel_by_index(int index, uint32_t *out_host, uint16_t *out_channel_id) {
	if (!store_ready())
		return false;
	int seen = 0;
	uint64_t id;
	uint8_t  type;
	for (int i = 0; file_list(i, &id, &type); i++) {
		if (type != FILE_TYPE_CHANNEL)
			continue;
		if (seen++ != index)
			continue;
		if (out_host)
			*out_host = (uint32_t)(id >> 32);
		if (out_channel_id)
			*out_channel_id = (uint16_t)(id & 0xFFFFu);
		return true;
	}
	return false;
}

// The length is the caller's: a line arrives as bytes and may contain NUL, so
// it never comes from strlen here.
uint32_t channel_append(uint32_t host, uint16_t channel_id,
                        uint32_t author, const char *text, int len) {
	if (!store_ready() || !text || len < 0)
		return FILE_NONE;
	if (len == 0 || len > CHANNEL_TEXT_MAX) {
		hal_debug(LOG_ERROR, "channel: %u bytes is not a line\n", (unsigned)len);
		return FILE_NONE;
	}
	struct channel_record record;
	if (!record_read(host, channel_id, &record)) {
		hal_debug(LOG_ERROR, "channel: no channel %u under %08x\n",
		          (unsigned)channel_id, (unsigned)host);
		return FILE_NONE;
	}

	uint8_t payload[sizeof(struct channel_line) + CHANNEL_TEXT_MAX];
	struct channel_line line = { author };
	memcpy(payload, &line, sizeof line);
	memcpy(payload + sizeof line, text, (size_t)len);
	size_t total = sizeof line + (size_t)len;

	uint64_t file_id = thread_file(host, channel_id);
	struct file_entry_meta meta = { ENTRY_CHANNEL_LINE, { 0, 0, 0 } };
	uint32_t entry = file_entry_create(file_id, (uint16_t)total, 0,
	                                   (const uint8_t *)&meta);
	if (entry == FILE_NONE) {
		hal_debug(LOG_ERROR, "channel: the store refused %u bytes\n", (unsigned)total);
		return FILE_NONE;
	}
	size_t done = 0;
	while (done < total) {
		size_t take = FILE_CHUNK;      // every write but the last is a full chunk
		if (total - done < take)
			take = total - done;
		if (file_entry_write(file_id, entry, payload + done, (int)take) != (int)take) {
			hal_debug(LOG_ERROR, "channel: write failed at %u\n", (unsigned)done);
			return FILE_NONE;
		}
		done += take;
	}
	if (!file_entry_commit(file_id, entry)) {
		hal_debug(LOG_ERROR, "channel: commit failed\n");
		return FILE_NONE;
	}
	return entry;
}

int channel_line_read(uint32_t host, uint16_t channel_id, uint32_t entry,
                      uint32_t *out_author, uint32_t *out_stamp,
                      char *buf, int max) {
	if (!store_ready() || !buf || max <= 0 || entry == FILE_NONE)
		return -1;
	uint64_t file_id = thread_file(host, channel_id);

	struct file_entry_info info;
	if (!file_entry_stat(file_id, entry, &info))
		return -1;
	if (info.length < sizeof(struct channel_line))
		return -1;
	if (out_stamp)
		*out_stamp = info.timestamp;

	struct channel_line line;
	if (file_entry_read(file_id, entry, 0, &line, (int)sizeof line) != (int)sizeof line)
		return -1;
	if (out_author)
		*out_author = line.author;

	int text_len = (int)info.length - (int)sizeof line;
	int want = text_len;
	if (want > max - 1)
		want = max - 1;
	if (want > 0 && file_entry_read(file_id, entry, (uint32_t)sizeof line,
	                                buf, want) != want)
		return -1;
	buf[want] = 0;
	return text_len;
}

uint32_t channel_newest(uint32_t host, uint16_t channel_id) {
	if (!store_ready())
		return FILE_NONE;
	return file_log_newest(thread_file(host, channel_id));
}

uint32_t channel_older(uint32_t host, uint16_t channel_id, uint32_t entry) {
	if (!store_ready())
		return FILE_NONE;
	return file_log_older(thread_file(host, channel_id), entry);
}

uint32_t channel_newer(uint32_t host, uint16_t channel_id, uint32_t entry) {
	if (!store_ready())
		return FILE_NONE;
	return file_log_newer(thread_file(host, channel_id), entry);
}
