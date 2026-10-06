// channel_log.h - a channel is a named log on a host: members send it lines and
// read them back. Only the host holds the log; a member keeps this record so
// home can name the channel before a stream is open.
//
// The file name is the identity: thread_file(host, channel_id). We host a
// channel iff host is our own partkey. Channel 0 is a contact's own thread.
//
// Portable C, core 0.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "filesystem.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHANNEL_VERSION_SHIFT   6
#define CHANNEL_VERSION_MASK    0xC0u
#define CHANNEL_VERSION_CURRENT 3
#define CHANNEL_NAME_MAX        32
#define CHANNEL_ID_MAX          65535u   // 16 bits, as the chunk header carries it
#define CHANNEL_MEMBERS_MAX     26       // 144 of the inode body's 152 bytes, leaving room to grow;
                                         // a build wanting more keeps its list elsewhere
#define CHANNEL_TEXT_MAX        960      // one stream segment is 1024, less the reply's framing

// The inode body: 144 of the 152 bytes a file header holds. member[] is LAST and
// `members` bounds it, and the body is zero-padded to 152, so the array can grow
// into the spare without a format version -- an older record's new slots read as
// zero and the count never reaches them.
#pragma pack(push, 1)
struct channel_record {
	uint8_t  flag;                     // [7:6] version, [5:0] unused
	uint16_t channel_id;
	char     name[CHANNEL_NAME_MAX];
	uint32_t epoch;                    // changes when the log's numbering does; a member's offsets are then void
	uint8_t  members;                  // slots of member[] in use
	uint32_t member[CHANNEL_MEMBERS_MAX];   // partkeys of our own contacts
};
#pragma pack(pop)

// A stored line: the author, then the text to the end of the entry. When is
// the entry's own timestamp; which channel is the file name.
#pragma pack(push, 1)
struct channel_line {
	uint32_t author;    // partkey the stream authenticated, never one the sender named
};
#pragma pack(pop)

bool     channel_create(uint32_t host, uint16_t channel_id, const char *name);   // host or joined; an existing one is left alone
uint16_t channel_new(const char *name);      // host a channel at our lowest free id; 0 if none
bool     channel_get(uint32_t host, uint16_t channel_id, struct channel_record *out);
bool     channel_rename(uint32_t host, uint16_t channel_id, const char *name);
uint32_t channel_epoch(uint32_t host, uint16_t channel_id);   // 0 = no such channel
bool     channel_new_epoch(uint32_t host, uint16_t channel_id);
int      channel_epochs_renew(void);   // after compaction: every channel we host, new numbering
bool     channel_destroy(uint32_t host, uint16_t channel_id);
bool     channel_renumber(uint32_t host, uint16_t from_id, uint16_t to_id);   // refused while the log holds anything
bool     channel_reset(uint32_t host, uint16_t channel_id);   // empty the log, keep the name, new epoch
bool     channel_by_index(int index, uint32_t *out_host, uint16_t *out_channel_id);   // false past the end

// Returns the entry id, or FILE_NONE.
uint32_t channel_append(uint32_t host, uint16_t channel_id,
                        uint32_t author, const char *text, int len);

// Text length, or -1. `buf` is NUL-terminated.
int channel_line_read(uint32_t host, uint16_t channel_id, uint32_t entry,
                      uint32_t *out_author, uint32_t *out_stamp,
                      char *buf, int max);

// FILE_NONE when empty or at either end.
uint32_t channel_newest(uint32_t host, uint16_t channel_id);
uint32_t channel_older(uint32_t host, uint16_t channel_id, uint32_t entry);
uint32_t channel_newer(uint32_t host, uint16_t channel_id, uint32_t entry);

// May this contact enter a channel we host? Asked on every inbound chunk.
// Defined per build, like validate_public_key: where the member list lives is
// the build's business.
int allow_into_channel(uint16_t channel_id, uint32_t contact_id);

// The member list, for a build that keeps one in the record.
bool channel_admits(uint32_t host, uint16_t channel_id, uint32_t contact_id);
bool channel_admit (uint32_t host, uint16_t channel_id, uint32_t contact_id);   // already a member: true, no change
bool channel_expel (uint32_t host, uint16_t channel_id, uint32_t contact_id);
int  channel_member_count(uint32_t host, uint16_t channel_id);
bool channel_member_at(uint32_t host, uint16_t channel_id, int index, uint32_t *out);

uint32_t channel_my_partkey(void);

// WHO WE ARE versus WHERE A LOG IS FILED. channel_my_partkey is the first: it
// answers "is this mine?" and every build gives the same answer. This is the
// second, and the APPLICATION answers it, like allow_into_channel:
//
//   A GROUP CHAT is one log that every member reads, so the answer is our own
//   partkey and `member` is ignored.
//
//   An EMAIL or AGENT PROXY is one log per user -- its own lines, its own epoch,
//   its own position, and no user sees another's -- so the answer is the member.
//
// Which it is belongs to the app that owns the channel, not to the build, and
// one build runs both: a group chat on one id and a proxy on another. That is
// why the id is asked about and not just the member.
//
// The high half of thread_file() is the only place a log's owner is recorded,
// and it is derived from the private key on purpose: change the key and what
// was under it stops being ours, which is what we want. Nothing stores it.
uint32_t channel_log_owner(uint16_t channel_id, uint32_t member);

// Which channel the next APP_CHANNEL foreground is for: screen_push carries
// one number and a channel name has two halves.
void channel_open(uint16_t channel_id);

// Send a line to the channel on screen. False when none is open. A bench entry point.
bool channel_screen_say(const char *text);

#ifdef __cplusplus
}
#endif
