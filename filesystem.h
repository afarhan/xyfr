// filesystem.h — THE LOGGING FILESYSTEM the device stores everything in.
//
// A FILE is a HEADER plus an append-only LOG of ENTRIES:
//
//   header  identity, type, this file's data key, and a fixed-size body the
//           filesystem stores but never reads.
//   entry   one item in the log. Framing the filesystem owns, and a payload it
//           never reads.
//
// Three prefixes, so a call says which of the three it acts on: file_ (the
// file), file_log_ (walking its entries), file_entry_ (one entry). file_storage_
// acts on the whole medium.
//
// THERE IS NO OPEN AND NO HANDLE. A file is named by (file_id, file_type) and an
// entry by its id, on every call — so this layer keeps no per-caller state at
// all. Two things fall out of that. A data key exists only inside the one call
// that needs it and is zeroed on the way out, never resident. And a torn 10 KB
// transfer resumes across a reboot with nothing in RAM, because the append point
// is the first still-erased page and the bound is the length in the entry's own
// header — both read from flash, neither remembered.
//
// WHAT IT KNOWS is deliberately almost nothing: which file an entry belongs to,
// when it was written, how long it is, whether it is deleted, and which KIND of
// entry it is. What a message means, what "read" or "delivered" mean, what a
// call record holds — all of that is the application's, carried in the FILE_META
// bytes this layer ferries and never interprets.
//
// TWO KEYS. The VOLUME key protects each header's key wrap and every entry's
// framing, so a mount can list files and scan entries without opening one. Each
// file's OWN key, minted at file_create and never leaving the device, protects
// that file's header body and its entry payloads. Which is why destroying a file
// is instant and total: scrub one key and every byte written under it is
// unreadable, with no other file touched.
//
// Portable C, core 0 only.
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>              // wg.h uses time_t and does not include this
#include "wg.h"               // KEY_LEN

#ifdef __cplusplus
extern "C" {
#endif

// ---- returns ---------------------------------------------------------------
// A call returns the value it found and reserves a sentinel. A walk returns the
// id it landed on, which is also the argument to the next call, so iteration
// needs no cursor variable of its own.
//
// FILE_NONE being 0 makes file_id 0 unusable, which costs nothing: a contact's
// file_id is its partkey, and an all-zero public key is rejected long before it
// could reach storage.
#define FILE_NONE        0u
#define FILE_ERROR       0xFFFFFFFFu

// ---- sizes -----------------------------------------------------------------
#define FILE_INODE_DATA  152u   // the application's bytes in a file header
#define FILE_META        4u     // per-entry app metadata: byte 0 below, 3 the app's
// Live inodes the directory will hold, which is the cap on FILES — one file is
// one inode. NOT a cap on contacts: a contact is one file and so is a group,
// and they share this number, 500 between them rather than 500 of each. The
// flash has 640 slots (FILE_INODE_SECTORS * 16), so this is the logical bound
// and the headroom above it absorbs a crash-left duplicate.
#define MAX_INODES       500u
#define FILE_ENTRY_MAX   10240u // the ONLY cap on an entry's payload
#define FILE_CHUNK       240u   // plaintext bytes per chunk: the unit of a write

// Flags are ACTIVE LOW, because erased NOR is 0xFF and a program can only clear
// bits — so a flag is named for its fresh state and marking something is
// file_entry_flag_clear. `flags & FILE_DELETED` therefore means NOT deleted.
//
// FILE_DELETED is the one bit this layer owns, because only it can act on the
// answer: clearing it scrubs the payload in place and compaction drops the
// entry. 0x10 is reserved (the entry seal) and is masked out of what stat
// returns; the remaining six bits are the application's — stored, returned,
// never interpreted.
#define FILE_DELETED     0x01u
#define FILE_APP_FLAGS   0xEEu

// ---- the entry kind: FILE_META byte 0 ---------------------------------------
// A log holds more than one KIND OF ENTRY — a message and a call record are
// different things sitting in the same file — so the vocabulary that tells them
// apart is defined HERE and not by any one app. If msg.c owned it, app_call.c
// would have to include msg.h to write a call.
//
// This layer defines these values and still never acts on them. What an entry
// MEANS stays the app's: msg.c reads the message kinds, app_call.c the call
// kinds, and each keeps whatever it likes in the three bytes after this one.
enum entry_kind {
	ENTRY_NONE = 0,
	ENTRY_MSG_IN,               // a message received       ) msg.c
	ENTRY_MSG_OUT,              // a message sent           )
	ENTRY_CALL_IN_MISSED,       //                          ) app_call.c
	ENTRY_CALL_IN_ANSWERED,     //                          )
	ENTRY_CALL_OUT_MISSED,      // we called, no answer     )
	ENTRY_CALL_OUT_ANSWERED,    //                          )
	ENTRY_CHANNEL_LINE,         // a line someone wrote     ) channel_log.c
};

// A channel line has no in/out: its author says who wrote it, and the host's
// copy is the only copy.

#define entry_is_message(k)  ((k) == ENTRY_MSG_IN || (k) == ENTRY_MSG_OUT)

// The meta slot laid out: the kind this layer defines, then the app's three.
#pragma pack(push, 1)
struct file_entry_meta {
	uint8_t kind;           // enum entry_kind
	uint8_t app[3];         // the writing app's, ferried and never read
};
#pragma pack(pop)

// ---- file types ------------------------------------------------------------
// What a filename extension is: one storage mechanism, several uses. A type is
// CLEARTEXT in the header, so every file of a type can be listed without
// unwrapping a key, and it is inside that header's key-wrap AAD, so it cannot be
// edited without destroying the key it describes.
//
// The type is STORED AND REPORTED, NEVER ENFORCED. It is supplied at file_create
// and on every file_header_write, and handed back by file_list and
// file_header_read — but no read call takes one and nothing in this layer
// compares one. A file_id alone names a file, so a caller that reaches a file by
// id gets whatever is stored there, of whatever type.
//
// So a caller that cares must check for itself, and the two that do both check
// while walking file_list: contacts.c skips anything that is not a contact,
// channel_log.c anything that is not a channel. Reaching a file by id and trusting
// its type is how a message once got written into a channel's log (msg.c, fixed
// 2026-08-24 by removing the caller, not by adding a check here).
#define FILE_TYPE_CONTACT 0u
#define FILE_TYPE_CHANNEL 1u

// ---- structs ---------------------------------------------------------------

// The file's head. Fixed size for every type, so no length ever crosses this
// boundary and no caller can be wrong about one. Only data[] is stored encrypted
// -- file_id and file_type live in the inode's cleartext head, which is what
// lets a mount rebuild the directory with no key, so they are filled in on read
// rather than kept twice. THE FILE_ID IS UNIQUE: it alone names the file, and
// file_type only says how to read data[]. The application overlays its own struct on data[],
// with its own size assert against FILE_INODE_DATA.
struct file_header {
	uint64_t file_id;
	uint8_t  file_type;
	uint8_t  reserved[3];
	uint8_t  data[FILE_INODE_DATA];
};

// What the filesystem knows about one entry. Filled by file_entry_stat for one
// entry, and by file_entry_scan_all for every entry in the store.
//
// No entry id here: file_entry_stat was given one and file_entry_scan_all
// returns one, so a copy in the struct could only ever echo an argument or
// disagree with it.
struct file_entry_info {
	uint64_t file_id;             // which file it belongs to, and that is the whole name
	uint32_t timestamp;           // unix seconds, stamped BY the filesystem
	uint16_t length;              // payload bytes
	uint8_t  flags;               // FILE_DELETED + FILE_APP_FLAGS, active low
	uint8_t  meta[FILE_META];     // the app's, verbatim
};

// ---- the storage medium ----------------------------------------------------

// Bring the store up over [base_sector, base_sector + sectors) of `device`:
// scan every header, rebuild the directory, recover the entry write head.
// `epoch` is the per-boot nonce epoch (store_current_epoch()) folded into every
// NEW entry's nonce; reads use each entry's own stored epoch, so any value is
// safe for a read-only mount.
bool file_storage_mount(uint8_t device, uint32_t base_sector, uint32_t sectors,
                        const uint8_t volume_key[KEY_LEN], uint32_t epoch);

// Push the page buffer to flash. The durability point: an entry is on the
// medium after this, not before.
bool file_storage_flush(void);

// How far compaction has got, in bytes of the region read. Called often enough
// to animate and rarely enough to be free: once per source sector, so a few
// hundred times over the whole region. It runs INSIDE the compaction, with core
// 0 blocked, so it may only paint — anything that touches flash or the log from
// here is looking at a store that is half-moved.
typedef void (*file_compact_progress_fn)(uint32_t done, uint32_t total);

// Reclaim the space held by deleted entries and dead headers, and the ONLY thing
// that ever frees any: a delete leaves a tombstone and the append head only goes
// forward, so without this a store fills once and stays full. A device that
// reaches 100% stops accepting messages from every peer, permanently
// (device-observed 2026-08-29).
//
// IT MOVES ENTRIES, so every entry id in existence goes stale — file_id does
// not, being an identity rather than a position. Nothing may hold an id across
// it. The device runs it from loop() and reboots the moment it returns, which is
// what makes that true: the RAM holding those ids does not survive to use them.
//
// `progress` may be NULL.
bool file_storage_compact(file_compact_progress_fn progress);

int  file_storage_usage(void);     // percent full — the About line

// Crypto-erase everything: every file key, every entry, the directory.
bool file_storage_wipe(void);

// Read-only post-mortem of the whole region, to the debug log. Writes NOTHING.
// Separates the three states that look identical from the API: a slot reading
// 0xFF was ERASED, 0x00 was deliberately blanked, and live-but-undecryptable is
// a key fault. Bench only (`fsdump`).
void file_storage_dump(void);

// ---- a file ----------------------------------------------------------------

// Create a file from its header, atomically, minting its data key. false if the
// id exists, the store is full, or the write did not verify.
bool file_create(const struct file_header *h);

// Scrub this file's data key. Its header body and every entry ever written under
// it become permanently unreadable; nothing else is touched.
bool file_destroy(uint64_t file_id);

// Walk the whole directory: `iter` counts from 0 across EVERY file, and the
// caller selects the ones it wants by type. Reads no flash and needs no key —
// the type is cleartext and cached at mount. false ends the walk.
//
// It enumerates rather than filters because the directory is a few tens of
// entries: filtering here would only let this layer guess at why a caller wants
// a subset, and it could not express "every group" at all.
bool file_list(int iter, uint64_t *out_file_id, uint8_t *out_file_type);

// ---- the header ------------------------------------------------------------
bool file_header_read (uint64_t file_id, struct file_header *out);
bool file_header_write(uint64_t file_id, const struct file_header *in);

// ---- the log: walk the entries ---------------------------------------------
// Each returns the entry it landed on, or FILE_NONE. Newest-first is the order
// readers want, so that is the direction with no cost.
uint32_t file_log_newest(uint64_t file_id);
uint32_t file_log_older (uint64_t file_id, uint32_t entry);
uint32_t file_log_newer (uint64_t file_id, uint32_t entry);

// ---- one entry -------------------------------------------------------------

// Reserve an entry of `length` bytes. THE LENGTH IS KNOWN UP FRONT: the whole
// span is erased now, which is what lets several files be filled at once and
// what lets a half-written entry resume after a reboot. `meta` is stored in the
// framing — so a scan can filter on it without this file's key — and never
// interpreted. Returns the entry id, FILE_NONE on failure.
//
// `timestamp` is unix seconds, and 0 means "you stamp it". A caller passes one
// only when the value came from somewhere else and has to be preserved: a group
// message carries the stamp its host minted, and every member must store that
// same number or they will disagree about the order of the group's messages.
// A stamp this file mints is always above every stamp already in the log, so
// entries are ordered by it even across a boot with no NTP time yet.
// Would an entry of this payload length reserve? Asked before taking bytes off a
// transport, since taking them and failing to store them loses them.
bool file_entry_fits(uint16_t length);

uint32_t file_entry_create(uint64_t file_id, uint16_t length,
                           uint32_t timestamp, const uint8_t meta[FILE_META]);

// Append at the resume point, which is found on flash, not remembered. `count`
// must be exactly FILE_CHUNK except for the last write of the entry, because a
// chunk is sealed on its own and a short one can only be the end. Writing past
// the reserved length FAILS rather than corrupting the next entry. Returns bytes
// written, -1 on error.
int file_entry_write(uint64_t file_id, uint32_t entry,
                     const void *data, int count);

// Seal it. Until this, a torn transfer is skipped by a scan.
bool file_entry_commit(uint64_t file_id, uint32_t entry);

// How much of the entry is already on flash — the resume point after a reboot,
// found by looking for the first still-erased page.
int file_entry_filled(uint64_t file_id, uint32_t entry);

// Read from `at` within the entry. Decrypts only the chunks it touches, so a
// 10 KB entry is never resident. Returns bytes read, -1 on error.
int file_entry_read(uint64_t file_id, uint32_t entry,
                    uint32_t at, void *buf, int max);

bool file_entry_stat(uint64_t file_id, uint32_t entry,
                     struct file_entry_info *out);

// Clear flag bits. Bits are only ever CLEARED — an in-place NOR program with no
// erase, which is what makes marking something deleted or delivered cost nothing.
bool file_entry_flag_clear(uint64_t file_id, uint32_t entry,
                           uint8_t bits);

// ---- every entry of every file ---------------------------------------------
// Framing ONLY, never payload — so it needs no file's data key and decrypts no
// chunk. That is what makes a whole-store sweep cheap, and why an unread count is
// a scan rather than something this layer keeps. Pass FILE_NONE to start; the
// returned id is the argument to the next call.
uint32_t file_entry_scan_all(uint32_t cursor, struct file_entry_info *out);

#ifdef __cplusplus
}
#endif
