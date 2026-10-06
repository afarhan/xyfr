//
// filesystem.c — the logging filesystem. See filesystem.h for the contract.
//
// Two internal layers:
//
//   the inode ring — a page-slotted wrap-around ring of fixed-size inodes with
//   per-inode AEAD. One inode is one flash page. Its keywrap doubles as the
//   liveness marker, so blanking that wrap is at once the delete and the
//   crypto-erase.
//
//   the entry log — an append-only byte log. Each entry names the file it
//   belongs to, and its framing is sealed under the volume key, so a scan can
//   attribute every entry without any file's own data key.
//
// An inode body is FILE_INODE_DATA bytes this file never reads and an entry
// carries a file_type it never interprets: what a file means is the
// application's business.
//
// Portable C (rawflash HAL + crypto.c via wg.h); host-tested under
// rawflash_posix. Core 0 only.
//

#include <string.h>
#include "config.h"    // kernel_cfg->max_files, kernel_alloc
#include "filesystem.h"
#include "rawflash.h"
#include "hal.h"    // hal_debug, LOG_* (pulls in time_t before wg.h needs it)
#include "wg.h"     // xchacha20poly1305_encrypt/decrypt, crypto_zero, AUTHTAG_LEN

// kernel.h holds the stamp clock, and this layer sits far below it — including
// that header here would drag the whole app world into the store. Declared, not
// included, the same way wg.h declares get_current_time_seconds.
uint32_t kernel_time_mint(void);
void     kernel_time_seen(uint32_t stamp);

// ---- structs ---------------------------------------------------------------
// The inode, as it sits on flash: one flash page. Everything ahead of the
// keywrap field is cleartext — the nonce, the identity, the type and the write
// counter — so a mount rebuilds the directory without unwrapping a single key.
// That same span is the AAD of the key wrap, so none of it can be edited
// without destroying the key it describes.
//
// The budget is exact. XChaCha20 needs all 24 nonce bytes, and file_id,
// write_seq, file_type and one spare fill what is left of the cleartext head.
#define FILE_NONCE_BYTES  24u    // XChaCha20 takes all 24
#define FILE_TAG_BYTES    16u    // Poly1305 authentication tag

#pragma pack(push, 1)
struct file_inode {
	uint8_t  nonce[FILE_NONCE_BYTES];   // random per write; no counter, so no epoch to keep
	uint64_t file_id;                   // THE identity, and it is unique: what every call names
	uint16_t write_seq;                 // bumped per write; breaks crash-left duplicate ties
	uint8_t  file_type;                 // FILE_TYPE_*; cleartext, so listing needs no key
	uint8_t  reserved[5];               // pads the cleartext head to 40 B
	uint8_t  keywrap[KEY_LEN + FILE_TAG_BYTES];         // the data key, under the VOLUME key
	uint8_t  body[FILE_INODE_DATA + FILE_TAG_BYTES];    // the header body, under the DATA key
};
#pragma pack(pop)
_Static_assert(sizeof(struct file_inode) == RAWFLASH_PAGE,
               "an inode must be exactly one flash page");

// ---- the entry log ----
// The cleartext head of an entry's header page. Readable with no key, which is
// what lets a mount walk the log before the store is unlocked.
#pragma pack(push, 1)
struct entry_hdr {
	uint32_t magic;         // ENTRY_MAGIC; anything else is a gap or corruption
	uint16_t payload_len;   // body bytes, across all chunks
	uint64_t nonce_seq;     // AEAD nonce counter; NOT monotonic (compaction drops entries)
	uint8_t  status;        // FILE_*; mutable IN PLACE, bits only ever cleared
	uint32_t epoch;         // per-boot nonce epoch; cleartext because it is part of the
	                        // nonce, so flipping it only fails the authentication tag.
	                        // It sits after status so status keeps a fixed offset.
};

// An entry's metadata, encrypted under the volume key and deliberately not
// under the file's own key, so a scan can learn which file an entry belongs to
// without ever opening that file.
// No file_type: a file_id is unique, so it alone says which file an entry
// belongs to and a second field could only disagree with it.
struct entry_framing {
	uint64_t file_id;
	uint32_t timestamp;     // unix seconds
	uint8_t  meta[FILE_META];
	uint8_t  reserved[8];   // spare, and the padding to a round 24 bytes
};
#pragma pack(pop)

// One entry decoded into RAM. struct file_entry_info is the public projection of
// this; nonce_seq, epoch and the seal bit stay here because only this file acts
// on them.
_Static_assert(sizeof(struct file_entry_meta) == FILE_META,
               "the meta slot is 4 bytes");

struct entry_meta {
	uint32_t entry_id;
	uint64_t nonce_seq;
	uint32_t epoch;
	uint64_t file_id;
	uint32_t timestamp;
	uint16_t payload_len;
	uint8_t  status;
	uint8_t  meta[FILE_META];
};

// One file's newest entry, so a log head is O(1) rather than a scan. Rebuilt by
// walking the log at mount: the entries on flash are the truth, this is the index.
struct log_index {
	uint64_t file_id;
	uint32_t offset;        // byte offset of the newest entry
	bool     used;
	bool     has_head;
};

// A walk over the log. Byte offset only: an entry is found by its magic, and a
// gap or a corrupt entry resyncs to the next page.
struct log_walk {
	uint32_t off;
};

// One row of the RAM directory: which slot holds this file. Rebuilt by scanning
// the ring at mount; the flash inodes are the truth, this is the index.
struct dir_entry {
	uint64_t file_id;
	uint32_t slot;
	uint8_t  file_type;     // cached from the inode's cleartext head
};

// What the cleartext head of an inode says. Readable with no key at all, which
// is what lets a mount rebuild the whole directory without the volume key.
struct slot_head {
	uint64_t file_id;
	uint32_t write_seq;
	uint8_t  file_type;
};

#define FILE_MEMBER_LEN(m)    ((uint32_t)sizeof(((struct file_inode *)0)->m))
#define FILE_INODE_REC_BYTES  ((uint32_t)sizeof(struct file_inode))
#define FILE_KEYWRAP_OFF      ((uint32_t)offsetof(struct file_inode, keywrap))
#define FILE_BODY_OFF         ((uint32_t)offsetof(struct file_inode, body))
#define FILE_BODY_CT_LEN      FILE_MEMBER_LEN(body)
#define FILE_KEYWRAP_LEN      FILE_MEMBER_LEN(keywrap)

// Slot classification comes from the keywrap field, not a magic byte: all-0xFF
// is erased/free, all-0x00 is blanked/dead, anything else is live.
#define SLOT_CLASS_FREE 0xFFu
#define SLOT_CLASS_DEAD 0x00u
#define SLOT_CLASS_LIVE 0xC0u
#define SLOT_CLASS_BAD  0xFEu   // unreadable, or live-looking but won't unwrap

#define RECS_PER_SECTOR  (RAWFLASH_SECTOR / FILE_INODE_REC_BYTES)   // 16

_Static_assert(FILE_TAG_BYTES == AUTHTAG_LEN, "authentication tag size must match the AEAD");
_Static_assert(RAWFLASH_SECTOR % FILE_INODE_REC_BYTES == 0, "inodes must tile the sector");
_Static_assert(FILE_INODE_DATA + FILE_TAG_BYTES == FILE_BODY_CT_LEN, "body = data + authentication tag");
_Static_assert(FILE_KEYWRAP_LEN == KEY_LEN + FILE_TAG_BYTES, "keywrap = key + authentication tag");

// ---- the entry log on flash ----
#define ENTRY_MAGIC        0x4D534734u   // marks an entry start; anything else is a gap or corruption
#define FILE_CHUNK_PLAIN   FILE_CHUNK    // plaintext bytes carried by one chunk
#define FILE_CHUNK_SLOT    RAWFLASH_PAGE // one page per chunk: plaintext + auth tag

// The status byte is active low (see filesystem.h). SEALED is ours alone and is
// masked out of what file_entry_stat returns.
#define FILE_ST_DELETED  FILE_DELETED   // clearing this bit is the delete
#define FILE_ST_SEALED   0x10u          // still set means reserved, filling or torn;
                                        // file_entry_commit clears it last

#define entry_is_deleted(m)   (!((m).status & FILE_ST_DELETED))

#define SLOT_FREE 0
#define SLOT_LIVE 1
#define SLOT_DEAD 2
#define MAX_SLOTS 1024   // covers the FILE_INODE_SECTORS ring (640 slots) with headroom

// One region, two tenants: the inode ring takes the first FILE_INODE_SECTORS and
// the entry log takes the rest. Each grows only within its own half, so neither
// can walk into the other.
#define FILE_INODE_SECTORS 40u

// The entry log is the second half of this file; the inode ring calls into it.
static bool entrylog_init(uint8_t device, uint32_t base_sector, uint32_t num_sectors,
                          const uint8_t volume_key[KEY_LEN], uint32_t epoch);
static bool entrylog_mount(void);
static bool entrylog_wipe(void);

// ---- ALL of this file's state, so its RAM cost is visible in one place -------
// Three layers share it: the inode ring, the page log underneath the entry log,
// and the entry log's own index.

// The inode ring.
static uint8_t  s_device;
static uint32_t s_base;          // base sector
static uint32_t s_sectors;       // sectors in the ring
static uint32_t s_slots;         // total slots = s_sectors * RECS_PER_SECTOR
static uint8_t  s_volume_key[KEY_LEN];
static uint8_t  s_state[MAX_SLOTS];
static struct dir_entry *s_dir;         // kernel_cfg->max_files entries, from mount
static int      s_dir_cap;              // what was allocated, and every bound below
static int      s_dir_count;
static uint32_t s_next_id;       // dup-tiebreak sequence only — NOT nonce material
static uint32_t s_cursor;        // round-robin free-slot search start
// The per-boot nonce epoch, taken at mount. nonce_seq regresses (compaction drops
// entries and the mount recomputes it from survivors), so it is the pair that
// must never repeat.
static uint32_t s_epoch;

// The page log: byte-addressable appending under the entry log. page_buffer is
// the only place page granularity matters -- everything on flash below
// durable_offset is durable, and the buffer is what is not yet written.
static uint8_t  pagelog_device;
static uint32_t pagelog_base_sector;
static uint32_t pagelog_sectors;
static uint32_t pagelog_capacity_bytes;
static uint32_t append_offset;                  // next append offset
static uint32_t durable_offset;                 // start of the RAM page (== bytes on flash)
static uint8_t  page_buffer[RAWFLASH_PAGE];     // 256 bytes
static uint16_t page_buffer_fill;               // append_offset - durable_offset, 0..256
static bool     pagelog_ready;

// The entry log.
static bool     s_log_ready;
static uint8_t  entrylog_device;
static uint32_t log_base_sector;
static uint32_t log_sector_count;
static uint64_t next_nonce_seq;
static uint32_t current_epoch;                  // per-boot nonce epoch stamped on NEW entries
static uint32_t live_entry_count;
static struct log_index *log_index_table;   // s_dir_cap entries, allocated with s_dir
static bool     s_ready;

// ---- slot addressing ----
static uint32_t slot_sector(uint32_t s) { return s_base + s / RECS_PER_SECTOR; }
static uint32_t slot_off(uint32_t s)    { return (s % RECS_PER_SECTOR) * FILE_INODE_REC_BYTES; }

// ---- crypto helpers ----
// Classify an inode image by its keywrap field alone: all-0xFF is an erased
// slot, all-0x00 a blanked one, anything else a live wrap. A live wrap coming
// out all-0xFF or all-0x00 by chance is a 2^-384 event.
static uint8_t classify(const uint8_t rec[FILE_INODE_REC_BYTES]) {
	const struct file_inode *r = (const struct file_inode *)rec;
	uint8_t and_all = 0xFF, or_all = 0x00;
	for (unsigned i = 0; i < sizeof r->keywrap; i++) {
		and_all &= r->keywrap[i];
		or_all  |= r->keywrap[i];
	}
	if (and_all == 0xFF)
		return SLOT_CLASS_FREE;
	if (or_all == 0x00)
		return SLOT_CLASS_DEAD;
	return SLOT_CLASS_LIVE;
}

// write_seq is stored little-endian, which is also how a packed uint32_t lands
// on both ends we build for (RP2350 and x86), so the field IS the on-disk value.
// The write counter only ever separates two crash-left duplicates of one file,
// and those are written consecutively — so 16 bits is ample and the wrap is
// harmless, provided the comparison is wrap-safe. Same idiom as every deadline
// in this codebase: subtract, then look at the sign.
static uint32_t write_seq_of(const uint8_t rec[FILE_INODE_REC_BYTES]) {
	const struct file_inode *r = (const struct file_inode *)rec;
	return r->write_seq;
}

static bool write_seq_newer(uint32_t a, uint32_t b) {
	return (int16_t)((uint16_t)a - (uint16_t)b) > 0;
}

// Build a full inode page. The nonce is fresh hardware randomness, so the inode
// carries everything needed to decrypt it and no external counter state has to
// survive. `data_key` is this file's own key: minted by the caller for a new
// file, carried forward unchanged for an update. All-zero is refused, because a
// known key is no key.
static bool build_inode(uint8_t rec[FILE_INODE_REC_BYTES], const void *body,
                        const uint8_t data_key[KEY_LEN], uint64_t file_id,
                        uint32_t write_seq, uint8_t file_type) {
	uint8_t key_or = 0;
	for (unsigned i = 0; i < KEY_LEN; i++)
		key_or |= data_key[i];
	if (key_or == 0) {
		hal_debug(LOG_ERROR, "filesystem: refusing to write a zero data key\n");
		return false;
	}

	struct file_inode *r = (struct file_inode *)rec;
	memset(rec, 0, FILE_INODE_REC_BYTES);
	fill_random(r->nonce, sizeof r->nonce);
	r->write_seq = (uint16_t)write_seq;
	r->file_id   = file_id;
	r->file_type = file_type;   // cleartext, but inside the keywrap's AAD below

	const uint8_t *nonce = r->nonce;

	// level 1: wrap this file's data key under the volume key. AAD = everything
	// before the wrap: nonce + write_seq + file_type + reserved. So the type
	// cannot be edited without destroying the key it describes.
	xchacha20poly1305_encrypt(r->keywrap, data_key, KEY_LEN,
	                          rec, FILE_KEYWRAP_OFF, nonce, s_volume_key);

	// level 2: the body under the data key, with that key's wrap as AAD so a body
	// cannot be spliced onto another inode. The body is FILE_INODE_DATA bytes the
	// filesystem never reads; what a file type keeps there is its own business.
	xchacha20poly1305_encrypt(r->body, body, FILE_INODE_DATA,
	                          rec, FILE_BODY_OFF, nonce, data_key);
	return true;
}

// Read a slot and classify it. If it is live, unwrap the data key and decrypt
// the body into the caller's buffers; either may be NULL. The key comes back
// separately because it belongs to the filesystem, not to whatever the body
// happens to be. SLOT_CLASS_BAD means a read failure, or a live-looking slot
// that will not open.
static uint8_t read_slot(uint32_t s, void *out_body, uint8_t out_key[KEY_LEN],
                         struct slot_head *out_head) {
	uint8_t rec[FILE_INODE_REC_BYTES];
	if (!rawflash_read(s_device, slot_sector(s), slot_off(s), rec, FILE_INODE_REC_BYTES))
		return SLOT_CLASS_BAD;
	uint8_t cls = classify(rec);
	if (cls != SLOT_CLASS_LIVE)  // free or dead — nothing to decrypt
		return cls;
	const struct file_inode *r = (const struct file_inode *)rec;
	if (out_head) {
		out_head->file_id   = r->file_id;
		out_head->write_seq = r->write_seq;
		out_head->file_type = r->file_type;
	}
	if (out_body || out_key) {
		const uint8_t *nonce = r->nonce;
		uint8_t key[KEY_LEN];
		// AAD is everything ahead of each ciphertext, so a body cannot be spliced
		// onto another inode and the cleartext head cannot be edited.
		if (!xchacha20poly1305_decrypt(key, r->keywrap, sizeof r->keywrap,
		                               rec, FILE_KEYWRAP_OFF, nonce, s_volume_key)) {
			hal_debug(LOG_ERROR, "filesystem: keywrap unwrap failed at slot %u"
			                     " (wrong volume key?)\n", s);
			return SLOT_CLASS_BAD;
		}
		if (out_body) {
			uint8_t pt[FILE_INODE_DATA];
			if (!xchacha20poly1305_decrypt(pt, r->body, sizeof r->body,
			                               rec, FILE_BODY_OFF, nonce, key)) {
				hal_debug(LOG_ERROR, "filesystem: body decrypt failed at slot %u\n", s);
				crypto_zero(key, sizeof key);
				return SLOT_CLASS_BAD;
			}
			memcpy(out_body, pt, FILE_INODE_DATA);
			crypto_zero(pt, sizeof pt);
		}
		if (out_key)
			memcpy(out_key, key, KEY_LEN);
		crypto_zero(key, sizeof key);
	}
	return SLOT_CLASS_LIVE;
}

static bool write_inode(uint32_t s, const uint8_t rec[FILE_INODE_REC_BYTES]) {
	return rawflash_program(s_device, slot_sector(s), slot_off(s), rec, FILE_INODE_REC_BYTES);
}

// Crypto-erase a slot. What matters is zeroing the keywrap, which destroys the
// file's data key and makes the inode body and every entry payload for that file
// permanently undecryptable. The whole page is zeroed because rawflash programs
// are page-granular (rawflash.h), so a keywrap-sized partial program would be
// rejected; zeroing the rest costs nothing and leaves no residual ciphertext. An
// all-zero keywrap is what classify() reads as SLOT_CLASS_DEAD.
static bool blank_slot(uint32_t s) {
	uint8_t zero[FILE_INODE_REC_BYTES];
	memset(zero, 0, sizeof zero);
	if (!rawflash_program(s_device, slot_sector(s), slot_off(s), zero, FILE_INODE_REC_BYTES))
		return false;
	s_state[s] = SLOT_DEAD;
	return true;
}

// ---- directory ----
// Keyed on file_id ALONE, which is the whole name of a file; file_type only says
// how to read data[] and is never matched on. Callers hold the id already, so a
// lookup asks one question.
static struct dir_entry *dir_find(uint64_t file_id) {
	for (int i = 0; i < s_dir_count; i++)
		if (s_dir[i].file_id == file_id)
			return &s_dir[i];
	return NULL;
}
static void dir_remove(uint64_t file_id) {
	for (int i = 0; i < s_dir_count; i++)
		if (s_dir[i].file_id == file_id) {
			s_dir[i] = s_dir[--s_dir_count];
			return;
		}
}

// ---- free-slot search + GC ----
static int sector_counts(uint32_t sec, int *live, int *dead) {
	int live_count = 0;
	int dead_count = 0;
	uint32_t first_slot = (sec - s_base) * RECS_PER_SECTOR;
	for (uint32_t i = 0; i < RECS_PER_SECTOR; i++) {
		if (s_state[first_slot + i] == SLOT_LIVE)
			live_count++;
		else if (s_state[first_slot + i] == SLOT_DEAD)
			dead_count++;
	}
	if (live)
		*live = live_count;
	if (dead)
		*dead = dead_count;
	return RECS_PER_SECTOR - live_count - dead_count;   // free
}

static int find_free(uint32_t exclude_sector) {
	for (uint32_t n = 0; n < s_slots; n++) {
		uint32_t s = (s_cursor + n) % s_slots;
		if (s_state[s] == SLOT_FREE && slot_sector(s) != exclude_sector) {
			s_cursor = (s + 1) % s_slots;
			return (int)s;
		}
	}
	return -1;
}

// Reclaim one sector: pick the live-poorest sector that has at least one dead
// slot, copy-forward its live entries (a byte copy — the nonce is stored in the
// inode, so the ciphertext is position-independent) to free slots elsewhere,
// then erase it.
// Returns true if it freed any space.
static bool gc_once(void) {
	int best = -1, best_live = RECS_PER_SECTOR + 1;
	for (uint32_t sec = s_base; sec < s_base + s_sectors; sec++) {
		int live, dead;
		sector_counts(sec, &live, &dead);
		if (dead == 0)  // nothing to reclaim here
			continue;
		if (live < best_live) {
			best_live = live;
			best = (int)sec;
		}
	}
	if (best < 0)
		return false;

	uint32_t victim = (uint32_t)best;
	uint32_t first_slot = (victim - s_base) * RECS_PER_SECTOR;
	for (uint32_t i = 0; i < RECS_PER_SECTOR; i++) {
		uint32_t s = first_slot + i;
		if (s_state[s] != SLOT_LIVE)
			continue;
		int dst = find_free(victim);           // never copy back into the victim
		if (dst < 0)  // wedged: no room to copy (shouldn't happen w/ headroom)
			return false;
		uint8_t rec[FILE_INODE_REC_BYTES];
		if (!rawflash_read(s_device, slot_sector(s), slot_off(s), rec, FILE_INODE_REC_BYTES))
			return false;
		if (!write_inode((uint32_t)dst, rec))
			return false;
		s_state[dst] = SLOT_LIVE;
		// remap the directory entry that pointed at the old (about-to-be-erased) slot
		for (int e = 0; e < s_dir_count; e++)
			if (s_dir[e].slot == s) {
				s_dir[e].slot = (uint32_t)dst;
				break;
			}
	}
	if (!rawflash_erase(s_device, victim))
		return false;
	for (uint32_t i = 0; i < RECS_PER_SECTOR; i++)
		s_state[first_slot + i] = SLOT_FREE;
	return true;
}

// Find a free slot, running GC if the ring has run dry.
static int acquire_free(void) {
	int s = find_free(UINT32_MAX);   // UINT32_MAX is never a real sector
	if (s >= 0)
		return s;
	if (!gc_once())
		return -1;
	return find_free(UINT32_MAX);
}

// ---- public API ----
bool file_storage_mount(uint8_t device, uint32_t base_sector, uint32_t sectors,
                        const uint8_t volume_key[KEY_LEN], uint32_t epoch) {
	s_epoch = epoch;
	s_ready = false;
	s_log_ready = false;
	// The two directories are allocated once and kept: a remount rebuilds their
	// contents, never their size.
	if (!s_dir) {
		int want = kernel_cfg->max_files;
		s_dir = kernel_alloc((size_t)want * sizeof *s_dir);
		log_index_table = kernel_alloc((size_t)want * sizeof *log_index_table);
		if (!s_dir || !log_index_table)
			return false;
		s_dir_cap = want;
	}
	if (sectors <= FILE_INODE_SECTORS)
		return false;
	if (base_sector + sectors > rawflash_sector_count(device))
		return false;
	uint32_t log_base = base_sector + FILE_INODE_SECTORS;
	uint32_t log_sectors = sectors - FILE_INODE_SECTORS;
	sectors = FILE_INODE_SECTORS;
	uint32_t slots = sectors * RECS_PER_SECTOR;
	if (slots > MAX_SLOTS)
		return false;
	if (base_sector + sectors > rawflash_sector_count(device))
		return false;

	s_device = device;
	s_base = base_sector;
	s_sectors = sectors;
	s_slots = slots;
	memcpy(s_volume_key, volume_key, KEY_LEN);
	memset(s_state, SLOT_FREE, sizeof s_state);
	s_dir_count = 0;
	s_next_id = 0;
	s_cursor = 0;

	// The scan needs no key: identity, type and the write counter are all in the
	// inode's cleartext head, so the directory is rebuilt without unwrapping
	// anything. A wrong volume key then shows up when a file is read, rather than
	// as a store that appears empty.
	for (uint32_t s = 0; s < s_slots; s++) {
		struct slot_head head;
		uint8_t cls = read_slot(s, NULL, NULL, &head);
		if (cls == SLOT_CLASS_FREE) {
			s_state[s] = SLOT_FREE;
			continue;
		}
		if (cls != SLOT_CLASS_LIVE) {  // dead or unreadable
			s_state[s] = SLOT_DEAD;
			continue;
		}

		// A live wrap advances the sequence even if the inode will not open;
		// skipping it lets write_seq regress far enough to collide.
		if (write_seq_newer(head.write_seq + 1, s_next_id))
			s_next_id = (head.write_seq + 1) & 0xFFFFu;

		struct dir_entry *e = dir_find(head.file_id);
		if (!e) {
			if (s_dir_count >= s_dir_cap) {
				s_state[s] = SLOT_LIVE;
				continue;
			}
			s_dir[s_dir_count].file_id   = head.file_id;
			s_dir[s_dir_count].slot      = s;
			s_dir[s_dir_count].file_type = head.file_type;
			s_dir_count++;
			s_state[s] = SLOT_LIVE;
		} else {
			// crash-left duplicate: keep the newer write_seq, blank the loser
			struct slot_head other;
			read_slot(e->slot, NULL, NULL, &other);
			if (write_seq_newer(head.write_seq, other.write_seq)) {
				uint32_t loser = e->slot;
				e->slot = s;
				s_state[s] = SLOT_LIVE;
				blank_slot(loser);
			} else {
				blank_slot(s);
			}
		}
	}
	s_ready = true;

	// The inode ring is up, so find_file() can resolve a data key -- which the
	// entry log needs before it reads a single payload.
	if (!entrylog_init(device, log_base, log_sectors, volume_key, s_epoch))
		return false;
	return entrylog_mount();
}

// ---- naming a file ----------------------------------------------------------
// Naming a file is a directory lookup plus a key unwrap, done per call. The key
// is a local that the caller zeroes, so no plaintext data key is ever resident,
// which is the whole reason there is no open() here.
static bool find_file(uint64_t file_id,
                      uint32_t *out_slot, uint8_t out_key[KEY_LEN]) {
	if (!s_ready)
		return false;
	struct dir_entry *e = dir_find(file_id);
	if (!e)
		return false;
	if (out_slot)
		*out_slot = e->slot;
	if (!out_key)
		return true;
	if (read_slot(e->slot, NULL, out_key, NULL) != SLOT_CLASS_LIVE) {
		crypto_zero(out_key, KEY_LEN);
		return false;
	}
	return true;
}

// ---- writing an inode ------------------------------------------------------
// The one write path, shared by file_create and file_header_write. Crash-safe in
// this order: write the new slot, verify the readback, flip the directory, and
// only then blank the old one, so a power loss anywhere leaves at least one
// readable copy and the higher write_seq says which.
static bool inode_store(uint64_t file_id, uint8_t file_type, const void *body,
                        const uint8_t data_key[KEY_LEN]) {
	struct dir_entry *e = dir_find(file_id);

	if (e) {
		uint8_t cur[FILE_INODE_DATA];
		if (read_slot(e->slot, cur, NULL, NULL) == SLOT_CLASS_LIVE &&
		    memcmp(cur, body, FILE_INODE_DATA) == 0)
			return true;                 // compare-before-write: no flash wear
	} else if (s_dir_count >= s_dir_cap) {
		hal_debug(LOG_WARNING, "filesystem: full (%d), reject new %08x\n",
		          s_dir_count, (unsigned)file_id);
		return false;
	}

	int dst = acquire_free();
	if (dst < 0) {
		hal_debug(LOG_ERROR, "filesystem: no free slot for %08x\n", (unsigned)file_id);
		return false;
	}

	uint32_t write_seq = s_next_id;
	uint8_t rec[FILE_INODE_REC_BYTES];
	if (!build_inode(rec, body, data_key, file_id, write_seq, file_type))
		return false;
	if (!write_inode((uint32_t)dst, rec))
		return false;

	uint8_t verify[FILE_INODE_DATA];
	if (read_slot((uint32_t)dst, verify, NULL, NULL) != SLOT_CLASS_LIVE ||
	    memcmp(verify, body, FILE_INODE_DATA) != 0) {
		hal_debug(LOG_ERROR, "filesystem: verify failed for %08x\n", (unsigned)file_id);
		return false;   // not committed to the directory; the slot reads as dead-ish
	}
	s_state[dst] = SLOT_LIVE;
	s_next_id = (write_seq + 1) & 0xFFFFu;

	uint32_t old_slot = UINT32_MAX;
	if (e)
		old_slot = e->slot;
	if (e) {
		e->slot = (uint32_t)dst;
	} else {
		s_dir[s_dir_count].file_id   = file_id;
		s_dir[s_dir_count].slot      = (uint32_t)dst;
		s_dir[s_dir_count].file_type = file_type;
		s_dir_count++;
	}

	if (old_slot != UINT32_MAX)
		blank_slot(old_slot);        // crypto-erase the superseded copy
	return true;
}

// ---- the file --------------------------------------------------------------

bool file_create(const struct file_header *h) {
	if (!s_ready || !h || h->file_id == FILE_NONE)
		return false;
	if (dir_find(h->file_id))
		return false;                // exists: this is create, not update
	// Mint this file's data key. It never leaves the device and is never shared
	// with the peer: it protects what is at rest, not what is transmitted.
	uint8_t data_key[KEY_LEN];
	fill_random(data_key, sizeof data_key);
	bool ok = inode_store(h->file_id, h->file_type, h->data, data_key);
	crypto_zero(data_key, sizeof data_key);
	return ok;
}

bool file_destroy(uint64_t file_id) {
	uint32_t slot;
	if (!find_file(file_id, &slot, NULL))
		return false;
	dir_remove(file_id);
	return blank_slot(slot);   // scrub the wrapped key: the crypto-erase
}

// Enumerates, it does not filter. The directory is a few tens of rows in RAM, so
// a caller walking all of them and ignoring most costs nothing, and this layer
// stays ignorant of why anyone wants a subset — the same reasoning that makes an
// unread count a scan rather than an index.
bool file_list(int iter, uint64_t *out_file_id, uint8_t *out_file_type) {
	if (!s_ready || iter < 0 || iter >= s_dir_count)
		return false;
	if (out_file_id)
		*out_file_id = s_dir[iter].file_id;
	if (out_file_type)
		*out_file_type = s_dir[iter].file_type;
	return true;
}

// ---- the header ------------------------------------------------------------
// file_id and file_type come from the slot's cleartext head, not from the
// ciphertext, so the two can never disagree.

bool file_header_read(uint64_t file_id, struct file_header *out) {
	if (!out || !s_ready)
		return false;
	struct dir_entry *e = dir_find(file_id);
	if (!e)
		return false;
	if (read_slot(e->slot, out->data, NULL, NULL) != SLOT_CLASS_LIVE)
		return false;
	out->file_id   = file_id;
	out->file_type = e->file_type;
	memset(out->reserved, 0, sizeof out->reserved);
	return true;
}

// Rewrites the body under the file's existing data key. Rotating it would orphan
// every entry already written for this file, so the key is read back and reused.
bool file_header_write(uint64_t file_id, const struct file_header *in) {
	uint8_t data_key[KEY_LEN];
	if (!in || !s_ready)
		return false;
	// The type is what the inode already says: a write replaces the BODY, and
	// nothing may change what kind of file this is under a caller that only
	// named its id.
	struct dir_entry *e = dir_find(file_id);
	if (!e || !find_file(file_id, NULL, data_key))
		return false;
	bool ok = inode_store(file_id, e->file_type, in->data, data_key);
	crypto_zero(data_key, sizeof data_key);
	return ok;
}


bool file_storage_wipe(void) {
	if (!s_ready)
		return false;
	for (uint32_t sec = s_base; sec < s_base + s_sectors; sec++)
		if (!rawflash_erase(s_device, sec))
			return false;
	if (s_log_ready && !entrylog_wipe())
		return false;
	memset(s_state, SLOT_FREE, sizeof s_state);
	s_dir_count = 0;
	s_cursor = 0;
	// write_seq is not nonce material: it only orders a crash-left duplicate pair,
	// and a wipe leaves no inodes to be ordered against, so restart at 0.
	s_next_id = 0;
	return true;
}

// Read-only post-mortem dump of the whole inode ring. Writes nothing to flash.
// It answers "where did the contacts go?" by separating three states that look
// identical from the API: a slot reading 0xFF was erased, 0x00 was deliberately
// blanked, and a live wrap that will not decrypt is a key or nonce fault.
// write_seq is printed because a counter that restarted near 0 says the region
// was erased rather than merely unreadable.
void file_storage_dump(void) {
	if (!s_ready) {
		hal_debug(LOG_CRITICAL, "fsdump: store NOT mounted\n");
		return;
	}
	hal_debug(LOG_CRITICAL, "fsdump: base=%u sectors=%u slots=%u next_id=%u dir=%d\n",
	          (unsigned)s_base, (unsigned)s_sectors, (unsigned)s_slots,
	          (unsigned)s_next_id, s_dir_count);

	uint32_t total_free = 0;
	uint32_t total_live = 0;
	uint32_t total_dead = 0;
	uint32_t total_undecryptable = 0;
	int shown = 0;

	for (uint32_t sec = 0; sec < s_sectors; sec++) {
		uint32_t free_here = 0;
		uint32_t live_here = 0;
		uint32_t dead_here = 0;
		for (uint32_t i = 0; i < RECS_PER_SECTOR; i++) {
			uint32_t s = sec * RECS_PER_SECTOR + i;
			uint8_t rec[FILE_INODE_REC_BYTES];
			if (!rawflash_read(s_device, slot_sector(s), slot_off(s), rec, sizeof rec)) {
				hal_debug(LOG_CRITICAL, "fsdump: slot %u READ FAILED\n", (unsigned)s);
				continue;
			}
			uint8_t cls = classify(rec);
			if (cls == SLOT_CLASS_FREE) {
				free_here++;
				continue;
			}
			if (cls == SLOT_CLASS_DEAD) {
				dead_here++;
				continue;
			}
			live_here++;
			uint8_t body[FILE_INODE_DATA];
			bool ok = (read_slot(s, body, NULL, NULL) == SLOT_CLASS_LIVE);
			if (!ok)
				total_undecryptable++;
			// Intact ciphertext under the wrong key is uniform random (~1 byte in 256
			// reads 0xFF, never in runs). A torn/incomplete program leaves long 0xFF
			// runs. Measuring both separates "key changed" from "write was damaged".
			uint32_t ff_bytes = 0;
			uint32_t run = 0;
			uint32_t longest_run = 0;
			for (uint32_t b = FILE_BODY_OFF; b < FILE_INODE_REC_BYTES; b++) {
				if (rec[b] == 0xFF) {
					ff_bytes++;
					run++;
					if (run > longest_run)
						longest_run = run;
				} else {
					run = 0;
				}
			}
			if (shown < 48) {
				shown++;
				const struct file_inode *r = (const struct file_inode *)rec;
				const char *verdict = "BAD ";
				if (ok)
					verdict = "OK  ";
				hal_debug(LOG_CRITICAL,
				          "fsdump:   slot %u sec %u rid=%u %s id=%08x type=%u ff=%u maxrun=%u\n",
				          (unsigned)s, (unsigned)(s_base + sec), (unsigned)write_seq_of(rec),
				          verdict, (unsigned)r->file_id, (unsigned)r->file_type,
				          (unsigned)ff_bytes, (unsigned)longest_run);
			}
		}
		total_free += free_here;
		total_live += live_here;
		total_dead += dead_here;
		if (free_here != RECS_PER_SECTOR)   // stay quiet about fully-erased sectors
			hal_debug(LOG_CRITICAL, "fsdump: sec %u: free=%u live=%u dead=%u\n",
			          (unsigned)(s_base + sec), (unsigned)free_here,
			          (unsigned)live_here, (unsigned)dead_here);
	}
	if (shown >= 48)
		hal_debug(LOG_CRITICAL, "fsdump: (slot detail truncated at 48)\n");
	hal_debug(LOG_CRITICAL, "fsdump: TOTAL free=%u live=%u dead=%u undecryptable=%u\n",
	          (unsigned)total_free, (unsigned)total_live, (unsigned)total_dead,
	          (unsigned)total_undecryptable);
}

void file_storage_stats(int *free_slots, int *live_slots, int *dead_slots) {
	int free_count = 0;
	int live_count = 0;
	int dead_count = 0;
	for (uint32_t s = 0; s < s_slots; s++) {
		if (s_state[s] == SLOT_FREE)
			free_count++;
		else if (s_state[s] == SLOT_LIVE)
			live_count++;
		else
			dead_count++;
	}
	if (free_slots)
		*free_slots = free_count;
	if (live_slots)
		*live_slots = live_count;
	if (dead_slots)
		*dead_slots = dead_count;
}

uint32_t file_storage_next_id(void) { return s_next_id; }

// ======================================================================
// Layer 1 — the append-only byte log underneath the entry log. Byte-addressable:
// reserve or append bytes, read at an offset, flush. The page buffer is the only
// place page granularity matters (write durability); reads are byte-indexed,
// which XIP makes free.
// ======================================================================
#define PAGELOG_NOSPACE 0xFFFFFFFFu


static bool pagelog_init(uint8_t device, uint32_t base_sector, uint32_t num_sectors) {
	if (!rawflash_init())
		return false;
	if (num_sectors < 1 || (uint64_t)base_sector + num_sectors > rawflash_sector_count(device))
		return false;
	if (RAWFLASH_SECTOR != rawflash_sector_size() || RAWFLASH_PAGE != rawflash_page_size())
		return false;
	pagelog_device = device;
	pagelog_base_sector = base_sector;
	pagelog_sectors = num_sectors;
	pagelog_capacity_bytes = num_sectors * RAWFLASH_SECTOR;
	append_offset = durable_offset = 0;
	page_buffer_fill = 0;
	pagelog_ready = true;
	return true;
}

static uint32_t pagelog_capacity(void)    { return pagelog_capacity_bytes; }
static uint32_t pagelog_head(void) { return append_offset; }

static void pagelog_reset_head(uint32_t off) {
	// off must be page-aligned; the bytes below are already on flash.
	append_offset = durable_offset = off - (off % RAWFLASH_PAGE);
	page_buffer_fill = 0;
}

// Save one page-sized buffer at a page-aligned byte offset, erasing the sector
// first if this is its first page (sector-offset 0 = a fresh sector).
static bool erase_if_new_sector_then_save(uint32_t byte_off, const uint8_t *page) {
	uint32_t sector = pagelog_base_sector + byte_off / RAWFLASH_SECTOR;
	uint32_t sector_off = byte_off % RAWFLASH_SECTOR;
	if (sector_off == 0) {
		if (!rawflash_erase(pagelog_device, sector))
			return false;
	}
	return rawflash_program(pagelog_device, sector, sector_off, page, RAWFLASH_PAGE);
}

static bool pagelog_flush(void) {
	if (!pagelog_ready)
		return false;
	if (page_buffer_fill == 0)  // append_offset already page-aligned
		return true;
	memset(page_buffer + page_buffer_fill, 0xFF, RAWFLASH_PAGE - page_buffer_fill);
	if (!erase_if_new_sector_then_save(durable_offset, page_buffer))
		return false;
	durable_offset += RAWFLASH_PAGE;
	append_offset = durable_offset;                            // gap [old append_offset, durable_offset) is padding
	page_buffer_fill = 0;
	return true;
}

// Reserve a contiguous `span` bytes (a page multiple) for an entry written later
// by random-access page programs (pagelog_program_at). Entries pack at page
// granularity, so the base is page-aligned rather than sector-aligned and a
// small entry costs a couple of pages instead of a whole sector. Only fresh
// sectors are erased: when the base sits mid-sector, a prior reservation already
// entered and erased that sector and left its tail at 0xFF. Concurrent transfers
// own disjoint page ranges. Returns the page-aligned base, or PAGELOG_NOSPACE.
static uint32_t pagelog_reserve(uint32_t span) {
	if (!pagelog_ready || span == 0 || span % RAWFLASH_PAGE != 0)
		return PAGELOG_NOSPACE;
	if (!pagelog_flush())  // page-align the head (no-op sans seq append)
		return PAGELOG_NOSPACE;
	if (append_offset + span > pagelog_capacity_bytes)  // won't fit
		return PAGELOG_NOSPACE;
	uint32_t base = append_offset;                             // page-aligned
	// base's sector is fresh iff base sits at its start; otherwise it was already
	// entered+erased by a prior reservation and its tail is still 0xFF.
	uint32_t first_fresh = base / RAWFLASH_SECTOR;
	if (base % RAWFLASH_SECTOR != 0)
		first_fresh++;
	uint32_t last_sec = (base + span - 1) / RAWFLASH_SECTOR;
	for (uint32_t s = first_fresh; s <= last_sec; s++)
		if (!rawflash_erase(pagelog_device, pagelog_base_sector + s))
			return PAGELOG_NOSPACE;
	append_offset = durable_offset = base + span;                  // head past the reserved region
	page_buffer_fill = 0;
	return base;
}

// Program one page (RAWFLASH_PAGE bytes) at a page-aligned byte offset inside a region
// already reserved+erased by pagelog_reserve. Random-access, below the head.
static bool pagelog_program_at(uint32_t off, const uint8_t *page) {
	if (!pagelog_ready || off % RAWFLASH_PAGE != 0 || off + RAWFLASH_PAGE > durable_offset)
		return false;
	uint32_t sector = pagelog_base_sector + off / RAWFLASH_SECTOR;
	return rawflash_program(pagelog_device, sector, off % RAWFLASH_SECTOR, page, RAWFLASH_PAGE);
}

static bool pagelog_clear_byte(uint32_t off, uint8_t and_mask) {
	if (!pagelog_ready || off >= append_offset)
		return false;
	if (off >= durable_offset) {                 // still in the RAM page buffer
		page_buffer[off - durable_offset] &= and_mask;
		return true;
	}
	// durable on flash: read the containing page, clear the bit, reprogram it
	// (no erase — only 1->0 transitions, which NOR honours).
	uint32_t page_off = off - (off % RAWFLASH_PAGE);
	uint32_t sector = pagelog_base_sector + page_off / RAWFLASH_SECTOR;
	uint32_t sector_off = page_off % RAWFLASH_SECTOR;
	uint8_t page_buf[RAWFLASH_PAGE];
	if (!rawflash_read(pagelog_device, sector, sector_off, page_buf, RAWFLASH_PAGE))
		return false;
	page_buf[off - page_off] &= and_mask;
	return rawflash_program(pagelog_device, sector, sector_off, page_buf, RAWFLASH_PAGE);
}

static bool pagelog_zero_range(uint32_t off, uint32_t len) {
	if (!pagelog_ready || len == 0 || off + len > append_offset)
		return false;
	uint32_t end = off + len;
	for (uint32_t p = off - (off % RAWFLASH_PAGE); p < end; p += RAWFLASH_PAGE) {
		uint32_t lo = p;
		if (off > lo)
			lo = off;
		uint32_t hi = p + RAWFLASH_PAGE;
		if (end < hi)
			hi = end;
		if (p >= durable_offset) {                       // current RAM page
			memset(page_buffer + (lo - durable_offset), 0, hi - lo);
		} else {                                  // flash page: read, zero, reprogram (no erase)
			uint32_t sector = pagelog_base_sector + p / RAWFLASH_SECTOR;
			uint32_t sector_off = p % RAWFLASH_SECTOR;
			uint8_t page_buf[RAWFLASH_PAGE];
			if (!rawflash_read(pagelog_device, sector, sector_off, page_buf, RAWFLASH_PAGE))
				return false;
			memset(page_buf + (lo - p), 0, hi - lo);
			if (!rawflash_program(pagelog_device, sector, sector_off, page_buf, RAWFLASH_PAGE))
				return false;
		}
	}
	return true;
}

static bool pagelog_read_flash(uint32_t off, void *buf, uint32_t len) {
	if (!pagelog_ready || off > pagelog_capacity_bytes ||
	    len > pagelog_capacity_bytes - off)      // cannot wrap; see pagelog_read
		return false;
	uint8_t *out = (uint8_t *)buf;
	while (len > 0) {
		uint32_t sector = pagelog_base_sector + off / RAWFLASH_SECTOR;
		uint32_t sector_off = off % RAWFLASH_SECTOR;
		uint32_t take = RAWFLASH_SECTOR - sector_off;
		if (take > len)
			take = len;
		if (!rawflash_read(pagelog_device, sector, sector_off, out, take))
			return false;
		out += take;
		off += take;
		len -= take;
	}
	return true;
}

static void pagelog_erase_tail(uint32_t old_head) {
	if (!pagelog_ready)
		return;
	uint32_t head_sector = pagelog_base_sector + append_offset / RAWFLASH_SECTOR;
	uint32_t last_old_sector = pagelog_base_sector;
	if (old_head)
		last_old_sector += (old_head - 1) / RAWFLASH_SECTOR;
	for (uint32_t s = head_sector + 1; s <= last_old_sector; s++)
		rawflash_erase(pagelog_device, s);
}

// Written so the bounds test cannot wrap: an offset near the top of the range
// makes off + len small again, and callers now pass offsets an app took from a
// peer (a channel member's cursor), so a wrap here reads outside the buffer.
static bool pagelog_read(uint32_t off, void *buf, uint32_t len) {
	if (!pagelog_ready || off > append_offset || len > append_offset - off)
		return false;
	uint8_t *out = (uint8_t *)buf;
	while (len > 0) {
		if (off >= durable_offset) {                  // unflushed tail → RAM page buffer
			uint32_t take = append_offset - off;
			if (take > len)
				take = len;
			memcpy(out, page_buffer + (off - durable_offset), take);
			out += take;
			off += take;
			len -= take;
		} else {                               // durable region → flash (per-sector)
			uint32_t sector = pagelog_base_sector + off / RAWFLASH_SECTOR;
			uint32_t sector_off = off % RAWFLASH_SECTOR;
			uint32_t take = RAWFLASH_SECTOR - sector_off;
			if (take > len)
				take = len;
			if (take > durable_offset - off)
				take = durable_offset - off;
			if (!rawflash_read(pagelog_device, sector, sector_off, out, take))
				return false;
			out += take;
			off += take;
			len -= take;
		}
	}
	return true;
}

// ======================================================================
// Layer 2 — the entry format and the per-file log index (the public API).
// ======================================================================

#define ENTRY_HDR_LEN  ((uint32_t)sizeof(struct entry_hdr))
#define STATUS_OFF     ((uint32_t)offsetof(struct entry_hdr, status))
#define FRAMING_LEN    ((uint32_t)sizeof(struct entry_framing))
#define FRAMING_CT_LEN (FRAMING_LEN + FILE_TAG_BYTES)
#define META_LEN       (ENTRY_HDR_LEN + FRAMING_CT_LEN)   // the header page's prefix

// ---- the one entry layout, chunked ------------------------------------------
// An entry is one header page ([entry_hdr][framing ciphertext][0xFF pad])
// followed by N chunk pages, each a standalone AEAD ciphertext of
// FILE_CHUNK_PLAIN plaintext bytes plus its authentication tag. N is
// ceil(payload_len / FILE_CHUNK_PLAIN), so a zero-payload entry is just the
// header page. Chunk k sits at base + FILE_CHUNK_SLOT * (1 + k), and the whole
// entry is page-aligned, so its pages can be reserve-erased and then programmed
// out of order while streaming.
//
// Below are the two counter-derived nonce domains. The inode ring needs none:
// its nonce is fresh randomness per write, so it cannot collide with a counter.
#define NONCE_DOM_FRAMING 0                 // framing_ct, under the volume key
#define NONCE_DOM_CHUNK   3                 // chunk payload (chunk index folded into the nonce)


// Biased by one so that 0 can mean "none": offset 0 is a real entry.
static uint32_t entry_id_at_offset(uint32_t offset)    { return offset + 1; }
static uint32_t offset_of_entry(uint32_t entry_id)    { return entry_id - 1; }

// ---- helpers ----

// nonce = [nonce_seq LE : 8][domain : 1][epoch LE : 4][zero : 11]. The domain is
// NONCE_DOM_FRAMING for the framing and NONCE_DOM_CHUNK for a payload chunk,
// which build_chunk_nonce also folds the chunk index into. nonce_seq regresses
// when a delete or a compaction drops entries, so it is the epoch that keeps the
// pair disjoint across boots.
static void build_framing_nonce(uint8_t nonce[FILE_NONCE_BYTES], uint64_t nonce_seq,
                                uint8_t domain, uint32_t epoch) {
	memset(nonce, 0, FILE_NONCE_BYTES);
	for (int i = 0; i < 8; i++)
		nonce[i] = (uint8_t)(nonce_seq >> (8 * i));
	nonce[8] = domain;
	for (int i = 0; i < 4; i++)
		nonce[9 + i] = (uint8_t)(epoch >> (8 * i));
}
static int find_log_index(uint64_t file_id) {
	for (int i = 0; i < s_dir_cap; i++)
		if (log_index_table[i].used && log_index_table[i].file_id == file_id)
			return i;
	return -1;
}
static int find_or_add_log_index(uint64_t file_id) {
	int i = find_log_index(file_id);
	if (i >= 0)
		return i;
	for (i = 0; i < s_dir_cap; i++)
		if (!log_index_table[i].used) {
			log_index_table[i].used = true;
			log_index_table[i].file_id = file_id;
			log_index_table[i].has_head = false;
			return i;
		}
	return -1;
}
// ---- entry geometry: one header page plus N chunk pages ----
// payload_len, the cleartext length in the header, gives the whole span, so
// there is no separate blob format and no size branch.
static uint32_t chunks_in_entry(uint16_t payload_len) {
	return (payload_len + FILE_CHUNK_PLAIN - 1) / FILE_CHUNK_PLAIN;
}
static uint32_t entry_span_bytes(uint16_t payload_len) {
	return FILE_CHUNK_SLOT * (1 + chunks_in_entry(payload_len));
}
// An entry still carrying its SEALED bit was reserved or is filling, never sealed.
static bool     entry_is_torn(const struct entry_meta *entry) { return (entry->status & FILE_ST_SEALED) != 0; }

// Chunk-payload nonce: as build_framing_nonce, but in NONCE_DOM_CHUNK and with
// the chunk index folded into bytes 13..16, so every (entry, chunk) pair is
// globally unique.
static void build_chunk_nonce(uint8_t nonce[FILE_NONCE_BYTES], uint64_t nonce_seq,
                              uint32_t epoch, uint32_t chunk) {
	memset(nonce, 0, FILE_NONCE_BYTES);
	for (int i = 0; i < 8; i++)
		nonce[i] = (uint8_t)(nonce_seq >> (8 * i));
	nonce[8] = NONCE_DOM_CHUNK;
	for (int i = 0; i < 4; i++)
		nonce[9 + i]  = (uint8_t)(epoch >> (8 * i));
	for (int i = 0; i < 4; i++)
		nonce[13 + i] = (uint8_t)(chunk >> (8 * i));
}


// Decode an entry's metadata from a META_LEN buffer read at byte `offset`.
static bool decode_entry_header(const uint8_t *rec, uint32_t offset, struct entry_meta *meta) {
	struct entry_hdr header;
	memcpy(&header, rec, ENTRY_HDR_LEN);
	if (header.magic != ENTRY_MAGIC)
		return false;
	if (header.payload_len > FILE_ENTRY_MAX)
		return false;
	if (meta) {
		meta->nonce_seq = header.nonce_seq;
		meta->entry_id = entry_id_at_offset(offset);
		meta->payload_len = header.payload_len;
		meta->status = header.status;
		meta->epoch = header.epoch;
		meta->file_id = 0;
		meta->timestamp = 0;
		memset(meta->meta, 0, FILE_META);
	}
	// A deleted entry has its framing and payload zeroed by the scrub, so do not
	// try to decrypt the framing: the cleartext header alone lets the scan walk
	// past it and see it is a tombstone.
	if (!(header.status & FILE_ST_DELETED))  // deleted: header-only
		return true;
	uint8_t nonce[FILE_NONCE_BYTES];
	struct entry_framing entry_framing;
	build_framing_nonce(nonce, header.nonce_seq, NONCE_DOM_FRAMING, header.epoch);
	if (!xchacha20poly1305_decrypt((uint8_t *)&entry_framing, rec + ENTRY_HDR_LEN, FRAMING_CT_LEN, NULL, 0, nonce, s_volume_key))
		return false;
	if (meta) {
		meta->file_id = entry_framing.file_id;
		meta->timestamp = entry_framing.timestamp;
		
		memcpy(meta->meta, entry_framing.meta, FILE_META);
	}
	return true;
}

static bool decode_entry_at(uint32_t offset, bool from_flash, struct entry_meta *meta) {
	uint8_t buf[META_LEN];
	bool ok;
	if (from_flash)
		ok = pagelog_read_flash(offset, buf, META_LEN);
	else
		ok = pagelog_read(offset, buf, META_LEN);
	return ok && decode_entry_header(buf, offset, meta);
}

static void scan_from_oldest(struct log_walk *walk) { walk->off = 0; }

// The cleartext header at this offset, if one is there. Everything past it is
// ciphertext, so this is the only part of an entry readable without a key --
// which is what lets both walks step over an entry without opening it.
static bool entry_header_at(uint32_t off, struct entry_hdr *out) {
	uint8_t hdr[ENTRY_HDR_LEN];
	if (!pagelog_read_flash(off, hdr, ENTRY_HDR_LEN))
		return false;
	memcpy(out, hdr, ENTRY_HDR_LEN);
	return out->magic == ENTRY_MAGIC && out->payload_len <= FILE_ENTRY_MAX;
}

// Is there a valid entry header (magic plus a sane length) at this offset? Used
// to sanity-check a length-based jump before trusting it.
static bool is_entry_start(uint32_t off) {
	struct entry_hdr header;
	return entry_header_at(off, &header);
}

// The entry that ends exactly where the one at from_off begins, as an entry id
// (offset 0 holds an entry, so an offset cannot double as "none").
//
// Entries are page-aligned, so stepping back a page at a time lands on every
// candidate. The span check is what makes a stray ENTRY_MAGIC in ciphertext
// harmless: a false start would have to carry a payload_len whose span ends
// exactly here. A flush pads to a page boundary, so a gap is not the end of the
// log -- step back another page.
static uint32_t prev_entry_id(uint32_t from_off) {
	uint32_t off = from_off;
	while (off >= RAWFLASH_PAGE) {
		off -= RAWFLASH_PAGE;
		struct entry_hdr header;
		if (!entry_header_at(off, &header))
			continue;
		if (off + entry_span_bytes(header.payload_len) == from_off)
			return entry_id_at_offset(off);
	}
	return FILE_NONE;
}

// Forward iterator over entries. They pack tight, so the next one is usually
// right after; on a gap (a flush pads to the page) or a corrupt entry the walk
// resyncs to the next page. It runs to the region end, where trailing blank
// pages fail the magic check cheaply.
static bool next_entry_including_torn(struct log_walk *walk, struct entry_meta *entry) {
	uint32_t region = log_sector_count * RAWFLASH_SECTOR;
	while (walk->off + ENTRY_HDR_LEN <= region) {
		uint32_t here = walk->off;
		if (decode_entry_at(here, true, entry)) {
			// Advance past this entry by its length, but never trust a cleartext,
			// unauthenticated length to jump over another valid entry. If the jump
			// does not land on an entry start, resync one page past this entry
			// instead, so one corrupt length cannot hide entries written after it.
			uint32_t next = here + entry_span_bytes(entry->payload_len);
			bool jump_lands_on_an_entry = next > here && next + ENTRY_HDR_LEN <= region
			                              && is_entry_start(next);
			if (jump_lands_on_an_entry)
				walk->off = next;
			else
				walk->off = ((here / RAWFLASH_PAGE) + 1) * RAWFLASH_PAGE;
			return true;
		}
		walk->off = ((here / RAWFLASH_PAGE) + 1) * RAWFLASH_PAGE;
	}
	return false;
}

static bool next_live_entry(struct log_walk *walk, struct entry_meta *entry) {
	while (next_entry_including_torn(walk, entry)) {
		if (!entry_is_torn(entry))
			return true;
	}
	return false;
}

// Self-check: is the entry at target_off reachable by the forward scan? (Used
// right after a store to detect a wedged log — see file_entry_commit.)
static bool forward_scan_reaches(uint32_t target_off) {
	struct log_walk walk;
	struct entry_meta entry;
	scan_from_oldest(&walk);
	while (next_live_entry(&walk, &entry))
		if (offset_of_entry(entry.entry_id) == target_off)
			return true;
	return false;
}

// The caller never supplies a key: it is unwrapped from the file's own inode on
// every call and zeroed afterwards. A file that will not resolve fails the
// operation and there is no fallback, so destroying a file makes its whole log
// unreadable.
static bool resolve_payload_key(uint64_t file_id, uint8_t out[KEY_LEN]) {
	return find_file(file_id, NULL, out);
}

// ---- public API ----

static bool entrylog_init(uint8_t device, uint32_t base_sector, uint32_t num_sectors,
                   const uint8_t volume_key[KEY_LEN], uint32_t epoch) {
	if (!pagelog_init(device, base_sector, num_sectors))
		return false;
	entrylog_device = device;
	log_base_sector = base_sector;
	log_sector_count = num_sectors;
	current_epoch = epoch;                 // stamps new entries; reads use each entry's stored epoch
	memcpy(s_volume_key, volume_key, KEY_LEN);
	memset(log_index_table, 0, (size_t)s_dir_cap * sizeof *log_index_table);
	next_nonce_seq = 1;
	live_entry_count = 0;
	s_log_ready = true;
	return true;
}

static bool entrylog_mount(void) {
	if (!s_log_ready)
		return false;
	memset(log_index_table, 0, (size_t)s_dir_cap * sizeof *log_index_table);
	live_entry_count = 0;
	next_nonce_seq = 1;
	struct log_walk walk;
	struct entry_meta entry;
	uint32_t end = 0;
	scan_from_oldest(&walk);
	while (next_entry_including_torn(&walk, &entry)) {
		if (entry.nonce_seq >= next_nonce_seq)
			next_nonce_seq = entry.nonce_seq + 1;
		// Before the torn and deleted skips below: a tombstone still carries a
		// real stamp, and letting a delete lower the floor would let the next
		// minted stamp sort under a record we already hold. THIS CRAWL IS WHERE
		// THE CLOCK'S FLOOR COMES FROM — a boot with no NTP has nothing else.
		kernel_time_seen(entry.timestamp);
		end = offset_of_entry(entry.entry_id) + entry_span_bytes(entry.payload_len);   // head resumes past ALL entries
		if (entry_is_torn(&entry))        // still filling, or abandoned: keeps its span, stays unindexed
			continue;
		if (entry_is_deleted(entry))  // tombstone: not indexed/counted
			continue;
		int i = find_or_add_log_index(entry.file_id);
		if (i >= 0) {
			log_index_table[i].offset = offset_of_entry(entry.entry_id);
			log_index_table[i].has_head = true;
		}
		live_entry_count++;
	}
	// Resume appending on a fresh page past the last entry (never reopen a page).
	pagelog_reset_head(((end + RAWFLASH_PAGE - 1) / RAWFLASH_PAGE) * RAWFLASH_PAGE);
	return true;
}

bool file_storage_flush(void) { return pagelog_flush(); }

// ======================================================================
// Entries: create, fill, seal. Reserve, then fill, then seal, one chunk at a
// time, so neither side ever holds the whole message.
//
// There is no write handle: how far a fill has got is read back from flash by
// count_filled_chunks(), so a transfer resumes after a dropped stream or a reboot.
// ======================================================================

static bool read_chunk_erased_state(uint32_t base, uint16_t payload_len, uint32_t k,
                                    bool *is_erased) {
	uint32_t done = k * FILE_CHUNK_PLAIN;
	uint16_t plain_len = FILE_CHUNK_PLAIN;
	if (payload_len - done < FILE_CHUNK_PLAIN)
		plain_len = (uint16_t)(payload_len - done);
	uint16_t cipher_len = (uint16_t)(plain_len + FILE_TAG_BYTES);
	uint8_t slot[FILE_CHUNK_SLOT];
	if (!pagelog_read_flash(base + FILE_CHUNK_SLOT * (1 + k), slot, cipher_len))
		return false;
	uint8_t all = 0xFF;
	for (uint16_t i = 0; i < cipher_len; i++)
		all &= slot[i];
	*is_erased = (all == 0xFF);
	return true;
}

// Chunks arrive in order, so the written pages form a prefix and a binary search
// finds the boundary in six reads for the largest (43-chunk) entry.
static int count_filled_chunks(uint32_t base, uint16_t payload_len) {
	uint32_t lo = 0, hi = chunks_in_entry(payload_len);   // < lo written, >= hi erased
	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;
		bool erased;
		if (!read_chunk_erased_state(base, payload_len, mid, &erased))
			return -1;
		if (erased)
			hi = mid;
		else
			lo = mid + 1;
	}
	return (int)lo;
}

bool file_entry_fits(uint16_t length) {
	if (!s_log_ready || length > FILE_ENTRY_MAX)
		return false;
	return append_offset + entry_span_bytes(length) <= pagelog_capacity_bytes;
}

uint32_t file_entry_create(uint64_t file_id, uint16_t length,
                           uint32_t timestamp, const uint8_t meta[FILE_META]) {
	if (!s_log_ready)
		return FILE_NONE;
	if (length > FILE_ENTRY_MAX)  // any size 0..MAX — one format for all
		return FILE_NONE;
	if (find_or_add_log_index(file_id) < 0)   // reserve an index slot up front
		return FILE_NONE;
	// Fail before reserving flash. A zero-length entry has no payload, so no key.
	uint8_t payload_key[KEY_LEN];
	if (length > 0 && !resolve_payload_key(file_id, payload_key))
		return FILE_NONE;
	crypto_zero(payload_key, sizeof payload_key);
	uint16_t total_len = length;

	uint64_t seq = next_nonce_seq++;
	// [entry_hdr][framing ciphertext][0xFF pad]. Status starts 0xFF, so SEALED is
	// set; file_entry_commit clears that bit last.
	uint8_t page[FILE_CHUNK_SLOT];
	memset(page, 0xFF, sizeof page);
	struct entry_hdr header = { ENTRY_MAGIC, total_len, seq, 0xFF, current_epoch };
	memcpy(page, &header, ENTRY_HDR_LEN);
	struct entry_framing entry_framing;
	memset(&entry_framing, 0, sizeof entry_framing);
	entry_framing.file_id = file_id;
	
	// A caller's stamp is stored VERBATIM. It is the one a group's host issued,
	// and rewriting it would leave that group's members disagreeing about the
	// order of its messages. Zero means the caller has no stamp of its own.
	// Either way the floor ends up at or above what is written. A create that
	// fails below has spent a stamp, which costs nothing — same as the nonce.
	if (timestamp == 0)
		timestamp = kernel_time_mint();
	kernel_time_seen(timestamp);
	entry_framing.timestamp = timestamp;
	memset(entry_framing.meta, 0, FILE_META);
	if (meta)
		memcpy(entry_framing.meta, meta, FILE_META);
	uint8_t nonce[FILE_NONCE_BYTES];
	build_framing_nonce(nonce, seq, NONCE_DOM_FRAMING, current_epoch);
	xchacha20poly1305_encrypt(page + ENTRY_HDR_LEN, (uint8_t *)&entry_framing, FRAMING_LEN, NULL, 0, nonce, s_volume_key);

	uint32_t base = pagelog_reserve(entry_span_bytes(total_len));
	if (base == PAGELOG_NOSPACE)  // seq skipped (harmless; nonces stay unique)
		return FILE_NONE;
	if (!pagelog_program_at(base, page))
		return FILE_NONE;
	return entry_id_at_offset(base);
}

int file_entry_write(uint64_t file_id, uint32_t entry_id,
                     const void *data, int count) {
	if (!s_log_ready || entry_id == FILE_NONE || count <= 0 || count > (int)FILE_CHUNK_PLAIN)
		return -1;
	uint16_t len = (uint16_t)count;
	uint32_t base = offset_of_entry(entry_id);
	struct entry_meta entry;
	if (!decode_entry_at(base, true, &entry))
		return -1;
	if (!entry_is_torn(&entry))        // already sealed: immutable
		return -1;
	if (entry.file_id != file_id)
		return -1;
	int done = count_filled_chunks(base, entry.payload_len);
	if (done < 0)
		return -1;
	uint32_t written = (uint32_t)done * FILE_CHUNK_PLAIN;
	if (written + len > entry.payload_len)  // would overrun the reservation
		return -1;
	// Chunk k is a fixed 240 B slice on the read side, so only the last may be short.
	if (written + len < entry.payload_len && len != FILE_CHUNK_PLAIN)
		return -1;
	uint8_t payload_key[KEY_LEN];
	if (!resolve_payload_key(file_id, payload_key))
		return -1;

	uint8_t page[FILE_CHUNK_SLOT];
	memset(page, 0xFF, sizeof page);
	uint8_t nonce[FILE_NONCE_BYTES];
	build_chunk_nonce(nonce, entry.nonce_seq, entry.epoch, (uint32_t)done);
	xchacha20poly1305_encrypt(page, (const uint8_t *)data, len, NULL, 0, nonce, payload_key);
	crypto_zero(payload_key, sizeof payload_key);
	if (!pagelog_program_at(base + FILE_CHUNK_SLOT * (1 + (uint32_t)done), page))
		return -1;
	return count;
}

int file_entry_filled(uint64_t file_id, uint32_t entry_id) {
	(void)file_id;
	if (!s_log_ready || entry_id == FILE_NONE)
		return -1;
	uint32_t base = offset_of_entry(entry_id);
	struct entry_meta entry;
	if (!decode_entry_at(base, true, &entry))
		return -1;
	if (!entry_is_torn(&entry))        // sealed: complete by definition
		return entry.payload_len;
	int done = count_filled_chunks(base, entry.payload_len);
	if (done < 0)
		return -1;
	uint32_t written = (uint32_t)done * FILE_CHUNK_PLAIN;
	if (written > entry.payload_len)
		return entry.payload_len;
	return (int)written;
}

bool file_entry_commit(uint64_t file_id, uint32_t entry_id) {
	(void)file_id;
	if (!s_log_ready || entry_id == FILE_NONE)
		return false;
	uint32_t base = offset_of_entry(entry_id);
	struct entry_meta entry;
	if (!decode_entry_at(base, true, &entry))
		return false;
	if (!entry_is_torn(&entry))        // already committed: idempotent
		return true;
	int done = count_filled_chunks(base, entry.payload_len);
	if (done < 0 || (uint32_t)done != chunks_in_entry(entry.payload_len))
		return false;            // incomplete: leave unsealed (torn), the scan skips it
	if (!pagelog_flush())        // commit order: flush, THEN seal
		return false;
	if (!pagelog_clear_byte(base + STATUS_OFF, (uint8_t)~FILE_ST_SEALED))
		return false;
	// A sealed entry the forward scan cannot reach means an earlier corrupt
	// entry is hiding it: the "received but not saved" failure, caught here.
	struct entry_meta recheck;
	if (decode_entry_at(base, true, &recheck) && !forward_scan_reaches(base))
		hal_debug(LOG_CRITICAL, "filesystem: sealed entry base=%u seq=%llu file=%08x decodes but the scan cannot reach it\n",
		          (unsigned)base, (unsigned long long)entry.nonce_seq, (unsigned)entry.file_id);
	int index_slot = find_or_add_log_index(entry.file_id);
	if (index_slot >= 0) {
		log_index_table[index_slot].offset = base;
		log_index_table[index_slot].has_head = true;
	}
	live_entry_count++;
	return true;
}

static uint16_t decrypt_chunk(uint32_t base, const struct entry_meta *entry,
                                const uint8_t *payload_key, uint32_t k, uint8_t *plaintext) {
	uint32_t chunk_start = k * FILE_CHUNK_PLAIN;
	if (chunk_start >= entry->payload_len)
		return 0;
	uint16_t plain_len = FILE_CHUNK_PLAIN;
	if (entry->payload_len - chunk_start < FILE_CHUNK_PLAIN)
		plain_len = (uint16_t)(entry->payload_len - chunk_start);
	uint16_t cipher_len = (uint16_t)(plain_len + FILE_TAG_BYTES);
	uint8_t slot[FILE_CHUNK_SLOT], nonce[FILE_NONCE_BYTES];
	if (!pagelog_read(base + FILE_CHUNK_SLOT * (1 + k), slot, cipher_len))
		return 0;
	build_chunk_nonce(nonce, entry->nonce_seq, entry->epoch, k);
	if (!xchacha20poly1305_decrypt(plaintext, slot, cipher_len, NULL, 0, nonce, payload_key))
		return 0;
	return plain_len;
}

int file_entry_read(uint64_t file_id, uint32_t entry_id,
                    uint32_t at, void *buf, int max) {
	if (!s_log_ready || !buf || max <= 0 || entry_id == FILE_NONE)
		return -1;
	uint32_t base = offset_of_entry(entry_id);
	struct entry_meta entry;
	if (!decode_entry_at(base, false, &entry))
		return -1;
	if (entry_is_torn(&entry) || entry_is_deleted(entry))
		return -1;
	if (entry.file_id != file_id)
		return -1;
	if (at >= entry.payload_len)
		return 0;
	uint32_t len = (uint32_t)max;
	if (at + len > entry.payload_len)
		len = entry.payload_len - at;
	uint8_t payload_key[KEY_LEN];
	if (!resolve_payload_key(file_id, payload_key))
		return -1;

	uint8_t *out = (uint8_t *)buf;
	uint32_t copied = 0;
	uint32_t first_chunk = at / FILE_CHUNK_PLAIN;
	uint32_t last_chunk  = (at + len - 1) / FILE_CHUNK_PLAIN;
	for (uint32_t k = first_chunk; k <= last_chunk; k++) {
		uint8_t plaintext[FILE_CHUNK_PLAIN];
		uint16_t plain_len = decrypt_chunk(base, &entry, payload_key, k, plaintext);
		if (plain_len == 0)
			return -1;
		uint32_t chunk_start = k * FILE_CHUNK_PLAIN;
		uint32_t sel_start = chunk_start;
		if (at > sel_start)
			sel_start = at;
		uint32_t sel_end = chunk_start + plain_len;
		if (at + len < sel_end)
			sel_end = at + len;
		if (sel_end > sel_start) {
			memcpy(out + copied, plaintext + (sel_start - chunk_start), sel_end - sel_start);
			copied += sel_end - sel_start;
		}
	}
	return (int)copied;
}


static bool entry_scrub(uint32_t entry_id);

// The public projection of struct entry_meta: nonce_seq, epoch and the seal bit
// are ours and do not cross the boundary.
static void fill_entry_info(const struct entry_meta *m, struct file_entry_info *out) {
	out->file_id   = m->file_id;
	
	
	out->timestamp = m->timestamp;
	out->length    = m->payload_len;
	out->flags     = m->status & (FILE_DELETED | FILE_APP_FLAGS);
	memcpy(out->meta, m->meta, FILE_META);
}

bool file_entry_stat(uint64_t file_id, uint32_t entry_id,
                     struct file_entry_info *out) {
	if (!s_log_ready || entry_id == FILE_NONE || !out)
		return false;
	struct entry_meta m;
	if (!decode_entry_at(offset_of_entry(entry_id), false, &m))
		return false;
	if (m.file_id != file_id)
		return false;
	fill_entry_info(&m, out);
	return true;
}

// Clearing FILE_DELETED is more than a bit: it scrubs the framing and every
// chunk in place, because this layer is the only one that can. The application
// bits are a plain in-place NOR program.
bool file_entry_flag_clear(uint64_t file_id, uint32_t entry_id,
                           uint8_t bits) {
	if (!s_log_ready || entry_id == FILE_NONE)
		return false;
	struct entry_meta m;
	if (!decode_entry_at(offset_of_entry(entry_id), true, &m))
		return false;
	if (m.file_id != file_id)
		return false;
	if (bits & FILE_APP_FLAGS) {
		uint8_t keep = (uint8_t)~(bits & FILE_APP_FLAGS);
		if (!pagelog_clear_byte(offset_of_entry(entry_id) + STATUS_OFF, keep))
			return false;
	}
	if (bits & FILE_DELETED)
		return entry_scrub(entry_id);
	return true;
}

static bool entry_scrub(uint32_t entry_id) {
	if (!s_log_ready || entry_id == 0)
		return false;
	uint32_t offset = offset_of_entry(entry_id);
	struct entry_meta entry;
	if (!decode_entry_at(offset, false, &entry))
		return false;
	if (entry_is_deleted(entry))
		return true;
	// 1) mark deleted first, so the entry becomes a header-only tombstone and the
	//    scan stops decrypting its framing before that framing is destroyed. A
	//    crash between the two steps leaves a valid, walkable tombstone.
	if (!pagelog_clear_byte(offset + STATUS_OFF, (uint8_t)~FILE_ST_DELETED))
		return false;
	// 2) zero the framing and every chunk page in place — everything past the
	//    cleartext header — destroying who, when and the text immediately.
	uint32_t scrub_len = entry_span_bytes(entry.payload_len) - ENTRY_HDR_LEN;
	return pagelog_zero_range(offset + ENTRY_HDR_LEN, scrub_len);
}








uint32_t file_entry_scan_all(uint32_t from, struct file_entry_info *out) {
	if (!s_log_ready)
		return FILE_NONE;
	struct log_walk walk;
	struct entry_meta entry;
	scan_from_oldest(&walk);
	while (next_live_entry(&walk, &entry)) {
		if (entry_is_deleted(entry))
			continue;
		if (from != FILE_NONE && offset_of_entry(entry.entry_id) <= offset_of_entry(from))
			continue;
		if (out)
			fill_entry_info(&entry, out);
		return entry.entry_id;
	}
	return FILE_NONE;
}

// ---- the log: walk one file's entries ---------------------------------------
// Newest-first is what readers want, and the index makes the head O(1). Older
// steps BACK one entry at a time and newer steps forward from where it is told,
// so the cost of either is the distance travelled, not the size of the log. Both
// used to rescan from the oldest entry on every call, which made reading a
// thread cost messages x entries: 1.4 s for 32 messages with the log 19% full,
// and it grew as the log filled.
//
// The entries on flash are still the truth -- neither walk consults an index.

uint32_t file_log_newest(uint64_t file_id) {
	if (!s_log_ready)
		return FILE_NONE;
	int i = find_log_index(file_id);
	if (i < 0 || !log_index_table[i].has_head)
		return FILE_NONE;
	return entry_id_at_offset(log_index_table[i].offset);
}

uint32_t file_log_older(uint64_t file_id, uint32_t entry_id) {
	if (!s_log_ready || entry_id == FILE_NONE)
		return FILE_NONE;
	uint32_t off = offset_of_entry(entry_id);
	for (;;) {
		uint32_t prev = prev_entry_id(off);
		if (prev == FILE_NONE)
			return FILE_NONE;
		off = offset_of_entry(prev);
		struct entry_meta entry;
		// Only a real entry costs a framing decrypt, and only that decrypt can
		// say which file it belongs to: file_id lives in the sealed framing.
		if (!decode_entry_at(off, true, &entry))
			continue;
		if (entry_is_torn(&entry))
			continue;
		if (entry_is_deleted(entry))
			continue;
		if (entry.file_id == file_id)
			return entry.entry_id;
	}
}

uint32_t file_log_newer(uint64_t file_id, uint32_t entry_id) {
	if (!s_log_ready || entry_id == FILE_NONE)
		return FILE_NONE;
	struct log_walk walk;
	struct entry_meta entry;
	walk.off = offset_of_entry(entry_id);
	// Consume the entry we were given, so the walk starts past it.
	if (!next_entry_including_torn(&walk, &entry))
		return FILE_NONE;
	while (next_live_entry(&walk, &entry)) {
		if (entry.file_id != file_id || entry_is_deleted(entry))
			continue;
		return entry.entry_id;
	}
	return FILE_NONE;
}

// Max bytes one entry occupies on flash: the header page plus the chunks for a
// full FILE_ENTRY_MAX payload.
#define ENTRY_SPAN_MAX  (FILE_CHUNK_SLOT * (1 + (FILE_ENTRY_MAX + FILE_CHUNK_PLAIN - 1) / FILE_CHUNK_PLAIN))

bool file_storage_compact(file_compact_progress_fn progress) {
	if (!s_log_ready)
		return false;
	uint32_t old_head = pagelog_head();
	uint32_t region = log_sector_count * RAWFLASH_SECTOR;
	uint32_t reported = 0;               // last source sector handed to progress
	if (progress)
		progress(0, region);

	// Copy forward one destination sector at a time, and that granularity is the
	// whole correctness argument. Writing the first page of a sector erases the
	// whole sector, so copying one entry at a time destroys the source of entries
	// further into that sector before they have been read. Buffering a full
	// destination sector makes that impossible: survivors are a subset of the
	// source, so bytes written can never exceed bytes read, and the sector about
	// to be erased ends at exactly the survivor count.
	static uint8_t sectorbuf[RAWFLASH_SECTOR];
	uint32_t fill = 0;         // bytes in sectorbuf
	uint32_t written = 0;      // survivor bytes already on flash
	uint32_t survivors = 0;

	pagelog_reset_head(0);
	memset(log_index_table, 0, (size_t)s_dir_cap * sizeof *log_index_table);

	uint32_t src = 0;
	struct entry_meta entry;
	while (src + ENTRY_HDR_LEN <= region) {
		if (!decode_entry_at(src, true, &entry)) {   // gap / erased / corrupt: resync
			src = ((src / RAWFLASH_PAGE) + 1) * RAWFLASH_PAGE;
			continue;
		}
		uint32_t span = entry_span_bytes(entry.payload_len);
		bool keep = !entry_is_deleted(entry) && !entry_is_torn(&entry);
		// An entry whose file is gone is permanently unreadable: destroying the
		// file scrubbed the only key. Reclaiming it here is what makes a destroy
		// eventually free space instead of leaving ciphertext forever.
		if (keep && !dir_find(entry.file_id))
			keep = false;
		if (keep) {
			int index_slot = find_or_add_log_index(entry.file_id);
			if (index_slot >= 0) {
				log_index_table[index_slot].offset = written + fill;   // where this entry lands
				log_index_table[index_slot].has_head = true;
			}
			for (uint32_t o = 0; o < span; o += RAWFLASH_PAGE) {
				if (!pagelog_read_flash(src + o, sectorbuf + fill, RAWFLASH_PAGE))
					return false;
				fill += RAWFLASH_PAGE;
				if (fill == RAWFLASH_SECTOR) {
					for (uint32_t p = 0; p < RAWFLASH_SECTOR; p += RAWFLASH_PAGE) {
						uint32_t dest = pagelog_reserve(RAWFLASH_PAGE);
						if (dest == PAGELOG_NOSPACE)
							return false;
						if (!pagelog_program_at(dest, sectorbuf + p))
							return false;
					}
					written += RAWFLASH_SECTOR;
					fill = 0;
				}
			}
			survivors++;
		}
		src += span;   // entries pack contiguously; the next one is right after
		// Once per source sector: often enough to animate, rare enough to cost
		// nothing against a region read a page at a time.
		if (progress && src / RAWFLASH_SECTOR != reported) {
			reported = src / RAWFLASH_SECTOR;
			progress(src, region);
		}
	}
	// The tail: fewer than a sector's worth left in the buffer. Everything it
	// covers has been read, so this write can erase nothing that still matters.
	for (uint32_t p = 0; p < fill; p += RAWFLASH_PAGE) {
		uint32_t dest = pagelog_reserve(RAWFLASH_PAGE);
		if (dest == PAGELOG_NOSPACE)
			return false;
		if (!pagelog_program_at(dest, sectorbuf + p))
			return false;
	}
	pagelog_flush();
	pagelog_erase_tail(old_head);
	live_entry_count = survivors;
	if (progress)
		progress(region, region);
	return true;
}

// The higher of the two tenants, because either one filling up stops writes. In
// practice the entry log dominates: the inode ring is a fixed FILE_INODE_SECTORS
// and caps at the configured file count.
int file_storage_usage(void) {
	int inodes = 0;
	if (s_ready && s_slots)
		inodes = (int)(((uint64_t)s_cursor * 100) / s_slots);
	int entries = 0;
	if (s_log_ready) {
		uint32_t cap = pagelog_capacity();
		if (cap)
			entries = (int)(((uint64_t)pagelog_head() * 100) / cap);
	}
	if (inodes > entries)
		return inodes;
	return entries;
}



// Erase just the entry-log half of the region, leaving keys, settings and the
// inode ring untouched, and reset the RAM state to an empty log. Bench recovery
// for an entry log that scans oddly.
static bool entrylog_wipe(void) {
	if (!pagelog_ready)
		return false;
	uint32_t sector_count = pagelog_capacity_bytes / RAWFLASH_SECTOR;
	for (uint32_t s = 0; s < sector_count; s++)
		if (!rawflash_erase(pagelog_device, pagelog_base_sector + s))
			return false;
	pagelog_reset_head(0);
	memset(log_index_table, 0, (size_t)s_dir_cap * sizeof *log_index_table);
	live_entry_count = 0;
	next_nonce_seq = 1;
	return true;
}
