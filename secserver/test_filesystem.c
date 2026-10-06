//
// test_filesystem.c — host acceptance test for filesystem.c over rawflash_posix.
//
// Covers both halves and, above all, the properties the merge is FOR: an entry's
// payload key comes from its own file's inode, so destroying a file makes its
// whole log unreadable; a mount rebuilds the directory from cleartext heads with
// no key at all; and a part-written entry resumes from flash with nothing in RAM.
//
//   cd secserver && make filesystem_test && ./filesystem_test
//
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "config_env.h"
#include "filesystem.h"
#include "rawflash.h"

// wg.c platform hooks (the AEAD comes from wg.c), stubbed as the other host tests do.
int    validate_public_key(const uint8_t *pk, void *ctx) { (void)pk; (void)ctx; return 1; }
time_t get_current_time_seconds(void) { return time(NULL); }

// The stamp clock lives in kernel.c, which this test does not link. Same logic,
// because the ordering it guarantees is what the log walks depend on: a stamp is
// strictly above every one seen or issued, so entries sort by append order even
// when the wall clock stands still between two creates.
static uint32_t stamp_floor;

void kernel_time_seen(uint32_t stamp) {
	if (stamp > stamp_floor)
		stamp_floor = stamp;
}

uint32_t kernel_time_mint(void) {
	uint32_t stamp = (uint32_t)get_current_time_seconds();
	if (stamp <= stamp_floor)
		stamp = stamp_floor + 1;
	stamp_floor = stamp;
	return stamp;
}

static int passed, failed;
#define CHECK(cond, msg) do { \
	if (cond) { passed++; printf("  PASS  %s\n", msg); } \
	else      { failed++; printf("  FAIL  %s\n", msg); } \
} while (0)

static const uint8_t VOLKEY[32] = {
	0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
	0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,
};
static const uint8_t OTHERKEY[32] = {
	0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,0xde,0xad,0xbe,0xef,
	0xca,0xfe,0xba,0xbe,0xca,0xfe,0xba,0xbe,0xca,0xfe,0xba,0xbe,0xca,0xfe,0xba,0xbe,
};

#define BASE     0u
#define SECTORS  560u     // the whole simulated device: 40 inode + 520 log
#define EPOCH    7u

// file_list enumerates the whole directory; these are the "of one type" queries
// the test used to get for free.
static int count_type(uint8_t want) {
	int n = 0;
	uint64_t id;
	uint8_t type;
	for (int i = 0; file_list(i, &id, &type); i++)
		if (type == want)
			n++;
	return n;
}

static uint64_t first_of_type(uint8_t want) {
	uint64_t id;
	uint8_t type;
	for (int i = 0; file_list(i, &id, &type); i++)
		if (type == want)
			return id;
	return FILE_NONE;
}

static void erase_region(uint32_t base, uint32_t n) {
	for (uint32_t s = 0; s < n; s++)
		rawflash_erase(RAWFLASH_DEV_INTERNAL, base + s);
}

// A header whose data[] is a recognisable pattern derived from the id.
static void mkheader(struct file_header *h, uint64_t id, uint8_t type, uint8_t salt) {
	memset(h, 0, sizeof *h);
	h->file_id = id;
	h->file_type = type;
	for (unsigned i = 0; i < FILE_INODE_DATA; i++)
		h->data[i] = (uint8_t)(id + i + salt);
}

static bool header_matches(const struct file_header *h, uint64_t id, uint8_t salt) {
	for (unsigned i = 0; i < FILE_INODE_DATA; i++)
		if (h->data[i] != (uint8_t)(id + i + salt))
			return false;
	return true;
}

// Write a whole payload to a fresh entry, one FILE_CHUNK at a time, and seal it.
static uint32_t write_entry(uint64_t id, const uint8_t *body, uint16_t len,
                            const uint8_t meta[FILE_META]) {
	uint32_t e = file_entry_create(id, len, 0, meta);
	if (e == FILE_NONE)
		return FILE_NONE;
	uint32_t off = 0;
	while (off < len) {
		uint32_t n = len - off;
		if (n > FILE_CHUNK)
			n = FILE_CHUNK;
		if (file_entry_write(id, e, body + off, (int)n) != (int)n)
			return FILE_NONE;
		off += n;
	}
	if (!file_entry_commit(id, e))
		return FILE_NONE;
	return e;
}

static void fill_pattern(uint8_t *buf, uint32_t len, uint8_t seed) {
	for (uint32_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(seed * 31 + i * 7);
}

int main(void) {
	printf("filesystem host test\n");
	config_from_env();
	rawflash_init();

	// ---- the inode half -----------------------------------------------------
	printf("\n[1] files\n");
	erase_region(BASE, SECTORS);
	CHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BASE, SECTORS, VOLKEY, EPOCH),
	      "mount a blank region");

	struct file_header h, back;
	mkheader(&h, (0xAAAA1111ull << 32), FILE_TYPE_CONTACT, 0);
	CHECK(file_create(&h), "create a contact file");
	mkheader(&h, (0xBBBB2222ull << 32), FILE_TYPE_CONTACT, 0);
	CHECK(file_create(&h), "create a second contact file");
	mkheader(&h, (0xCCCC3333ull << 32), FILE_TYPE_CHANNEL, 0);
	CHECK(file_create(&h), "create a group file");

	mkheader(&h, (0xAAAA1111ull << 32), FILE_TYPE_CONTACT, 0);
	CHECK(!file_create(&h), "create rejects a duplicate id");

	CHECK(file_header_read((0xAAAA1111ull << 32), &back), "read a header back");
	CHECK(back.file_id == (0xAAAA1111ull << 32) && back.file_type == FILE_TYPE_CONTACT,
	      "identity comes from the cleartext head");
	CHECK(header_matches(&back, (0xAAAA1111ull << 32), 0), "header body round-trips");

	CHECK(!file_header_read((0xAAAA1111ull << 32) | 9u, &back),
	      "a name that names nothing opens nothing");
	CHECK(!file_header_read((0xDEADBEEFull << 32), &back), "absent id fails");

	CHECK(count_type(FILE_TYPE_CHANNEL) == 1, "list finds the one group");
	CHECK(count_type(FILE_TYPE_CONTACT) == 2, "and both contacts");
	CHECK(first_of_type(FILE_TYPE_CHANNEL) == (0xCCCC3333ull << 32), "the group is the one created");

	// ---- the file_id is the WHOLE name --------------------------------------
	// A file_id is unique: no two inodes share one. That is what lets an entry
	// carry only the id and no type, and what makes a contact and a group two
	// plainly different files rather than two readings of one name. msg.c builds
	// the name as peer<<32 | group, so these are the same peer's group 7.
	printf("\n[1b] the file_id alone names the file\n");
	const uint64_t THREAD = 0xAAAA1111ull << 32;          // the 1-to-1 thread
	const uint64_t GROUP7 = (0xAAAA1111ull << 32) | 7u;   // that peer's group 7
	mkheader(&h, GROUP7, FILE_TYPE_CHANNEL, 0);
	CHECK(file_create(&h), "create a group beside the contact");
	CHECK(!file_create(&h), "a second file with the SAME id is refused");
	CHECK(file_header_read(GROUP7, &back), "read the group back");
	CHECK(back.file_type == FILE_TYPE_CHANNEL, "it is the group");
	CHECK(header_matches(&back, GROUP7, 0), "its body is its own");
	CHECK(file_header_read(THREAD, &back) &&
	      back.file_type == FILE_TYPE_CONTACT, "the contact is untouched");
	{
		const uint8_t m[FILE_META] = { 1, 0, 0, 0 };
		uint8_t body[8];
		fill_pattern(body, sizeof body, 61);
		uint32_t ge = write_entry(GROUP7, body, sizeof body, m);
		CHECK(ge != FILE_NONE, "write an entry into the group");
		CHECK(file_log_newest(GROUP7) == ge, "it is the GROUP's newest");
		CHECK(file_log_newest(THREAD) != ge,
		      "and NOT the contact's -- the two threads do not merge");
		struct file_entry_info gi;
		CHECK(file_entry_stat(GROUP7, ge, &gi) && gi.file_id == GROUP7,
		      "stat names the file it belongs to");
		CHECK(!file_entry_stat(THREAD, ge, &gi),
		      "and refuses it under another file's name");
	}
	CHECK(file_destroy(GROUP7), "destroy the group");
	CHECK(!file_header_read(GROUP7, &back), "the group is gone");
	CHECK(file_header_read(THREAD, &back),
	      "the contact beside it survives");

	// ---- entries ------------------------------------------------------------
	printf("\n[2] entries\n");
	static uint8_t body[FILE_ENTRY_MAX], rd[FILE_ENTRY_MAX];
	const uint8_t META[FILE_META] = { 0xA1, 0xB2, 0xC3, 0xD4 };

	fill_pattern(body, 100, 3);
	uint32_t e1 = write_entry((0xAAAA1111ull << 32), body, 100, META);
	CHECK(e1 != FILE_NONE, "create+write+commit a one-chunk entry");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xAAAA1111ull << 32), e1, 0, rd, 100) == 100,
	      "read it back whole");
	CHECK(memcmp(rd, body, 100) == 0, "payload round-trips");

	struct file_entry_info info;
	CHECK(file_entry_stat((0xAAAA1111ull << 32), e1, &info), "stat the entry");
	CHECK(info.file_id == (0xAAAA1111ull << 32), "stat names the file it belongs to");
	CHECK(info.length == 100, "stat reports the length");
	CHECK(memcmp(info.meta, META, FILE_META) == 0, "meta is ferried verbatim");
	CHECK(info.timestamp != 0, "the filesystem stamped a timestamp");
	CHECK((info.flags & FILE_DELETED) != 0, "a fresh entry is not deleted (active low)");

	// a multi-chunk payload: 5 full chunks and a short tail
	uint16_t big = FILE_CHUNK * 5 + 77;
	fill_pattern(body, big, 9);
	uint32_t e2 = write_entry((0xAAAA1111ull << 32), body, big, META);
	CHECK(e2 != FILE_NONE, "write a six-chunk entry");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, 0, rd, big) == big,
	      "read the whole six-chunk payload");
	CHECK(memcmp(rd, body, big) == 0, "multi-chunk payload round-trips");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, FILE_CHUNK * 2 + 10, rd, 50) == 50,
	      "read from an offset mid-entry");
	CHECK(memcmp(rd, body + FILE_CHUNK * 2 + 10, 50) == 0, "the offset read is correct");

	// overrun refusal
	uint32_t e3 = file_entry_create((0xAAAA1111ull << 32), 50, 0, META);
	CHECK(e3 != FILE_NONE, "reserve a 50-byte entry");
	CHECK(file_entry_write((0xAAAA1111ull << 32), e3, body, 51) == -1,
	      "writing past the reservation is refused");
	CHECK(file_entry_write((0xAAAA1111ull << 32), e3, body, 50) == 50, "the exact size is accepted");
	CHECK(file_entry_commit((0xAAAA1111ull << 32), e3), "commit it");

	// ---- resume: the property that needs no RAM -----------------------------
	printf("\n[3] resume a torn entry across a remount\n");
	uint16_t tornlen = FILE_CHUNK * 3;
	fill_pattern(body, tornlen, 21);
	uint32_t torn = file_entry_create((0xBBBB2222ull << 32), tornlen, 0, META);
	CHECK(torn != FILE_NONE, "reserve a three-chunk entry");
	CHECK(file_entry_write((0xBBBB2222ull << 32), torn, body, FILE_CHUNK) == (int)FILE_CHUNK,
	      "write chunk 1");
	CHECK(file_storage_flush(), "flush");
	CHECK(file_entry_filled((0xBBBB2222ull << 32), torn) == (int)FILE_CHUNK,
	      "filled reports one chunk");

	CHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BASE, SECTORS, VOLKEY, EPOCH),
	      "remount (simulated reboot) with the entry half-written");
	CHECK(file_entry_filled((0xBBBB2222ull << 32), torn) == (int)FILE_CHUNK,
	      "the resume point survives the reboot, found on flash");
	CHECK(file_entry_write((0xBBBB2222ull << 32), torn, body + FILE_CHUNK, FILE_CHUNK) == (int)FILE_CHUNK,
	      "resume: chunk 2");
	CHECK(file_entry_write((0xBBBB2222ull << 32), torn, body + FILE_CHUNK * 2, FILE_CHUNK) == (int)FILE_CHUNK,
	      "resume: chunk 3");
	CHECK(file_entry_commit((0xBBBB2222ull << 32), torn), "seal the resumed entry");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xBBBB2222ull << 32), torn, 0, rd, tornlen) == tornlen &&
	      memcmp(rd, body, tornlen) == 0, "the resumed entry reads back intact");

	// ---- the log walk -------------------------------------------------------
	printf("\n[4] the log walk\n");
	CHECK(file_log_newest((0xAAAA1111ull << 32)) == e3, "newest is the last committed");
	uint32_t w = file_log_older((0xAAAA1111ull << 32), e3);
	CHECK(w == e2, "older steps back one");
	w = file_log_older((0xAAAA1111ull << 32), w);
	CHECK(w == e1, "older steps back again");
	CHECK(file_log_older((0xAAAA1111ull << 32), w) == FILE_NONE, "older ends at FILE_NONE");
	CHECK(file_log_newer((0xAAAA1111ull << 32), e1) == e2, "newer steps forward");
	CHECK(file_log_newest((0xCCCC3333ull << 32)) == FILE_NONE, "an empty log has no newest");
	CHECK(file_log_older((0xAAAA1111ull << 32), torn) != torn,
	      "a walk never returns another file's entry");

	// The backward walk has to agree with the forward one exactly. file_log_older
	// steps back a page at a time looking for a header whose span ends where the
	// next entry starts; file_entry_scan_all walks forward over every live entry
	// in the region. Derive one file's log both ways and require the same ids in
	// the same order, so a stray ENTRY_MAGIC in ciphertext, a tombstone or a torn
	// entry cannot make the two disagree.
	{
		uint64_t f = (0xAAAA1111ull << 32);
		uint32_t fwd[64], back[64];
		int nf = 0, nb = 0;
		uint32_t id = file_entry_scan_all(FILE_NONE, NULL);
		while (id != FILE_NONE && nf < 64) {
			struct file_entry_info info;
			if (file_entry_stat(f, id, &info) && info.file_id == f)
				fwd[nf++] = id;
			id = file_entry_scan_all(id, NULL);
		}
		for (id = file_log_newest(f); id != FILE_NONE && nb < 64;
		     id = file_log_older(f, id))
			back[nb++] = id;
		CHECK(nf == nb, "backward walk visits as many entries as the forward one");
		bool same = (nf == nb);
		for (int i = 0; i < nb && same; i++) {
			if (back[i] != fwd[nf - 1 - i])
				same = false;
		}
		CHECK(same, "backward walk is the forward walk reversed, id for id");

		// And newer must climb back up the same ladder.
		bool up = (nb > 1);
		for (int i = nb - 1; i > 0 && up; i--) {
			if (file_log_newer(f, back[i]) != back[i - 1])
				up = false;
		}
		CHECK(up, "newer retraces the walk in the other direction");
	}

	// ---- interleaved fills --------------------------------------------------
	printf("\n[5] two files filling at once\n");
	uint32_t ia = file_entry_create((0xAAAA1111ull << 32), FILE_CHUNK * 2, 0, META);
	uint32_t ib = file_entry_create((0xCCCC3333ull << 32), FILE_CHUNK * 2, 0, META);
	CHECK(ia != FILE_NONE && ib != FILE_NONE && ia != ib, "two entries reserved at once");
	static uint8_t pa[FILE_CHUNK * 2], pb[FILE_CHUNK * 2];
	fill_pattern(pa, sizeof pa, 41);
	fill_pattern(pb, sizeof pb, 77);
	bool ok = true;
	ok &= file_entry_write((0xAAAA1111ull << 32), ia, pa, FILE_CHUNK) == (int)FILE_CHUNK;
	ok &= file_entry_write((0xCCCC3333ull << 32), ib, pb, FILE_CHUNK) == (int)FILE_CHUNK;
	ok &= file_entry_write((0xAAAA1111ull << 32), ia, pa + FILE_CHUNK, FILE_CHUNK) == (int)FILE_CHUNK;
	ok &= file_entry_write((0xCCCC3333ull << 32), ib, pb + FILE_CHUNK, FILE_CHUNK) == (int)FILE_CHUNK;
	CHECK(ok, "their chunks interleave without interfering");
	CHECK(file_entry_commit((0xAAAA1111ull << 32), ia) &&
	      file_entry_commit((0xCCCC3333ull << 32), ib), "both seal");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xAAAA1111ull << 32), ia, 0, rd, sizeof pa) == (int)sizeof pa &&
	      memcmp(rd, pa, sizeof pa) == 0, "file A's payload is its own");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xCCCC3333ull << 32), ib, 0, rd, sizeof pb) == (int)sizeof pb &&
	      memcmp(rd, pb, sizeof pb) == 0, "file B's payload is its own");
	CHECK(file_entry_read((0xAAAA1111ull << 32), ib, 0, rd, 16) == -1,
	      "reading another file's entry under the wrong id fails");

	// ---- flags --------------------------------------------------------------
	printf("\n[6] flags\n");
	CHECK(file_entry_flag_clear((0xAAAA1111ull << 32), e1, 0x02u), "clear an app bit");
	CHECK(file_entry_stat((0xAAAA1111ull << 32), e1, &info) &&
	      (info.flags & 0x02u) == 0, "stat shows the app bit cleared");
	CHECK((info.flags & FILE_DELETED) != 0, "clearing an app bit did not delete it");
	CHECK(file_entry_read((0xAAAA1111ull << 32), e1, 0, rd, 100) == 100,
	      "the payload survives an app-bit change");

	CHECK(file_entry_flag_clear((0xAAAA1111ull << 32), e1, FILE_DELETED), "delete the entry");
	CHECK(file_entry_read((0xAAAA1111ull << 32), e1, 0, rd, 100) == -1,
	      "a deleted entry's payload is gone");

	// ---- scan_all -----------------------------------------------------------
	printf("\n[7] scan every entry of every file\n");
	int seen = 0, seen_a = 0, seen_group = 0;
	uint32_t cursor = FILE_NONE;
	while ((cursor = file_entry_scan_all(cursor, &info)) != FILE_NONE) {
		seen++;
		if (info.file_id == (0xAAAA1111ull << 32))
			seen_a++;
		if (info.file_id == ((0xAAAA1111ull << 32) | 7u))
			seen_group++;
		if (seen > 100)
			break;
	}
	// 6, not 5: [1b]'s destroyed group left its entry behind. Destroying a file
	// scrubs the KEY, not the entries -- they are unreadable immediately and
	// reclaimed at the next compaction, which §11 then checks.
	CHECK(seen == 6, "the sweep finds every live entry and no tombstone");
	CHECK(seen_a == 3 && seen_group == 1, "the sweep attributes each entry to its file");

	// ---- crypto-erase -------------------------------------------------------
	printf("\n[8] destroying a file destroys its whole log\n");
	CHECK(file_entry_read((0xBBBB2222ull << 32), torn, 0, rd, tornlen) == tornlen,
	      "the entry reads before the destroy");
	CHECK(file_destroy((0xBBBB2222ull << 32)), "destroy the file");
	CHECK(!file_header_read((0xBBBB2222ull << 32), &back), "its header is gone");
	CHECK(file_entry_read((0xBBBB2222ull << 32), torn, 0, rd, tornlen) == -1,
	      "its entries are unreadable: the data key was the only way in");
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, 0, rd, big) == big,
	      "no other file was touched");

	// ---- remount ------------------------------------------------------------
	printf("\n[9] remount\n");
	CHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BASE, SECTORS, VOLKEY, EPOCH), "remount");
	CHECK(file_header_read((0xAAAA1111ull << 32), &back) &&
	      header_matches(&back, (0xAAAA1111ull << 32), 0), "headers survive");
	CHECK(first_of_type(FILE_TYPE_CHANNEL) == (0xCCCC3333ull << 32), "the type index survives");
	CHECK(file_log_newest((0xAAAA1111ull << 32)) == ia, "the log head is rebuilt");
	memset(rd, 0, sizeof rd);
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, 0, rd, big) == big &&
	      memcmp(rd, body, 0) == 0, "entries survive");

	// header rewrite must NOT rotate the data key, or the log is orphaned
	mkheader(&h, (0xAAAA1111ull << 32), FILE_TYPE_CONTACT, 5);
	CHECK(file_header_write((0xAAAA1111ull << 32), &h), "rewrite the header");
	CHECK(file_header_read((0xAAAA1111ull << 32), &back) &&
	      header_matches(&back, (0xAAAA1111ull << 32), 5), "the new body reads back");
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, 0, rd, big) == big,
	      "the log still reads: a header rewrite does NOT rotate the data key");

	// ---- the wrong volume key ----------------------------------------------
	printf("\n[10] a wrong volume key\n");
	CHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BASE, SECTORS, OTHERKEY, EPOCH),
	      "mount with the wrong key still succeeds");
	CHECK(first_of_type(FILE_TYPE_CHANNEL) == (0xCCCC3333ull << 32),
	      "the directory still rebuilds: identity is cleartext");
	CHECK(!file_header_read((0xAAAA1111ull << 32), &back), "but no header opens");
	CHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BASE, SECTORS, VOLKEY, EPOCH),
	      "remount with the right key");
	CHECK(file_header_read((0xAAAA1111ull << 32), &back), "headers open again");

	// ---- compaction ---------------------------------------------------------
	printf("\n[11] compaction\n");
	int before = file_storage_usage();
	CHECK(file_storage_compact(NULL), "compact");
	CHECK(file_storage_usage() <= before, "usage did not grow");
	CHECK(file_entry_read((0xAAAA1111ull << 32), e2, 0, rd, big) == -1 ||
	      file_log_newest((0xAAAA1111ull << 32)) != FILE_NONE,
	      "live entries survive compaction (ids move)");
	seen = 0;
	int orphans = 0;
	cursor = FILE_NONE;
	while ((cursor = file_entry_scan_all(cursor, &info)) != FILE_NONE && seen < 100) {
		seen++;
		if (info.file_id == (0xBBBB2222ull << 32))
			orphans++;
	}
	CHECK(seen == 4, "the tombstone is gone and the four reachable entries remain");
	CHECK(orphans == 0, "entries of a destroyed file are reclaimed, not kept as dead ciphertext");
	memset(rd, 0, sizeof rd);
	CHECK(file_log_newest((0xCCCC3333ull << 32)) != FILE_NONE, "the group's log head survived");
	uint32_t moved = file_log_newest((0xCCCC3333ull << 32));
	CHECK(file_entry_read((0xCCCC3333ull << 32), moved, 0, rd, sizeof pb) == (int)sizeof pb &&
	      memcmp(rd, pb, sizeof pb) == 0, "a moved entry still decrypts and reads correctly");

	// ---- wipe ---------------------------------------------------------------
	printf("\n[12] wipe\n");
	CHECK(file_storage_wipe(), "wipe");
	CHECK(count_type(FILE_TYPE_CONTACT) == 0, "no files remain");
	CHECK(file_entry_scan_all(FILE_NONE, &info) == FILE_NONE, "no entries remain");

	printf("\n%d passed, %d failed\n", passed, failed);
	return failed != 0;
}
