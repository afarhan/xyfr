//
// test_filesystem_device.cpp — ON-DEVICE acceptance test for filesystem.c on
// REAL RP2350 flash, in the reserved FS region (_FS_start).
//
// The host suite (secserver/test_filesystem.c) proves the algorithms. This one
// proves what only hardware shows: real flash_range erase/program, XIP reads,
// and above all that the IN-PLACE NOR bit clear (a flag change with no erase)
// and a PART-WRITTEN entry both survive an actual power cycle.
//
// Two-phase, keyed off what is already in the region:
//   first boot (blank) → erase, mount, create files, write one sealed entry and
//                        leave one entry deliberately half-written, clear a flag.
//                        then: POWER-CYCLE the device.
//   next boot          → remount, verify everything survived, resume the torn
//                        entry from flash, and crypto-erase a file.
//
// NOT wired by default — runs only under -DFILESYSTEM_DEVICE_TEST (the .ino
// skips the normal boot, so nothing else touches the region).
//
// WARNING: it owns the whole contacts+logbook region. Running it DESTROYS the
// unit's contacts and message history.
//
#include <Arduino.h>
#include <string.h>
#include "debug.h"
#include "rawflash.h"
#include "secure_store.h"        // CONTACTSBLOCK_BASE_SECTOR — where the region starts
#include "filesystem.h"

#define TFS_ID_A     (0xA1B2C3D4ull << 32)        // a contact: peer, group 0
#define TFS_ID_G     ((0xA1B2C3D4ull << 32) | 7u) // that peer's group 7
#define TFS_APP_BIT  0x02u

static int tfs_pass = 0, tfs_fail = 0;
#define TFCHECK(c, m) do { if (c) { Debug.printf("  PASS  %s\n", m); tfs_pass++; } \
                           else  { Debug.printf("  FAIL  %s\n", m); tfs_fail++; } } while (0)

// A fixed volume key: this test exercises the filesystem, not the keystore.
static const uint8_t TFS_VOLKEY[32] = {
	0x5a,0xa5,0x3c,0xc3,0x0f,0xf0,0x69,0x96,0x17,0x71,0x28,0x82,0x39,0x93,0x4a,0xa4,
	0x5b,0xb5,0x6c,0xc6,0x7d,0xd7,0x8e,0xe8,0x9f,0xf9,0xa0,0x0a,0xb1,0x1b,0xc2,0x2c,
};

static char tfs_summary[96] = "filesystem device test: (running)";

static void tfs_pattern(uint8_t *buf, uint32_t len, uint8_t seed) {
	for (uint32_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(seed * 31 + i * 7);
}

static void tfs_header(struct file_header *h, uint64_t id, uint8_t type, uint8_t salt) {
	memset(h, 0, sizeof *h);
	h->file_id = id;
	h->file_type = type;
	for (unsigned i = 0; i < FILE_INODE_DATA; i++)
		h->data[i] = (uint8_t)(id + i + salt);
}

static bool tfs_header_ok(const struct file_header *h, uint64_t id, uint8_t salt) {
	for (unsigned i = 0; i < FILE_INODE_DATA; i++)
		if (h->data[i] != (uint8_t)(id + i + salt))
			return false;
	return true;
}

// The sealed entry: 2 full chunks + a short tail, so the multi-chunk read path
// and the short-last-chunk case both cross a power cycle.
#define TFS_SEALED_LEN  (FILE_CHUNK * 2 + 91)
#define TFS_TORN_LEN    (FILE_CHUNK * 3)

static uint8_t tfs_buf[TFS_SEALED_LEN > TFS_TORN_LEN ? TFS_SEALED_LEN : TFS_TORN_LEN];
static uint8_t tfs_read[sizeof tfs_buf];

extern "C" void test_filesystem_device(void) {
	Debug.printf("\n=== filesystem device test ===\n");
	if (!rawflash_init()) {
		Debug.printf("  rawflash_init FAILED\n");
		return;
	}
	uint32_t base = CONTACTSBLOCK_BASE_SECTOR;
	uint32_t total = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	if (total <= base) {
		Debug.printf("  no room: total=%u base=%u\n", (unsigned)total, (unsigned)base);
		return;
	}
	uint32_t sectors = total - base;
	Debug.printf("  region: base=%u sectors=%u\n", (unsigned)base, (unsigned)sectors);

	// Phase detection: mount first and ask whether our file is already there.
	bool second = false;
	if (file_storage_mount(RAWFLASH_DEV_INTERNAL, base, sectors, TFS_VOLKEY, 1)) {
		struct file_header probe;
		second = file_header_read(TFS_ID_A, &probe);
	}

	struct file_header h, back;

	if (!second) {
		Debug.printf("\n[phase 1] fresh region\n");
		for (uint32_t s = base; s < base + sectors; s++) {
			if (!rawflash_erase(RAWFLASH_DEV_INTERNAL, s)) {
				Debug.printf("  erase FAILED at sector %u\n", (unsigned)s);
				return;
			}
		}
		TFCHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, base, sectors, TFS_VOLKEY, 1),
		        "mount the erased region");

		tfs_header(&h, TFS_ID_A, FILE_TYPE_CONTACT, 0);
		TFCHECK(file_create(&h), "create the contact file");
		tfs_header(&h, TFS_ID_G, FILE_TYPE_CHANNEL, 0);
		TFCHECK(file_create(&h), "create the group file");

		const uint8_t meta[FILE_META] = { 0x11, 0x22, 0x33, 0x44 };
		tfs_pattern(tfs_buf, TFS_SEALED_LEN, 5);
		uint32_t e = file_entry_create(TFS_ID_A, TFS_SEALED_LEN, 0, meta);
		TFCHECK(e != FILE_NONE, "reserve the sealed entry");
		uint32_t off = 0;
		bool wrote = true;
		while (off < TFS_SEALED_LEN) {
			uint32_t n = TFS_SEALED_LEN - off;
			if (n > FILE_CHUNK)
				n = FILE_CHUNK;
			wrote &= file_entry_write(TFS_ID_A, e, tfs_buf + off, (int)n) == (int)n;
			off += n;
		}
		TFCHECK(wrote, "write every chunk of it");
		TFCHECK(file_entry_commit(TFS_ID_A, e), "seal it");
		TFCHECK(file_entry_flag_clear(TFS_ID_A, e, TFS_APP_BIT),
		        "clear an app flag IN PLACE (no erase)");

		// One entry deliberately left half-written, with nothing in RAM to say so.
		tfs_pattern(tfs_buf, TFS_TORN_LEN, 19);
		uint32_t t = file_entry_create(TFS_ID_G, TFS_TORN_LEN, 0, meta);
		TFCHECK(t != FILE_NONE, "reserve the torn entry");
		TFCHECK(file_entry_write(TFS_ID_G, t, tfs_buf, FILE_CHUNK) == (int)FILE_CHUNK,
		        "write chunk 1 of 3");
		TFCHECK(file_entry_write(TFS_ID_G, t, tfs_buf + FILE_CHUNK, FILE_CHUNK) == (int)FILE_CHUNK,
		        "write chunk 2 of 3, then STOP");
		TFCHECK(file_storage_flush(), "flush to flash");

		snprintf(tfs_summary, sizeof tfs_summary,
		         "phase 1: %d passed %d failed — POWER-CYCLE NOW, then read phase 2",
		         tfs_pass, tfs_fail);
		Debug.printf("\n  %s\n", tfs_summary);
		return;
	}

	Debug.printf("\n[phase 2] after a power cycle\n");
	TFCHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, base, sectors, TFS_VOLKEY, 2),
	        "remount (a new boot epoch)");

	TFCHECK(file_header_read(TFS_ID_A, &back), "the contact header survived");
	TFCHECK(tfs_header_ok(&back, TFS_ID_A, 0), "its body is byte-exact");
	uint64_t lid = FILE_NONE;
	uint8_t  ltype = 0;
	for (int i = 0; file_list(i, &lid, &ltype); i++)
		if (ltype == FILE_TYPE_CHANNEL)
			break;
	TFCHECK(lid == TFS_ID_G, "the group is still listed by type");

	uint32_t e = file_log_newest(TFS_ID_A);
	TFCHECK(e != FILE_NONE, "the log head was rebuilt from flash");

	struct file_entry_info info;
	TFCHECK(file_entry_stat(TFS_ID_A, e, &info), "stat the sealed entry");
	TFCHECK(info.length == TFS_SEALED_LEN, "its length survived");
	TFCHECK((info.flags & TFS_APP_BIT) == 0,
	        "THE IN-PLACE FLAG CLEAR SURVIVED THE POWER CYCLE");
	TFCHECK((info.flags & FILE_DELETED) != 0, "and it is still not deleted");

	tfs_pattern(tfs_buf, TFS_SEALED_LEN, 5);
	memset(tfs_read, 0, sizeof tfs_read);
	TFCHECK(file_entry_read(TFS_ID_A, e, 0, tfs_read, TFS_SEALED_LEN) == TFS_SEALED_LEN,
	        "read the whole sealed payload back");
	TFCHECK(memcmp(tfs_read, tfs_buf, TFS_SEALED_LEN) == 0, "it is byte-exact across the power cycle");

	// The torn entry: nothing in RAM said how far it got, so this is read off flash.
	uint32_t t = file_log_newest(TFS_ID_G);
	TFCHECK(t == FILE_NONE, "a torn entry is NOT the log head (it never sealed)");
	t = file_entry_scan_all(FILE_NONE, &info);
	uint32_t torn = FILE_NONE;
	while (t != FILE_NONE) {
		if (info.file_id == TFS_ID_G)
			torn = t;
		t = file_entry_scan_all(t, &info);
	}
	TFCHECK(torn == FILE_NONE, "and a scan skips it too");

	// Resume it by id. The id is its offset+1, which the reservation fixed at
	// create time, so the app would have had it in its own record.
	uint32_t resume = file_entry_create(TFS_ID_G, 8, 0, NULL);
	TFCHECK(resume != FILE_NONE, "the write head resumed PAST the torn entry's span");

	TFCHECK(file_destroy(TFS_ID_G), "destroy the group file");
	TFCHECK(!file_header_read(TFS_ID_G, &back), "its header is crypto-erased");
	TFCHECK(file_header_read(TFS_ID_A, &back), "the contact file is untouched");
	TFCHECK(file_entry_read(TFS_ID_A, e, 0, tfs_read, TFS_SEALED_LEN) == TFS_SEALED_LEN,
	        "and its log still reads");

	Debug.printf("  usage: %d%%\n", file_storage_usage());
	snprintf(tfs_summary, sizeof tfs_summary, "filesystem device test: %d passed, %d failed",
	         tfs_pass, tfs_fail);
	Debug.printf("\n  %s\n", tfs_summary);
}

// Reprinted from loop() so a monitor attaching late still sees the result.
extern "C" void test_filesystem_device_report(void) {
	Debug.printf("%s\n", tfs_summary);
}
