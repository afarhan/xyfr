//
// bootflash_posix.c — HOST backend for the bootblock raw-sector storage HAL
// (declared in ../bootblock.h). Simulates the device's dedicated flash sectors
// with a file (./fsroot/bootblock.img) so the key schedule can be exercised and
// power-cycled on Linux under gdb/valgrind, before any device flash code runs.
// The device backend is ../bootflash_arduino.cpp (flash_range_*). Host only.
//
// Fault injection: set bootflash_test_truncate_next >= 0 to make the NEXT program
// write only that many bytes and then report failure — modelling a power loss
// mid-write, so the A/B recovery path in bootblock.c can be tested.
//

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "bootblock.h"

#define IMG_PATH "fsroot/bootblock.img"
#define IMG_BYTES (ZB_NUM_SLOTS * ZB_SECTOR_SIZE)

int bootflash_test_truncate_next = -1;   // -1 = no injected fault

static bool ensure_image(void) {
	mkdir("fsroot", 0777);   // harmless if it exists
	FILE *f = fopen(IMG_PATH, "rb");
	if (f) { fclose(f); return true; }
	// create, filled with 0xFF (erased flash)
	f = fopen(IMG_PATH, "wb");
	if (!f) return false;
	unsigned char ff[256];
	memset(ff, 0xFF, sizeof ff);
	for (int i = 0; i < IMG_BYTES; i += (int)sizeof ff)
		fwrite(ff, 1, sizeof ff, f);
	fclose(f);
	return true;
}

bool bootflash_init(void) { return ensure_image(); }

int bootflash_sector_size(void) { return ZB_SECTOR_SIZE; }

static bool slot_ok(int slot) { return slot >= 0 && slot < ZB_NUM_SLOTS; }

bool bootflash_read(int slot, uint32_t off, void *buf, int len) {
	if (!slot_ok(slot) || len < 0 ||
	    off > (uint32_t)ZB_SECTOR_SIZE || (uint32_t)len > ZB_SECTOR_SIZE - off) return false;
	if (!ensure_image()) return false;
	FILE *f = fopen(IMG_PATH, "rb");
	if (!f) return false;
	bool ok = (fseek(f, (long)slot * ZB_SECTOR_SIZE + (long)off, SEEK_SET) == 0) &&
	          (fread(buf, 1, (size_t)len, f) == (size_t)len);
	fclose(f);
	return ok;
}

bool bootflash_erase(int slot) {
	if (!slot_ok(slot)) return false;
	if (!ensure_image()) return false;
	FILE *f = fopen(IMG_PATH, "r+b");
	if (!f) return false;
	unsigned char ff[256];
	memset(ff, 0xFF, sizeof ff);
	bool ok = (fseek(f, (long)slot * ZB_SECTOR_SIZE, SEEK_SET) == 0);
	for (int i = 0; ok && i < ZB_SECTOR_SIZE; i += (int)sizeof ff)
		ok = (fwrite(ff, 1, sizeof ff, f) == sizeof ff);
	fflush(f);
	fclose(f);
	return ok;
}

bool bootflash_program(int slot, const void *buf, int len) {
	if (!slot_ok(slot) || len < 0 || len > ZB_SECTOR_SIZE) return false;
	if (!ensure_image()) return false;

	int wlen = len;
	bool injected = false;
	if (bootflash_test_truncate_next >= 0) {
		injected = true;
		wlen = bootflash_test_truncate_next < len ? bootflash_test_truncate_next : len;
		bootflash_test_truncate_next = -1;   // one-shot
	}

	FILE *f = fopen(IMG_PATH, "r+b");
	if (!f) return false;
	bool ok = (fseek(f, (long)slot * ZB_SECTOR_SIZE, SEEK_SET) == 0) &&
	          (fwrite(buf, 1, (size_t)wlen, f) == (size_t)wlen);
	fflush(f);
	fclose(f);

	if (injected) return false;   // simulated torn write: bytes partly written, then "power loss"
	return ok;
}
