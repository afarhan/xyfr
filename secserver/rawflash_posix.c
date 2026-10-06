//
// rawflash_posix.c — HOST backend for rawflash.h. Simulates a NOR-flash chip
// with a file (./fsroot/rawflash.img), faithfully enough to catch device-only
// bugs: erase->0xFF, page-granular program, 1->0-only bit transitions.
//
// Size is fixed by RAWFLASH_SIM_SECTORS below; the device version carves a real
// flash region. Fault injection (rawflash_test_fail_after_pages) drops a write
// part-way to model a power loss mid-program, so the store's crash recovery can
// be tested deterministically. Host only.
//

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "rawflash.h"

#define RAWFLASH_SIM_SECTORS 560u   // ~2.3 MB: room for a fixed block + a ring
#define IMG_PATH "fsroot/rawflash.img"
#define IMG_BYTES (RAWFLASH_SIM_SECTORS * RAWFLASH_SECTOR)

// Test fault injection: if >= 0, the next rawflash_program writes only this many
// PAGES and then reports failure (power loss mid-write). One-shot. -1 = off.
int rawflash_test_fail_after_pages = -1;

static bool ensure_image(void) {
	mkdir("fsroot", 0777);   // harmless if it exists
	FILE *f = fopen(IMG_PATH, "rb");
	if (f) { fclose(f); return true; }
	f = fopen(IMG_PATH, "wb");
	if (!f) return false;
	unsigned char ff[RAWFLASH_PAGE];
	memset(ff, 0xFF, sizeof ff);
	for (uint32_t i = 0; i < IMG_BYTES; i += sizeof ff)
		fwrite(ff, 1, sizeof ff, f);
	fclose(f);
	return true;
}

bool rawflash_init(void) { return ensure_image(); }

uint32_t rawflash_sector_size(void)  { return RAWFLASH_SECTOR; }
uint32_t rawflash_page_size(void)    { return RAWFLASH_PAGE; }
uint32_t rawflash_sector_count(uint8_t device) {
	return device == RAWFLASH_DEV_INTERNAL ? RAWFLASH_SIM_SECTORS : 0;
}

bool rawflash_read(uint8_t device, uint32_t sector, uint32_t off, void *buf, uint32_t len) {
	if (device != RAWFLASH_DEV_INTERNAL) return false;
	if (sector >= RAWFLASH_SIM_SECTORS || off + len > RAWFLASH_SECTOR) return false;
	if (!ensure_image()) return false;
	FILE *f = fopen(IMG_PATH, "rb");
	if (!f) return false;
	long pos = (long)sector * RAWFLASH_SECTOR + off;
	bool ok = (fseek(f, pos, SEEK_SET) == 0) &&
	          (fread(buf, 1, len, f) == len);
	fclose(f);
	return ok;
}

bool rawflash_erase(uint8_t device, uint32_t sector) {
	if (device != RAWFLASH_DEV_INTERNAL) return false;
	if (sector >= RAWFLASH_SIM_SECTORS) return false;
	if (!ensure_image()) return false;
	FILE *f = fopen(IMG_PATH, "r+b");
	if (!f) return false;
	unsigned char ff[RAWFLASH_PAGE];
	memset(ff, 0xFF, sizeof ff);
	bool ok = (fseek(f, (long)sector * RAWFLASH_SECTOR, SEEK_SET) == 0);
	for (uint32_t i = 0; ok && i < RAWFLASH_SECTOR; i += sizeof ff)
		ok = (fwrite(ff, 1, sizeof ff, f) == sizeof ff);
	fflush(f);
	fclose(f);
	return ok;
}

bool rawflash_program(uint8_t device, uint32_t sector, uint32_t off, const void *buf, uint32_t len) {
	if (device != RAWFLASH_DEV_INTERNAL) return false;
	// Enforce the device's program constraints.
	if (sector >= RAWFLASH_SIM_SECTORS) return false;
	if (off % RAWFLASH_PAGE || len % RAWFLASH_PAGE) return false;   // page-granular
	if (off + len > RAWFLASH_SECTOR) return false;
	if (!ensure_image()) return false;

	// Compare-before-write (mirror the device HAL): if the target already holds
	// these exact bytes, skip — no wear, no torn-write risk. Whole-range compare
	// so host and device skip at the same granularity. Done before the fault
	// injection so a no-op write doesn't consume the one-shot.
	{
		unsigned char cmp[RAWFLASH_SECTOR];
		FILE *fc = fopen(IMG_PATH, "rb");
		if (!fc) return false;
		bool same = (fseek(fc, (long)sector * RAWFLASH_SECTOR + off, SEEK_SET) == 0) &&
		            (fread(cmp, 1, len, fc) == len) &&
		            (memcmp(cmp, buf, len) == 0);
		fclose(fc);
		if (same) return true;
	}

	uint32_t npages = len / RAWFLASH_PAGE;
	uint32_t write_pages = npages;
	bool injected = false;
	if (rawflash_test_fail_after_pages >= 0) {
		injected = true;
		uint32_t lim = (uint32_t)rawflash_test_fail_after_pages;
		if (lim < write_pages) write_pages = lim;
		rawflash_test_fail_after_pages = -1;   // one-shot
	}

	FILE *f = fopen(IMG_PATH, "r+b");
	if (!f) return false;
	const unsigned char *src = (const unsigned char *)buf;
	bool ok = true;
	for (uint32_t p = 0; ok && p < write_pages; p++) {
		long pos = (long)sector * RAWFLASH_SECTOR + off + p * RAWFLASH_PAGE;
		unsigned char cur[RAWFLASH_PAGE];
		ok = (fseek(f, pos, SEEK_SET) == 0) &&
		     (fread(cur, 1, RAWFLASH_PAGE, f) == RAWFLASH_PAGE);
		if (!ok) break;
		// NOR: program only clears bits (1->0). dst &= src.
		for (uint32_t i = 0; i < RAWFLASH_PAGE; i++)
			cur[i] &= src[p * RAWFLASH_PAGE + i];
		ok = (fseek(f, pos, SEEK_SET) == 0) &&
		     (fwrite(cur, 1, RAWFLASH_PAGE, f) == RAWFLASH_PAGE);
	}
	fflush(f);
	fclose(f);

	if (injected) return false;   // simulated power loss: wrote write_pages, then "died"
	return ok;
}
