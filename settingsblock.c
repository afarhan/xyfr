//
// settingsblock.c — the settings block: a multi-sector A/B opaque-image store,
// as an N-sectors-per-slot instance of the shared abblock engine (abblock.c)
// over the general rawflash HAL (page-granular program). See settingsblock.h
// for the contract. Portable C, core 0 only.
//

#include <string.h>
#include "settingsblock.h"
#include "rawflash.h"
#include "abblock.h"

#if AB_SECTOR != RAWFLASH_SECTOR
#error "abblock engine sector size must match RAWFLASH_SECTOR"
#endif
#if AB_SLOTS != SB_SLOTS
#error "abblock engine slot count must match SB_SLOTS"
#endif
#if AB_FRAME_LEN != FB_FRAME_LEN
#error "abblock engine frame length must match FB_FRAME_LEN"
#endif

#define FB_MAGIC 0x46424C4Bu   // "FBLK", the on-flash magic

static uint8_t  settings_device;
static uint32_t settings_base_sector;    // first sector of slot 0
static uint32_t settings_slot_sectors;   // sectors per slot
static bool     settings_ready = false;

static uint32_t slot_base_sector(int slot) {
	return settings_base_sector + (uint32_t)slot * settings_slot_sectors;
}

// ---- abblock instance: slot-relative byte addressing over rawflash_* ----

static bool settings_slot_read(int slot, uint32_t off, void *buf, uint32_t len) {
	uint8_t *out = (uint8_t *)buf;
	uint32_t base = slot_base_sector(slot);
	while (len) {
		uint32_t sector     = base + off / RAWFLASH_SECTOR;
		uint32_t sector_off = off % RAWFLASH_SECTOR;
		uint32_t chunk      = RAWFLASH_SECTOR - sector_off;
		if (chunk > len)
			chunk = len;
		if (!rawflash_read(settings_device, sector, sector_off, out, chunk))
			return false;
		out += chunk;
		off += chunk;
		len -= chunk;
	}
	return true;
}

static bool settings_slot_erase(int slot) {
	// Attempt every sector even after a failure (wipe wants max effort).
	bool ok = true;
	for (uint32_t i = 0; i < settings_slot_sectors; i++)
		ok = rawflash_erase(settings_device, slot_base_sector(slot) + i) && ok;
	return ok;
}

static bool settings_slot_program(int slot, uint32_t off, const void *buf, uint32_t len) {
	// The engine calls with off sector-aligned and len <= one sector,
	// already rounded up to RAWFLASH_PAGE (prog_align below).
	return rawflash_program(settings_device, slot_base_sector(slot) + off / RAWFLASH_SECTOR,
	                        0, buf, len);
}

static struct abblock settings_ab;   // geometry is runtime config — filled by init

// ---- public API (settingsblock.h) ----

bool settingsblock_init(uint8_t device, uint32_t base_sector, uint32_t slot_sectors) {
	if (slot_sectors == 0)
		return false;
	if (!rawflash_init())
		return false;
	uint32_t total = rawflash_sector_count(device);
	if (base_sector + (uint32_t)SB_SLOTS * slot_sectors > total)
		return false;
	settings_device  = device;
	settings_base_sector = base_sector;
	settings_slot_sectors = slot_sectors;
	settings_ab.magic      = FB_MAGIC;
	settings_ab.slot_bytes = slot_sectors * RAWFLASH_SECTOR;
	settings_ab.prog_align = RAWFLASH_PAGE;
	settings_ab.read       = settings_slot_read;
	settings_ab.erase_slot = settings_slot_erase;
	settings_ab.program    = settings_slot_program;
	settings_ready = true;
	return true;
}

uint32_t settingsblock_max_payload(void) {
	if (!settings_ready)
		return 0;
	return settings_slot_sectors * RAWFLASH_SECTOR - FB_FRAME_LEN;
}

struct sb_diag g_sb_diag;   // TEMP diagnostic (see settingsblock.h)

int settingsblock_load(void *buf, int max) {
	if (!settings_ready)
		return -1;
	struct ab_slot_info info[AB_SLOTS];
	int n = abblock_load(&settings_ab, buf, max, info);
	// Mirror the slot scan into the sdiag view (winner = highest valid seq,
	// lower slot wins a tie — the engine's own rule).
	const int diag_slots = (int)(sizeof g_sb_diag.slot_valid / sizeof g_sb_diag.slot_valid[0]);
	g_sb_diag.nslots = AB_SLOTS;
	int best = -1;
	uint32_t best_seq = 0;
	for (int s = 0; s < AB_SLOTS && s < diag_slots; s++) {
		g_sb_diag.slot_valid[s] = info[s].valid;
		g_sb_diag.slot_seq[s]   = info[s].seq;
		if (info[s].valid && (best < 0 || info[s].seq > best_seq)) {
			best = s;
			best_seq = info[s].seq;
		}
	}
	g_sb_diag.winner = best;
	g_sb_diag.winner_seq = best_seq;
	return n;
}

bool settingsblock_save(const void *buf, int len) {
	if (!settings_ready)
		return false;
	return abblock_save(&settings_ab, buf, len);
}

bool settingsblock_erase_all(void) {
	if (!settings_ready)
		return false;
	return abblock_erase_all(&settings_ab);
}
