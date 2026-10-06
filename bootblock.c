//
// bootblock.c — the boot block: A/B-redundant persistence of the keystore
// image, as a single-sector-per-slot instance of the shared abblock engine
// (abblock.c) over the bootflash_* raw-sector HAL. See bootblock.h for the
// contract and STORAGE_SECURITY.md §II.2 for the design. Portable C (no
// Arduino, no wg.h); compiled for both device and host. Core 0 only.
//

#include <string.h>
#include "bootblock.h"
#include "abblock.h"

#if AB_SECTOR != ZB_SECTOR_SIZE
#error "abblock engine sector size must match the bootflash sector size"
#endif
#if AB_SLOTS != ZB_NUM_SLOTS
#error "abblock engine slot count must match ZB_NUM_SLOTS"
#endif

// ---- abblock instance: slot-relative byte addressing over bootflash_* ----

static bool boot_slot_read(int slot, uint32_t off, void *buf, uint32_t len) {
	return bootflash_read(slot, off, buf, (int)len);
}

static bool boot_slot_erase(int slot) {
	return bootflash_erase(slot);
}

static bool boot_slot_program(int slot, uint32_t off, const void *buf, uint32_t len) {
	if (off != 0)  // 1 sector/slot: the engine only programs offset 0
		return false;
	return bootflash_program(slot, buf, (int)len);
}

static const struct abblock boot_ab = {
	0x5A45524Fu,      // "ZERO" — the on-flash magic, kept from when this was zeroblock
	ZB_SECTOR_SIZE,   // one sector per slot
	1,                // bootflash_program pads to a full sector itself
	boot_slot_read,
	boot_slot_erase,
	boot_slot_program,
};

// ---- public API (bootblock.h) ----

bool bootblock_init(void) {
	return bootflash_init();
}

int bootblock_load(void *buf, int len) {
	return abblock_load(&boot_ab, buf, len, NULL);
}

bool bootblock_save(const void *buf, int len) {
	return abblock_save(&boot_ab, buf, len);
}

bool bootblock_erase_all(void) {
	return abblock_erase_all(&boot_ab);
}
