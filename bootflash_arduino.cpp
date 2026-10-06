//
// bootflash_arduino.cpp — DEVICE (RP2350) backend for the bootblock raw-sector HAL
// (bootblock.h). The bootblock lives in the FIRST ZB_NUM_SLOTS sectors of the
// same reserved FS region the message store uses (rawflash_arduino.cpp), keyed
// off the core's _FS_start linker symbol — so the two never overlap (logbook
// starts at sector >= BOOTBLOCK_SECTORS). LittleFS must not be mounted on this
// region. Read via memory-mapped XIP; erase/program via the Pico SDK.
//

#include <Arduino.h>
#include <hardware/flash.h>
#include <hardware/sync.h>
#include "bootblock.h"

extern uint8_t _FS_start;   // start of the reserved FS region (shared with rawflash)
extern uint32_t flash_settle_us;   // settle delay after each flash op (rawflash_arduino.cpp)
void flash_guard_touch(void);      // pause audio DMA before a flash op (rawflash_arduino.cpp)

static inline uint32_t slot_offset(int slot) {
	return ((uint32_t)&_FS_start - XIP_BASE) + (uint32_t)slot * ZB_SECTOR_SIZE;
}

bool bootflash_init(void) {
	return (ZB_SECTOR_SIZE == FLASH_SECTOR_SIZE);
}

int bootflash_sector_size(void) { return ZB_SECTOR_SIZE; }

bool bootflash_read(int slot, uint32_t off, void *buf, int len) {
	if (slot < 0 || slot >= ZB_NUM_SLOTS || len < 0 ||
	    off > (uint32_t)ZB_SECTOR_SIZE || (uint32_t)len > ZB_SECTOR_SIZE - off) return false;
	// Read via the NON-CACHED XIP alias: the cached window (XIP_BASE) isn't
	// invalidated by flash_range_erase/program, so a cached read after a write is
	// stale. Harmless for the keystore today (written once at boot, cold cache) but
	// a post-boot re-key (disk-key change) would read stale without this. Same fix
	// as rawflash_arduino.cpp. XIP_NOCACHE_NOALLOC_BASE: RP2040 0x13000000 / RP2350 0x14000000.
	const uint8_t *src = (const uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + slot_offset(slot) + off);
	memcpy(buf, src, (size_t)len);
	return true;
}

bool bootflash_erase(int slot) {
	if (slot < 0 || slot >= ZB_NUM_SLOTS)
		return false;
	flash_guard_touch();
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();   // park core1: it must not fetch from XIP during the erase
	flash_range_erase(slot_offset(slot), ZB_SECTOR_SIZE);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	if (flash_settle_us)
		delayMicroseconds(flash_settle_us);
	return true;
}

bool bootflash_program(int slot, const void *buf, int len) {
	if (slot < 0 || slot >= ZB_NUM_SLOTS || len < 0 || len > ZB_SECTOR_SIZE)
		return false;
	static uint8_t page[ZB_SECTOR_SIZE];
	memset(page, 0xFF, sizeof page);
	memcpy(page, buf, (size_t)len);
	flash_guard_touch();
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();   // park core1: it must not fetch from XIP during the program
	flash_range_program(slot_offset(slot), page, ZB_SECTOR_SIZE);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	if (flash_settle_us)
		delayMicroseconds(flash_settle_us);
	return true;
}
