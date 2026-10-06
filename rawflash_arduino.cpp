//
// rawflash_arduino.cpp — DEVICE (RP2350) backend for rawflash.h. The message
// store lives in the FS region the build reserves (the Arduino "Flash Size" /
// FQBN `flash=4194304_2097152` split): we use the WHOLE region via the core's
// _FS_start/_FS_end linker symbols, instead of mounting a filesystem there.
// Read via memory-mapped XIP; erase/program via the Pico SDK.
//
// The bootblock (bootflash_arduino.cpp) shares the same region base: it occupies
// the first BOOTBLOCK_SECTORS sectors, logbook the rest (logbook_init passes
// base_sector >= BOOTBLOCK_SECTORS). LittleFS must NOT be mounted on this region
// (it would auto-format over us) — the firmware skips the mount under
// STORAGE_DEVICE_TEST.
//

#include <Arduino.h>
#include <hardware/flash.h>
#include <hardware/sync.h>
#include "rawflash.h"
#include "audio.h"        // audio_dma_pause/resume — quiesce audio DMA around a flash write

extern uint8_t _FS_start, _FS_end;   // core linker symbols: the reserved FS region
extern volatile bool audio_ready;    // audio.cpp — true once the mic/speaker DMA is up

// Settle delay (microseconds) after EACH flash erase/program, run with interrupts
// back on (outside the XIP-off critical section). Spaces out successive sector
// writes so we never slam the flash back-to-back. Tunable global (0 = none).
uint32_t flash_settle_us = 1000;

// FLASH GUARD. The free-running mic ADC + speaker PWM DMA must not stream during a
// flash erase/program (XIP off) — it wedges the core (device-proven). So we pause
// that DMA on the first flash op and resume it once flash has been idle for
// flash_resume_idle_ms (a device pump calls flash_guard_pump). This batches a
// multi-sector write into ONE pause/resume instead of churning the DMA per op.
uint32_t flash_resume_idle_ms = 100;
static volatile bool s_audio_paused = false;
static volatile uint32_t s_flash_last_ms = 0;

void flash_guard_touch(void) {           // call right before every real flash op
	if (!audio_ready)  // audio not up yet (e.g. boot seed writes) → nothing to pause
		return;
	if (!s_audio_paused) {
		audio_dma_pause();
		s_audio_paused = true;
	}
	s_flash_last_ms = millis();
}

void flash_guard_pump(void) {            // call from loop(): lazy resume after the burst
	if (s_audio_paused && (uint32_t)(millis() - s_flash_last_ms) >= flash_resume_idle_ms) {
		audio_dma_resume();
		s_audio_paused = false;
	}
}

static inline uint32_t region_base(void)    { return (uint32_t)&_FS_start - XIP_BASE; }
static inline uint32_t region_sectors(void) { return (uint32_t)(&_FS_end - &_FS_start) / RAWFLASH_SECTOR; }
static inline uint32_t abs_offset(uint32_t sector) { return region_base() + sector * RAWFLASH_SECTOR; }

// Read through the NON-CACHED XIP alias so every read reflects PHYSICAL NOR. The
// SDK's flash_range_erase/program do NOT invalidate the cached XIP window
// (XIP_BASE), so a cached read after a write returns stale bytes. That made the
// compare-before-write below skip real programs (it saw stale "already-matching"
// data), and made writes appear to persist within a boot yet vanish on the next
// reboot (cold cache reveals the never-written flash). Uncached reads are a touch
// slower but keep the store coherent. XIP_NOCACHE_NOALLOC_BASE = 0x13000000 on
// RP2040, 0x14000000 on RP2350 — the header picks the right one for the target.
static inline const uint8_t *xip_uncached(uint32_t sector, uint32_t off) {
	return (const uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + abs_offset(sector) + off);
}

bool rawflash_init(void) {
	return (RAWFLASH_SECTOR == FLASH_SECTOR_SIZE) && (RAWFLASH_PAGE == FLASH_PAGE_SIZE);
}

uint32_t rawflash_sector_size(void)  { return RAWFLASH_SECTOR; }
uint32_t rawflash_page_size(void)    { return RAWFLASH_PAGE; }
uint32_t rawflash_sector_count(uint8_t device) {
	if (device == RAWFLASH_DEV_INTERNAL)  // no SD yet
		return region_sectors();
	return 0;
}

bool rawflash_read(uint8_t device, uint32_t sector, uint32_t off, void *buf, uint32_t len) {
	if (device != RAWFLASH_DEV_INTERNAL)
		return false;
	if (sector >= region_sectors() || off + len > RAWFLASH_SECTOR)
		return false;
	const uint8_t *src = xip_uncached(sector, off);
	memcpy(buf, src, len);
	return true;
}

bool rawflash_erase(uint8_t device, uint32_t sector) {
	if (device != RAWFLASH_DEV_INTERNAL)
		return false;
	if (sector >= region_sectors())
		return false;
	flash_guard_touch();   // stop the audio DMA before the erase (XIP goes off)
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();   // park core1: it must not fetch from XIP during the erase
	flash_range_erase(abs_offset(sector), RAWFLASH_SECTOR);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	if (flash_settle_us)  // don't slam successive sectors
		delayMicroseconds(flash_settle_us);
	return true;
}

bool rawflash_program(uint8_t device, uint32_t sector, uint32_t off, const void *buf, uint32_t len) {
	if (device != RAWFLASH_DEV_INTERNAL)
		return false;
	if (sector >= region_sectors())
		return false;
	if (off % RAWFLASH_PAGE || len % RAWFLASH_PAGE)  // page-granular
		return false;
	if (off + len > RAWFLASH_SECTOR)
		return false;
	// Compare-before-write: if flash already holds these exact bytes, skip the
	// program. Saves a program cycle (wear) and the core-park/XIP-off stall when a
	// caller rewrites unchanged data. Safe because NOR program is `dst &= src`, a
	// no-op when dst == src. (The encrypted tenants filter no-ops at the plaintext
	// layer too — fresh nonces make ciphertext differ — so this is the universal
	// backstop for opaque/idempotent writes.)
	const uint8_t *cur = xip_uncached(sector, off);   // uncached: coherent with the just-erased NOR
	if (memcmp(cur, buf, len) == 0)  // no-op write: skip (and don't disturb audio)
		return true;
	flash_guard_touch();   // stop the audio DMA before the program (XIP goes off)
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();   // park core1: it must not fetch from XIP during the program
	flash_range_program(abs_offset(sector) + off, (const uint8_t *)buf, len);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	if (flash_settle_us)  // don't slam successive sectors
		delayMicroseconds(flash_settle_us);
	return true;
}
