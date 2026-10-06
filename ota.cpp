// ota.cpp — firmware OTA staging flash primitives (device, core 0).
//
// Writes to the STAGING region (ota.h) live BELOW the store, so they can't use the
// rawflash HAL (which is offset from _FS_start). They go straight to the pico SDK
// flash_range_* at absolute flash offsets, mirroring rawflash_arduino.cpp's guard
// exactly: quiesce audio DMA (flash_guard_touch), disable IRQs, park core1 (it must
// not fetch from XIP while XIP is off during erase/program), then restore. Read-back
// is through the NON-CACHED XIP alias so it reflects physical NOR.
//
// SAFETY (2026-07-22): a previous version hardcoded the staging END at 0x200000 while
// the store actually begins at _FS_start = 0x1FE000, so a full-region erase wiped the
// keystore bootblock. NOW the upper bound is DERIVED from &_FS_start with a guard
// band (ota_stage_capacity), and every op clamps to it. There is no hardcoded store
// base anywhere in this file.
//
// This module only STAGES + verifies. The apply-on-reboot copier is a separate step.

#include <Arduino.h>
#include <hardware/flash.h>       // flash_range_erase/program, FLASH_SECTOR_SIZE/PAGE_SIZE
#include <hardware/sync.h>        // save_and_disable_interrupts / restore_interrupts
#include <hardware/watchdog.h>    // watchdog_hw + WATCHDOG_CTRL_TRIGGER_BITS (apply reset + flag)
#include <hardware/address_mapped.h> // hw_set_bits (atomic register set — RAM-safe reset)
#include "ota.h"
#include "wg.h"                   // blake2s (crypto.c) — the device has no SHA-256
#include "debug.h"

// Defined in rawflash_arduino.cpp: pause the audio DMA before a flash op (XIP off).
extern void flash_guard_touch(void);
// The store base — the SAME linker symbol rawflash/bootflash use. Staging must stop
// (with a guard band) BELOW this.
extern uint8_t _FS_start;

uint32_t ota_stage_capacity(void) {
	uint32_t store_off = (uint32_t)&_FS_start - XIP_BASE;   // store base as a flash offset
	// No room below the store, or the offset is impossibly low -> refuse.
	if (store_off <= OTA_STAGING_OFFSET + OTA_STAGING_GUARD)
		return 0;
	uint32_t end = store_off - OTA_STAGING_GUARD;           // leave one erased sector clear of the store
	end &= ~(FLASH_SECTOR_SIZE - 1);                        // sector-align the end (erase is per-sector)
	if (end <= OTA_STAGING_OFFSET)
		return 0;
	return end - OTA_STAGING_OFFSET;
}

static inline const uint8_t *stage_uncached(uint32_t off) {
	return (const uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + OTA_STAGING_OFFSET + off);
}

void ota_stage_erase(void) {
	uint32_t cap = ota_stage_capacity();
	if (cap == 0) {
		Debug.println("ota: staging capacity 0 (unsafe layout) — refusing to erase");
		return;
	}
	for (uint32_t o = 0; o < cap; o += FLASH_SECTOR_SIZE) {
		flash_guard_touch();
		uint32_t ints = save_and_disable_interrupts();
		rp2040.idleOtherCore();
		flash_range_erase(OTA_STAGING_OFFSET + o, FLASH_SECTOR_SIZE);
		rp2040.resumeOtherCore();
		restore_interrupts(ints);
	}
}

bool ota_stage_program(uint32_t off, const void *buf, uint32_t len) {
	if (off + len > ota_image_cap())  // reserves the top descriptor sector
		return false;
	if (off % FLASH_PAGE_SIZE || len % FLASH_PAGE_SIZE)  // page-granular
		return false;
	flash_guard_touch();
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();
	flash_range_program(OTA_STAGING_OFFSET + off, (const uint8_t *)buf, len);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	return true;
}

bool ota_stage_read(uint32_t off, void *buf, uint32_t len) {
	if (off + len > ota_stage_capacity())
		return false;
	memcpy(buf, stage_uncached(off), len);
	return true;
}

void ota_stage_hash(uint32_t len, uint8_t out[32]) {
	uint32_t cap = ota_stage_capacity();
	if (len > cap)
		len = cap;
	blake2s_ctx ctx;
	blake2s_init(&ctx, 32, NULL, 0);
	uint32_t done = 0;
	while (done < len) {
		uint32_t n = len - done;
		if (n > 4096)
			n = 4096;
		blake2s_update(&ctx, stage_uncached(done), n);   // uncached: physical NOR
		done += n;
	}
	blake2s_final(&ctx, out);
}

bool ota_selftest(void) {
	uint32_t cap = ota_stage_capacity();
	Debug.printf("otatest: staging base=0x%06x capacity=%u bytes (ends 0x%06x, store _FS_start below)\n",
	             (unsigned)OTA_STAGING_OFFSET, (unsigned)cap, (unsigned)(OTA_STAGING_OFFSET + cap));
	if (cap < 512) {
		Debug.println("otatest: FAIL — staging capacity too small / unsafe");
		return false;
	}

	const uint32_t N = 512;
	static uint8_t pat[N];
	for (uint32_t i = 0; i < N; i++)
		pat[i] = (uint8_t)((i * 7 + 0x5A) & 0xFF);

	Debug.println("otatest: erasing staging...");
	ota_stage_erase();

	static uint8_t rb[N];
	ota_stage_read(0, rb, N);
	for (uint32_t i = 0; i < N; i++) {
		if (rb[i] != 0xFF) {
			Debug.printf("otatest: FAIL — post-erase byte %u = %02x (expected ff)\n",
			             (unsigned)i, rb[i]);
			return false;
		}
	}

	Debug.println("otatest: programming pattern...");
	if (!ota_stage_program(0, pat, N)) {
		Debug.println("otatest: FAIL — program returned false");
		return false;
	}

	memset(rb, 0, N);
	ota_stage_read(0, rb, N);
	if (memcmp(rb, pat, N) != 0) {
		Debug.println("otatest: FAIL — read-back mismatch");
		return false;
	}

	uint8_t h[32];
	ota_stage_hash(N, h);
	char hex[65];
	for (int i = 0; i < 32; i++)
		snprintf(hex + i * 2, 3, "%02x", h[i]);
	Debug.printf("otatest: PASS — %u bytes staged, blake2s=%s\n", (unsigned)N, hex);
	return true;
}

// ---- apply: descriptor + RAM-resident reboot-copier ------------------------

uint32_t ota_image_cap(void) {
	uint32_t cap = ota_stage_capacity();
	if (cap < FLASH_SECTOR_SIZE)
		return 0;
	return cap - FLASH_SECTOR_SIZE;          // reserve the top sector for the descriptor
}

// Descriptor flash offset = the reserved sector just above the image region.
static inline uint32_t ota_desc_offset(void) {
	return OTA_STAGING_OFFSET + ota_image_cap();
}

bool ota_stage_finalize(uint32_t image_len, const uint8_t hash[32]) {
	if (image_len == 0 || image_len > ota_image_cap())
		return false;
	struct ota_desc d;
	memset(&d, 0, sizeof d);
	d.magic     = OTA_DESC_MAGIC;
	d.image_len = image_len;
	memcpy(d.hash, hash, 32);
	static uint8_t pg[FLASH_PAGE_SIZE];
	memset(pg, 0xFF, sizeof pg);
	memcpy(pg, &d, sizeof d);
	uint32_t doff = ota_desc_offset();
	flash_guard_touch();
	uint32_t ints = save_and_disable_interrupts();
	rp2040.idleOtherCore();
	flash_range_erase(doff, FLASH_SECTOR_SIZE);
	flash_range_program(doff, pg, FLASH_PAGE_SIZE);
	rp2040.resumeOtherCore();
	restore_interrupts(ints);
	return true;
}

bool ota_read_desc(struct ota_desc *out) {
	const uint8_t *src = (const uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + ota_desc_offset());
	struct ota_desc d;
	for (size_t i = 0; i < sizeof d; i++)
		((uint8_t *)&d)[i] = src[i];
	if (d.magic != OTA_DESC_MAGIC)
		return false;
	if (d.image_len == 0 || d.image_len > ota_image_cap())
		return false;
	if (out)
		*out = d;
	return true;
}

// RAM-resident: copy the staged image over the LIVE code region, then reset. Runs
// entirely from RAM (__not_in_flash_func) so erasing the code we came from can't
// fault; reads staging via the no-cache alias BETWEEN flash ops (XIP is on then).
// After the first erase it must touch NOTHING in flash — hence the volatile byte
// copy (no memcpy call) and the register-write reset. DOES NOT RETURN.
// SAFE on RP2350: flash_range_* re-enable XIP from a RAM/BOOTRAM boot2 copy (cached,
// idempotent), so erasing flash sector 0 never breaks XIP.
static uint8_t s_apply_buf[FLASH_SECTOR_SIZE] __attribute__((aligned(256)));

static void __no_inline_not_in_flash_func(ota_apply_copy)(uint32_t len) {
	uint32_t nsect = (len + FLASH_SECTOR_SIZE - 1) / FLASH_SECTOR_SIZE;
	(void)save_and_disable_interrupts();                 // never re-enabled; we reset below
	// Disable the watchdog: the copy is ~10 s with IRQs off, and the warm-reboot
	// path may have left it armed — it would reset mid-copy (brick). We do our own
	// TRIGGER reset when done.
	hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
	for (uint32_t s = 0; s < nsect; s++) {
		uint32_t off = s * FLASH_SECTOR_SIZE;
		const volatile uint8_t *src =
			(const volatile uint8_t *)(XIP_NOCACHE_NOALLOC_BASE + OTA_STAGING_OFFSET + off);
		volatile uint8_t *dst = s_apply_buf;
		for (uint32_t i = 0; i < FLASH_SECTOR_SIZE; i++)  // volatile: no memcpy
			dst[i] = src[i];
		flash_range_erase(off, FLASH_SECTOR_SIZE);        // LIVE code sector (flash offset off)
		flash_range_program(off, s_apply_buf, FLASH_SECTOR_SIZE);
	}
	// Reliable RAM-safe reset via ARM SYSRESETREQ (no watchdog-tick dependency, and
	// works with the watchdog disabled above). The reset re-runs the boot ROM, which
	// boots the freshly-written image.
	__asm volatile("dsb");
	*(volatile uint32_t *)0xE000ED0Cu = 0x05FA0004u;   // SCB->AIRCR = VECTKEY | SYSRESETREQ
	__asm volatile("dsb");
	while (1) {
		__asm volatile("nop");
	}
}

void ota_apply_run(void) {
	if (watchdog_hw->scratch[OTA_APPLY_SCRATCH_REG] != OTA_APPLY_MAGIC)
		return;
	watchdog_hw->scratch[OTA_APPLY_SCRATCH_REG] = 0;     // one-shot: clear BEFORE the copy
	struct ota_desc d;
	if (!ota_read_desc(&d)) {
		Debug.println("ota-apply: no valid staged image — booting normally");
		return;
	}
	uint8_t h[32];
	ota_stage_hash(d.image_len, h);                      // re-hash the staged image
	if (memcmp(h, d.hash, 32) != 0) {
		Debug.println("ota-apply: staged image FAILED re-verify — NOT applying");
		return;
	}
	Debug.printf("ota-apply: applying %u bytes staged->live; DO NOT power off...\n",
	             (unsigned)d.image_len);
	delay(60);                                            // let the serial line flush (still in flash)
	ota_apply_copy(d.image_len);                         // RAM-resident; does not return (resets)
}
