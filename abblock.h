#pragma once
//
// abblock.h — the shared A/B-image engine: power-loss-atomic persistence of ONE
// opaque image in two redundant slots. This is the discipline bootblock.c and
// settingsblock.c each used to implement separately (STORAGE_SECURITY.md §II.2):
//
//   - the image is framed magic + monotonic seq + len + CRC32;
//   - a save writes the INACTIVE slot, verifies the readback, and only then
//     does its higher seq make it authoritative on the next load;
//   - the previous slot is never erased until a newer copy is proven good, so
//     a power loss mid-write reverts cleanly to the prior image.
//
// The engine is geometry- and HAL-agnostic: an instance is a `struct abblock`
// naming its magic, its slot capacity, and three slot-relative byte-addressed
// callbacks. bootblock.c (1 sector/slot over bootflash_*) and settingsblock.c
// (N sectors/slot over rawflash_*) are the two instances. The on-flash format
// is unchanged from the two separate implementations — per-instance magic, same
// 16-byte frame, same CRC — so existing images load as-is.
//
// Portable C, core 0 only.
//

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AB_SLOTS      2      // A/B redundancy
#define AB_FRAME_LEN  16     // magic + seq + len + crc
#define AB_SECTOR     4096   // erase-sector size both HALs share

// Per-slot scan result reported by abblock_load (for diagnostics — sdiag).
struct ab_slot_info {
	bool     valid;   // frame structurally sound + CRC matched
	uint32_t seq;     // its seq if valid, else 0
};

// One A/B instance. `read`/`program` address bytes WITHIN a slot (the instance
// owns the mapping to real sectors). The engine calls `program` with `off`
// sector-aligned and `len` <= AB_SECTOR, rounded up to `prog_align` (pass 1 if
// the backend pads to a full sector itself). `erase_slot` erases the whole
// slot to 0xFF.
struct abblock {
	uint32_t magic;
	uint32_t slot_bytes;   // capacity of one slot (a multiple of AB_SECTOR)
	uint32_t prog_align;   // program-length granularity (e.g. RAWFLASH_PAGE), or 1
	bool (*read)(int slot, uint32_t off, void *buf, uint32_t len);
	bool (*erase_slot)(int slot);
	bool (*program)(int slot, uint32_t off, const void *buf, uint32_t len);
};

// Load the newest valid image into buf (up to `max` bytes). Returns the payload
// byte count, or -1 if no valid image exists (blank region) or buf is too
// small. If `info` is non-NULL it receives the per-slot scan verdicts (always
// filled, even on -1).
int abblock_load(const struct abblock *ab, void *buf, int max,
                 struct ab_slot_info info[AB_SLOTS]);

// Persist `len` payload bytes atomically: write+verify the inactive slot before
// its higher seq makes it authoritative. Returns true on success.
//
// NOTE on secure-erase: a single save leaves the PRIOR image in the other slot.
// To scrub a secret from both slots save twice; for a destructive wipe use
// abblock_erase_all.
bool abblock_save(const struct abblock *ab, const void *buf, int len);

// Erase every slot to 0xFF — destroys all stored images (crypto-erase / wipe).
// Attempts every slot even after a failure; returns true only if all erased.
bool abblock_erase_all(const struct abblock *ab);

#ifdef __cplusplus
}
#endif
