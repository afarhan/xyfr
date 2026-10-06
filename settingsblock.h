#pragma once
//
// settingsblock.h — A/B-redundant persistence of ONE opaque image over the
// rawflash HAL, scaled to MULTIPLE sectors per slot. It is bootblock's exact
// discipline (magic+seq+CRC frame, write-the-inactive-slot-verify-then-win,
// never erase the only valid copy → power-loss-atomic) but for an image too big
// for a single 4 KB sector — the settings + contact table (STORAGE_SECURITY.md
// §III, the "fixed block"). bootblock stays single-sector for the keystore EDEK;
// this is its larger sibling for mutable bulk state.
//
// The image is opaque bytes: callers (store.c) handle encryption. Two slots of
// `slot_sectors` sectors each occupy a contiguous 2*slot_sectors-sector region
// of `device`, starting at `base_sector`. Core 0 only; portable C.
//

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SB_SLOTS       2     // A/B redundancy

// TEMP boot diagnostic (`sdiag` serial cmd): the last settingsblock_load() slot
// scan — which A/B slots were CRC-valid, their seq, and the winner. Sized 4 for
// headroom though SB_SLOTS is 2. For the settings-persistence investigation.
struct sb_diag {
	int      nslots;
	int      slot_valid[4];
	unsigned slot_seq[4];
	int      winner;          // winning slot index, -1 = none valid
	unsigned winner_seq;
};
extern struct sb_diag g_sb_diag;
#define FB_FRAME_LEN   16    // magic+seq+len+crc

// Configure the region: two slots of `slot_sectors` each on `device`, the first
// starting at `base_sector`. Idempotent; returns false on a bad geometry.
bool settingsblock_init(uint8_t device, uint32_t base_sector, uint32_t slot_sectors);

// Usable payload bytes per slot with the current config (0 before init).
uint32_t settingsblock_max_payload(void);

// Load the newest valid image into buf (up to `max` bytes). Returns the payload
// byte count, or -1 if no valid image exists (blank region).
int settingsblock_load(void *buf, int max);

// Persist `len` payload bytes atomically: write+verify the inactive slot before
// its higher seq makes it authoritative. Returns true on success. As with
// bootblock, a single save leaves the prior image in the other slot — call
// twice to scrub a secret from both slots, or settingsblock_erase_all() to wipe.
bool settingsblock_save(const void *buf, int len);

// Erase every slot to 0xFF — destroys all stored images (crypto-erase / wipe).
bool settingsblock_erase_all(void);

#ifdef __cplusplus
}
#endif
