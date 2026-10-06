#pragma once
//
// bootblock.h — the raw-flash secure keystore's storage layer (see
// STORAGE_SECURITY.md §II.2). Two parts:
//
//   1. bootflash_* — a tiny raw-sector storage HAL. A small fixed set of
//      dedicated erasable sectors that support a deterministic in-place erase
//      (erase a sector to all-0xFF, then program in place). Device backend
//      (bootflash_arduino.cpp) uses flash_range_erase/program on dedicated
//      sectors; host backend (secserver/bootflash_posix.c) uses a file under
//      ./fsroot. This is the one surface a port reimplements.
//
//   2. bootblock_load / bootblock_save — A/B-redundant persistence of ONE opaque image. The
//      image is framed with a magic + monotonic seq + CRC and written to the
//      *inactive* of two slots, verified, and only then becomes authoritative
//      (its higher seq wins on the next load). The previous slot is never
//      erased until a newer copy is proven good, so a power loss mid-write
//      reverts cleanly to the prior image. This is the power-loss-atomicity
//      lesson from the lost-key incident (a truncating in-place write left a
//      0-byte block).
//
// The key schedule on top of this lives in keystore.c. Core 0 only.

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- raw-sector storage HAL ----
#define ZB_SECTOR_SIZE 4096   // one flash erase sector
#define ZB_NUM_SLOTS   2      // A/B redundancy

// Sectors the bootblock reserves at the very start of the internal-flash storage
// region. The message log (logbook) must begin at or after this so it can never
// overwrite the keystore — logbook_init checks against it. Bump if the bootblock
// grows (e.g. when the contact-key slab scales toward 500).
#define BOOTBLOCK_SECTORS ZB_NUM_SLOTS

// Prepare the backing store (idempotent). Returns true once ready.
bool bootflash_init(void);
// The usable bytes per slot.
int  bootflash_sector_size(void);
// Read `len` bytes from byte offset `off` of slot's sector into buf.
bool bootflash_read(int slot, uint32_t off, void *buf, int len);
// Erase slot's sector (to all-0xFF).
bool bootflash_erase(int slot);
// Program `len` bytes at offset 0 of slot's sector. The sector must be erased
// first. Returns false on failure (incl. a simulated torn write on host).
bool bootflash_program(int slot, const void *buf, int len);

// ---- A/B persistence of one opaque image ----
// Maximum image payload bootblock_save accepts (sector minus the frame header).
#define ZB_MAX_PAYLOAD (ZB_SECTOR_SIZE - 16)

bool bootblock_init(void);
// Load the newest valid image into buf (up to `len` bytes). Returns the payload
// byte count on success, or -1 if no valid image exists (blank device).
int  bootblock_load(void *buf, int len);
// Persist `len` payload bytes atomically (write+verify the inactive slot before
// it becomes authoritative). Returns true on success.
//
// NOTE on secure-erase: because bootblock_save writes only the inactive slot, the
// PREVIOUS image survives in the other slot until a later save overwrites it.
// So a single bootblock_save does NOT scrub old secrets. For a sensitive transition
// (e.g. erasing the plaintext volume key when enabling a passphrase) call
// bootblock_save twice so both slots are overwritten; for a destructive wipe use
// bootblock_erase_all().
bool bootblock_save(const void *buf, int len);

// Erase every slot (to all-0xFF) — destroys all stored images, including the
// stale copy in the inactive slot. Used for crypto-erase / duress wipe.
bool bootblock_erase_all(void);

#ifdef __cplusplus
}
#endif
