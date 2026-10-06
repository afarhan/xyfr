#pragma once
#include <stdint.h>
#include <stddef.h>

// Firmware OTA staging region (THREAT_MODEL 9.1 secure-update, flash carve "A").
//
// The 4 MB flash is [code region | encrypted store]. The store base is the linker
// symbol `_FS_start` — NOT a round number: on this build it is flash offset
// 0x1FE000 (the core reserves a couple of sectors at the top of the code region),
// NOT 0x200000. STAGING is the free tail of the code region — above the live
// sketch, and a guard band BELOW `_FS_start`:
//
//   0x000000 [ sketch ] 0x100000 [ STAGING ......... ] guard | _FS_start [ store ]
//
// HARD RULE (a bug here erased the keystore once — 2026-07-22): the staging bounds
// are DERIVED from `&_FS_start` at runtime via ota_stage_capacity(); nothing here
// hardcodes the store base. Every staging op is clamped to that capacity, and it
// returns 0 (=> the op refuses) if the layout is ever unsafe.
#define OTA_STAGING_OFFSET  0x100000u   // 1 MB — fixed base; MUST stay above the sketch
#define OTA_STAGING_GUARD   0x1000u     // one erased-sector guard band kept below _FS_start

#ifdef __cplusplus
extern "C" {
#endif

// Usable staging bytes: from OTA_STAGING_OFFSET up to OTA_STAGING_GUARD below the
// store (`_FS_start`), computed from the ACTUAL linker symbol. Sector-aligned.
// Returns 0 (unsafe — callers must refuse to write) if the sketch has grown into
// the staging base, or there is no room below the store.
uint32_t ota_stage_capacity(void);

// Erase the whole staging region (NOR -> 0xFF), one 4 KB sector at a time, each
// under the audio-quiesce + core-park + IRQ-off guard. No-op if capacity is 0.
void ota_stage_erase(void);

// Program `len` bytes at `off` within staging (page-granular). false on a range/
// alignment error OR if off+len exceeds ota_stage_capacity(). Same core guard.
bool ota_stage_program(uint32_t off, const void *buf, uint32_t len);

// Read `len` bytes at `off` from staging through the NON-CACHED XIP alias. false on
// a range error (off+len > ota_stage_capacity()).
bool ota_stage_read(uint32_t off, void *buf, uint32_t len);

// BLAKE2s-256 over the first `len` staged bytes (clamped to capacity). Fills out[32].
void ota_stage_hash(uint32_t len, uint8_t out[32]);

// Developer-Mode self-test (`otatest` serial cmd): erase, program a known pattern,
// hash it, read it back and verify — proves the staging flash mechanics with NO
// network and NO apply (writes only the guarded staging region). true on pass.
bool ota_selftest(void);

// ---- apply (increment 3): staged-image descriptor + the reboot-copier ----------
// After a VERIFIED upload the receiver writes a descriptor (magic + length + hash)
// to the LAST sector of the staging region (the image is capped one sector below
// capacity to leave room). To apply, firmware mode sets a warm-reboot scratch flag
// (OTA_APPLY_MAGIC on OTA_APPLY_SCRATCH_REG) and reboots; ota_apply_run() — the
// FIRST thing in setup() — consumes it, RE-VERIFIES the staged hash, then a
// RAM-resident copier writes staged->live code and resets. BOOTSEL stays on, so a
// botched copy is recoverable by dragging a .uf2.
#define OTA_APPLY_SCRATCH_REG  2u
#define OTA_APPLY_MAGIC        0x4F544150u   // "OTAP"
#define OTA_DESC_MAGIC         0x4F544144u   // "OTAD"

struct ota_desc {
	uint32_t magic;        // OTA_DESC_MAGIC
	uint32_t image_len;    // firmware image byte length
	uint8_t  hash[32];     // BLAKE2s-256 of the image
};

// Max firmware image the receiver accepts = staging capacity minus the reserved
// descriptor sector.
uint32_t ota_image_cap(void);

// Write the staged-image descriptor (called after a verified upload). false on error.
bool ota_stage_finalize(uint32_t image_len, const uint8_t hash[32]);

// Read + validate the descriptor. false if absent/corrupt.
bool ota_read_desc(struct ota_desc *out);

// FIRST thing in setup(): if an apply is pending (scratch flag set), re-verify the
// staged image and copy it over the live firmware, then reset (DOES NOT RETURN). A
// no-op (returns) if no apply is pending or the staged image fails re-verification.
void ota_apply_run(void);

#ifdef __cplusplus
}
#endif
