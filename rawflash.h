#pragma once
//
// rawflash.h — the general raw-flash HAL the message store (logbook.c) and,
// later, the bootblock run on. A flat array of fixed-size erase sectors,
// addressed by absolute sector index. This is the one platform seam for the
// custom storage layer (STORAGE_SECURITY.md §III.11): the complex logic is
// portable C above it; only this is per-platform.
//
//   - device : flash_range_erase/program on a carved region (later).
//   - host   : a file (secserver/rawflash_posix.c), so the whole store —
//              including GC crash-safety — is testable on Linux under
//              gdb/valgrind/ASan.
//
// NOR-flash semantics, modelled faithfully so device-only bugs surface on host:
//   * erase sets a whole sector to all-0xFF.
//   * program can only flip bits 1->0 (it never sets a 0 bit back to 1 without
//     an erase); the host backend enforces this with `dst &= src`.
//   * program is PAGE-granular: offset and length must be multiples of
//     RAWFLASH_PAGE (matches the Pico SDK's flash_range_program). Reads are
//     byte-granular (XIP is memory-mapped).
//

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RAWFLASH_SECTOR 4096u   // erase unit
#define RAWFLASH_PAGE    256u   // program unit

// Storage device id. Today only the internal flash exists; the parameter is
// threaded through so an external store (e.g. an SD card) can be added later
// without touching the callers — they pass a device, the backend dispatches.
#define RAWFLASH_DEV_INTERNAL 0
#define RAWFLASH_DEV_SD       1   // reserved (not implemented)

// Prepare the backing store(s) (idempotent). Returns true once ready.
bool rawflash_init(void);

// Geometry (the internal flash's erase/program units; constant for now).
uint32_t rawflash_sector_size(void);   // RAWFLASH_SECTOR
uint32_t rawflash_page_size(void);     // RAWFLASH_PAGE
uint32_t rawflash_sector_count(uint8_t device);  // total sectors on `device`

// Sector indices are 32-bit: a large external device can hold far more than the
// 65 k sectors a 16-bit index would cap at (16-bit * 4 KB = 256 MB).

// Read `len` bytes from byte offset `off` within `sector` of `device`.
bool rawflash_read(uint8_t device, uint32_t sector, uint32_t off, void *buf, uint32_t len);

// Erase a whole sector of `device` to 0xFF.
bool rawflash_erase(uint8_t device, uint32_t sector);

// Program `len` bytes at `off` within `sector` of `device`. `off` and `len` MUST
// be multiples of RAWFLASH_PAGE, and the target must be erased (0xFF) where bits
// are set — only 1->0 transitions are honoured. Returns false on a constraint
// violation or a simulated torn write.
bool rawflash_program(uint8_t device, uint32_t sector, uint32_t off, const void *buf, uint32_t len);

#ifdef __cplusplus
}
#endif
