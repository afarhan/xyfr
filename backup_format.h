#pragma once
//
// backup_format.h — the format of an Xyfr device backup file, shared by the
// firmware (webbackup.cpp) and the host CLI tool (secserver/backup_tool.c).
//
// File = base64 of: [bk_header] followed by `sector_count` sector records. Each
// record is the per-sector OUTER AEAD:
//     xchacha20poly1305(key  = BK_OUTER_KEY,
//                       nonce = salt(20) || sector_index_be32(4),
//                       aad   = bk_header || sector_index_be32(4),
//                       plain = the raw 4096-byte FS sector)            -> 4112 bytes
//
// The OUTER layer is INTEGRITY ONLY: BK_OUTER_KEY is a FIXED, NON-SECRET key
// compiled into both the firmware and this open tool, so a backup restores on
// ANY Xyfr device (device migration / upgrade). CONFIDENTIALITY comes entirely
// from the INNER at-rest encryption — every block is already encrypted under the
// volume_key, which is wrapped by the disk passphrase. So a backup is only as
// private as the disk key; with the default key its contents are readable.
// Machine-config metadata (sector count, block offsets) is intentionally NOT
// hidden — it carries no user data.
//
#include <stdint.h>

#define BK_MAGIC          "XYFRBK01"
#define BK_FORMAT_VERSION 1

// BUMP when the storage LAYOUT changes — i.e. any of BOOTBLOCK_SECTORS,
// STORE_SB_BASE_SECTOR, STORE_SB_SLOT_SECTORS, SB_SLOTS, CONTACTSBLOCK_BASE_SECTOR,
// CONTACTSBLOCK_SECTORS, STORE_LOG_BASE_SECTOR (see store.h). Restore refuses a
// backup whose layout_version != the running firmware's, rather than brick on a
// mismatched on-flash layout. Raw-image migration only works across firmwares
// that keep the fixed-position blocks at the same offsets (only the logbook tail
// may grow).
#define BK_LAYOUT_VERSION 1

// Fixed, NON-SECRET outer integrity key (see the header comment). It provides no
// confidentiality — do not treat it as a secret.
static const uint8_t BK_OUTER_KEY[32] __attribute__((unused)) = {
	0xa9,0x80,0x65,0xde,0x8c,0x4e,0x27,0x4b,0x08,0xe7,0xb4,0xa6,0xde,0x68,0xfd,0x32,
	0x40,0x27,0x12,0xd7,0x27,0x72,0x22,0x7d,0xd5,0xd7,0x3b,0x48,0x31,0x62,0x21,0xef,
};

#pragma pack(push, 1)
typedef struct {
	char     magic[8];        // BK_MAGIC
	uint16_t format_version;  // BK_FORMAT_VERSION
	uint16_t layout_version;  // BK_LAYOUT_VERSION at backup time
	uint8_t  device_hash[8];  // source device id (informational only; NOT a restore gate)
	uint16_t sector_count;    // number of sector records that follow
	uint8_t  salt[20];        // nonce base: nonce[i] = salt(20) || sector_index_be32(4)
} bk_header;                  // 42 bytes
#pragma pack(pop)

#define BK_SECTOR_BYTES 4096u
#define BK_TAG_BYTES    16u
#define BK_RECORD_BYTES (BK_SECTOR_BYTES + BK_TAG_BYTES)   // 4112
