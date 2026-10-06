//
// abblock.c — the shared A/B-image engine (see abblock.h for the contract).
// bootblock.c and settingsblock.c are its two instances. Portable C, core 0
// only.
//

#include <string.h>
#include <stddef.h>
#include "abblock.h"

// ---- structs ---------------------------------------------------------------
// On-flash frame at byte 0 of a slot: this header, then the payload. The CRC
// covers magic+seq+len+payload, so a torn write fails the check. All fields
// little-endian, which both targets are.
struct ab_frame {
	uint32_t magic;
	uint32_t seq;     // monotonic; the highest valid seq across slots wins
	uint32_t len;     // payload byte count
	uint32_t crc;     // CRC32 of [magic, seq, len, payload]
};

// Everything ahead of the crc field is what the CRC starts over.
#define AB_CRC_HEADER_LEN  ((uint32_t)offsetof(struct ab_frame, crc))

// CRC32 (IEEE 802.3), bitwise so it needs no table, and with running state so a
// flash-resident payload can be fed in chunks.
static uint32_t crc32_update(uint32_t crc, const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++) {
		crc ^= p[i];
		for (int k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1)));
	}
	return crc;
}

static uint32_t max_payload(const struct abblock *ab) {
	return ab->slot_bytes - AB_FRAME_LEN;
}

// Serialise the CRC-covered part of the frame header into a byte buffer.
static void frame_crc_header(const struct ab_frame *f, uint8_t hdr[AB_CRC_HEADER_LEN]) {
	memcpy(hdr,                                   &f->magic, sizeof f->magic);
	memcpy(hdr + sizeof f->magic,                 &f->seq,   sizeof f->seq);
	memcpy(hdr + sizeof f->magic + sizeof f->seq, &f->len,   sizeof f->len);
}

// Structural + CRC check of one slot, streaming the payload from flash in
// small chunks (no image-sized buffer). Fills *out_seq/*out_len if valid.
static bool slot_valid(const struct abblock *ab, int slot,
                       uint32_t *out_seq, uint32_t *out_len) {
	struct ab_frame f;
	if (!ab->read(slot, 0, &f, sizeof f))
		return false;
	if (f.magic != ab->magic)
		return false;
	if (f.len > max_payload(ab))
		return false;

	uint8_t hdr[AB_CRC_HEADER_LEN];
	frame_crc_header(&f, hdr);
	uint32_t crc = crc32_update(0xFFFFFFFFu, hdr, sizeof hdr);

	uint8_t chunk_buf[256];
	uint32_t off = 0;
	while (off < f.len) {
		uint32_t chunk = f.len - off;
		if (chunk > sizeof chunk_buf)
			chunk = sizeof chunk_buf;
		if (!ab->read(slot, AB_FRAME_LEN + off, chunk_buf, chunk))
			return false;
		crc = crc32_update(crc, chunk_buf, chunk);
		off += chunk;
	}
	if ((crc ^ 0xFFFFFFFFu) != f.crc)
		return false;

	*out_seq = f.seq;
	*out_len = f.len;
	return true;
}

// Scan all slots; returns the newest valid slot (highest seq; the lower index
// wins a tie), or -1 if none. *out_seq/*out_len describe the winner (seq 0 /
// len 0 when none). `info`, if non-NULL, receives every slot's verdict.
static int newest_slot(const struct abblock *ab,
                       uint32_t *out_seq, uint32_t *out_len,
                       struct ab_slot_info *info) {
	int best = -1;
	uint32_t best_seq = 0;
	uint32_t best_len = 0;
	for (int s = 0; s < AB_SLOTS; s++) {
		uint32_t seq, len;
		bool ok = slot_valid(ab, s, &seq, &len);
		if (info) {
			info[s].valid = ok;
			if (ok)
				info[s].seq = seq;
			else
				info[s].seq = 0;
		}
		if (!ok)
			continue;
		if (best < 0 || seq > best_seq) {
			best = s;
			best_seq = seq;
			best_len = len;
		}
	}
	*out_seq = best_seq;
	*out_len = best_len;
	return best;
}

int abblock_load(const struct abblock *ab, void *buf, int max,
                 struct ab_slot_info info[AB_SLOTS]) {
	uint32_t seq, len;
	int best = newest_slot(ab, &seq, &len, info);
	if (best < 0)  // blank — no valid image
		return -1;
	if ((int)len > max)  // caller's buffer too small
		return -1;
	if (!ab->read(best, AB_FRAME_LEN, buf, len))
		return -1;
	return (int)len;
}

bool abblock_save(const struct abblock *ab, const void *buf, int len) {
	// One sector of build scratch (core 0, single-threaded for storage — a
	// static buffer keeps it off the stack while interrupts are disabled).
	static uint8_t sector_buf[AB_SECTOR];

	if (len < 0 || (uint32_t)len > max_payload(ab))
		return false;

	// Find the current newest valid slot so we write the OTHER one — never
	// erasing the only valid copy.
	uint32_t newest_seq, newest_len;
	int newest = newest_slot(ab, &newest_seq, &newest_len, NULL);
	int target = 0;
	if (newest >= 0)
		target = newest ^ 1;
	uint32_t seq = newest_seq + 1;

	struct ab_frame f;
	f.magic = ab->magic;
	f.seq   = seq;
	f.len   = (uint32_t)len;
	uint8_t hdr[AB_CRC_HEADER_LEN];
	frame_crc_header(&f, hdr);
	uint32_t crc = crc32_update(0xFFFFFFFFu, hdr, sizeof hdr);
	crc = crc32_update(crc, (const uint8_t *)buf, (size_t)len);
	f.crc = crc ^ 0xFFFFFFFFu;

	if (!ab->erase_slot(target))
		return false;

	// Program [frame | payload] sector by sector. The caller's buf is never
	// handed to the HAL directly — each sector's slice is built in sector_buf
	// and programmed from there. Sectors past the data stay 0xFF from the erase.
	uint32_t total = AB_FRAME_LEN + (uint32_t)len;
	for (uint32_t off = 0; off < total; off += AB_SECTOR) {
		uint32_t used = total - off;
		if (used > AB_SECTOR)
			used = AB_SECTOR;
		memset(sector_buf, 0xFF, sizeof sector_buf);
		for (uint32_t b = 0; b < used; b++) {
			uint32_t pos = off + b;
			if (pos < AB_FRAME_LEN)
				sector_buf[b] = ((const uint8_t *)&f)[pos];
			else
				sector_buf[b] = ((const uint8_t *)buf)[pos - AB_FRAME_LEN];
		}
		uint32_t prog = (used + ab->prog_align - 1) / ab->prog_align * ab->prog_align;
		if (!ab->program(target, off, sector_buf, prog))
			return false;
	}

	// Verify the readback (full CRC re-scan) before declaring success — the new
	// higher seq is what makes `target` authoritative on the next load.
	uint32_t vseq, vlen;
	if (!slot_valid(ab, target, &vseq, &vlen))
		return false;
	return vseq == seq && vlen == (uint32_t)len;
}

bool abblock_erase_all(const struct abblock *ab) {
	bool ok = true;
	for (int s = 0; s < AB_SLOTS; s++)
		ok = ab->erase_slot(s) && ok;
	return ok;
}
