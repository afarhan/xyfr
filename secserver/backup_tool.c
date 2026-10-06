// backup_tool — host-side inspector/decryptor for an Xyfr device backup file.
//
//   ./backup_tool <backup.txt> [--key <disk-passphrase>] [--image out.img] [--json]
//
// Always: decode the base64, peel the per-sector OUTER AEAD with the fixed
// BK_OUTER_KEY (the real crypto.c), authenticate every sector, and reconstruct
// the raw flash image in memory (proves the backup is genuine + intact).
//   --image  also writes that raw image to a file.
//   --json   mounts the reconstructed image with the REAL portable storage stack
//            (keystore -> volume_key -> store / filesystem) using the disk
//            passphrase, and dumps settings + contacts + messages as JSON.
//
// The disk passphrase defaults to the known placeholder (STORE_DEFAULT_PASSPHRASE)
// used until the on-device passphrase UI exists.
//
// Build: make backup_tool   (see secserver/Makefile)
//
// TODO(task12): remove — read into a fixed buffer; the MSG path should stream chunk-by-chunk.
#define MSG_CALLER_RDBUF 1024
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>

#include "wg.h"              // xchacha20poly1305_decrypt, get_part_key (decl), AUTHTAG_LEN
#include "hal.h"             // now_ms / hal_debug / hal_rand signatures (we define them below)
#include "rawflash.h"        // the HAL we implement over the in-memory image
#include "bootblock.h"       // bootflash HAL we implement; ZB_*, BOOTBLOCK_SECTORS
#include "device_record.h"      // struct device_record, MAX_*
#include "contacts.h"          // struct contact_record, MAX_NAME, CONTACT_*
#include "secure_store.h"           // store_init, block_read, STORE_*/CONTACTSBLOCK_*/STORE_LOG_BASE_SECTOR
#include "keystore.h"        // ks_init, ks_state_get, ks_unlock_passphrase, ks_get_volume_key
#include "filesystem.h"      // one contact is one file; its thread is that file's log
#include "msg.h"             // the status bits; enum entry_kind is filesystem.h's
#include "backup_format.h"   // bk_header, BK_OUTER_KEY, BK_* (shared with firmware)

#ifndef STORE_DEFAULT_PASSPHRASE
#define STORE_DEFAULT_PASSPHRASE "scramler-default-0000"
#endif


// ---- in-memory flash backend (over the reconstructed image) -----------------

static uint8_t  *g_img = NULL;     // the 2 MB raw flash image
static uint32_t  g_sectors = 0;

bool     rawflash_init(void){ return g_img != NULL; }
uint32_t rawflash_sector_size(void){ return RAWFLASH_SECTOR; }
uint32_t rawflash_page_size(void){ return RAWFLASH_PAGE; }
uint32_t rawflash_sector_count(uint8_t dev){ (void)dev; return g_sectors; }
bool rawflash_read(uint8_t dev, uint32_t s, uint32_t off, void *buf, uint32_t len){
	(void)dev;
	if ((uint64_t)s * RAWFLASH_SECTOR + off + len > (uint64_t)g_sectors * RAWFLASH_SECTOR) return false;
	memcpy(buf, g_img + (size_t)s * RAWFLASH_SECTOR + off, len);
	return true;
}
bool rawflash_erase(uint8_t dev, uint32_t s){
	(void)dev; if (s >= g_sectors) return false;
	memset(g_img + (size_t)s * RAWFLASH_SECTOR, 0xFF, RAWFLASH_SECTOR); return true;
}
bool rawflash_program(uint8_t dev, uint32_t s, uint32_t off, const void *buf, uint32_t len){
	(void)dev; if (s >= g_sectors) return false;
	uint8_t *d = g_img + (size_t)s * RAWFLASH_SECTOR + off; const uint8_t *src = buf;
	for (uint32_t i = 0; i < len; i++) d[i] &= src[i];   // NOR 1->0
	return true;
}

bool bootflash_init(void){ return g_img != NULL; }
int  bootflash_sector_size(void){ return ZB_SECTOR_SIZE; }
bool bootflash_read(int slot, uint32_t off, void *buf, int len){
	if (slot < 0 || slot >= ZB_NUM_SLOTS || len < 0 ||
	    off > (uint32_t)ZB_SECTOR_SIZE || (uint32_t)len > ZB_SECTOR_SIZE - off) return false;
	memcpy(buf, g_img + (size_t)slot * ZB_SECTOR_SIZE + off, len); return true;
}
bool bootflash_erase(int slot){
	if (slot < 0 || slot >= ZB_NUM_SLOTS) return false;
	memset(g_img + (size_t)slot * ZB_SECTOR_SIZE, 0xFF, ZB_SECTOR_SIZE); return true;
}
bool bootflash_program(int slot, const void *buf, int len){
	if (slot < 0 || slot >= ZB_NUM_SLOTS || len < 0 || len > ZB_SECTOR_SIZE) return false;
	uint8_t *d = g_img + (size_t)slot * ZB_SECTOR_SIZE; const uint8_t *s = buf;
	for (int i = 0; i < len; i++) d[i] &= s[i]; return true;
}

// ---- platform stubs the storage stack links against -------------------------

uint32_t now_ms(void){ return 0; }
uint32_t hal_rand(void){ return 0; }   // read path never needs randomness
void hal_debug(int level, const char *fmt, ...){
	(void)level; va_list a; va_start(a, fmt); vfprintf(stderr, fmt, a); va_end(a);
}
uint32_t get_part_key(const uint8_t *k){
	return ((uint32_t)k[0] << 24) | ((uint32_t)k[1] << 16) | ((uint32_t)k[2] << 8) | k[3];
}
// store.c references these (write path / public-key derivation); only the read
// path runs here, but they must resolve at link. basepoint = Curve25519 base.
const unsigned char basepoint[32] = { 9 };
void fill_random(uint8_t *buff, int length){ for (int i = 0; i < length; i++) buff[i] = (uint8_t)hal_rand(); }

// ---- base64 decode ----------------------------------------------------------

static int b64val(int c){
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}
static long b64decode(const unsigned char *src, long n, unsigned char *out){
	long o = 0; int acc = 0, bits = 0;
	for (long i = 0; i < n; i++){
		int v = b64val(src[i]);
		if (v < 0) continue;
		acc = (acc << 6) | v; bits += 6;
		if (bits >= 8){ bits -= 8; out[o++] = (unsigned char)(acc >> bits); }
	}
	return o;
}

// ---- JSON helpers -----------------------------------------------------------

static void json_str(FILE *o, const char *s, int n){
	fputc('"', o);
	for (int i = 0; (n < 0) ? (s[i] != '\0') : (i < n); i++){
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\') { fputc('\\', o); fputc(c, o); }
		else if (c == '\n') fputs("\\n", o);
		else if (c == '\r') fputs("\\r", o);
		else if (c == '\t') fputs("\\t", o);
		else if (c < 0x20)  fprintf(o, "\\u%04x", c);
		else fputc(c, o);
	}
	fputc('"', o);
}
static int key_present(const uint8_t *k, int n){ for (int i = 0; i < n; i++) if (k[i]) return 1; return 0; }
static const char *status_str(uint8_t st){
	return st == CONTACT_KEY_VALID ? "VALID" : st == CONTACT_KEY_FAILED ? "FAILED" : "PENDING";
}
// filesystem.c stamps every entry it creates, so it needs a clock even though
// this tool only ever reads. Nothing here creates an entry.
time_t get_current_time_seconds(void) { return time(NULL); }

// The stamp clock lives in kernel.c, which this tool does not link — the same
// reason get_current_time_seconds is defined here. Kept behaving identically so
// a store written by a tool and one written by the device sort together.
static uint32_t stamp_floor;

void kernel_time_seen(uint32_t stamp) {
	if (stamp > stamp_floor)
		stamp_floor = stamp;
}

uint32_t kernel_time_mint(void) {
	uint32_t stamp = (uint32_t)get_current_time_seconds();
	if (stamp <= stamp_floor)
		stamp = stamp_floor + 1;
	stamp_floor = stamp;
	return stamp;
}

static const char *kind_str(uint8_t k){
	switch (k){
		case ENTRY_MSG_IN:      return "MSG_IN";
		case ENTRY_MSG_OUT:     return "MSG_OUT";
		case ENTRY_CALL_IN_MISSED:    return "CALL_IN_MISSED";
		case ENTRY_CALL_IN_ANSWERED:  return "CALL_IN_ANSWERED";
		case ENTRY_CALL_OUT_MISSED:   return "CALL_OUT_MISSED";
		case ENTRY_CALL_OUT_ANSWERED: return "CALL_OUT_ANSWERED";
		default:                        return "NONE";
	}
}
static void ip_str(char *buf, size_t n, uint32_t ip4){
	snprintf(buf, n, "%u.%u.%u.%u", ip4 & 0xff, (ip4 >> 8) & 0xff, (ip4 >> 16) & 0xff, (ip4 >> 24) & 0xff);
}
static void ts_str(char *buf, size_t n, uint32_t secs){
	time_t t = (time_t)secs; struct tm *tm = gmtime(&t);
	if (tm) strftime(buf, n, "%Y-%m-%d %H:%M:%S UTC", tm); else snprintf(buf, n, "%u", secs);
}

// ---- JSON dump of the mounted store -----------------------------------------

static int dump_json(const bk_header *h, const char *passphrase){
	if (!store_init()){ fprintf(stderr, "store_init failed\n"); return 1; }

	ks_state st = ks_state_get();
	if (st == KS_LOCKED){
		if (!ks_unlock_passphrase(passphrase)){
			fprintf(stderr, "unlock failed — wrong disk key?\n"); return 1;
		}
	} else if (st == KS_BLANK){
		fprintf(stderr, "keystore is BLANK (no identity in this image)\n"); return 1;
	}

	uint8_t vk[32];
	if (!ks_get_volume_key(vk)){ fprintf(stderr, "no volume_key (locked)\n"); return 1; }
	if (!block_read()){ fprintf(stderr, "block_read failed\n"); return 1; }
	file_storage_mount(RAWFLASH_DEV_INTERNAL, CONTACTSBLOCK_BASE_SECTOR,
	                   g_sectors - CONTACTSBLOCK_BASE_SECTOR, vk, 0);

	FILE *o = stdout;
	fprintf(o, "{\n");

	// header
	fprintf(o, "  \"backup\": { \"device_hash\": \"");
	for (int i = 0; i < 8; i++) fprintf(o, "%02x", h->device_hash[i]);
	fprintf(o, "\", \"sector_count\": %u, \"format_version\": %u, \"layout_version\": %u },\n",
	        h->sector_count, h->format_version, h->layout_version);

	// settings
	fprintf(o, "  \"settings\": {\n");
	fprintf(o, "    \"userid\": \"%08x\",\n", (unsigned)device_record.my_id);
	fprintf(o, "    \"ringer\": %u,\n", device_record.ringer);
	fprintf(o, "    \"private_key_present\": %s,\n", key_present(device_record.my_private_key, KEY_LEN) ? "true" : "false");
	fprintf(o, "    \"server_key_present\": %s,\n", key_present(device_record.server_static_public, KEY_LEN) ? "true" : "false");
	fprintf(o, "    \"wifi\": [");
	int first = 1;
	for (int i = 0; i < MAX_APS; i++){
		if (!device_record.ap_list[i].ssid[0]) continue;
		fprintf(o, "%s\n      { \"ssid\": ", first ? "" : ","); first = 0;
		json_str(o, device_record.ap_list[i].ssid, -1);
		fprintf(o, ", \"key\": ");
		json_str(o, device_record.ap_list[i].key, -1);
		fprintf(o, " }");
	}
	fprintf(o, "%s],\n", first ? "" : "\n    ");
	fprintf(o, "    \"endpoints\": [");
	first = 1;
	for (int i = 0; i < MAX_SERVER_ENDPOINTS; i++){
		if (device_record.endpoints[i].ip4 == 0) continue;
		char ip[20]; ip_str(ip, sizeof ip, device_record.endpoints[i].ip4);
		fprintf(o, "%s { \"ip\": \"%s\", \"port\": %u }", first ? "" : ",", ip, device_record.endpoints[i].port);
		first = 0;
	}
	fprintf(o, " ]\n  },\n");

	// contacts + their message threads
	fprintf(o, "  \"contacts\": [");
	int ci = 0; struct contact_record c; uint64_t uid; int firstc = 1;
	uint8_t ftype;
	for (;; ci++){
		struct file_header fh;
		if (!file_list(ci, &uid, &ftype))
			break;
		if (ftype != FILE_TYPE_CONTACT)     // groups are not dumped (yet)
			continue;
		if (!file_header_read(uid, &fh))
			continue;
		memcpy(&c, fh.data, sizeof c);
		char relay[28] = "";
		if (c.status == CONTACT_KEY_VALID){
			char ip[20]; ip_str(ip, sizeof ip, c.relay_ip4);
			snprintf(relay, sizeof relay, "%s:%u", ip, c.relay_port);
		}
		fprintf(o, "%s\n    {\n", firstc ? "" : ","); firstc = 0;
		fprintf(o, "      \"name\": "); json_str(o, c.name, -1);
		fprintf(o, ",\n      \"userid\": \"%08x\",\n", (unsigned)(uid >> 32));
		fprintf(o, "      \"status\": \"%s\",\n", status_str(c.status));
		fprintf(o, "      \"relay\": \"%s\",\n", relay);

		// The thread is this contact's log. Walk it newest-first into a buffer,
		// then print oldest-first for readability.
		static uint32_t entries[256];
		int nr = 0;
		uint32_t eid = file_log_newest(uid);
		while (eid != FILE_NONE && nr < 256){
			entries[nr++] = eid;
			eid = file_log_older(uid, eid);
		}
		fprintf(o, "      \"messages\": [");
		int firstm = 1;
		for (int i = nr - 1; i >= 0; i--){
			struct file_entry_info info; static uint8_t body[MSG_CALLER_RDBUF + 1];
			if (!file_entry_stat(uid, entries[i], &info)) continue;
			if (!(info.flags & FILE_DELETED)) continue;      // active low: cleared = deleted
			int got = file_entry_read(uid, entries[i], 0, body, MSG_CALLER_RDBUF);
			if (got < 0) got = 0;
			body[got] = 0;
			char ts[40]; ts_str(ts, sizeof ts, info.timestamp);
			const char *delivered = "false";
			if (!(info.flags & MSG_ST_DELIVERED))
				delivered = "true";
			fprintf(o, "%s\n        { \"time\": \"%s\", \"kind\": \"%s\", \"delivered\": %s, \"text\": ",
			        firstm ? "" : ",", ts, kind_str(info.meta[0]), delivered);
			firstm = 0;
			json_str(o, (const char *)body, got);
			fprintf(o, " }");
		}
		fprintf(o, "%s]\n    }", firstm ? "" : "\n      ");
	}
	fprintf(o, "%s]\n}\n", firstc ? "" : "\n  ");
	return 0;
}

// ---- main -------------------------------------------------------------------

int main(int argc, char **argv){
	if (argc < 2){
		fprintf(stderr, "usage: %s <backup.txt> [--key <passphrase>] [--image out.img] [--json]\n", argv[0]);
		return 2;
	}
	const char *path = argv[1], *imgpath = NULL, *passphrase = STORE_DEFAULT_PASSPHRASE;
	int do_json = 0;
	for (int i = 2; i < argc; i++){
		if (!strcmp(argv[i], "--image") && i + 1 < argc) imgpath = argv[++i];
		else if (!strcmp(argv[i], "--key") && i + 1 < argc) passphrase = argv[++i];
		else if (!strcmp(argv[i], "--json")) do_json = 1;
	}

	FILE *f = fopen(path, "rb");
	if (!f){ perror("open"); return 1; }
	fseek(f, 0, SEEK_END); long flen = ftell(f); fseek(f, 0, SEEK_SET);
	unsigned char *text = malloc(flen);
	if (fread(text, 1, flen, f) != (size_t)flen){ perror("read"); return 1; }
	fclose(f);

	unsigned char *data = malloc(flen);
	long dlen = b64decode(text, flen, data);
	free(text);
	if (dlen < (long)sizeof(bk_header)){ fprintf(stderr, "too short / not base64\n"); return 1; }

	bk_header h; memcpy(&h, data, sizeof h);
	if (memcmp(h.magic, BK_MAGIC, 8) != 0){ fprintf(stderr, "bad magic (not an Xyfr backup)\n"); return 1; }

	long body = dlen - (long)sizeof h, want = (long)h.sector_count * BK_RECORD_BYTES;
	if (body != want){ fprintf(stderr, "TRUNCATED/EXTRA: body %ld, expected %ld\n", body, want); return 1; }

	// Reconstruct the raw image, authenticating every sector under the fixed key.
	g_sectors = h.sector_count;
	g_img = malloc((size_t)g_sectors * BK_SECTOR_BYTES);
	unsigned char aad[sizeof(bk_header) + 4]; memcpy(aad, &h, sizeof h);
	const unsigned char *rec = data + sizeof h;
	long bad = 0;
	for (uint32_t s = 0; s < h.sector_count; s++){
		unsigned char nonce[24]; memcpy(nonce, h.salt, 20);
		nonce[20] = (unsigned char)(s >> 24); nonce[21] = (unsigned char)(s >> 16);
		nonce[22] = (unsigned char)(s >> 8);  nonce[23] = (unsigned char)s;
		aad[sizeof h + 0] = (unsigned char)(s >> 24); aad[sizeof h + 1] = (unsigned char)(s >> 16);
		aad[sizeof h + 2] = (unsigned char)(s >> 8);  aad[sizeof h + 3] = (unsigned char)s;
		if (!xchacha20poly1305_decrypt(g_img + (size_t)s * BK_SECTOR_BYTES,
		                               rec + (long)s * BK_RECORD_BYTES, BK_RECORD_BYTES,
		                               aad, sizeof aad, nonce, BK_OUTER_KEY)){
			if (bad < 5) fprintf(stderr, "sector %u: AUTH FAILED\n", s);
			bad++;
		}
	}
	free(data);
	if (bad){ fprintf(stderr, "%ld/%u sectors FAILED authentication\n", bad, h.sector_count); return 1; }

	if (!do_json){
		printf("magic           : %.8s\n", h.magic);
		printf("format_version  : %u\n", h.format_version);
		printf("layout_version  : %u%s\n", h.layout_version,
		       h.layout_version == BK_LAYOUT_VERSION ? "" : "  (MISMATCH)");
		printf("device_hash     : ");
		for (int i = 0; i < 8; i++) printf("%02x", h.device_hash[i]);
		printf("\nsector_count    : %u  (%.1f KB image)\n", h.sector_count, h.sector_count * 4.0);
		printf("\nOK: all %u sectors authenticated\n", h.sector_count);
	}
	if (imgpath){
		FILE *im = fopen(imgpath, "wb");
		if (im){ fwrite(g_img, 1, (size_t)g_sectors * BK_SECTOR_BYTES, im); fclose(im);
		         if (!do_json) printf("raw image       : %s\n", imgpath); }
	}

	int rc = 0;
	if (do_json) rc = dump_json(&h, passphrase);
	free(g_img);
	return rc;
}
