#include "debug.h"
#include <Arduino.h>
#include <WiFi.h>
#include <WiFiServer.h>
#include <WiFiClient.h>
#include <pico/unique_id.h>
#include <string.h>

#include "wg.h"          // blake2s, xchacha20poly1305, AUTHTAG_LEN
#include "rawflash.h"    // rawflash_read / rawflash_sector_count / RAWFLASH_SECTOR
#include "hal.h"         // hal_rand
#include "ui.h"          // TERMINAL_*, WIFI_ONLINE, wifi_get_status, go_home
#include "view.h"        // the backup-mode screen
#include "backup_format.h"   // bk_header, BK_OUTER_KEY, BK_* constants (shared w/ the CLI tool)
#include "webbackup.h"
#include <time.h>
extern "C" time_t get_current_time_seconds();   // ui.cpp — NTP-synced UTC epoch (~0 until synced)

// BACKUP ONLY. The on-device web server here streams a download of the whole
// encrypted FS region. RESTORE is a separate, dedicated flow (restore_net.cpp):
// it needs poll-mode cyw43 to write flash while receiving, which this tsb-based
// WiFiServer can't do without wedging — so restore is NOT served here.

// ---- backup header ----------------------------------------------------------

// device_hash is informational only (which device this came from); the outer key
// is FIXED (backup_format.h) so a backup restores on any Xyfr device. blake2s of
// the chip's unique id, truncated to 8 bytes.
static void backup_device_hash(uint8_t out[8]){
	pico_unique_board_id_t id;
	pico_get_unique_board_id(&id);
	blake2s_ctx ctx;
	uint8_t full[16];
	blake2s_init(&ctx, sizeof full, NULL, 0);
	static const char dom[] = "xyfr-backup-id-v1";
	blake2s_update(&ctx, dom, sizeof dom - 1);
	blake2s_update(&ctx, id.id, sizeof id.id);
	blake2s_final(&ctx, full);
	memcpy(out, full, 8);
}

static void rand_bytes(uint8_t *p, size_t n){
	while (n) {
		uint32_t r = hal_rand();
		size_t k = n < 4 ? n : 4;
		memcpy(p, &r, k);
		p += k;
		n -= k;
	}
}

// ---- streaming base64 encoder (over a WiFiClient) ---------------------------

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

struct b64_stream {
	WiFiClient *cli;
	uint8_t     car[3];
	int         cn;        // 0..2 carry bytes
	uint8_t     out[4104]; // batched output (flush threshold below)
	int         on;
};
static void b64_open(b64_stream *s, WiFiClient *c){ s->cli = c; s->cn = 0; s->on = 0; }
// write() can accept fewer bytes than asked when the TCP send buffer is full;
// loop until the whole batch is enqueued (yielding to let lwIP drain) so the
// tail of the stream is never dropped. Bails if the client disconnects.
static void b64_flush(b64_stream *s){
	int off = 0;
	while (off < s->on){
		if (!s->cli->connected()) {
			s->on = 0;
			return;
		}
		size_t w = s->cli->write(s->out + off, (size_t)(s->on - off));
		if (w > 0)
			off += (int)w;
		else
			delay(1);
	}
	s->on = 0;
}
static inline void b64_put(b64_stream *s, char c){
	s->out[s->on++] = (uint8_t)c;
	if (s->on >= 4096)
		b64_flush(s);
}
static void b64_feed(b64_stream *s, const uint8_t *p, size_t len){
	for (size_t i = 0; i < len; i++){
		s->car[s->cn++] = p[i];
		if (s->cn == 3){
			uint32_t v = ((uint32_t)s->car[0] << 16) | ((uint32_t)s->car[1] << 8) | s->car[2];
			b64_put(s, B64[(v >> 18) & 63]); b64_put(s, B64[(v >> 12) & 63]);
			b64_put(s, B64[(v >>  6) & 63]); b64_put(s, B64[v & 63]);
			s->cn = 0;
		}
	}
}
static void b64_finish(b64_stream *s){
	if (s->cn == 1){
		uint32_t v = (uint32_t)s->car[0] << 16;
		b64_put(s, B64[(v >> 18) & 63]); b64_put(s, B64[(v >> 12) & 63]);
		b64_put(s, '='); b64_put(s, '=');
	} else if (s->cn == 2){
		uint32_t v = ((uint32_t)s->car[0] << 16) | ((uint32_t)s->car[1] << 8);
		b64_put(s, B64[(v >> 18) & 63]); b64_put(s, B64[(v >> 12) & 63]);
		b64_put(s, B64[(v >> 6) & 63]);  b64_put(s, '=');
	}
	s->cn = 0;
	b64_flush(s);
}

// ---- HTTP ------------------------------------------------------------------

static WiFiServer s_server(80);
static bool       s_active = false;

// Read one CRLF-terminated line (the trailing CR/LF stripped) with a timeout.
static bool http_read_line(WiFiClient &c, char *buf, size_t n){
	size_t i = 0; uint32_t t0 = millis();
	while ((uint32_t)(millis() - t0) < 4000){
		if (!c.connected() && !c.available())
			break;
		int ch = c.read();
		if (ch < 0) {
			delay(1);
			continue;
		}
		if (ch == '\n') {
			if (i && buf[i-1] == '\r')
				i--;
			buf[i] = 0;
			return true;
		}
		if (i < n - 1)
			buf[i++] = (char)ch;
	}
	buf[i < n ? i : n - 1] = 0;
	return i > 0;
}

static const char PAGE[] =
	"<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">"
	"<title>Xyfr Backup</title>"
	"<body style=\"font-family:sans-serif;max-width:30em;margin:2em auto;padding:0 1em\">"
	"<h2>Xyfr Backup</h2>"
	"<p>Save a full encrypted backup of this device.</p>"
	"<p><a href=\"/backup\" download=\"xyfr-backup.txt\">"
	"<button style=\"font-size:1.1em;padding:.8em 1.6em\">Backup &#8595;</button></a></p>"
	"<hr>"
	"<p style=\"color:#666\">To <b>restore</b> a backup, choose <b>Settings &rarr; Restore</b> on the "
	"device itself — it reboots into a dedicated restore page with an access code.</p>"
	"</body>";

static void http_send(WiFiClient &c, const char *status, const char *ctype, const char *body){
	c.print("HTTP/1.1 "); c.print(status); c.print("\r\n");
	c.print("Content-Type: "); c.print(ctype); c.print("\r\n");
	c.print("Connection: close\r\n\r\n");
	if (body)
		c.print(body);
}

// GET /backup : stream the per-sector AEAD records, base64, as a download.
static void http_send_backup(WiFiClient &c){
	bk_header h;
	memset(&h, 0, sizeof h);
	memcpy(h.magic, BK_MAGIC, 8);
	h.format_version = BK_FORMAT_VERSION;
	h.layout_version = BK_LAYOUT_VERSION;
	backup_device_hash(h.device_hash);
	uint32_t nsec = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	h.sector_count = (uint16_t)nsec;
	rand_bytes(h.salt, sizeof h.salt);

	// Unique filename so the user can keep many backups without renaming. Prefer a
	// sortable UTC timestamp; if the clock isn't NTP-synced, fall back to the 8-hex
	// device_hash so names still never collide (no colons — Windows-safe).
	char fname[52];
	time_t now = get_current_time_seconds();
	if (now > (time_t)1600000000) {
		struct tm *t = gmtime(&now);
		snprintf(fname, sizeof fname, "xyfr-backup-%04d%02d%02d-%02d%02d%02d.txt",
		         t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
	} else {
		snprintf(fname, sizeof fname, "xyfr-backup-%02x%02x%02x%02x.txt",
		         h.device_hash[0], h.device_hash[1], h.device_hash[2], h.device_hash[3]);
	}

	c.print("HTTP/1.1 200 OK\r\n");
	c.print("Content-Type: text/plain\r\n");
	c.print("Content-Disposition: attachment; filename=\"");
	c.print(fname);
	c.print("\"\r\n");
	c.print("Connection: close\r\n\r\n");

	b64_stream b; b64_open(&b, &c);
	b64_feed(&b, (const uint8_t *)&h, sizeof h);          // header first (also authenticated below)

	static uint8_t sec[BK_SECTOR_BYTES];
	static uint8_t ct [BK_RECORD_BYTES];
	uint8_t aad[sizeof(bk_header) + 4];
	memcpy(aad, &h, sizeof h);

	for (uint32_t s = 0; s < nsec; s++){
		if (!c.connected())  // client aborted the download
			break;
		rawflash_read(RAWFLASH_DEV_INTERNAL, s, 0, sec, BK_SECTOR_BYTES);
		uint8_t nonce[24];
		memcpy(nonce, h.salt, 20);
		nonce[20] = (uint8_t)(s >> 24); nonce[21] = (uint8_t)(s >> 16);
		nonce[22] = (uint8_t)(s >> 8);  nonce[23] = (uint8_t)s;
		aad[sizeof h + 0] = (uint8_t)(s >> 24); aad[sizeof h + 1] = (uint8_t)(s >> 16);
		aad[sizeof h + 2] = (uint8_t)(s >> 8);  aad[sizeof h + 3] = (uint8_t)s;
		xchacha20poly1305_encrypt(ct, sec, BK_SECTOR_BYTES, aad, sizeof aad, nonce, BK_OUTER_KEY);
		b64_feed(&b, ct, BK_RECORD_BYTES);
	}
	b64_finish(&b);
	Debug.printf("backup: streamed %u sectors\n", (unsigned)nsec);
}

static void http_handle(WiFiClient &c){
	char req[200];
	if (!http_read_line(c, req, sizeof req))
		return;
	char method[8] = {0}, path[96] = {0};
	sscanf(req, "%7s %95s", method, path);

	char hdr[200];                                        // drain remaining request headers
	while (http_read_line(c, hdr, sizeof hdr) && hdr[0]) { }

	if (!strcmp(method, "GET") && !strcmp(path, "/")){
		http_send(c, "200 OK", "text/html", PAGE); return;
	}
	if (!strcmp(method, "GET") && !strcmp(path, "/backup")){
		http_send_backup(c); return;
	}
	http_send(c, "404 Not Found", "text/plain", "Not found");
}

// ---- the backup-mode screen (a view) ---------------------------------------

static char s_ip_line[40];   // "http://A.B.C.D"

static int backup_cb(view_op_t op, int i, void *data){
	switch (op){
		case LIST_GET_ITEM: {
			view_item_t *it = (view_item_t *)data;
			if (i == 0) {
				it->text = s_ip_line;
				it->style = TERMINAL_HIGHLIGHT;
				return 0;
			}
			// The backup is only as private as the disk key; until that UI exists the
			// store is on the known default key, so always warn.
			if (i == 1){ it->text = LV_SYMBOL_WARNING "  Private only if a disk key is set";
			             it->style = TERMINAL_GRAY; return 0; }
			if (i == 2) {
				it->text = LV_SYMBOL_CLOSE "  Exit";
				it->user = (void *)1;
				return 0;
			}
			return -1;
		}
		case LIST_SELECTED:
			if (data) {  // the Exit row
				backup_mode_exit();
				go_home();
			}
			return 0;
		default:
			return 0;
	}
}

static void backup_show_screen(){
	IPAddress ip = WiFi.localIP();
	snprintf(s_ip_line, sizeof s_ip_line, "http://%u.%u.%u.%u",
	         ip[0], ip[1], ip[2], ip[3]);
	view_set(backup_cb, "Backup",
	         "On a computer on this same WiFi, type the address below into the "
	         "browser EXACTLY as shown.\nIt must start with http:// - typing just "
	         "the numbers, or https://, will not reach the phone.",
	         NULL, NULL, NULL);
	view_select(2);   // focus Exit
}

// ---- public API ------------------------------------------------------------

void backup_mode_enter(void){
	if (s_active)
		return;
	if (wifi_get_status() != WIFI_ONLINE)  // caller only offers this when online
		return;
	s_server.begin();
	s_active = true;
	backup_show_screen();
	Debug.println("backup: web server up on :80");
}

void backup_mode_exit(void){
	if (!s_active)
		return;
	s_server.end();
	s_active = false;
	Debug.println("backup: web server down");
}

bool backup_mode_active(void){ return s_active; }

void backup_pump(void){
	if (!s_active)
		return;
	WiFiClient c = s_server.accept();
	if (!c)
		return;
	http_handle(c);
	c.flush();
	c.stop();
}
