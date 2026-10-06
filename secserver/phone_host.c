// phone_host.c — host (Linux) shell for the SHARED portable phone core.
//
// This is the CLI counterpart of xyfr.ino: it links the SAME C sources
// the device firmware does (kernel.c + session/requests/call/cmdq/text +
// storage/contacts) behind the POSIX HAL backends (net_posix / fs_posix /
// hal_posix), so the wg/session/call stack is exercised by ONE implementation
// on both targets.
//
// Two threads mirror the device's two cores:
//   - stack thread  (≈ core 0): loops kernel_pump() every ~5 ms.
//   - main/console  (≈ core 1 UI): reads stdin, ferries commands to the stack
//                    over the lock-free SPSC cmdq (console = producer).
//
// Everything platform-specific the core expects but the host lacks (WiFi/UI
// state, NTP, LVGL terminal, contact-lookup, the audio HAL) is stubbed below.
// Endpoint resolution is NOT done here (no DoH on host): we populate device_record.endpoints[1] straight from client.conf.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <termios.h>

#include "view.h"        // view_cb_t, for the UI stubs below
#include "hal.h"          // net_open/now_ms/hal_delay_ms, LOG_*, hal_log_level
#include "device_record.h"  // struct device_record, block_ready
#include "cmdq.h"
#include "netif.h"       // netif_setkey — identity comes from client.conf
#include "kernel.h"      // kernel_slice + the screen table the platform owns
#include "phone_state.h" // WIFI_* + enum phone_state (the stubs below implement these)
#include "wg.h"           // KEY_LEN, struct peer
#include "call.h"         // call_originate (call-by-key console cmd)
#include "audio_alsa.h"   // host audio backend (ALSA) behind the audio.h HAL
#include "term_host.h"    // TERM app (server) + the `term` client mode
#include "config.h"
#include "config_env.h"
#include "contacts.h"     // contact_get — this build's answer to allow_into_channel
#include "msg.h"          // msg_post/msg_read — the machine verbs call these direct
#include "channel_log.h"      // channel_append/channel_line_read — likewise

// Portable entry points (defined in ../kernel.c, C linkage).
extern void kernel_init(void);
extern void kernel_pump(void);
extern void kernel_slice(void);

// Device core-0 hang-trace checkpoint (set in the .ino on device; call.c writes
// it around a LittleFS read). Unused on host, but call.c references it.
volatile int debug_line0 = 0;

// ===========================================================================
//  Platform stubs — the device side these in real subsystems; the host doesn't
//  have them (or doesn't need them for the CLI), so they are inert.
// ===========================================================================

// WiFi is the OS's job on host: always "online" so the login/keepalive pumps run.
int  wifi_get_status(void) { return WIFI_ONLINE; }
// UI state machine — no UI on host.
void phone_state_set(enum phone_state s) { (void)s; }
// Wall-clock seconds (device: NTP-corrected; host: system clock).
time_t get_current_time_seconds(void) { return time(NULL); }
// wg responder hook: accept inbound peer msg1 (the CLI is a willing test peer).
int  validate_public_key(const uint8_t *k, void *ctx) { (void)k; (void)ctx; return 1; }
// Onboarding's partkey probe (device: registeration.cpp). contacts.c hands a
// query answer here when the device has no private key; the CLI always has one
// from client.conf, so this can never fire and exists only to link.
void registration_query_answer(const uint8_t key[32], int status) {
	(void)key; (void)status;
}
// Non-wg datagrams: the device routes NTP here; the host has none.
bool kernel_handle_non_wg(uint8_t *b, int n, uint32_t ip, uint16_t port) {
	(void)b; (void)n; (void)ip; (void)port; return false;
}
// The LVGL terminal is device-only; inert on host.
void terminal_net_pump(void)    {}

// Contact lookup + missed requests are NO LONGER STUBBED. They moved into
// contacts.c (2026-08-09) when contact_lookup.c was absorbed, and contacts.c is
// already linked here — so the CLI now gets the real resolver over netif's
// remote_query() instead of six no-ops. Redefining them here would be a
// duplicate-symbol link error, which is how this was noticed.

// Audio HAL (audio.h) — backed by ALSA (audio_alsa.c, 8 kHz/mono/S16_LE). The
// call layer drives it: audio_open on call start, audio_play_voice for inbound
// speaker, audio_capture_ready/voice for outbound mic. Ringback + local ring
// are device-UI niceties — silent/no-op on the CLI (use HEADPHONES; open mic +
// speaker feed back). Transmission format == ALSA format == int16 LE, so play is a
// straight reinterpret (host is little-endian).
static int16_t ph_cap_buf[AUDIO_FRAME_SAMPLES];
static int     ph_cap_have = 0;

// ---- UI stubs -------------------------------------------------------------
// app_call.c is one file holding the call model AND its screen, and the model
// is what makes this binary a usable test peer. So a headless build links the
// screen half too and answers for the UI it calls.
int  speaker_level = 5;
int  mic_muted     = 0;
void audio_set_speaker_level(int notch) { speaker_level = notch; }
// No keyboard here, so nothing is ever a volume key.
int  ui_volume_key(int key) { (void)key; return 0; }
volatile bool ui_locked = false;
uint32_t display_kicked_ms = 0;
void display_kick(void) {}
void go_home(void) {}
void view_set(view_cb_t cb, const char *title, const char *prompt,
              const char **items, const char *input_hint, const char *input_prefill) {
	(void)cb; (void)title; (void)prompt; (void)items; (void)input_hint; (void)input_prefill;
}
void view_select(int item_index) { (void)item_index; }
int  view_selected(void) { return 0; }

// The terminal is a device screen: its parser, grid and panel code are all
// device-side, so a headless build only has to satisfy the screen table.
int app_terminal_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}

// A channel prints text through the terminal's grid, which is device-side, so a
// headless build serves channels (app_channel.c is linked in full) and displays
// nothing.
void channel_display_reset(void) { }
void channel_display_clear(void) { }
void channel_display_text(const char *text, int len) {
	fwrite(text, 1, (size_t)len, stdout);   // a console IS this build's panel
	fflush(stdout);
}
void channel_display_pump(void) { }
const char *channel_display_key(int key) { (void)key; return NULL; }
bool channel_display_has_text(void) { return false; }
// No panel to fill, so this only has to be a sane screenful for the ring.
int channel_display_capacity(void) { return 80 * 23; }

// THIS BUILD'S ANSWER to "who may enter a channel we host" (channel_log.h). A
// desktop deployment may serve far more peers than any record could name, so
// the list is not one: every contact we hold is admitted, and a real
// deployment replaces this body with its own database or flat file. The
// handshake has already refused anyone who is not a contact at all.
int allow_into_channel(uint16_t channel_id, uint32_t contact_id) {
	struct contact_record c;
	(void)channel_id;
	if (!contact_get(&c, contact_id))
		return 0;
	if (c.settings & CONTACT_BLOCKED)
		return 0;
	return 1;
}

// THIS BUILD'S ANSWER to "under whose name is a member's log filed"
// (channel_log.h). Every channel this binary hosts today is a group chat, so
// one log serves all of it. A proxy serving a log per user answers `member` for
// the ids it owns, and both can live in one build.
uint32_t channel_log_owner(uint16_t channel_id, uint32_t member) {
	(void)channel_id;
	(void)member;
	return channel_my_partkey();
}
bool channel_display_move(int dir) {
	(void)dir;
	return false;
}

// ===========================================================================
//  The machine interface — one JSON object per received message, on stdout.
//
//  stderr is where hal_debug writes, so stdout is free to be a pipe a program
//  reads. A MESSAGE arrives twice by the same function -- the `msg-recv` verb,
//  and app_chat_main below on every NOTIFY_MSG_UPDATE. A CHANNEL LINE has only
//  the verb: channel_append posts no notification, so `channel-recv` is asked,
//  not awaited.
//
//  THE READ BIT IS THE CURSOR, and printing is what clears it -- so each message
//  crosses this boundary once and a restart does not re-serve it. msg_mark_read
//  clears a whole thread, which is why the unread ones are always the newest run
//  and the walk can stop at the first inbound already read.
//
//  A READER MUST KEEP READING. The live print runs on the stack thread with
//  core_lock held, so a reader that stops draining stdout fills the pipe and
//  stalls the whole client -- netif, keepalives and storage with it. Read into a
//  queue and do the work elsewhere.
// ===========================================================================

static void json_text(FILE *o, const char *s, int n) {
	for (int i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];
		if (c == '"' || c == '\\') {
			fprintf(o, "\\%c", c);
			continue;
		}
		if (c == '\n') {
			fputs("\\n", o);
			continue;
		}
		if (c == '\r') {
			fputs("\\r", o);
			continue;
		}
		if (c == '\t') {
			fputs("\\t", o);
			continue;
		}
		if (c < 0x20) {
			fprintf(o, "\\u%04x", c);
			continue;
		}
		// UTF-8 above 0x7f is valid JSON as it stands.
		fputc(c, o);
	}
}

static void print_message(const struct msg_record *m) {
	int len = msg_body_len(m->contact_id, m->record_id);
	if (len < 0)
		return;
	char *text = malloc((size_t)len + 1);
	if (!text)
		return;
	int got = 0;
	while (got < len) {
		int r = msg_read(m->contact_id, m->record_id, (uint32_t)got, text + got, len - got);
		if (r <= 0)
			break;
		got += r;
	}
	printf("{\"t\":\"msg\",\"from\":\"%08x\",\"id\":%u,\"ts\":%u,\"len\":%d,\"text\":\"",
	       (unsigned)m->contact_id, (unsigned)m->record_id,
	       (unsigned)m->timestamp, got);
	json_text(stdout, text, got);
	printf("\"}\n");
	fflush(stdout);
	free(text);
}

static void dump_thread_unread(uint32_t partkey) {
	struct msg_record page[32];
	struct msg_record *held = NULL;
	int count = 0;
	int cap = 0;
	int n = msg_recent(partkey, page, 32);
	int reached_read = 0;
	while (n > 0 && !reached_read) {
		for (int i = 0; i < n; i++) {
			if (page[i].kind != ENTRY_MSG_IN)
				continue;
			if (msg_is_read(page[i])) {
				reached_read = 1;
				break;
			}
			if (count == cap) {
				cap = cap * 2 + 32;
				struct msg_record *grown = realloc(held, (size_t)cap * sizeof *held);
				if (!grown) {
					free(held);
					return;
				}
				held = grown;
			}
			held[count++] = page[i];
		}
		if (reached_read)
			break;
		n = msg_recent_before(partkey, page[n - 1].record_id, page, 32);
	}
	// Gathered newest first; a conversation reads the other way.
	for (int i = count - 1; i >= 0; i--)
		print_message(&held[i]);
	if (count > 0)
		msg_mark_read(partkey);
	free(held);
}

// The lines a MEMBER wrote into a channel we host, oldest first. Ours are the
// answers we already know about, so they are skipped: what a reader wants is
// what somebody asked. `after` is the last entry it handled -- a channel line
// has no read bit, so the cursor is the caller's and this host keeps none.
static void channel_dump_incoming(uint16_t id, uint32_t after) {
	uint32_t me = channel_my_partkey();
	uint32_t entry = channel_newest(me, id);
	if (entry == FILE_NONE)
		return;
	uint32_t oldest = entry;
	while (1) {
		uint32_t older = channel_older(me, id, oldest);
		if (older == FILE_NONE || older == after)
			break;
		oldest = older;
	}
	if (after != 0)
		oldest = channel_newer(me, id, after);
	for (entry = oldest; entry != FILE_NONE; entry = channel_newer(me, id, entry)) {
		uint32_t author = 0;
		uint32_t stamp = 0;
		char text[CHANNEL_TEXT_MAX + 1];
		int len = channel_line_read(me, id, entry, &author, &stamp,
		                            text, (int)sizeof text);
		if (len < 0)
			continue;
		if (author == me)
			continue;
		printf("{\"t\":\"line\",\"room\":%u,\"from\":\"%08x\",\"id\":%u,"
		       "\"ts\":%u,\"len\":%d,\"text\":\"",
		       (unsigned)id, (unsigned)author, (unsigned)entry,
		       (unsigned)stamp, len);
		json_text(stdout, text, len);
		printf("\"}\n");
		fflush(stdout);
	}
}

// partkey 0 means every contact.
static void msg_dump_received(uint32_t partkey) {
	if (partkey != 0) {
		dump_thread_unread(partkey);
		return;
	}
	struct contact_record c;
	for (int i = 0; contact_by_index(i, &c); i++)
		dump_thread_unread(contact_userid(&c));
}

// The chat screens likewise (app_chat.c): pure view code over the logbook, so a
// headless build only has to satisfy the screen table. This one is not inert:
// msg.c posts NOTIFY_MSG_UPDATE on every stored message, so answering it here is
// the whole of the real-time channel. It runs inside kernel_slice, which the
// stack thread already holds core_lock for -- do not take the lock again.
// Only this handler prints: broadcast() walks each distinct handler once, and
// the other stubs are distinct functions, so a second one would double every
// event.
int app_chat_main(int message, uint32_t param) {
	if (message == NOTIFY_MSG_UPDATE)
		msg_dump_received(param);
	return 0;
}
int app_msg_menu_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_msg_view_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
// And the home app's screens (app_home.c).
int app_home_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_settings_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_admin_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_security_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_ptt_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
void app_ptt_inbound(uint32_t remote_userid, const uint8_t *pcm, int len) {
	(void)remote_userid; (void)pcm; (void)len;
}
int app_pick_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}
int app_ask_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
}

// ---- VOX test rig: file voice source/sink (env-gated, ALSA stays default) ----
// LTP_VOICE_IN=<file.s16>  stream this raw S16_LE/8k/mono file as the far-end
//                          voice instead of the live mic. It rides the ALSA
//                          CAPTURE clock (see audio_capture_ready): each real
//                          40 ms capture frame is the transmit tick, and we
//                          overwrite its samples with the next chunk of the
//                          file. Using the sound card's own 8 kHz clock (not a
//                          software timer) keeps the outbound cadence jitter-free
//                          against the device's playback consumer. Looped at EOF.
// LTP_VOICE_OUT=<file.s16> append the inbound device->CLI voice to this file so
//                          the gate's effect (mic silenced under far-end speech,
//                          open in the gaps) can be measured offline.
// Both are raw headerless S16_LE 8 kHz mono == the DATA_VOICE payload == ALSA
// format, so there is nothing to parse. See tools/vox_test/.
static FILE    *voice_in       = NULL;
static FILE    *voice_out      = NULL;

// Overwrite a just-captured frame with the next chunk of the clip (loop at EOF).
static void voice_in_fill(int16_t *buf, int n) {
	size_t got = fread(buf, sizeof(int16_t), (size_t)n, voice_in);
	if (got < (size_t)n) {                 // EOF mid-frame -> wrap and fill the rest
		rewind(voice_in);
		fread(buf + got, sizeof(int16_t), (size_t)n - got, voice_in);
	}
}

static void voice_files_init(void) {
	static int done = 0;
	if (done) return;                    // read env once; open persists for the run
	done = 1;
	const char *in  = getenv("LTP_VOICE_IN");
	const char *out = getenv("LTP_VOICE_OUT");
	if (in) {
		voice_in = fopen(in, "rb");
		if (!voice_in) fprintf(stderr, "phone: LTP_VOICE_IN: cannot open %s\n", in);
		else           fprintf(stderr, "phone: far-end voice from %s (looped)\n", in);
	}
	if (out) {
		voice_out = fopen(out, "wb");
		if (!voice_out) fprintf(stderr, "phone: LTP_VOICE_OUT: cannot open %s\n", out);
		else            fprintf(stderr, "phone: recording device->CLI voice to %s\n", out);
	}
}

void audio_init(void)  { audio_alsa_init(); voice_files_init(); }
void audio_open(void)  { audio_alsa_init(); ph_cap_have = 0; voice_files_init(); }
// voice_in/voice_out are deliberately NOT closed here: one test run's return
// stream should accumulate in LTP_VOICE_OUT across the whole call (and any
// redial) until the process exits.
void audio_close(void) { audio_alsa_close(); ph_cap_have = 0; }

void audio_play_voice(const uint8_t *pcm_le, int len) {
	if (voice_out) { fwrite(pcm_le, 1, (size_t)len, voice_out); fflush(voice_out); }
	audio_alsa_playback_frame((const int16_t *)pcm_le, len / 2);
}

// PTT inbound — the host has no "loud" concept (ALSA plays at system volume), so
// this is a straight passthrough like audio_play_voice.
void audio_play_ptt(const uint8_t *pcm_le, int len) {
	audio_alsa_playback_frame((const int16_t *)pcm_le, len / 2);
}

int audio_capture_ready(void) {
	// Stage one hardware-clocked frame from ALSA capture (non-blocking; returns 1
	// on a full 320-sample/40 ms frame). This IS the transmit clock — the sound
	// card's 8 kHz domain, the same one the real firmware mic rides — so there is
	// no software-timer drift. For the VOX test we keep the timing but replace the
	// mic samples with the clip (LTP_VOICE_IN); the ALSA capture is then only the
	// pacing source.
	if (!ph_cap_have && audio_alsa_capture_frame(ph_cap_buf) == 1) {
		if (voice_in) voice_in_fill(ph_cap_buf, AUDIO_FRAME_SAMPLES);
		ph_cap_have = AUDIO_FRAME_SAMPLES;
	}
	return ph_cap_have;
}

int audio_capture_voice(int16_t *out, int max_samples) {
	if (!ph_cap_have) return 0;
	int n = (max_samples < ph_cap_have) ? max_samples : ph_cap_have;
	memcpy(out, ph_cap_buf, (size_t)n * sizeof(int16_t));
	ph_cap_have = 0;
	return n;
}

void audio_ringback_frame(int16_t *o, int n, uint16_t *fc) { (void)fc; memset(o, 0, (size_t)n * sizeof(int16_t)); }
void audio_ring_start(void) {}
void audio_ring_stop(void)  {}

// ===========================================================================
//  client.conf — same format the legacy client.c reads (key=value lines).
// ===========================================================================
static int hex2bytes(const char *hex, uint8_t *out, int out_len) {
	for (int i = 0; i < out_len; i++) {
		int hi, lo;
		char c;
		c = hex[2*i];     hi = (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1;
		c = hex[2*i + 1]; lo = (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1;
		if (hi < 0 || lo < 0) return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

// Dotted-quad -> uint32 with octet 0 in the LOW byte (storage.h / net HAL order).
static uint32_t parse_ipv4(const char *s) {
	unsigned a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
	return (uint32_t)a | ((uint32_t)b << 8) | ((uint32_t)c << 16) | ((uint32_t)d << 24);
}

static uint8_t  cfg_priv[KEY_LEN];
static uint8_t  cfg_server_pub[KEY_LEN];
static uint32_t cfg_server_ip   = 0;
static uint16_t cfg_server_port = 5004;   // relay port by default (see client.conf)
static int      have_priv = 0, have_server_pub = 0;

static int load_config(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "phone: cannot open %s\n", path); return -1; }
	char line[512];
	while (fgets(line, sizeof(line), f)) {
		char *eq = strchr(line, '=');
		if (!eq || line[0] == '#') continue;
		*eq = 0;
		char *key = line, *val = eq + 1;
		val[strcspn(val, "\r\n")] = 0;
		if      (!strcmp(key, "my_private"))  have_priv       = (hex2bytes(val, cfg_priv, KEY_LEN) == 0);
		else if (!strcmp(key, "server_key"))  have_server_pub = (hex2bytes(val, cfg_server_pub, KEY_LEN) == 0);
		else if (!strcmp(key, "server_ip"))   cfg_server_ip   = parse_ipv4(val);
		else if (!strcmp(key, "server_port")) cfg_server_port = (uint16_t)atoi(val);
		else if (!strcmp(key, "allow_terminal")) {
			while (*val == ' ') val++;
			if (strlen(val) >= 8) term_allow_add((uint32_t)strtoul(val, NULL, 16));  // 8-hex partkey
		}
	}
	fclose(f);
	if (!have_priv || !have_server_pub || !cfg_server_ip) {
		fprintf(stderr, "phone: client.conf needs my_private, server_key, server_ip\n");
		return -1;
	}
	return 0;
}

// ===========================================================================
//  threads
// ===========================================================================
static volatile int running = 1;

// The console thread may call into the core directly (msg-send/msg-recv, which
// carry more than the cmdq line fits). The core is the stack thread's, so those
// calls take this and the stack loop holds it while it runs. The 5 ms sleep is
// outside it, which is the console's window.
static pthread_mutex_t core_lock = PTHREAD_MUTEX_INITIALIZER;

static void *stack_thread(void *arg) {
	(void)arg;
	while (running) {
		pthread_mutex_lock(&core_lock);
		kernel_pump();
		kernel_slice();    // no UI here, so the stack thread owns the app tick too
		term_pump();       // TERM server PTY drain + client stdin ring drain
		pthread_mutex_unlock(&core_lock);
		hal_delay_ms(5);   // mirror the device loop()'s 5 ms pacing
	}
	return NULL;
}

static void print_help(void) {
	printf("commands:\n"
	       "  call-key <64hex>    originate a call to a peer by static pubkey\n"
	       "  call-answer | call-hangup | call-refuse   call control\n"
	       "  contact-add <8hex-uid> <nm>   add a (pending) contact\n"
	       "  call <8hex-uid>     call a VALID contact by userid\n"
	       "  msg-key <64hex> <text>        send a message by raw pubkey\n"
	       "  msg <8hex-uid> <text>         send a message to a VALID contact\n"
	       "  msg-list <8hex-uid>           dump a stored thread\n"
	       "  msg-send <8hex-uid> <nbytes>  then that many bytes of body, any size\n"
	       "  msg-recv [8hex-uid]           received messages as JSON, marks them read\n"
	       "  channel-send <id> <nbytes>    then that many bytes, split into lines\n"
	       "  channel-recv <id> [after]     members' lines as JSON, after that entry id\n"
	       "  log <0..3>          set verbosity floor (0=all .. 3=critical)\n"
	       "  ?                   this help        q | quit   exit\n");
}

static void print_usage(const char *prog) {
	printf("phone - host test peer (runs the firmware's shared portable core)\n\n"
	       "usage:\n"
	       "  %s                             run using ./client.conf\n"
	       "  %s <config>                    run using an alternate config file\n"
	       "  %s msg <64hex-key> <text...>   one-shot: send a message, then stay running\n"
	       "  %s -h | --help                 this help\n\n"
	       "config file (key=value lines): my_private, server_key, server_ip [, server_port]\n"
	       "audio: real ALSA mic/speaker (env LTP_AUDIO_GAIN, LTP_AUDIO_DEBUG=1)\n\n",
	       prog, prog, prog, prog);
	print_help();   // the interactive console commands
}

int main(int argc, char **argv) {
	// NOTE: no logstamp_install() here. The phone is an INTERACTIVE client, not a
	// logging daemon: in term/termg mode its stdout carries the raw remote-shell
	// byte stream, and line-prefixing that with timestamps corrupts the terminal.
	// Its diagnostic TX->/RX<- lines already carry inline [HH:MM:SS.mmm] stamps.
	if (argc >= 2 && (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))) {
		print_usage(argv[0]);
		return 0;
	}
	// Optional one-shot send:  ./phone msg <64hex-key> "<text>"   (uses client.conf,
	// then stays running so the message delivers + you can watch / 'q' to quit).
	const char *msg_key = NULL;
	static char msg_text[120];
	const char *conf = "client.conf";
	// `./phone term <64hex-key> [command...]` — open a remote terminal to a peer.
	int term_mode = 0;
	uint8_t term_key[KEY_LEN];
	static char term_cmd[400];
	term_cmd[0] = 0;
	int termg_mode = 0;
	if (argc >= 3 && (!strcmp(argv[1], "term") || !strcmp(argv[1], "termg"))) {
		termg_mode = !strcmp(argv[1], "termg");
		if (strlen(argv[2]) < KEY_LEN * 2 || hex2bytes(argv[2], term_key, KEY_LEN) != 0) {
			fprintf(stderr, "%s: need a 64-hex peer key\n", argv[1]); return 1;
		}
		for (int i = 3; i < argc; i++) {
			if (i > 3) strncat(term_cmd, " ", sizeof term_cmd - strlen(term_cmd) - 1);
			strncat(term_cmd, argv[i], sizeof term_cmd - strlen(term_cmd) - 1);
		}
		term_mode = 1;
	} else if (argc >= 4 && !strcmp(argv[1], "msg")) {
		msg_key = argv[2];
		msg_text[0] = 0;
		for (int i = 3; i < argc; i++) {
			if (i > 3) strncat(msg_text, " ", sizeof msg_text - strlen(msg_text) - 1);
			strncat(msg_text, argv[i], sizeof msg_text - strlen(msg_text) - 1);
		}
	} else if (argc > 1) {
		conf = argv[1];
	}
	if (load_config(conf) != 0) return 1;

	// Test-only overrides so the soak harness can shrink the expiry to fit a short
	// run without a rebuild. The per-peer backoff table is gone with the scheduler
	// — pacing is now one lap hop per msg_hop_interval_ms.
	{
		extern uint32_t msg_expiry_secs, msg_hop_interval_ms;
		extern uint32_t msg_retry_min_ms, msg_retry_max_ms;
		const char *e;
		if ((e = getenv("LTP_MSG_EXPIRY_SECS"))) msg_expiry_secs     = (uint32_t)strtoul(e, NULL, 10);
		if ((e = getenv("LTP_MSG_HOP_MS")))      msg_hop_interval_ms = (uint32_t)strtoul(e, NULL, 10);
		if ((e = getenv("LTP_MSG_RETRY_MIN_MS"))) msg_retry_min_ms   = (uint32_t)strtoul(e, NULL, 10);
		if ((e = getenv("LTP_MSG_RETRY_MAX_MS"))) msg_retry_max_ms   = (uint32_t)strtoul(e, NULL, 10);
		if (getenv("LTP_MSG_EXPIRY_SECS") || getenv("LTP_MSG_HOP_MS") ||
		    getenv("LTP_MSG_RETRY_MIN_MS") || getenv("LTP_MSG_RETRY_MAX_MS"))
			fprintf(stderr, "phone: delivery tunables expiry=%u s hop=%u ms retry=%u..%u ms\n",
			        msg_expiry_secs, msg_hop_interval_ms, msg_retry_min_ms, msg_retry_max_ms);
	}

	// Bring up the portable stack (request/contacts/block_read/cache/session/
	// call/cmdq + wireguard_ask_mac2). block_read pulls ./fsroot/device_record.bin (or
	// resets); we then override identity + endpoint from client.conf — there is
	// no DoH on host, so we ARE the endpoint resolver here.
	config_from_env();   // XYFR_* — the same binary at handheld or host sizes
	kernel_init();
	fprintf(stderr, "config: %u bytes of capacity\n", (unsigned)kernel_alloc_total());
	// phone NO LONGER serves terminals: that is xyfr-termd's job, a separate
	// binary with its own key that runs as its own unprivileged user, so a shell
	// can never touch this process's messaging identity (THREAT_MODEL J-8). phone
	// keeps the `./phone termg <key>` CLIENT for testing, which needs no register.
	memcpy(device_record.my_private_key,       cfg_priv,       KEY_LEN);
	memcpy(device_record.server_static_public, cfg_server_pub, KEY_LEN);
	device_record.endpoints[1].ip4  = cfg_server_ip;
	device_record.endpoints[1].port = cfg_server_port;
	// TELL netif THE IDENTITY CHANGED. It snapshots the key at frame_init (inside
	// kernel_init, above) and does not re-read block afterwards, so writing
	// device_record.my_private_key here is invisible to it. The old login pump re-read the
	// key every tick, which is why this ordering never mattered before.
	//
	// Silently ignoring it is worse than it sounds: block_read had already loaded
	// whatever key this fsroot was last used with, so the CLI came up as THAT
	// identity — observed 2026-08-09 running as a key belonging to another live
	// service, stealing its route at the relay. NULL = plain login, no activation.
	netif_setkey(cfg_priv, NULL);
	block_write();   // persist settings AND provision the keystore from the private key
	                 // (the device does this in seed_test_defaults) — required so the
	                 // encrypted contact ring can mount (it needs the volume_key).
	block_ready = 1;

	fprintf(stderr, "phone: logging in to %u.%u.%u.%u:%u\n",
	        cfg_server_ip & 0xff, (cfg_server_ip >> 8) & 0xff,
	        (cfg_server_ip >> 16) & 0xff, (cfg_server_ip >> 24) & 0xff,
	        (unsigned)cfg_server_port);

	pthread_t stk;
	if (pthread_create(&stk, NULL, stack_thread, NULL) != 0) {
		fprintf(stderr, "phone: pthread_create failed\n"); return 1;
	}

	// TERM client mode: bridge our raw tty <-> the remote shell. The stack thread
	// originates the wg session, opens the "TERM" stream, and pumps the rings; we
	// just shovel raw stdin bytes at it and let its on_data print the output.
	if (term_mode) {
		if (termg_mode) termg_client_start(term_key, term_cmd[0] ? term_cmd : NULL);
		else            term_client_start (term_key, term_cmd[0] ? term_cmd : NULL);
		struct termios oldt, raw;
		int have_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);
		if (have_tty) { raw = oldt; cfmakeraw(&raw); tcsetattr(STDIN_FILENO, TCSANOW, &raw); }
		int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
		fcntl(STDIN_FILENO, F_SETFL, fl | O_NONBLOCK);
		unsigned char ibuf[512];
		while (running && (termg_mode ? termg_client_running() : term_client_running())) {
			int n = (int)read(STDIN_FILENO, ibuf, sizeof ibuf);
			if (n > 0) {
				int cut = -1;                        // Ctrl-] (0x1d) = local quit
				for (int i = 0; i < n; i++) if (ibuf[i] == 0x1d) { cut = i; break; }
				if (termg_mode) termg_client_feed(ibuf, cut >= 0 ? cut : n);
				else            term_client_feed (ibuf, cut >= 0 ? cut : n);
				if (cut >= 0) break;
			} else {
				usleep(5000);
			}
		}
		fcntl(STDIN_FILENO, F_SETFL, fl);
		if (have_tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
		fprintf(stderr, "\r\n%s: session ended\r\n", termg_mode ? "termg" : "term");
		running = 0;
		pthread_join(stk, NULL);
		return 0;
	}

	// One-shot send from the command line: post it on the stack thread (mk =
	// message-by-key, no contact_lookup needed). Then fall into the console loop
	// so the pumps run, the message delivers, and you can watch / 'q' to quit.
	if (msg_key) {
		char mkline[80 + sizeof msg_text];
		snprintf(mkline, sizeof mkline, "msg-key %s %s", msg_key, msg_text);
		cmdq_post(&cmdq_ui_to_fs, mkline);
		fprintf(stderr, "phone: queued msg to %.16s… : \"%s\"\n", msg_key, msg_text);
	}

	print_help();
	char line[512];
	while (running && fgets(line, sizeof(line), stdin)) {
		line[strcspn(line, "\r\n")] = 0;
		if (!line[0]) continue;
		if (!strcmp(line, "q") || !strcmp(line, "quit")) break;
		if (!strcmp(line, "?")) { print_help(); continue; }
		if (!strncmp(line, "log ", 4)) { hal_log_level = atoi(line + 4); continue; }
		if (!strncmp(line, "call-key ", 9)) {
			// Validate the key here so a typo is caught at the console, then post
			// the whole line so call_originate runs on the stack thread (the
			// core-0-only invariant). No contact is added.
			uint8_t pub[KEY_LEN];
			const char *h = line + 9;
			while (*h == ' ')
				h++;
			if (strlen(h) < KEY_LEN * 2 || hex2bytes(h, pub, KEY_LEN) != 0) {
				printf("call-key: need 64 hex chars\n");
				continue;
			}
			cmdq_post(&cmdq_ui_to_fs, line);   // dispatched by cmdq_dispatch (see cmdq.c)
			continue;
		}
		// The two machine verbs go straight into the core under core_lock rather
		// than through the cmdq. A message runs to FILE_ENTRY_MAX and the ring is
		// a tenth of that, so the ferry cannot carry one.
		if (!strncmp(line, "msg-send ", 9)) {
			// "msg-send <8hex-uid> <nbytes>", then exactly nbytes of body on
			// stdin. A count rather than an escape, so every byte of a written
			// answer -- newlines above all -- arrives as it was written.
			uint32_t uid = 0;
			int want = 0;
			if (sscanf(line + 9, "%8x %d", &uid, &want) != 2 || want <= 0) {
				printf("msg-send: need <8hex-uid> <nbytes>, then that many bytes\n");
				continue;
			}
			char *body = malloc((size_t)want + 1);
			if (!body) {
				printf("msg-send: out of memory\n");
				continue;
			}
			size_t got = fread(body, 1, (size_t)want, stdin);
			body[got] = 0;
			if ((int)got != want) {
				printf("msg-send: short body, wanted %d got %zu\n", want, got);
				free(body);
				continue;
			}
			pthread_mutex_lock(&core_lock);
			int rc = msg_post(uid, body);
			pthread_mutex_unlock(&core_lock);
			printf("{\"t\":\"sent\",\"to\":\"%08x\",\"len\":%d,\"ok\":%d}\n",
			       (unsigned)uid, want, rc == 0);
			fflush(stdout);
			free(body);
			continue;
		}
		if (!strncmp(line, "channel-send ", 13)) {
			// "channel-send <id> <nbytes>", then that many bytes on stdin.
			// A line is capped at CHANNEL_TEXT_MAX and nothing stitches two
			// together, so a long answer is split on newlines and posted as
			// several -- which is how it renders anyway.
			unsigned id = 0;
			int want = 0;
			if (sscanf(line + 13, "%u %d", &id, &want) != 2 ||
			    id == 0 || id > CHANNEL_ID_MAX || want <= 0) {
				printf("channel-send: need <id> <nbytes>, then that many bytes\n");
				continue;
			}
			char *body = malloc((size_t)want + 1);
			if (!body) {
				printf("channel-send: out of memory\n");
				continue;
			}
			size_t got = fread(body, 1, (size_t)want, stdin);
			body[got] = 0;
			if ((int)got != want) {
				printf("channel-send: short body, wanted %d got %zu\n", want, got);
				free(body);
				continue;
			}
			// ONE SOURCE LINE PER CHANNEL LINE. A line is rendered with its own
			// "\r\n" (app_channel.c line_render), so a newline left inside one
			// reaches the grid as a bare LF and the next row starts wherever
			// the last one ended.
			uint32_t me = channel_my_partkey();
			int posted = 0;
			int at = 0;
			pthread_mutex_lock(&core_lock);
			while (at < want) {
				int end = at;
				while (end < want && body[end] != '\n')
					end++;
				int len = end - at;
				while (len > 0 && body[at + len - 1] == '\r')
					len--;
				if (len == 0) {
					// channel_append refuses an empty line, so a blank one is
					// a space -- otherwise every paragraph break disappears.
					if (channel_append(me, (uint16_t)id, me, " ", 1) != FILE_NONE)
						posted++;
				}
				int off = 0;
				while (off < len) {
					int take = len - off;
					if (take > CHANNEL_TEXT_MAX)
						take = CHANNEL_TEXT_MAX;
					if (channel_append(me, (uint16_t)id, me,
					                   body + at + off, take) != FILE_NONE)
						posted++;
					off += take;
				}
				at = end + 1;
			}
			pthread_mutex_unlock(&core_lock);
			printf("{\"t\":\"posted\",\"room\":%u,\"len\":%d,\"lines\":%d}\n",
			       id, want, posted);
			fflush(stdout);
			free(body);
			continue;
		}
		if (!strncmp(line, "channel-recv ", 13)) {
			// "channel-recv <id> [after-entry]" — the lines a member wrote into
			// a channel we host, as JSON, oldest first. There is no read bit on
			// a channel line, so the caller carries the cursor and the host
			// stays stateless, which is the whole design.
			unsigned id = 0;
			unsigned long after = 0;
			if (sscanf(line + 13, "%u %lu", &id, &after) < 1 ||
			    id == 0 || id > CHANNEL_ID_MAX) {
				printf("channel-recv: need <id> [after-entry]\n");
				continue;
			}
			pthread_mutex_lock(&core_lock);
			channel_dump_incoming((uint16_t)id, (uint32_t)after);
			pthread_mutex_unlock(&core_lock);
			printf("{\"t\":\"end\"}\n");
			fflush(stdout);
			continue;
		}
		if (!strncmp(line, "msg-recv", 8) && (line[8] == 0 || line[8] == ' ')) {
			// "msg-recv [8hex-uid]" — the same dump app_chat_main prints live,
			// asked for. What a reader missed while it was down.
			const char *a = line + 8;
			while (*a == ' ')
				a++;
			uint32_t uid = 0;
			if (*a && sscanf(a, "%8x", &uid) != 1) {
				printf("msg-recv: bad userid: [%s]\n", a);
				continue;
			}
			pthread_mutex_lock(&core_lock);
			msg_dump_received(uid);
			pthread_mutex_unlock(&core_lock);
			printf("{\"t\":\"end\"}\n");
			fflush(stdout);
			continue;
		}
		// Everything else is a cmdq verb — hand it to the stack (verb_table, cmdq.c).
		if (!cmdq_post(&cmdq_ui_to_fs, line))
			printf("(cmdq full; dropped: %s)\n", line);
	}

	running = 0;
	pthread_join(stk, NULL);
	return 0;
}
