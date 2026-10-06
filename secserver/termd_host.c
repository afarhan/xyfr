// termd_host.c — the standalone REMOTE-TERMINAL server (THREAT_MODEL J-8).
//
// Split out of `phone` on purpose. `phone` is the messaging/voice/PTT client
// and runs as YOU, holding your identity key. This daemon does nothing but
// serve terminals, holds its OWN separate key, and is meant to run as a
// dedicated unprivileged user (e.g. `xyfr`). The consequences:
//
//   * a shell it forks is a child of THIS process, so it already runs as that
//     user -- no setuid, no per-fork privilege drop.
//   * that shell cannot read your messaging private key, because that key lives
//     in a different file owned by a different user. The isolation is plain
//     filesystem permissions, not a policy we have to enforce in code.
//
// It links the same shared portable core as `phone` (the pump is monolithic),
// but registers ONLY the terminal app, runs no console, and provides null audio
// -- so there is no ALSA dependency and a stray inbound voice/PTT frame to this
// key is simply dropped.
//
// Config `termd.conf` (own key!):  server_key, my_private, server_ip,
// server_port, and allow_terminal=<8hex> lines (default deny -- see term_host).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include "view.h"        // view_cb_t, for the UI stubs below
#include "hal.h"
#include "device_record.h"
#include "kernel.h"       // kernel_slice + the screen table the platform owns
#include "term_host.h"    // term_host_register / term_allow_add / term_pump
#include "config_env.h"
#include "logstamp.h"     // timestamp every stdout/stderr line
#include "phone_state.h" // WIFI_* + enum phone_state (the stubs below implement these)

extern void kernel_init(void);
extern void kernel_pump(void);
extern void kernel_slice(void);

volatile int debug_line0 = 0;
static volatile int running = 1;

// ---- platform seam the shared core expects (host side) --------------------
// Same inert stubs as phone_host.c: no WiFi state machine, no UI, no NTP, no
// contact-lookup, no DoH. A headless Linux daemon is simply always "online".
int    wifi_get_status(void)              { return WIFI_ONLINE; }
void   phone_state_set(enum phone_state s) { (void)s; }
time_t get_current_time_seconds(void)     { return time(NULL); }
int    validate_public_key(const uint8_t *k, void *ctx) { (void)k; (void)ctx; return 1; }
// contacts.c hands a query answer here on a device with no private key. A daemon
// always has one from termd.conf, so this cannot fire; it exists to link.
void   registration_query_answer(const uint8_t key[32], int status) {
	(void)key; (void)status;
}
bool   kernel_handle_non_wg(uint8_t *b, int n, uint32_t ip, uint16_t port) {
	(void)b; (void)n; (void)ip; (void)port; return false;
}
void   terminal_net_pump(void)            {}   // the DEVICE-side client; unused here
// Contact lookup is no longer stubbed: it moved into contacts.c (2026-08-09)
// when contact_lookup.c was absorbed. Any target linking BOTH this file and
// contacts.c gets the real resolver; redefining them here would be a duplicate
// symbol. (This TU currently has no linking target — vterm_glue_test compiles
// it but links td_contacts.o without td_host.o.)

// ---- null audio HAL -------------------------------------------------------
// call.c / ptt.c are linked (kernel_pump calls their pumps) but this daemon
// never runs audio. Provide no-op sinks/sources so there is no ALSA dependency;
// a voice/PTT frame arriving on this key is decoded and dropped.
void audio_init(void)  {}
void audio_open(void)  {}
void audio_close(void) {}
void audio_play_voice(const uint8_t *pcm, int len) { (void)pcm; (void)len; }
void audio_play_ptt(const uint8_t *pcm, int len)   { (void)pcm; (void)len; }
int  audio_capture_ready(void)                     { return 0; }
int  audio_capture_voice(int16_t *out, int max)    { (void)out; (void)max; return 0; }
void audio_ringback_frame(int16_t *o, int n, uint16_t *fc) { (void)fc; memset(o, 0, (size_t)n * sizeof(int16_t)); }
void audio_ring_start(void) {}
void audio_ring_stop(void)  {}

// ---- UI stubs -------------------------------------------------------------
// app_call.c is one file holding the call model AND its screen, and the model
// is what makes this binary a usable test peer. So a headless build links the
// screen half too and answers for the UI it calls.
int  speaker_level = 5;
int  mic_muted     = 0;
void audio_set_speaker_level(int notch) { speaker_level = notch; }
// No keyboard here, so nothing is ever a volume key. app_call.c calls this.
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

// The chat screens likewise (app_chat.c): pure view code over the logbook, so a
// headless build only has to satisfy the screen table.
// A channel prints text through the terminal's grid, which is device-side. This
// daemon serves terminals only, so it displays nothing and answers nothing.
void channel_display_reset(void) { }
void channel_display_clear(void) { }
void channel_display_text(const char *text, int len) { (void)text; (void)len; }
void channel_display_pump(void) { }
const char *channel_display_key(int key) { (void)key; return NULL; }
bool channel_display_has_text(void) { return false; }
int channel_display_capacity(void) { return 80 * 23; }

bool channel_display_move(int dir) {
	(void)dir;
	return false;
}

// THIS BUILD'S ANSWER to "who may enter a channel we host" (channel_log.h). This
// daemon serves terminals and hosts no channels, so nobody enters one.
int allow_into_channel(uint16_t channel_id, uint32_t contact_id) {
	(void)channel_id;
	(void)contact_id;
	return 0;
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

int app_chat_main(int message, uint32_t param) {
	(void)message; (void)param; return 0;
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

// ---- config ---------------------------------------------------------------

static int hex2bytes(const char *hex, uint8_t *out, int out_len) {
	for (int i = 0; i < out_len; i++) {
		int hi, lo;
		char c = hex[2 * i], d = hex[2 * i + 1];
		if      (c >= '0' && c <= '9') hi = c - '0';
		else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
		else return -1;
		if      (d >= '0' && d <= '9') lo = d - '0';
		else if (d >= 'a' && d <= 'f') lo = d - 'a' + 10;
		else if (d >= 'A' && d <= 'F') lo = d - 'A' + 10;
		else return -1;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static uint32_t parse_ipv4(const char *s) {
	unsigned a, b, c, d;
	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
	return (uint32_t)(a | (b << 8) | (c << 16) | (d << 24));   // little-endian, as the core stores it
}

static uint8_t  cfg_priv[KEY_LEN];
static uint8_t  cfg_server_pub[KEY_LEN];
static uint32_t cfg_server_ip   = 0;
static uint16_t cfg_server_port = 5004;
static int      have_priv = 0, have_server_pub = 0;

static int load_config(const char *path) {
	FILE *f = fopen(path, "r");
	if (!f) { fprintf(stderr, "termd: cannot open %s\n", path); return -1; }
	char line[512];
	while (fgets(line, sizeof line, f)) {
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
			if (strlen(val) >= 8) term_allow_add((uint32_t)strtoul(val, NULL, 16));
		}
		else if (!strcmp(key, "persistent"))           term_set_persistent(atoi(val));
		else if (!strcmp(key, "persist_timeout_secs")) term_set_persist_timeout_secs(atoi(val));
	}
	fclose(f);
	if (!have_priv || !have_server_pub || !cfg_server_ip) {
		fprintf(stderr, "termd: %s needs my_private, server_key, server_ip\n", path);
		return -1;
	}
	return 0;
}

static void on_signal(int s) { (void)s; running = 0; }

int main(int argc, char **argv) {
	logstamp_install();   // timestamp every stdout/stderr line from here on
	const char *conf = (argc > 1) ? argv[1] : "termd.conf";
	if (load_config(conf) != 0) return 1;

	signal(SIGINT,  on_signal);
	signal(SIGTERM, on_signal);
	signal(SIGCHLD, SIG_IGN);      // reap forked shells without zombies (we also waitpid)

	config_from_env();   // XYFR_* — a daemon serving many peers is sized larger
	kernel_init();
	term_host_register();          // THE point of this binary: serve inbound terminals

	memcpy(device_record.my_private_key,       cfg_priv,       KEY_LEN);
	memcpy(device_record.server_static_public, cfg_server_pub, KEY_LEN);
	device_record.endpoints[1].ip4  = cfg_server_ip;
	device_record.endpoints[1].port = cfg_server_port;
	block_write();
	block_ready = 1;

	fprintf(stderr, "termd: terminal server up; logging in to %u.%u.%u.%u:%u\n",
	        cfg_server_ip & 0xff, (cfg_server_ip >> 8) & 0xff,
	        (cfg_server_ip >> 16) & 0xff, (cfg_server_ip >> 24) & 0xff,
	        (unsigned)cfg_server_port);

	while (running) {
		kernel_pump();
		kernel_slice();
		term_pump();
		hal_delay_ms(5);
	}
	fprintf(stderr, "termd: shutting down\n");
	return 0;
}
