// app_home.c - the home app: the conversations list, Settings, Security, Admin,
// and the two generic screens every app can use - the pick (a chooser; a
// confirm is a pick of two) and the ask (a text prompt).
//
// The settings are the model: every row renders live from device_record and
// every action writes it back (plus flag_save_block), so a screen re-render is
// the refresh, with no cached state to keep coherent.
//
// The flows that are still driven by commands.cpp (WiFi, Register/Sign In, disk
// key, PIN, burner, Backup/Restore reboots, Find-a-Relay) are launched through
// one handoff seam: screen_clear() empties the kernel stack without go_home,
// the opener view_set()s its own screen, and its eventual go_home() lands back
// here.
//
// Core 0. Portable C (host stubs satisfy the screen table).

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "hal.h"
#include "kernel.h"
#include "device_record.h" // struct device_record, flag_save_block
#include "audio.h"         // audio_set_mode, AUDIO_* modes
#include "ui.h"            // the commands.cpp launchers + wifi state
#include "ui_symbols.h"
#include "config.h"
#include "view.h"
#include "contacts.h"      // contact_by_index + the missed-request (knock) ring
#include "msg.h"           // msg_ensure_log, thread heads, unread state, previews
#include "filesystem.h"    // file_list, FILE_TYPE_CHANNEL
#include "channel_log.h"
#include "call.h"          // call_holding_audio - the pinned return-to-call row
#include "cmdq.h"          // home_needs_refresh - the peer-less repaint flag
#include "wg.h"            // curve25519 + get_part_key: the title is our userid

// A radio pick shows at most this many options, each label this long.
#define RADIO_MAX_OPTIONS 4
#define RADIO_LABEL_MAX   24

#define SECONDS_PER_DAY  86400u
#define SECONDS_PER_HOUR 3600u
#define SECONDS_PER_MIN  60u

#define ARRAY_COUNT(a) ((int)(sizeof (a) / sizeof (a)[0]))

// app_chat.c's, declared here as kernel.c declares the app entry points: the
// screen push carries one uint32_t and a thread's name needs two halves, so
// this names the group the next APP_CHAT push is for.
void channel_open(uint16_t channel_id);
void channel_menu_open(uint32_t host, uint16_t channel_id);

// ---- structs ---------------------------------------------------------------

struct home_row {
	uint32_t partkey;       // the peer, or the host for a group
	uint16_t channel_id;    // 0 = the 1:1 thread, else one of that host's channels
	uint64_t seq;           // newest record's id (0 = silent thread)
	char     name[MAX_NAME];
	uint8_t  is_contact;    // 0 for a group row
	uint8_t  status;        // CONTACT_KEY_*, which drives the dot
	uint8_t  verified;      // user-confirmed key: green vs orange dot
	uint8_t  unread;        // red dot
	uint8_t  no_endpoint;   // contact with no endpoint -> "?" prefix
	char     preview[32];   // start of the newest message
};

// What a selected row asks home_legacy_open() for, carried past the kernel's
// selection queue.
enum home_open_what {
	HOME_OPEN_REQUESTS = 0,
	HOME_OPEN_ADD,
	HOME_OPEN_CONTACT,
	HOME_OPEN_STRANGER,
};

// Launchers that live in C++ translation units and are not yet in a shared
// header. C linkage is required at their definitions; the link fails loudly
// if it is missing.
void registration_start(void);
void key_import_start(void);
void disk_key_start(void);
void pin_set_start(void);
void burner_set_start(void);
void pin_lock(void);
void backup_mode_enter(void);
void restore_request_reboot(void);
void firmware_request_reboot(void);
void bootsel_reboot(void);
void do_unblocking(void);
void wifi_open(void);
void relay_step_mark_done(void);   // commands.cpp: onboarding relay gate latch
bool parse_ip_port(const char *in, uint32_t *ip4, uint16_t *port);
extern volatile int flag_wipe_device;
// uint8_t, matching its definition in xyfr.ino. The line above does not
// match its own -- that one is a uint8_t too, and writing it through an int
// lvalue is undefined. Left alone rather than changed in passing.
extern volatile uint8_t flag_compact_store;

// Short names for the current setting values, shown in the Settings rows.
const char *presence_name(int p) {
	switch (p) {
	case PRESENCE_BUSY:    return "Busy";
	case PRESENCE_NOCALLS: return "No Calls";
	case PRESENCE_OFFLINE: return "Offline";
	default:               return "Normal";
	}
}

const char *allow_name(int a) {
	if (a == ALLOW_CONTACTS)
		return "Contacts";
	return "Requests";
}

const char *audio_mode_name(int m) {
	switch (m) {
	case AUDIO_HANDSFREE:    return "Hands free";
	case AUDIO_SPEAKERPHONE: return "Speakerphone";
	default:                 return "Normal";
	}
}

// ---- the pick screen (APP_PICK) -----------------------------------------
// One request at a time, stashed here by screen_pick(). The callback runs from
// the kernel's queued-selection path and must not transition: the pick pops
// itself afterwards, and the caller's FOREGROUND-on-return renders the new
// state.

static const char  *pick_title;
static const char  *pick_prompt;
static const char **pick_items;
static void        (*pick_cb)(int index, const char *text);
static int          pick_idx;         // index the bridge saw, for APP_SELECTION

static int pick_bridge_cb(view_op_t op, int i, void *data) {
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	if (!pick_items)
		return 0;
	int n = 0;
	while (pick_items[n])
		n++;
	if (i < 0 || i >= n)
		return 0;
	pick_idx = i;
	screen_selection(pick_items[i]);
	return 0;
}

void screen_pick(const char *title, const char *prompt, const char **items,
                 void (*on_pick)(int index, const char *text)) {
	pick_title  = title;
	pick_prompt = prompt;
	pick_items  = items;
	pick_cb     = on_pick;
	screen_push(APP_PICK, 0);
}

int app_pick_main(int message, uint32_t param) {
	switch (message) {
	case APP_FOREGROUND:
		view_set(pick_bridge_cb, pick_title, pick_prompt, pick_items, NULL, NULL);
		return 1;
	case APP_SELECTION: {
		void (*cb)(int, const char *) = pick_cb;
		pick_cb = NULL;                    // one answer per request
		if (cb)
			cb(pick_idx, (const char *)(uintptr_t)param);
		screen_pop();
		return 1;
	}
	default:
		return 0;
	}
}

// ---- the ask screen (APP_ASK) -------------------------------------------
// A question and a text field. on_answer returns NULL to accept (the screen
// pops) or an error prompt to re-show with the typed text preserved.

static const char *ask_title;
static const char *ask_question;
static const char *ask_mask;
static const char *ask_prefill;
static bool        ask_secret;         // accepted; echo masking waits on the engine
static const char *(*ask_cb)(const char *text);
static char        ask_retext[64];     // survives the re-render on a rejected answer

// The view needs a cb even with no list: -1 bounds the (empty) list and
// EDIT_ENTER carries the answer into the kernel's selection queue.
static int ask_view_cb(view_op_t op, int i, void *data) {
	(void)i;
	if (op == LIST_GET_ITEM)
		return -1;
	if (op != EDIT_ENTER)
		return 0;
	screen_selection((const char *)data);
	return 0;
}

static void ask_show(const char *question, const char *prefill) {
	view_set(ask_view_cb, ask_title, question, NULL, "", prefill);
	if (ask_mask)
		view_set_input_filter(ask_mask);
}

void screen_ask(const char *title, const char *question, const char *mask,
                const char *prefill, bool is_secret,
                const char *(*on_answer)(const char *text)) {
	ask_title    = title;
	ask_question = question;
	ask_mask     = mask;
	ask_prefill  = prefill;
	ask_secret   = is_secret;
	ask_cb       = on_answer;
	screen_push(APP_ASK, 0);
}

int app_ask_main(int message, uint32_t param) {
	switch (message) {
	case APP_FOREGROUND:
		ask_show(ask_question, ask_prefill);
		return 1;
	case APP_SELECTION: {
		const char *text = (const char *)(uintptr_t)param;
		if (!ask_cb) {
			screen_pop();
			return 1;
		}
		const char *err = ask_cb(text);
		if (!err) {
			ask_cb = NULL;
			screen_pop();
			return 1;
		}
		// Rejected: re-show with the error as the question and the input kept.
		snprintf(ask_retext, sizeof ask_retext, "%s", text);
		ask_show(err, ask_retext);
		return 1;
	}
	default:
		return 0;
	}
}

// ---- Settings (APP_SETTINGS) --------------------------------------------

static const char *settings_items[12];
static char label_wifi[64];
static char label_ringer[32];
static char label_presence[32];
static char label_allow[32];
static char label_audio[32];
static char label_conf[40];

static int settings_bridge_cb(view_op_t op, int i, void *data) {
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	if (i >= 0 && settings_items[i])
		screen_selection(settings_items[i]);
	return 0;
}

static void settings_render(void) {
	extern char wifi_ap_name[];        // wifi_ui.cpp: live SSID ("" when offline)
	if (wifi_ap_name[0])
		snprintf(label_wifi, sizeof label_wifi, LV_SYMBOL_WIFI "  WiFi (%s) ...", wifi_ap_name);
	else
		snprintf(label_wifi, sizeof label_wifi, LV_SYMBOL_WIFI "  WiFi ...");
	const char *ringer = "Off";
	if (device_record.ringer)
		ringer = "On";
	snprintf(label_ringer, sizeof label_ringer, LV_SYMBOL_BELL "  Ringer - %s", ringer);
	snprintf(label_presence, sizeof label_presence,
	         LV_SYMBOL_BELL "  Presence - %s", presence_name(device_record.presence));
	snprintf(label_allow, sizeof label_allow,
	         LV_SYMBOL_EYE_OPEN "  Allow - %s", allow_name(device_record.allow_policy));
	snprintf(label_audio, sizeof label_audio,
	         LV_SYMBOL_VOLUME_MAX "  Audio - %s", audio_mode_name(device_record.audio_mode));
	const char *conf = "Off";
	if (device_record.ptt_conference)
		conf = "On";
	snprintf(label_conf, sizeof label_conf,
	         LV_SYMBOL_VOLUME_MAX "  PTT Conference - %s", conf);
	int n = 0;
	settings_items[n++] = label_wifi;
	settings_items[n++] = label_ringer;
	settings_items[n++] = label_presence;
	settings_items[n++] = label_allow;
	settings_items[n++] = label_audio;
	settings_items[n++] = label_conf;
	settings_items[n++] = LV_SYMBOL_EYE_CLOSE "  Lock";
	settings_items[n++] = LV_SYMBOL_KEYBOARD  "  Security...";
	settings_items[n++] = LV_SYMBOL_LIST      "  Admin...";
	settings_items[n]   = NULL;
	view_set(settings_bridge_cb, "Settings", NULL, settings_items, NULL, NULL);
}

// The three radios, each a screen_pick over a static table. The OK mark is
// rebuilt on every open from device_record.
static const char *radio_items[RADIO_MAX_OPTIONS + 2];
static char        radio_marked[RADIO_MAX_OPTIONS][RADIO_LABEL_MAX];

static void radio_build(const char **names, int count, int current) {
	for (int i = 0; i < count && i < RADIO_MAX_OPTIONS; i++) {
		const char *mark = "     ";
		if (i == current)
			mark = LV_SYMBOL_OK "  ";
		snprintf(radio_marked[i], sizeof radio_marked[i], "%s%s", mark, names[i]);
		radio_items[i] = radio_marked[i];
	}
	radio_items[count] = NULL;
}

static void on_presence_pick(int i, const char *text) {
	(void)text;
	if (i >= PRESENCE_NORMAL && i <= PRESENCE_OFFLINE) {
		device_record.presence = (uint8_t)i;
		flag_save_block = 1;
	}
}

static void on_allow_pick(int i, const char *text) {
	(void)text;
	if (i == ALLOW_ALL || i == ALLOW_CONTACTS) {
		device_record.allow_policy = (uint8_t)i;
		flag_save_block = 1;
	}
}

static void on_audio_pick(int i, const char *text) {
	(void)text;
	if (i == AUDIO_NORMAL || i == AUDIO_HANDSFREE || i == AUDIO_SPEAKERPHONE) {
		device_record.audio_mode = (uint8_t)i;
		audio_set_mode(i);         // apply now: route the ISRs, arm the VOX
		flag_save_block = 1;
	}
}

int app_settings_main(int message, uint32_t param) {
	switch (message) {
	case APP_FOREGROUND:
		settings_render();
		return 1;
	case APP_SELECTION: {
		const char *text = (const char *)(uintptr_t)param;
		if (strstr(text, "WiFi")) {
			screen_clear();
			wifi_open();
			return 1;
		}
		if (strstr(text, "PTT Conference")) {
			if (device_record.ptt_conference)
				device_record.ptt_conference = 0;
			else
				device_record.ptt_conference = 1;
			flag_save_block = 1;
			settings_render();
			return 1;
		}
		if (strstr(text, "Ringer")) {
			if (device_record.ringer)
				device_record.ringer = 0;
			else
				device_record.ringer = 1;
			flag_save_block = 1;
			settings_render();
			return 1;
		}
		if (strstr(text, "Presence")) {
			static const char *names[] = { "Normal", "Busy", "No Calls", "Offline" };
			radio_build(names, ARRAY_COUNT(names), device_record.presence);
			screen_pick("Presence",
			            "Normal: everything rings.\nBusy: only Star rings.\n"
			            "No Calls: calls off, texts on.\nOffline: reject everyone.",
			            radio_items, on_presence_pick);
			return 1;
		}
		if (strstr(text, "Allow")) {
			static const char *names[] = { "Requests", "Contacts" };
			radio_build(names, ARRAY_COUNT(names), device_record.allow_policy);
			screen_pick("Allow",
			            "Who may reach you.\nRequests: strangers can knock;\n"
			            "you approve them.\nContacts: only saved contacts.",
			            radio_items, on_allow_pick);
			return 1;
		}
		if (strstr(text, "Audio")) {
			static const char *names[] = { "Normal", "Hands free", "Speakerphone" };
			radio_build(names, ARRAY_COUNT(names), device_record.audio_mode);
			screen_pick("Audio", NULL, radio_items, on_audio_pick);
			return 1;
		}
		if (strstr(text, "Lock")) {
			screen_clear();
			pin_lock();
			return 1;
		}
		if (strstr(text, "Security")) {
			screen_push(APP_SECURITY, 0);
			return 1;
		}
		if (strstr(text, "Admin")) {
			screen_push(APP_ADMIN, 0);
			return 1;
		}
		return 1;
	}
	default:
		return 0;
	}
}

// ---- Admin (APP_ADMIN) --------------------------------------------------

static const char *admin_items[16];
static char        label_devmode[36];

static int admin_bridge_cb(view_op_t op, int i, void *data) {
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	if (i >= 0 && admin_items[i])
		screen_selection(admin_items[i]);
	return 0;
}

static void admin_render(void) {
	int n = 0;
	admin_items[n++] = LV_SYMBOL_GPS      "  Relay IP...";
	admin_items[n++] = LV_SYMBOL_REFRESH  "  Find a Relay...";
	admin_items[n++] = LV_SYMBOL_UPLOAD   "  Backup...";
	admin_items[n++] = LV_SYMBOL_DOWNLOAD "  Restore...";
	admin_items[n++] = LV_SYMBOL_UPLOAD   "  Firmware Update...";
	admin_items[n++] = LV_SYMBOL_SAVE     "  Compact Storage...";
	admin_items[n++] = LV_SYMBOL_LIST     "  About";
	admin_items[n]   = NULL;
	view_set(admin_bridge_cb, "Admin", NULL, admin_items, NULL, NULL);
}

// ---- Security (APP_SECURITY): identity, locks, and the dev-mode gate ----

static const char *security_items[10];

static int security_bridge_cb(view_op_t op, int i, void *data) {
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	if (i >= 0 && security_items[i])
		screen_selection(security_items[i]);
	return 0;
}

static void security_render(void) {
	const char *dev = "Off";
	if (device_record.dev_mode)
		dev = "On";
	snprintf(label_devmode, sizeof label_devmode,
	         LV_SYMBOL_SETTINGS "  Developer Mode: %s", dev);
	int n = 0;
	security_items[n++] = LV_SYMBOL_SD_CARD  "  Register...";
	security_items[n++] = LV_SYMBOL_EDIT     "  Sign In...";
	security_items[n++] = LV_SYMBOL_SAVE     "  Change Disk Key...";
	security_items[n++] = LV_SYMBOL_KEYBOARD "  Set PIN...";
	security_items[n++] = LV_SYMBOL_WARNING  "  Set Burner Code...";
	security_items[n++] = label_devmode;
	if (device_record.dev_mode)
		security_items[n++] = LV_SYMBOL_DOWNLOAD "  BOOTSEL...";
	security_items[n++] = LV_SYMBOL_TRASH    "  Wipe Out!";
	security_items[n]   = NULL;
	view_set(security_bridge_cb, "Security", NULL, security_items, NULL, NULL);
}

static void on_devmode_pick(int i, const char *text) {
	(void)text;
	if (i == 0) {                      // OK -> enable + persist
		device_record.dev_mode = 1;
		flag_save_block = 1;
	}
}

static void on_bootsel_pick(int i, const char *text) {
	(void)text;
	if (i == 0)
		bootsel_reboot();              // reboots into the UF2 bootloader; does not return
}

static void on_restore_pick(int i, const char *text) {
	(void)text;
	if (i == 0)
		restore_request_reboot();      // warm-reboot into restore; does not return
}

static void on_firmware_pick(int i, const char *text) {
	(void)text;
	if (i == 0)
		firmware_request_reboot();     // warm-reboot into firmware mode; does not return
}

// Compaction is the only thing that frees space, and it is a long blocking pass
// over the whole region -- 17 s just to erase it on this hardware. Say what the
// user will see, because a screen that sits still for minutes reads as a crash.
static void on_compact_pick(int index, const char *text) {
	(void)text;
	if (index != 0)
		return;
	hal_debug(LOG_WARNING, "compact: requested - core 0 will compact + reboot\n");
	flag_compact_store = 1;        // consumed in loop(): compact with progress, then reboot
}

static const char *on_wipe_answer(const char *text) {
	if (text && strcmp(text, "yes") == 0) {
		hal_debug(LOG_WARNING, "wipe: requested - core 0 will crypto-erase + reboot\n");
		flag_wipe_device = 1;          // consumed in loop(): store_wipe + reboot
		return NULL;
	}
	return "This wipes out everything from this phone.\n"
	       "Type exactly 'yes' and press Enter to proceed.";
}

static const char *on_relay_ip_answer(const char *text) {
	uint32_t ip4 = 0;
	uint16_t port = 50004;             // default when :PORT is omitted
	if (!parse_ip_port(text, &ip4, &port))
		return "Not a valid address.\nType A.B.C.D or A.B.C.D:PORT, then Enter.";
	device_record.endpoints[1].ip4  = ip4;
	device_record.endpoints[1].port = port;
	flag_save_block = 1;
	relay_step_mark_done();            // only matters during onboarding; harmless after
	return NULL;
}

// Shared with the legacy onboarding gate (commands.cpp go_relay_ip): one entry
// screen for both worlds.
void relay_ip_ask_open(void) {
	static char prefill[24];
	const char *seed = NULL;
	uint32_t ip = device_record.endpoints[1].ip4;
	if (ip) {
		snprintf(prefill, sizeof prefill, "%u.%u.%u.%u:%u",
		         (unsigned)(ip & 0xFF), (unsigned)((ip >> 8) & 0xFF),
		         (unsigned)((ip >> 16) & 0xFF), (unsigned)((ip >> 24) & 0xFF),
		         (unsigned)device_record.endpoints[1].port);
		seed = prefill;
	}
	screen_ask("Relay IP",
	           "Enter the relay address\nA.B.C.D or A.B.C.D:PORT, then Enter.",
	           "0123456789.:", seed, false, on_relay_ip_answer);
}

static const char *confirm_ok_cancel[] = {
	LV_SYMBOL_OK    "  OK",
	LV_SYMBOL_CLOSE "  Cancel",
	NULL,
};
static const char *info_return[] = {
	"Return",
	NULL,
};

// The Restore confirm, WiFi-gated. Exported because the welcome chooser's
// "Restore from a backup" path pushes the same screen.
void restore_confirm_push(void) {
	if (wifi_get_status() != WIFI_ONLINE) {
		screen_pick("Restore",
		            "Restore needs a WiFi connection.\nConnect WiFi, then try again.",
		            info_return, NULL);
		return;
	}
	screen_pick("Restore",
	            "You are going to Restore an earlier backup of this device.\n\n"
	            "This needs to reboot the device. The screen will go blank "
	            "for a while - don't panic.",
	            confirm_ok_cancel, on_restore_pick);
}

static char about_text[280];

int app_security_main(int message, uint32_t param) {
	switch (message) {
	case APP_FOREGROUND:
		security_render();
		return 1;
	case APP_SELECTION: {
		const char *text = (const char *)(uintptr_t)param;
		if (strstr(text, "Register")) {
			screen_clear();
			registration_start();
			return 1;
		}
		if (strstr(text, "Sign In")) {
			screen_clear();
			key_import_start();
			return 1;
		}
		if (strstr(text, "Disk Key")) {
			screen_clear();
			disk_key_start();
			return 1;
		}
		if (strstr(text, "Set PIN")) {
			screen_clear();
			pin_set_start();
			return 1;
		}
		if (strstr(text, "Burner")) {
			screen_clear();
			burner_set_start();
			return 1;
		}
		if (strstr(text, "Developer Mode")) {
			if (device_record.dev_mode) {          // on -> off directly (tightens)
				device_record.dev_mode = 0;
				flag_save_block = 1;
				security_render();
				return 1;
			}
			screen_pick("Developer Mode",
			            "\nDeveloper Mode is only meant for development.\n\n"
			            "DO NOT enable this if your phone has data that shouldn't be "
			            "read by others: it opens the serial port and relaxes the "
			            "update protections.",
			            confirm_ok_cancel, on_devmode_pick);
			return 1;
		}
		if (strstr(text, "BOOTSEL")) {
			screen_pick("BOOTSEL",
			            "\nThis reboots into the UF2 bootloader for a reflash.\n\n"
			            "The screen goes dark and the device shows up on your "
			            "computer as a USB drive named RP2350. Drop the new "
			            "firmware .uf2 file onto that drive.\n\n"
			            "Changed your mind? Switch the device off and on.",
			            confirm_ok_cancel, on_bootsel_pick);
			return 1;
		}
		if (strstr(text, "Wipe Out")) {
			screen_ask("Wipe Out",
			           "This wipes out everything from this phone.\n"
			           "Type 'yes' and press Enter to proceed.",
			           NULL, NULL, false, on_wipe_answer);
			return 1;
		}
		return 1;
	}
	default:
		return 0;
	}
}

int app_admin_main(int message, uint32_t param) {
	switch (message) {
	case APP_FOREGROUND:
		admin_render();
		return 1;
	case APP_SELECTION: {
		const char *text = (const char *)(uintptr_t)param;
		if (strstr(text, "Relay IP")) {
			relay_ip_ask_open();
			return 1;
		}
		if (strstr(text, "Find a Relay")) {
			screen_clear();
			do_unblocking();
			return 1;
		}
		if (strstr(text, "Backup")) {
			screen_clear();
			backup_mode_enter();
			return 1;
		}
		if (strstr(text, "Restore")) {
			restore_confirm_push();
			return 1;
		}
		if (strstr(text, "Firmware")) {
			if (wifi_get_status() != WIFI_ONLINE) {
				screen_pick("Firmware Update",
				            "The update needs a WiFi connection.\nConnect WiFi, then try again.",
				            info_return, NULL);
				return 1;
			}
			screen_pick("Firmware Update",
			            "You are going to update this device's firmware over WiFi.\n\n"
			            "This needs to reboot the device. The screen will go blank "
			            "for a while - don't panic.",
			            confirm_ok_cancel, on_firmware_pick);
			return 1;
		}
		if (strstr(text, "Compact")) {
			screen_pick("Compact Storage",
			            "Deleted messages still hold their space until this runs. "
			            "It reclaims it.\n\n"
			            "The screen shows progress and the phone restarts when it "
			            "finishes. It can take a few minutes.\n\n"
			            "KEEP THE POWER CONNECTED.",
			            confirm_ok_cancel, on_compact_pick);
			return 1;
		}
		if (strstr(text, "About")) {
			const int checksum_len = (int)sizeof device_record.ota_checksum;
			bool have_checksum = false;
			for (int k = 0; k < checksum_len; k++) {
				if (device_record.ota_checksum[k]) {
					have_checksum = true;
					break;
				}
			}
			char checksum_hex[80];
			if (have_checksum) {
				for (int k = 0; k < checksum_len; k++)
					snprintf(checksum_hex + k * 2, 3, "%02x",
					         device_record.ota_checksum[k]);
			} else {
				strcpy(checksum_hex, "not set (flashed directly)");
			}
			// Uptime, for measuring battery life. now_ms() wraps at ~49 days, far
			// past any charge.
			uint32_t up_secs = now_ms() / 1000u;
			unsigned up_days = up_secs / SECONDS_PER_DAY;
			unsigned up_hrs  = (up_secs % SECONDS_PER_DAY) / SECONDS_PER_HOUR;
			unsigned up_mins = (up_secs % SECONDS_PER_HOUR) / SECONDS_PER_MIN;
			// Storage, because a full store is silent otherwise: the phone
			// simply stops accepting messages, from everyone, for good. The
			// number was only ever visible over the serial `logstat`, which
			// nobody holding the phone can reach. Compact Storage is what acts
			// on it, and it is one screen away in this same menu.
			int used = file_storage_usage();
			// Storage FIRST. The prompt is longer than the screen shows and
			// the tail is simply not visible -- the checksum has been off the
			// bottom all along -- so a line added in the middle reads as a line
			// that never arrived.
			snprintf(about_text, sizeof about_text,
			         "\nStorage: %d%% used, %d contacts\n\n"
			         "Since %u day(s) %u:%02u hours\n\n"
			         "Build: %s %s\n\n"
			         "Checksum:\n%s\n\n"
			         "(c) Ashhar Farhan, 2026\nReleased under GPL 3.0",
			         used, contact_count(), up_days, up_hrs, up_mins,
			         __DATE__, __TIME__, checksum_hex);
			screen_pick("About", about_text, info_return, NULL);
			return 1;
		}
		return 1;
	}
	default:
		return 0;
	}
}

// ---- home (APP_HOME) -----------------------------------------------------
// The conversations list: one row per saved contact, sorted
// newest-activity-first, with the pinned return-to-call and knock-requests rows
// above the fixed Settings and Add rows. The store is the model: a render
// re-reads the filesystem, and home_rows is only a bounded cache of that walk,
// invalidated on any change signal.

static struct home_row *home_rows;       // home_cap rows, allocated on the first walk
static int      home_cap;
static int      home_n;
static uint32_t home_seen_epoch = 0xFFFFFFFF;
static bool     home_dirty = true;
static bool     home_on_top;

static int      home_sel_what;
static uint32_t home_sel_partkey;

// commands.cpp: the screens home still launches there (requests, add-contact,
// the contact menu) behind one seam.
void home_legacy_open(int what, uint32_t pk);
void home_vol_arm(void);

// A leading "###" is the view engine's heading marker (view.cpp:63), so no '#'
// from a contact name is allowed to reach a row.
static void copy_without_hash(char *dst, int cap, const char *src) {
	int n = 0;
	for (; src && src[n] && n < cap - 1; n++) {
		if (src[n] == '#')
			dst[n] = ' ';
		else
			dst[n] = src[n];
	}
	dst[n] = 0;
}

// One-line preview of a thread's newest message; empty for a call record.
static void home_fill_preview(const struct msg_record *h, char *out, int cap) {
	out[0] = 0;
	if (h->payload_len == 0)
		return;                       // a call record: no payload at all
	uint8_t buf[48];
	// No length arithmetic: msg_read stops at the end of the message, so asking
	// for more than there is costs nothing and saves a read per contact on every
	// home rebuild.
	int want = cap - 1;
	if (want > (int)sizeof buf)
		want = (int)sizeof buf;
	int got = msg_read(h->contact_id, h->record_id, 0, buf, want);
	if (got < 0)
		return;
	int n = 0;
	for (int i = 0; i < got && n < cap - 1; i++) {
		char c = (char)buf[i];
		if (c == '\n' || c == '\r' || c == '#')
			c = ' ';
		out[n++] = c;
	}
	out[n] = 0;
}

static void home_add(uint32_t pk, uint16_t channel_id, uint64_t seq, const char *name,
                     bool is_contact, uint8_t status, bool verified, bool unread,
                     bool no_endpoint, const char *preview) {
	if (!home_rows) {
		home_rows = kernel_alloc((size_t)kernel_cfg->max_files * sizeof *home_rows);
		if (!home_rows)
			return;
		home_cap = kernel_cfg->max_files;
	}
	if (home_n >= home_cap)
		return;
	struct home_row *r = &home_rows[home_n++];
	r->partkey = pk;
	r->channel_id = channel_id;
	r->seq = seq;
	snprintf(r->name, sizeof r->name, "%s", name);
	r->is_contact = 0;
	if (is_contact)
		r->is_contact = 1;
	r->status = status;
	r->verified = 0;
	if (verified)
		r->verified = 1;
	r->unread = 0;
	if (unread)
		r->unread = 1;
	r->no_endpoint = 0;
	if (no_endpoint)
		r->no_endpoint = 1;
	snprintf(r->preview, sizeof r->preview, "%s", preview);
}

// a sorts before b: newer first; the silent (seq 0) group last, by name.
static bool home_row_less(const struct home_row *a, const struct home_row *b) {
	if (a->seq != b->seq)
		return a->seq > b->seq;
	return strcasecmp(a->name, b->name) < 0;
}

static void home_rebuild(void) {
	home_n = 0;
	msg_ensure_log();
	struct contact_record c;
	for (int i = 0; contact_by_index(i, &c); i++) {
		uint32_t pk = contact_userid(&c);
		struct msg_record h;
		char pv[32];
		pv[0] = 0;
		uint64_t seq = 0;
		if (msg_head(pk, &h))
			seq = h.record_id;
		if (seq)
			home_fill_preview(&h, pv, sizeof pv);
		home_add(pk, 0, seq, c.name, true, c.status,
		         (c.settings & CONTACT_VERIFIED) != 0,
		         msg_thread_unread(pk), c.relay_ip4 == 0, pv);
	}
	// Groups are files too, so the same walk finds them -- but contact_by_index
	// filters them out, the contact list being contacts. A group's name carries
	// its host in the high half and the group id in the low.
	uint64_t fid;
	uint8_t ftype;
	for (int i = 0; file_list(i, &fid, &ftype); i++) {
		if (ftype != FILE_TYPE_CHANNEL)
			continue;
		uint32_t host = (uint32_t)(fid >> 32);
		uint16_t gid  = (uint16_t)(fid & 0xFFFFu);
		struct channel_record record;
		if (!channel_get(host, gid, &record))
			continue;
		// A channel keeps no log here, so a row is a name and a host: there
		// is nothing local to preview and nothing local to count unread.
		home_add(host, gid, 0, record.name, false, CONTACT_KEY_VALID, false,
		         0, false, "");
	}
	for (int i = 1; i < home_n; i++) {         // insertion sort: few rows
		struct home_row key = home_rows[i];
		int j = i - 1;
		while (j >= 0 && home_row_less(&key, &home_rows[j])) {
			home_rows[j + 1] = home_rows[j];
			j--;
		}
		home_rows[j + 1] = key;
	}
	home_seen_epoch = view_epoch;
	home_dirty = false;
}

static void home_ensure(void) {
	if (home_dirty || home_seen_epoch != view_epoch)
		home_rebuild();
}

// C linkage: the commands.cpp callers (cmdq handlers, the verify gate) raise
// this after a contact mutation.
void home_invalidate(void) {
	home_dirty = true;
}

static uint8_t home_dot(const struct home_row *r) {
	if (r->unread)
		return VIEW_DOT_UNREAD;
	if (!r->is_contact)
		return VIEW_DOT_REACHABLE;     // a group has no key of its own to verify
	if (r->status != CONTACT_KEY_VALID)
		return VIEW_DOT_PENDING;
	if (r->verified)
		return VIEW_DOT_REACHABLE;
	return VIEW_DOT_UNVERIFIED;
}

// The number of rows above the contact list: Return-to-call and Requests when
// they apply, then the three fixed Settings, Add and Join rows.
#define HOME_FIXED_ROWS 3

static int home_contacts_first_row(void) {
	int n = HOME_FIXED_ROWS;
	if (call_holding_audio())
		n++;
	if (missed_request_count() > 0)
		n++;
	return n;
}

// The contact row the highlight is on, or -1 on one of the rows above them.
static int home_selected_row(void) {
	int k = view_selected() - home_contacts_first_row();
	if (k < 0 || k >= home_n)
		return -1;
	return k;
}

// ---- one channel's actions --------------------------------------------------
//
// Selecting a channel opens this rather than the session, because the session
// is not the only thing you can want from one. Open is first, so the common
// action is still one press away.
//
// A pick may not transition from its own callback, so it leaves what was chosen
// here and home acts when it comes back to the top.

enum {
	CH_ACT_NONE = 0,
	CH_ACT_OPEN,
	CH_ACT_EDIT,
	CH_ACT_DELETE,
	CH_ACT_DELETE_OK
};

static int      chan_action;
static uint32_t chan_host;
static uint16_t chan_id;

static const char *chan_items[] = {
	LV_SYMBOL_KEYBOARD "  Open...",
	LV_SYMBOL_EDIT     "  Edit...",
	LV_SYMBOL_TRASH    "  Delete",
	NULL
};
static const char *chan_confirm[] = { "No", "Yes", NULL };

static void chan_on_pick(int index, const char *text) {
	(void)text;
	if (index == 0)
		chan_action = CH_ACT_OPEN;
	else if (index == 1)
		chan_action = CH_ACT_EDIT;
	else if (index == 2)
		chan_action = CH_ACT_DELETE;
}

static void chan_on_delete(int index, const char *text) {
	(void)text;
	if (index == 1)
		chan_action = CH_ACT_DELETE_OK;
}

static const char *chan_on_name(const char *text) {
	if (!text || !text[0])
		return "A channel needs a name. Enter:";
	if (!channel_rename(chan_host, chan_id, text))
		return "Could not rename it. Enter:";
	home_invalidate();
	return NULL;
}

void channel_menu_open(uint32_t host, uint16_t channel_id) {
	struct channel_record record;
	static char title[CHANNEL_NAME_MAX + 2];
	chan_host = host;
	chan_id   = channel_id;
	snprintf(title, sizeof title, "#%u", (unsigned)channel_id);
	if (channel_get(host, channel_id, &record) && record.name[0])
		snprintf(title, sizeof title, "#%s", record.name);
	screen_pick(title, NULL, chan_items, chan_on_pick);
}

// Run whatever the last pick chose. Called from home's FOREGROUND, which is
// where control lands once a pick has popped itself.
static void chan_action_run(void) {
	int what = chan_action;
	chan_action = CH_ACT_NONE;
	switch (what) {
	case CH_ACT_OPEN:
		channel_open(chan_id);
		screen_push(APP_CHANNEL, chan_host);
		break;
	case CH_ACT_EDIT: {
		// The prefill is BORROWED by the ask screen and read when it renders,
		// which is after this returns — so it cannot point into a local.
		static char had[CHANNEL_NAME_MAX];
		struct channel_record record;
		had[0] = 0;
		if (channel_get(chan_host, chan_id, &record))
			snprintf(had, sizeof had, "%s", record.name);
		screen_ask("Channel", "Name?", NULL, had, false, chan_on_name);
		break;
	}
	case CH_ACT_DELETE:
		screen_pick("Delete", "Remove this channel and everything in it?",
		            chan_confirm, chan_on_delete);
		break;
	case CH_ACT_DELETE_OK:
		if (!channel_destroy(chan_host, chan_id))
			hal_debug(LOG_ERROR, "home: channel delete failed\n");
		home_invalidate();
		break;
	default:
		break;
	}
}

// ---- hosting a channel of our own -------------------------------------------
// A channel we host needs only a name: the id is ours to allocate and the host
// half of its name is our own partkey. Joining somebody ELSE'S channel is a
// different act and lives on their contact menu, where the contact already
// says whose it is.

static const char *create_on_name(const char *text) {
	if (!text || !text[0])
		return "A channel needs a name. Enter:";
	if (!channel_new(text))
		return "Could not create it. Enter:";
	home_invalidate();
	return NULL;
}

static int home_view_cb(view_op_t op, int i, void *data) {
	call_handle live_call = call_holding_audio();
	int requests_row = 0;
	if (live_call)
		requests_row = 1;
	int request_count = missed_request_count();
	int settings_row = requests_row;
	if (request_count > 0)
		settings_row++;
	switch (op) {
	case LIST_GET_ITEM: {
		if (i < 0)
			return -1;
		view_item_t *it = (view_item_t *)data;
		if (live_call && i == 0) {
			uint32_t pk = call_peer_of(live_call);
			struct contact_record c;
			static char cbuf[MAX_NAME + 40];
			if (contact_get(&c, pk) && c.name[0])
				snprintf(cbuf, sizeof cbuf, LV_SYMBOL_CALL " Return to call - %s", c.name);
			else
				snprintf(cbuf, sizeof cbuf, LV_SYMBOL_CALL " Return to call - %08X", (unsigned)pk);
			it->text = cbuf;
			it->user = (void *)(uintptr_t)pk;
			return 0;
		}
		if (request_count > 0 && i == requests_row) {
			static char requests_text[48];
			const char *who = "users";
			if (request_count == 1)
				who = "user";
			snprintf(requests_text, sizeof requests_text,
			         LV_SYMBOL_BELL " Requests from (%d) %s", request_count, who);
			it->text = requests_text;
			it->dot = VIEW_DOT_UNVERIFIED;
			return 0;
		}
		if (i == settings_row) {
			it->text = LV_SYMBOL_SETTINGS " Settings...";
			return 0;
		}
		if (i == settings_row + 1) {
			it->text = LV_SYMBOL_PLUS " Add Contact...";
			return 0;
		}
		if (i == settings_row + 2) {
			it->text = LV_SYMBOL_PLUS " Create Channel...";
			return 0;
		}
		home_ensure();
		int k = i - settings_row - HOME_FIXED_ROWS;
		if (k < 0 || k >= home_n)
			return -1;
		struct home_row *r = &home_rows[k];
		// One line: [?] name, then partkey + preview small (meta_inline). The "?"
		// flags a contact with no endpoint (unresolved or mistyped userid).
		static char row_text[MAX_NAME + 96];
		static char row_meta[24 + 32];
		char name[MAX_NAME];
		copy_without_hash(name, sizeof name, r->name);
		if (r->is_contact) {
			const char *unresolved = "";
			if (r->no_endpoint)
				unresolved = "? ";
			snprintf(row_text, sizeof row_text, "%s%s", unresolved, name);
			if (r->preview[0])
				snprintf(row_meta, sizeof row_meta, "%08X  %s",
				         (unsigned)r->partkey, r->preview);
			else
				snprintf(row_meta, sizeof row_meta, "%08X", (unsigned)r->partkey);
		} else {
			// A group: the title if its host has told us one, and its id until
			// then. A group we host is under our own userid, so only a joined
			// one has a host worth naming.
			// A channel is named like one, so a glance separates it from the
			// contacts it shares the list with.
			if (name[0])
				snprintf(row_text, sizeof row_text, "#%s", name);
			else
				snprintf(row_text, sizeof row_text, "#%u", (unsigned)r->channel_id);
			const char *preview = "no messages";
			if (r->preview[0])
				preview = r->preview;
			if (r->partkey == channel_my_partkey())
				snprintf(row_meta, sizeof row_meta, "%s", preview);
			else
				snprintf(row_meta, sizeof row_meta, "%08X  %s",
				         (unsigned)r->partkey, preview);
		}
		it->text = row_text;
		it->meta = row_meta;
		it->meta_inline = true;
		it->dot = home_dot(r);
		it->user = (void *)(uintptr_t)r->partkey;
		return 0;
	}
	case LIST_SELECTED: {
		if (live_call && i == 0) {
			screen_push(APP_CALL, call_peer_of(live_call));
			return 0;
		}
		if (request_count > 0 && i == requests_row) {
			home_sel_what = HOME_OPEN_REQUESTS;
			screen_selection("open");
			return 0;
		}
		if (i == settings_row) {
			screen_push(APP_SETTINGS, 0);
			return 0;
		}
		if (i == settings_row + 1) {
			home_sel_what = HOME_OPEN_ADD;
			screen_selection("open");
			return 0;
		}
		if (i == settings_row + 2) {
			screen_ask("New Channel", "Name?", NULL, NULL, false,
			           create_on_name);
			return 0;
		}
		home_ensure();
		int k = i - settings_row - HOME_FIXED_ROWS;
		if (k < 0 || k >= home_n)
			return 0;
		struct home_row *r = &home_rows[k];
		if (!r->is_contact) {
			channel_menu_open(r->partkey, r->channel_id);
			return 0;
		}
		home_sel_partkey = r->partkey;
		home_sel_what = HOME_OPEN_CONTACT;
		screen_selection("open");
		return 0;
	}
	default:
		return 0;
	}
}

int app_home_main(int message, uint32_t param) {
	switch (message) {

	case APP_FOREGROUND: {
		if (chan_action != CH_ACT_NONE) {
			chan_action_run();
			return 1;
		}
		home_invalidate();       // rebuild the merge fresh on every arrival
		uint8_t pub[KEY_LEN];
		curve25519(pub, device_record.my_private_key, basepoint);
		char title[24];
		snprintf(title, sizeof title, "%08X", get_part_key(pub));
		view_set(home_view_cb, title, NULL, NULL, NULL, NULL);
		home_on_top = true;
		return 1;
	}

	case APP_BACKGROUND:
		home_on_top = false;
		return 1;

	case APP_SELECTION:
		// Every launch that leaves the kernel world goes through the one seam.
		screen_clear();
		home_legacy_open(home_sel_what, home_sel_partkey);
		return 1;

	case APP_KEYSTROKE: {
		int key = (int)param;

		// Shortcuts on a contact row: the same screens the contact menu pushes,
		// without the menu. Space holds, so PTT starts talking as soon as the
		// link comes up.
		int shortcut = -1;
		if (key == 'p' || key == 'P')
			shortcut = APP_CALL;
		else if (key == 'm' || key == 'M')
			shortcut = APP_CHAT;
		else if (key == ' ')
			shortcut = APP_PTT;
		if (shortcut >= 0) {
			home_ensure();
			int k = home_selected_row();
			if (k >= 0 && home_rows[k].is_contact)
				screen_push(shortcut, home_rows[k].partkey);
			return 1;
		}

		return ui_volume_key(key);
	}

	case NOTIFY_MSG_UPDATE:
		if (!home_on_top)
			return 0;
		home_invalidate();
		view_invalidate();
		return 1;

	case APP_PUMP:
		// Events from commands.cpp (contact edits, call end) raise the peer-less
		// flag instead of naming a peer.
		if (home_on_top && home_needs_refresh) {
			home_needs_refresh = 0;
			home_invalidate();
			view_invalidate();
		}
		return 0;

	default:
		return 0;
	}
}
