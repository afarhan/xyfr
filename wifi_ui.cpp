#include "debug.h"
#include "ui_symbols.h"
#include <Arduino.h>
#include <stdarg.h>
#include <WiFi.h>
// The core hardcodes one auth mode (CYW43shim.cpp) and exposes no way to change
// it, so the join is re-issued straight at the driver. See the auth ladder.
#include <pico/cyw43_arch.h>
#include "ui.h"
#include "view.h"
#include "device_record.h"
#include "bootstrap.h"

WiFiMulti multi;
char wifi_indicator_str[100];
char wifi_ap_name[40] = { 0 };   // live SSID, shown on the Settings > WiFi row

// Defined with the connect state machine below: a newly entered AP restarts
// both the attempt budget and the auth ladder.
static void wifi_attempts_reset(void);

// The connect progress log, defined with the views further down. Declared here
// because the connect machinery above it is what writes to the log.
static void wifi_log_add(const char *fmt, ...);
static void wifi_log_clear(void);
static void wifi_log_finished(uint32_t linger_ms);
static void wifi_progress_open(const char *ssid);
// How long a finished progress screen holds before returning home on its own.
// A success leaves quickly; a failure holds long enough to scroll back and
// PHOTOGRAPH -- the screenshot is the field report.
static const uint32_t WIFI_LINGER_SUCCESS_MS = 5000;
static const uint32_t WIFI_LINGER_FAILURE_MS = 120000;
static void wifi_log_linger_pump(void);

// A DISCONNECT IS ASYNCHRONOUS. WiFi.disconnect() returns while the supplicant
// is still tearing down, and a begin() in the same tick lands on a driver that
// is not ready: the attempt then sits in WL_DISCONNECTED for its whole timeout.
// The FIRST AP after a boot works -- nothing was disconnected before it -- and
// everything picked later does not, which is what "it lists but will not
// connect" looks like from the outside. Every disconnect arms this; the wait is
// WC_DISCONNECT_COOLDOWN, declared with the rest of the connect machine below.
static uint32_t wc_cooldown_ms = 0;

static char temp_ssid[64];
static char temp_key[64];
// The row the user picked out of the scan list. Two access points can share an
// SSID -- a mesh, or a router naming both bands alike -- so the NAME does not
// identify what they chose and the BSSID does. The first connection goes to that
// exact radio; joining by name would let the driver take whichever it prefers,
// which may be the weak one they were trying to avoid.
//
// It stays a property of the pick, never of the saved network: a saved AP always
// joins by SSID, so the far end can roam or have a radio replaced without
// stranding us.
static char    wifi_sel_ssid[33];
static uint8_t wifi_sel_bssid[6];
static bool    wifi_sel_has_bssid = false;   // false for a saved AP the scan never saw
static uint8_t wifi_sel_channel   = 0;       // 0 = let the driver find it
// Last FAILED manual attempt, kept so re-picking that SSID prefills the key the
// user tried (a failure is usually a typo). temp_* can't serve this: they are
// cleared on failure because a non-empty temp_key retriggers a connect attempt.
static char failed_ssid[64];
static char failed_key[64];
static int8_t wifi_state = WIFI_OFFLINE;

// Set in the WiFi-up edge below to re-schedule a server login as soon as
// the association is fresh. Defined in xyfr.ino.
#include "netif.h"   // netif_relogin

int wifi_get_status(){
	return wifi_state;
}

// removes the matching ssid (and its key) from device_record.ap_list and
// shifts the remaining entries down to cover the gap
void wifi_forget(char *ssid){
	for (int i = 0; i < MAX_APS; i++){
		if (!strcmp(device_record.ap_list[i].ssid, ssid)){
			for (int j = i; j < MAX_APS - 1; j++){
				strcpy(device_record.ap_list[j].ssid, device_record.ap_list[j+1].ssid);
				strcpy(device_record.ap_list[j].key, device_record.ap_list[j+1].key);
			}
			device_record.ap_list[MAX_APS - 1].ssid[0] = 0;
			device_record.ap_list[MAX_APS - 1].key[0] = 0;
			Debug.printf("forgot ap %s\n", ssid);
			flag_save_block = 1;
			return;
		}
	}
	Debug.printf("wifi_forget: %s not found\n", ssid);
}

// stores a successfully paired wifi ssid/key pair
static void wifi_save(char *new_ssid, char *new_key){
	//Debug.println("block before:\n");
	block_dump();
	//first check if the already stored, if so, we just update it
	for (int i = 0; i < MAX_APS; i++)
		if (!strcmp(device_record.ap_list[i].ssid, new_ssid)){
			if (strcmp(device_record.ap_list[i].key, new_key)){
				// The record's fields are 32 bytes and the entry buffers 64: a
				// passphrase over 31 characters ran into the next record.
				snprintf(device_record.ap_list[i].key, sizeof device_record.ap_list[i].key, "%s", new_key);
				Debug.printf("updated the previous key %s with %s\n", new_ssid, new_key);
				flag_save_block = 1;
			}
      else
        Debug.printf("ssid key is not updated.\n");
      return;
		}
	//now, we have to shift out one ssid and add this
	for (int i = MAX_APS -1; 0 < i; i--){
		Debug.printf("shifting ap %d to %d\n", i, i-1);
		strcpy(device_record.ap_list[i].ssid, device_record.ap_list[i-1].ssid);
		strcpy(device_record.ap_list[i].key, device_record.ap_list[i-1].key);
	}
	Debug.printf("inserted new ap %s\n", new_ssid)	;
	snprintf(device_record.ap_list[0].ssid, sizeof device_record.ap_list[0].ssid, "%s", new_ssid);
	snprintf(device_record.ap_list[0].key,  sizeof device_record.ap_list[0].key,  "%s", new_key);
	flag_save_block = 1;
	block_dump();
}

// ===================== WiFi flow on the view model =========================
// Three view screens:
//   wifi_open()        scan list — saved SSIDs flagged + shown first; select a
//                      saved one -> manage, an unsaved one -> key dialog.
//   wifi_manage_open() a saved SSID: prompt "SSID : xxxx" + "Edit Key..." / "Delete".
//   wifi_key_open()    prompt "Enter the SSID key for xxxx" + editor (prefilled
//                      with the saved key) + Go -> connect.
// The connect runs in the background (wifi_poll on core 0); there's no "wait"
// screen — the home title-bar WiFi icon shows the result.

// Kick off a connect to (ssid,key): stash the temp creds, drop any current link,
// and go home. wifi_poll tries the temp AP first (and wifi_save's it on success);
// the home title-bar WiFi icon reflects the outcome.
static void wifi_connect_begin(const char *ssid, const char *key){
	if (strlen(key) >= 32) {
		// The stored record's key field is 32 bytes, so 31 characters is the cap
		// (WPA2 itself allows 63). Say so ON SCREEN: the silent return here left
		// the user pressing Go with nothing happening at all.
		Debug.println("wifi: key too long");
		wifi_log_clear();
		wifi_log_add("The key is %u characters long.", (unsigned)strlen(key));
		wifi_log_add("FAILED: this phone can only use keys");
		wifi_log_add("up to 31 characters, for now.");
		wifi_progress_open(ssid);
		wifi_log_finished(WIFI_LINGER_FAILURE_MS);
		return;
	}
	snprintf(temp_key,  sizeof temp_key,  "%s", key);
	snprintf(temp_ssid, sizeof temp_ssid, "%s", ssid);
	wifi_attempts_reset();           // full budget, from the usual auth mode
	wifi_log_clear();
	wifi_log_add("Connecting to %s", ssid);
	// Disconnect, and START THE COOLDOWN with it. The teardown is asynchronous,
	// so a begin() before it finishes sits in DISCONNECTED for its whole 8 s
	// (see WC_DISCONNECT_COOLDOWN). Only the timeout path used to arm this, which
	// left the FIRST attempt at a freshly typed AP -- the one the user is
	// watching -- as the single attempt that skipped the wait.
	WiFi.disconnect();   // wifi_poll picks up the temp creds and associates in the background
	wc_cooldown_ms = millis();
	// Flip to CONNECTING synchronously (wifi_poll would only do it a tick later) so
	// anything reading the state right now sees the attempt, not OFFLINE.
	wifi_state = WIFI_CONNECTING;
	phone_state_set(PS_WIFI_CONNECTING);
	ui_wifi_state(WIFI_CONNECTING);
	// The progress screen is where the user lands, and it is opened LAST: this
	// runs inside the editor's EDIT_ENTER dispatch, so anything setting a view
	// after it would replace it -- which is what go_home() did here.
	wifi_progress_open(ssid);
}

#define WIFI_LIST_MAX 24
// ONE ROW PER RADIO, not per name. Two access points can broadcast the same
// SSID, and they are different things to connect to: different signal, different
// channel, sometimes only one of them working. Listing them by name hides the
// choice, and hides it hardest in the case where it matters.
//
// The scan's radio facts are kept, not just the name: when an AP lists but will
// not associate, the answer is usually its cipher or its channel, and by the
// time the join fails that information is gone.
static struct {
	char    ssid[33];
	uint8_t bssid[6];    // which radio -- what makes two rows of one name distinct
	bool    saved;
	bool    seen;        // in the last scan (a saved AP may not be)
	int8_t  rssi;
	uint8_t channel;
	uint8_t enc;
} wifi_entries[WIFI_LIST_MAX];
static int  wifi_entry_count = 0;
// wifi_sel_* (what the user picked out of the list) are declared with temp_*
// near the top, because wifi_connect_begin sits above this point and copies one
// into the other.

static const char *saved_key_for(const char *ssid){
	for (int i = 0; i < MAX_APS; i++)
		if (device_record.ap_list[i].ssid[0] && !strcmp(device_record.ap_list[i].ssid, ssid))
			return device_record.ap_list[i].key;
	return NULL;
}

// WL_* as words. A bare number sends the reader to a header mid-diagnosis, and
// the distinction that matters most -- "the radio cannot see it" versus "the AP
// refused us" -- is invisible as 1 against 4.
static const char *wl_name(int st) {
	switch (st) {
	case 0:   return "IDLE";
	case 1:   return "NO_SSID_AVAIL";
	case 2:   return "SCAN_COMPLETED";
	case 3:   return "CONNECTED";
	case 4:   return "CONNECT_FAILED";    // FAIL, NONET or BADAUTH - the L value says which
	case 5:   return "CONNECTION_LOST";
	case 6:   return "DISCONNECTED";      // never associated
	case 255: return "NO_SHIELD";         // the radio itself is not up
	default:  return "?";
	}
}

// wl_definitions.h's wl_enc_type holds 802.11 CIPHER ALGORITHM IDENTIFIERS, not
// a dense enum: 2/4/5/6 are TKIP/CCMP/WEP/GCMP and 7 is open. Reading them as
// 0,1,2,3 mislabels every network, which is how a plain WPA2 AP was first
// reported here as WPA/WPA2 mixed.
static const char *enc_name(uint8_t e) {
	switch (e) {
	case 2:   return "WPA/TKIP";
	case 4:   return "WPA2/CCMP";
	case 5:   return "WEP";
	case 6:   return "WPA3/GCMP";
	case 7:   return "open";
	case 8:   return "auto";
	case 255: return "unknown";
	default:  return "enc?";
	}
}

// What the last scan saw for this name, logged as we try it.
static void log_scan_facts(const char *ssid) {
	for (int i = 0; i < wifi_entry_count; i++) {
		if (strcmp(wifi_entries[i].ssid, ssid) || !wifi_entries[i].seen)
			continue;
		Debug.printf("wifi:   scan saw it: rssi=%d ch=%u %s\n",
		             (int)wifi_entries[i].rssi, (unsigned)wifi_entries[i].channel,
		             enc_name(wifi_entries[i].enc));
		wifi_log_add("Signal %d dBm, channel %u, %s",
		             (int)wifi_entries[i].rssi, (unsigned)wifi_entries[i].channel,
		             enc_name(wifi_entries[i].enc));
		return;
	}
	Debug.println("wifi:   NOT in the last scan (out of range, hidden, or 5 GHz)");
	wifi_log_add("Not seen in the last scan");
}

// ---- the connect progress log ---------------------------------------------
// What the connect state machine is doing, as a list the user can read. The
// same events the serial telemetry prints go here: a device in a coffee shop
// has no serial cable, and "it just says connecting" is the report we cannot
// act on.
//
// A RING, oldest first, newest at the bottom. Sized to hold a whole fresh-key
// struggle -- a few lines per attempt, eight attempts -- so a screenshot of the
// scrolled-back list carries every try; it drops the oldest rather than
// stopping, so a longer struggle still shows its ending.
#define WIFI_LOG_LINES 64
#define WIFI_LOG_COLS  56
static char wifi_log[WIFI_LOG_LINES][WIFI_LOG_COLS];
static int  wifi_log_count;        // lines held, capped at WIFI_LOG_LINES
static int  wifi_log_first;        // ring start once it has wrapped
static bool wifi_log_showing;      // the progress view is the current screen
// Set when the attempt reaches a FINAL state. The screen then holds for the
// linger passed to wifi_log_finished (see the WIFI_LINGER_* constants up top)
// and returns on its own, so a success needs no keypress and a failure is not
// a dead end.
static uint32_t wifi_log_done_ms;
static uint32_t wifi_log_linger_ms;

static int wifi_progress_cb(view_op_t op, int i, void *data);

// Append one line. Safe to call from the connect pump on every tick: it repaints
// only while the progress screen is actually up.
static void wifi_log_add(const char *fmt, ...) {
	char line[WIFI_LOG_COLS];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(line, sizeof line, fmt, ap);
	va_end(ap);

	int slot;
	if (wifi_log_count < WIFI_LOG_LINES) {
		slot = (wifi_log_first + wifi_log_count) % WIFI_LOG_LINES;
		wifi_log_count++;
	} else {
		slot = wifi_log_first;                       // full: drop the oldest
		wifi_log_first = (wifi_log_first + 1) % WIFI_LOG_LINES;
	}
	snprintf(wifi_log[slot], WIFI_LOG_COLS, "%s", line);

	if (wifi_log_showing) {
		view_follow_newest();       // keep the tail in view as it grows
		view_invalidate();
	}
}

static void wifi_log_clear(void) {
	wifi_log_count  = 0;
	wifi_log_first  = 0;
	wifi_log_done_ms = 0;
}

// The outcome is in: start the linger.
static void wifi_log_finished(uint32_t linger_ms) {
	wifi_log_linger_ms = linger_ms;
	wifi_log_done_ms = millis();
	if (wifi_log_done_ms == 0)
		wifi_log_done_ms = 1;          // 0 means "still going"
}

// Called from wifi_poll, i.e. OUTSIDE the view engine's own dispatch, which is
// where a view_set is safe to make.
static void wifi_log_linger_pump(void) {
	if (!wifi_log_showing || !wifi_log_done_ms)
		return;
	if ((uint32_t)(millis() - wifi_log_done_ms) < wifi_log_linger_ms)
		return;
	wifi_log_showing = false;
	wifi_log_done_ms = 0;
	go_home();
}

static int wifi_progress_cb(view_op_t op, int i, void *data) {
	switch (op) {
		case LIST_GET_ITEM: {
			// Oldest at the top, so the story reads downward. One row past the
			// end is Return, which is also what gives the user a way out while a
			// connect is still grinding.
			if (i < 0 || i > wifi_log_count)
				return -1;
			view_item_t *it = (view_item_t *)data;
			if (i == wifi_log_count) {
				it->text = LV_SYMBOL_LEFT "  Return";
				return 0;
			}
			it->text = wifi_log[(wifi_log_first + i) % WIFI_LOG_LINES];
			return 0;
		}
		case LIST_SELECTED:
			if (i == wifi_log_count) {
				wifi_log_showing = false;
				go_home();
			}
			return 0;
		case LIST_BACK:
			wifi_log_showing = false;
			go_home();
			return 0;
		default:
			return 0;
	}
}

// Shown the moment a key is entered, so the wait is legible rather than blank.
static void wifi_progress_open(const char *ssid) {
	static char title[48];
	snprintf(title, sizeof title, LV_SYMBOL_WIFI " %s", ssid);
	wifi_log_showing = true;
	view_set(wifi_progress_cb, title, NULL, NULL, NULL, NULL);
}

static bool ssid_is_saved(const char *ssid){
	for (int i = 0; i < MAX_APS; i++)
		if (device_record.ap_list[i].ssid[0] && !strcmp(device_record.ap_list[i].ssid, ssid))
			return true;
	return false;
}

// Build the scan list FROM THE SCAN, one row per radio, strongest first; then
// append the saved networks the scan did not see.
//
// The order matters. Listing the saved ones first and then skipping any scanned
// SSID that matched left the saved entries with no signal, no channel and no
// cipher -- the networks we most want to diagnose were the only ones carrying no
// facts, and log_scan_facts then reported "NOT in the last scan" for an AP that
// was plainly visible. Starting from the scan gives every row its radio facts
// and separates same-SSID radios, both from the same pass.
//
// Blocking scan (~seconds).
static void wifi_scan_build(void){
	wifi_entry_count = 0;

	int n = WiFi.scanNetworks();
	for (int i = 0; i < n && wifi_entry_count < WIFI_LIST_MAX; i++){
		String ss = WiFi.SSID(i);
		const char *s = ss.c_str();
		if (!s || !s[0])
			continue;
		uint8_t bssid[6] = {0};
		WiFi.BSSID((uint8_t)i, bssid);
		// Deduplicate on the RADIO, not the name: one physical AP can appear twice
		// in a scan, but two APs sharing a name are two rows.
		bool dup = false;
		for (int j = 0; j < wifi_entry_count; j++)
			if (!memcmp(wifi_entries[j].bssid, bssid, 6)) {
				dup = true;
				break;
			}
		if (dup)
			continue;
		int e = wifi_entry_count;
		strncpy(wifi_entries[e].ssid, s, 32);
		wifi_entries[e].ssid[32] = 0;
		memcpy(wifi_entries[e].bssid, bssid, 6);
		wifi_entries[e].seen    = true;
		wifi_entries[e].rssi    = (int8_t)WiFi.RSSI(i);
		wifi_entries[e].channel = (uint8_t)WiFi.channel(i);
		wifi_entries[e].enc     = (uint8_t)WiFi.encryptionType(i);
		wifi_entries[e].saved   = ssid_is_saved(s);
		wifi_entry_count++;
	}

	// Strongest first. With one row per radio the list is longer than it was, and
	// the row worth picking should not be the one below the fold.
	for (int i = 1; i < wifi_entry_count; i++)
		for (int j = i; j > 0 && wifi_entries[j].rssi > wifi_entries[j - 1].rssi; j--) {
			auto t = wifi_entries[j];
			wifi_entries[j] = wifi_entries[j - 1];
			wifi_entries[j - 1] = t;
		}

	// A saved network the scan missed still belongs on the list: it is what the
	// user reaches for, and "out of range" is itself the answer they need.
	for (int i = 0; i < MAX_APS && wifi_entry_count < WIFI_LIST_MAX; i++){
		if (!device_record.ap_list[i].ssid[0])
			continue;
		bool listed = false;
		for (int j = 0; j < wifi_entry_count; j++)
			if (!strcmp(wifi_entries[j].ssid, device_record.ap_list[i].ssid)) {
				listed = true;
				break;
			}
		if (listed)
			continue;
		int e = wifi_entry_count;
		memset(&wifi_entries[e], 0, sizeof wifi_entries[e]);
		strncpy(wifi_entries[e].ssid, device_record.ap_list[i].ssid, 32);
		wifi_entries[e].ssid[32] = 0;
		wifi_entries[e].saved = true;
		wifi_entries[e].seen  = false;
		wifi_entry_count++;
	}
}

// --- key screen (view): prompt + (Delete, if saved) + editor (prefilled) + Go ---
// One screen for both edit and delete: a saved SSID gets a "Delete" list item
// above the key editor; a new SSID gets just the editor + Go.
static void wifi_delete_sel(void){
	String cur = WiFi.SSID();
	bool was_current = (WiFi.status() == WL_CONNECTED && !strcmp(cur.c_str(), wifi_sel_ssid));
	wifi_forget(wifi_sel_ssid);
	if (was_current)  // wifi_poll reconnects to a remaining saved AP
		WiFi.disconnect();
	wifi_open();                          // restart the scan / re-list
}
static int wifi_key_cb(view_op_t op, int i, void *data){
	(void)i;
	switch (op){
		case LIST_GET_ITEM: return -1;                                  // no list (unsaved SSID)
		case LIST_SELECTED:
			wifi_delete_sel();          // the "Delete" item (saved SSID)
			return 0;
		case EDIT_ENTER:
			wifi_connect_begin(wifi_sel_ssid, (const char *)data);
			return 0;
		default:            return 0;
	}
}
static void wifi_key_open(const char *ssid){
	strncpy(wifi_sel_ssid, ssid, 32);
	wifi_sel_ssid[32] = 0;
	static char prompt[80];
	snprintf(prompt, sizeof prompt, "Enter the SSID key for %s", ssid);
	const char *saved   = saved_key_for(ssid);
	const char *prefill = saved;
	// Re-picking the SSID we just failed on almost always means "fix the key", so
	// put the failed attempt back in the box to be edited rather than retyped.
	if (failed_key[0] && !strcmp(ssid, failed_ssid))
		prefill = failed_key;
	static char forget_label[48];
	static const char *del_items[] = { forget_label, NULL };
	snprintf(forget_label, sizeof forget_label, LV_SYMBOL_TRASH "  Forget %s", ssid);
	// "Forget <ssid>" is offered only for an SSID we already hold a key for.
	const char **items = NULL;
	if (saved)
		items = del_items;
	view_set(wifi_key_cb, LV_SYMBOL_WIFI " WiFi Key", prompt,
	         items, "WiFi Key", prefill);
}

// --- scan list (view) + entry point ---
static int wifi_cb(view_op_t op, int i, void *data){
	switch (op){
		case LIST_GET_ITEM: {
			if (i < 0 || i > wifi_entry_count + 1)
				return -1;
			view_item_t *it = (view_item_t *)data;
			// Rescan FIRST so it's always visible (with many APs a trailing one would
			// scroll below the fold) — re-runs the scan, e.g. for a phone hotspot
			// switched on mid-onboarding. Then the scanned APs, then Return last.
			if (i == 0) {
				it->text = LV_SYMBOL_REFRESH "  Rescan";
				return 0;
			}
			if (i == wifi_entry_count + 1) {
				it->text = LV_SYMBOL_LEFT    "  Return";
				return 0;
			}
			int a = i - 1;   // scanned-AP index (Rescan occupies row 0)
			// The signal and channel are on the row because two rows can carry the
			// same name: without them the user is asked to choose between things
			// that look identical. They are also the two facts a failing AP is
			// diagnosed from, so they are worth a photograph.
			const char *icon = LV_SYMBOL_WIFI;
			if (wifi_entries[a].saved)
				icon = LV_SYMBOL_OK;
			static char buf[72];
			if (wifi_entries[a].seen)
				snprintf(buf, sizeof buf, "%s  %s   %d  ch%u", icon, wifi_entries[a].ssid,
				         (int)wifi_entries[a].rssi, (unsigned)wifi_entries[a].channel);
			else
				snprintf(buf, sizeof buf, "%s  %s   not in range", icon, wifi_entries[a].ssid);
			it->text = buf;
			it->separator = true;
			return 0;
		}
		case LIST_SELECTED: {
			if (i < 0 || i > wifi_entry_count + 1)
				return 0;
			if (i == 0) {  // Rescan
				wifi_open();
				return 0;
			}
			if (i == wifi_entry_count + 1) {  // Return
				go_home();
				return 0;
			}
			int a = i - 1;
			strncpy(wifi_sel_ssid, wifi_entries[a].ssid, 32);
			wifi_sel_ssid[32] = 0;
			// Remember WHICH radio was picked, not just its name, so the join can
			// go to the one the user chose. A row with no signal was never in the
			// scan, so there is no radio to aim at -- join by name.
			wifi_sel_has_bssid = wifi_entries[a].seen;
			memcpy(wifi_sel_bssid, wifi_entries[a].bssid, 6);
			wifi_sel_channel = wifi_entries[a].channel;
			wifi_key_open(wifi_sel_ssid);   // key screen (with Delete if the SSID is saved)
			return 0;
		}
		default: return 0;
	}
}
void wifi_open(void){
	wifi_scan_build();
	view_set(wifi_cb, LV_SYMBOL_WIFI " WiFi Networks", "Choose WiFi", NULL, NULL, NULL);
}

void wifi_init(){
	temp_ssid[0] = 0;
	temp_key[0] = 0;
	wifi_indicator_str[0] = 0;
	wifi_ap_name[0] = 0;
	// Sets the WiFi class's _calledESP flag, which makes WiFi.begin() SKIP its
	// internal "block until connected" wait loop (WiFiClass::begin) — so our
	// wifi_poll's begin returns immediately and we poll status across calls.
	WiFi.mode(WIFI_STA);
}

static void update_wifi(){
	static unsigned int next_update = 0;
 	unsigned int now = millis();

	if (now < next_update)
		return;
	next_update = now + 1000;

	// CLEARED first, refilled only while associated: written in the connected
	// branch alone it outlived the connection, so Settings kept showing an SSID
	// the device had forgotten and disconnected from.
	wifi_ap_name[0] = 0;

	switch(wifi_state){
		case WIFI_OFFLINE:
			strcpy(wifi_indicator_str, LV_SYMBOL_CLOSE " Offline");
			//lv_label_set_text(wifi_indicator, LV_SYMBOL_CLOSE " Offline");
			break;
	  case WIFI_CONNECTING:
		  strcpy(wifi_indicator_str, LV_SYMBOL_LOOP " ...");
		  //lv_label_set_text(wifi_indicator, LV_SYMBOL_LOOP " ...");
			break;
		case WIFI_FAILED:
			strcpy(wifi_indicator_str, LV_SYMBOL_CLOSE " No WiFi");
			break;
		default:
		{
			int signal = 130 + WiFi.RSSI();
			if (signal > 100)
				signal = 100;
			if (signal < 0)
				signal = 0;
			// Signal strength only. The access point NAME is not title-bar
			// information -- it never changes while you are connected and it
			// crowds out everything else; it lives on the Settings > WiFi row.
			sprintf(wifi_indicator_str, LV_SYMBOL_WIFI " %d", signal);
			snprintf(wifi_ap_name, sizeof wifi_ap_name, "%s", WiFi.SSID().c_str());
		}
		//Debug.println(wifi_indicator_str);
	}
}


// --- non-blocking WiFi connect (replaces the blocking WiFiMulti.run() pump) ---
// The old pump called WiFiMulti.run() (a synchronous scan + connect, several
// seconds) plus delay(1000)/delay(2000), freezing the whole loop during
// association — and, on a single core, the UI with it. This is a state machine
// instead: WiFi.begin() to ONE AP at a time (non-blocking) and poll
// WiFi.status() across calls, rotating through the temp (user-entered) AP, then
// device_record.ap_list[]. Every wifi_poll() returns immediately.
static bool     wc_trying      = false;  // a WiFi.begin attempt is in flight
static bool     wc_trying_temp = false;  // the in-flight attempt is the user's new AP
static int      wc_ap_idx      = -1;     // last device_record.ap_list[] index tried (round-robin)
static uint32_t wc_attempt_ms  = 0;
static const uint32_t WC_ATTEMPT_TIMEOUT = 8000;   // per-AP association timeout

static const uint32_t WC_DISCONNECT_COOLDOWN = 600;

// Consecutive failed attempts before wifi_get_status() reports WIFI_FAILED. The
// device keeps retrying underneath — an AP can come back — but a caller can tell
// "connecting" from "has been failing for a while", which it could not before.
int wifi_fail_streak_limit = 6;
static int wc_fail_streak = 0;

// A freshly entered AP gets several attempts. One 8 s window is easy to miss on
// a busy channel, and the user has just typed the key: discarding it on a single
// failure reads as "wrong password" for an AP that works. Eight tries walks the
// whole four-rung auth ladder twice before the key is given up on.
static int wc_temp_tries = 0;
static const int WC_TEMP_MAX_TRIES = 8;

// THE AUTH LADDER. The core hardcodes CYW43_AUTH_WPA2_AES_PSK and offers no way
// to change it, so an AP wanting WPA-TKIP, WPA/WPA2 mixed or WPA3 can never
// associate -- the join is never accepted and the attempt sits in DISCONNECTED.
// A product meets whatever access point is in front of it, so each retry
// re-issues the join one rung further down.
//
// cyw43_wifi_join() is public SDK against the global cyw43_state, and
// WiFi.begin() returns immediately here (wifi_init sets WIFI_STA, which makes it
// non-blocking), so re-issuing right after replaces the core's choice. It is the
// same call the core's own retry loop makes.
static const uint32_t wc_auth_ladder[] = {
	CYW43_AUTH_WPA2_AES_PSK,      // the common case, and what the core would do
	CYW43_AUTH_WPA2_MIXED_PSK,    // WPA/WPA2 transition APs
	CYW43_AUTH_WPA3_WPA2_AES_PSK, // WPA2/WPA3 transition APs
	CYW43_AUTH_WPA_TKIP_PSK,      // old WPA-only
};
#define WC_AUTH_COUNT ((int)(sizeof wc_auth_ladder / sizeof wc_auth_ladder[0]))
static int wc_auth_rung = 0;

static void wifi_attempts_reset(void) {
	wc_temp_tries = 0;
	wc_auth_rung  = 0;
}

// Re-issue the join the core just made, with the mode we actually want -- and at
// a named radio when we have one. `bssid` NULL joins by name and lets the driver
// pick, which is what a saved network wants; a non-NULL bssid pins the attempt to
// the radio the user chose out of the list, and naming its channel with it spares
// the join a scan of its own.
static void wc_join_with_auth(const char *ssid, const char *key,
                              const uint8_t *bssid, uint8_t chan) {
	if (!key || !key[0])
		return;                       // open network: nothing to authenticate
	uint32_t auth = wc_auth_ladder[wc_auth_rung];
	static const char *auth_label[] = { "WPA2", "WPA/WPA2", "WPA2/WPA3", "WPA" };
	Debug.printf("wifi:   auth %d/%d (0x%08lx)\n",
	             wc_auth_rung + 1, WC_AUTH_COUNT, (unsigned long)auth);
	wifi_log_add("Security: %s", auth_label[wc_auth_rung]);

	uint32_t channel = CYW43_CHANNEL_NONE;
	if (bssid) {
		if (chan)
			channel = chan;
		Debug.printf("wifi:   at %02x:%02x:%02x:%02x:%02x:%02x ch%u\n",
		             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
		             (unsigned)chan);
		wifi_log_add("Radio %02X:%02X:%02X ch%u",
		             bssid[3], bssid[4], bssid[5], (unsigned)chan);
	}
	cyw43_wifi_join(&cyw43_state, strlen(ssid), (const uint8_t *)ssid,
	                strlen(key), (const uint8_t *)key, auth, bssid, channel);
}

// The key, for a screen we ask people to PHOTOGRAPH and send us. Masked, so that
// request does not also ask for their WiFi password.
//
// What the diagnosis actually needs survives masking. The length is already on
// the line above. The other fault a length cannot show is a stray space at
// either end -- invisible on screen, and easy to pick up from a keyboard with
// symbol layers -- so that is called out in words rather than left to the reader
// to spot between brackets. Developer Mode prints the key itself, for a bench
// unit whose screen only its owner is reading.
static void wifi_log_key(const char *key) {
	if (device_record.dev_mode) {
		wifi_log_add("Key [%s]", key);
		return;
	}
	char masked[40];
	size_t n = strlen(key);
	if (n > sizeof masked - 1)
		n = sizeof masked - 1;
	memset(masked, '*', n);
	masked[n] = 0;
	wifi_log_add("Key [%s]", masked);
	if (n && (key[0] == ' ' || key[strlen(key) - 1] == ' '))
		wifi_log_add("NOTE: the key starts or ends with a space");
}

// Kick off WiFi.begin() to the next candidate AP. Returns false if none configured.
static bool wc_begin_next(){
	if (strlen(temp_key) && !wc_trying_temp){       // user's new AP — tried first
		Debug.printf("wifi: begin NEW AP [%s] keylen=%u try %d/%d\n",
		             temp_ssid, (unsigned)strlen(temp_key),
		             wc_temp_tries + 1, WC_TEMP_MAX_TRIES);
		log_scan_facts(temp_ssid);
		wifi_log_add("Try %d of %d, key %u chars", wc_temp_tries + 1,
		             WC_TEMP_MAX_TRIES, (unsigned)strlen(temp_key));
		wifi_log_key(temp_key);
		WiFi.begin(temp_ssid, temp_key);
		// At the radio the user picked, if the pick came out of the scan. A saved
		// AP they chose that the scan never saw has no radio to aim at.
		const uint8_t *aim = NULL;
		uint8_t aim_chan = 0;
		if (wifi_sel_has_bssid) {
			aim = wifi_sel_bssid;
			aim_chan = wifi_sel_channel;
		}
		wc_join_with_auth(temp_ssid, temp_key, aim, aim_chan);
		wc_trying_temp = true;
		wc_trying      = true;
		wc_attempt_ms  = millis();
		return true;
	}
	wc_trying_temp = false;
	for (int step = 0; step < MAX_APS; step++){
		wc_ap_idx = (wc_ap_idx + 1) % MAX_APS;
		if (device_record.ap_list[wc_ap_idx].ssid[0]){
			// Name the attempt with the stored SSID and key so a corrupt,
			// truncated or empty credential shows up in a screenshot.
			Debug.printf("wifi: begin AP[%d] ssid=[%s] ssidlen=%u keylen=%u\n",
			             wc_ap_idx, device_record.ap_list[wc_ap_idx].ssid,
			             (unsigned)strlen(device_record.ap_list[wc_ap_idx].ssid),
			             (unsigned)strlen(device_record.ap_list[wc_ap_idx].key));
			wifi_log_add("Trying %s, key %u chars",
			             device_record.ap_list[wc_ap_idx].ssid,
			             (unsigned)strlen(device_record.ap_list[wc_ap_idx].key));
			wifi_log_key(device_record.ap_list[wc_ap_idx].key);
			log_scan_facts(device_record.ap_list[wc_ap_idx].ssid);
			WiFi.begin(device_record.ap_list[wc_ap_idx].ssid, device_record.ap_list[wc_ap_idx].key);
			// By NAME, never pinned: a saved network must survive the far end
			// roaming or having a radio replaced.
			wc_join_with_auth(device_record.ap_list[wc_ap_idx].ssid,
			                  device_record.ap_list[wc_ap_idx].key, NULL, 0);
			wc_trying     = true;
			wc_attempt_ms = millis();
			return true;
		}
	}
	// Rate-limited: wc_begin_next() runs on EVERY wifi_poll tick, so an
	// unconfigured device emitted this ~107x/s. That saturates serial, and since
	// Debug drops on a full TX it silently discarded other diagnostics -- it ate
	// the keyboard rollover telemetry we were trying to capture, on exactly the
	// onboarding path where the log matters most. Once per 5 s shows the same
	// state without blinding everything else.
	static uint32_t no_ap_last = 0;
	if (no_ap_last == 0 || (uint32_t)(millis() - no_ap_last) >= 5000){
		no_ap_last = millis();
		Debug.println("wifi: NO APs configured in device_record.ap_list[]");
	}
	return false;   // nothing configured
}

//To be called only by core0 — NON-BLOCKING (returns immediately every call).
void wifi_poll(){
	update_wifi();
	wifi_log_linger_pump();

	// RECOVERY: status 255 = WL_NO_SHIELD — the CYW43 radio did NOT initialize
	// (cyw43_arch_init failed at boot, usually a power/brownout issue). WiFi.begin
	// then does nothing and scans see 0 APs. Re-run the init (throttled) to try to
	// bring the radio up; if it's a hard power issue this won't help, but a marginal
	// init often recovers on a retry once the chip has settled.
	if ((int)WiFi.status() == 255){
		static uint32_t next_reinit = 0;
		if (next_reinit == 0 || (uint32_t)(millis() - next_reinit) >= 3000){
			next_reinit = millis();
			Debug.println("wifi: radio NOT up (status 255 WL_NO_SHIELD) — re-init WiFi.mode(STA)");
			WiFi.mode(WIFI_STA);
			wc_trying = false;   // let the next tick start a fresh begin()
		}
		return;
	}

	if (WiFi.status() == WL_CONNECTED){
		if (wifi_state != WIFI_ONLINE){
			Debug.print("Local IP:");
			Debug.println(WiFi.localIP());
			// (WiFi power-save left at the core default / no-PM: CYW43_DEFAULT_PM
			// made packet delivery bursty and destabilised calls. Revisit for
			// battery only once call audio is solid.)
			wifi_log_add("CONNECTED  %s", WiFi.localIP().toString().c_str());
			wifi_log_finished(WIFI_LINGER_SUCCESS_MS);
			netif_relogin();   // our source endpoint changed: re-join on this association
			if (wc_trying_temp && strlen(temp_key))
				wifi_save(temp_ssid, temp_key);   // the freshly-entered AP worked
			failed_ssid[0] = 0;                   // a success retires the stale bad key
			failed_key[0]  = 0;
		}
		wifi_state = WIFI_ONLINE;
		wc_fail_streak = 0;
		phone_state_set(PS_WIFI_CONNECTED);
		ui_wifi_state(100 - WiFi.RSSI());
		bootstrap_pump();              // run a pending DoH resolve from core 0
		wc_trying      = false;
		wc_trying_temp = false;
		return;
	}

	// Not connected.
	if (wc_trying){
		// DEBUG: trace the association status while the attempt is in flight.
		// WL_ codes: 0 IDLE · 1 NO_SSID_AVAIL (radio can't see the AP → band/range)
		// · 3 CONNECTED · 4 CONNECT_FAILED (the driver's FAIL, NONET or BADAUTH
		// — the logged L value says which) · 6 DISCONNECTED (join in progress OR
		// joined without a DHCP lease — the J bits say which).
		// EVERY TRANSITION, not a 1 Hz sample. An association can pass through
		// three states inside a second: 0 -> 6 -> 4 is an auth rejection, while 6
		// held throughout is an association that never started, and a
		// once-a-second look cannot tell those apart.
		static int wc_last_status = -1;
		int st_now = (int)WiFi.status();
		if (st_now != wc_last_status) {
			// The WL_ code is a COLLAPSE: the core maps the driver's FAIL, NONET
			// and BADAUTH all to WL 4, and "joined, waiting for DHCP" to WL 6.
			// So log the driver's own words too: the link status (-1 FAIL,
			// -2 NONET, -3 BADAUTH, 1 JOIN) and the join-state bits (0x0200
			// = 802.11 auth done, 0x0400 = associated, 0x0800 = 4-way keyed).
			int      link = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
			unsigned join = (unsigned)cyw43_state.wifi_join_state;
			Debug.printf("wifi:   %s -> %s at t=%lums link=%d join=%04x\n",
			             wl_name(wc_last_status), wl_name(st_now),
			             (unsigned long)(millis() - wc_attempt_ms), link, join);
			wifi_log_add("  %s (%lu ms) L%d J%04x", wl_name(st_now),
			             (unsigned long)(millis() - wc_attempt_ms), link, join);
			wc_last_status = st_now;
		}
		if ((uint32_t)(millis() - wc_attempt_ms) < WC_ATTEMPT_TIMEOUT)
			return;                    // still associating — let it cook, don't block
		{
			int      st   = (int)WiFi.status();
			int      link = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
			unsigned join = (unsigned)cyw43_state.wifi_join_state;
			// Name the failure from the DRIVER's state, not the collapsed WL_
			// code: WL 4 covers three different endings (FAIL, NONET, BADAUTH)
			// and WL 6 covers both "never associated" and "associated, no DHCP
			// lease". A failure wipes the join progress bits, so the finer story
			// (how far did the 4-way get) is in the transition lines above.
			const char *why = "no association - cipher, channel, or noise";
			if (st == 255)
				why = "the radio is not up";
			else if (st == 1)
				why = "cannot see that SSID - range or 5 GHz";
			else if (link == CYW43_LINK_BADAUTH)
				why = "the AP refused our key";
			else if (link == CYW43_LINK_NONET)
				why = "no AP matched this security mode";
			else if (link == CYW43_LINK_FAIL)
				why = "the join failed";
			else if ((join & 0x0e00) == 0x0e00)
				why = "WiFi joined but got no DHCP lease";
			Debug.printf("wifi: GAVE UP after %lums, %s link=%d join=%04x: %s\n",
			             (unsigned long)(millis() - wc_attempt_ms), wl_name(st),
			             link, join, why);
			wifi_log_add("FAILED: %s", why);
			wifi_log_add("  (%s L%d J%04x)", wl_name(st), link, join);
			wc_fail_streak++;
			// Walk the ladder on EVERY failure. A refusal under one mode says
			// nothing about the others: a WPA2/WPA3 transition AP that wants
			// management-frame protection refuses the plain-WPA2 join, and only
			// the WPA2/WPA3 rung changes what we offer it.
			wc_auth_rung = (wc_auth_rung + 1) % WC_AUTH_COUNT;
		}
		if (wc_trying_temp){           // the user's new AP did not associate
			wc_temp_tries++;
			if (wc_temp_tries >= WC_TEMP_MAX_TRIES){
				snprintf(failed_ssid, sizeof failed_ssid, "%s", temp_ssid);
				snprintf(failed_key,  sizeof failed_key,  "%s", temp_key);
				temp_ssid[0] = 0;
				temp_key[0] = 0;
				wc_temp_tries = 0;
				wifi_log_add("Giving up on this network");
				wifi_log_add("Send a photo of this screen for help");
				wifi_log_finished(WIFI_LINGER_FAILURE_MS);
			}
			wc_trying_temp = false;
		}
		WiFi.disconnect();             // abandon the stuck attempt before the next
		wc_trying = false;
		wc_cooldown_ms = millis();     // let the teardown finish before beginning again
	}

	// Still settling from the last disconnect: beginning now is what produces an
	// attempt that never leaves DISCONNECTED.
	if (wc_cooldown_ms && (uint32_t)(millis() - wc_cooldown_ms) < WC_DISCONNECT_COOLDOWN)
		return;
	wc_cooldown_ms = 0;

	// Start the next attempt. Past the streak limit the reported state stays
	// FAILED while the retries continue, so a caller is not told "connecting"
	// about something that has not connected in a dozen tries.
	wifi_state = WIFI_CONNECTING;
	phone_state_set(PS_WIFI_CONNECTING);
	if (wc_fail_streak >= wifi_fail_streak_limit) {
		wifi_state = WIFI_FAILED;
		phone_state_set(PS_WIFI_FAILED);
	}
	ui_wifi_state(WIFI_CONNECTING);
	if (!wc_begin_next()){
		wifi_state = WIFI_OFFLINE;     // nothing configured — retry next tick
		phone_state_set(PS_OFFLINE);
	}
}
