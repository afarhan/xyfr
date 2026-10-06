#include "debug.h"
#include <Arduino.h>
#include <WiFi.h>
#include "ui_symbols.h"
#include "ui.h"
#include "view.h"      // the chat thread is now a view (view.h), not imperative list_view calls
#include "view_theme.h" // view_theme — home's inline dim colours come from the ACTIVE theme
#include "view_backend.h" // rb_row_text_width — keep a home row to ONE line (no wrap)
#include "terminal.h"
#include "device_record.h"
#include "secure_store.h"      // store_needs_passphrase — a LOCKED store must never reach the welcome flow
#include "wg.h"
#include "bootstrap.h"
#include "contacts.h"
#include "msg.h"        // msg_ensure_log (mount the log for offline reads)
#include "channel_log.h"   // channel_create — Join Channel on the contact menu
#include "cmdq.h"
#include "audio.h"       // audio_set_mode / AUDIO_* (Settings > Audio route)
#include "webbackup.h"   // backup_mode_enter (the web backup server)
#include "restore_net.h" // restore_request_reboot (poll-mode restore via warm reboot)
#include <ctype.h>
#include <time.h>      // gmtime for message HH:MM

// Live-call queries, forward-declared here to avoid including call.h/session.h —
// they re-include the guard-less wg.h that this TU already pulls in.
#include "call.h"      // call_holding_audio / call_peer_of — the pinned "return to call" row
#include "kernel.h"    // screen_push, APP_CALL
extern volatile uint8_t flag_wipe_device;           // xyfr.ino: Wipe Out -> core-0 crypto-erase + reboot
#include <strings.h>   // strcasecmp

void go_settings();
void go_audio();
static void wipe_out();   // Wipe Out view (defined below; referenced by the Your Keys view)

/* contact ui */

static char selected_userid[32];

// Non-empty (an 8-hex userid) while the "Edit..." flow is active: the next
// Send (user_input) is treated as the new name for this contact, not a typed
// command. Cleared by go_home() (so Cancel / any navigation home resets it).
static char editing_uid[9];

// Copy the display name out of selected_userid (" <name>  <8hex-uid>" format:
// leading space, then the name, terminated by the double-space before the uid).
static void selected_contact_name(char *out, size_t n){
  out[0] = 0;
  const char *src = selected_userid;
  while (*src == ' ')
    src++;
  size_t i = 0;
  while (*src && i < n - 1) {
    if (src[0] == ' ' && src[1] == ' ')
      break;
    out[i++] = *src++;
  }
  out[i] = 0;
}

// Trailing 8 hex chars of selected_userid — set by on_contact() from the
// list label, which add_contacts() formats as " <name>  <8hex-uid>".
// Returns true on success and writes a lowercase 8-char nul-terminated
// string into out (caller-allocated, ≥9 bytes).
static bool parse_selected_uid(char out[9]){
  size_t n = strlen(selected_userid);
  if (n < 8)
    return false;
  const char *p = selected_userid + n - 8;
  for (int i = 0; i < 8; i++){
    if (!isxdigit((unsigned char)p[i]))
      return false;
    out[i] = (char)tolower((unsigned char)p[i]);
  }
  out[8] = 0;
  return true;
}

// Call... button: hop the work to core 0 via cmdq, where contacts/call
// can run safely. dispatch_cl() handles the contact lookup + originate.
// Pushing the call screen IS placing the call: its APP_FOREGROUND calls
// call_originate() and gets the handle on the spot, so there is no cmdq verb to
// post and no window to hold open while core 0 catches up.
static void on_call_selected(const char *message){
  (void)message;
  char uid[9];
  if (!parse_selected_uid(uid)){
    Debug.printf("call: can't parse uid from [%s]\n", selected_userid);
    return;
  }
  uint32_t partkey = 0;
  for (int j = 0; j < 8; j++) {
    char d = uid[j];
    uint8_t v = 0;
    if (d >= '0' && d <= '9')
      v = d - '0';
    else if (d >= 'a' && d <= 'f')
      v = 10 + d - 'a';
    else if (d >= 'A' && d <= 'F')
      v = 10 + d - 'A';
    partkey = (partkey << 4) | v;
  }
  screen_push(APP_CALL, partkey);
}

static void on_contact_delete(const char *message){
  (void)message;
  char uid[9];
  if (!parse_selected_uid(uid)){
    Debug.printf("contact delete: can't parse uid from [%s]\n",
      selected_userid);
    go_home();
    return;
  }
  char line[CMDQ_VERB_MAX + 8 + 2];
  snprintf(line, sizeof(line), "contact-del %s\n", uid);
  if (cmdq_post(&cmdq_ui_to_fs, line))
    Debug.printf("contact delete queued: %s", line);
  else
    Debug.println("contact delete: cmdq full, dropped");
  // Single-core: drain now so the delete is applied before go_home() re-reads the
  // list.
  cmdq_dispatch();
  go_home();
}

// Edit... : a VIEW — prompt directly above the entry, prefilled with the current
// name (rb_list_dock pins the prompt to the editor since there's no list). The
// target contact is carried in editing_uid; EDIT_ENTER applies the rename via c+
// (add-or-update keeps the key/status, changes only the name). ESC cancels
// (go_home clears editing_uid).
static int edit_name_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // no list — just the prompt + the entry
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *input = (const char *)data;
  bool has_char = false;
  for (const char *p = input; p && *p; p++)
    if (*p != ' ') {
      has_char = true;
      break;
    }
  if (!has_char)  // ignore an empty name; stay on the screen
    return 0;
  if (!editing_uid[0]) {
    go_home();
    return 0;
  }
  char line[CMDQ_VERB_MAX + 8 + 1 + MAX_NAME + 2];
  snprintf(line, sizeof line, "contact-add %s %s", editing_uid, input);
  editing_uid[0] = 0;
  if (cmdq_post(&cmdq_ui_to_fs, line))
    Debug.printf("contact rename queued: %s\n", line);
  else
    Debug.println("contact rename: cmdq full, dropped");
  // Single-core: drain now so the rename lands before go_home() re-reads the list.
  cmdq_dispatch();
  go_home();
  return 0;
}

static void on_contact_edit(const char *message){
  (void)message;
  char uid[9];
  if (!parse_selected_uid(uid)){
    Debug.printf("contact edit: can't parse uid from [%s]\n", selected_userid);
    go_home();
    return;
  }
  strcpy(editing_uid, uid);

  char name[MAX_NAME];
  selected_contact_name(name, sizeof(name));
  view_set(edit_name_cb, "Edit Name", "Edit the name and press Go.",
           NULL, "Contact name", name);   // entry prefilled with the current name
  view_set_input_max(MAX_NAME - 1);       // AFTER view_set, which resets the cap
}

// ---- Requests (missed handshakes) -------------------------------------------
// A handshake from a non-contact is refused, but the knock is filed (contacts.h
// contact_knock) and shown here once the server confirms the knocker is a
// registered user. Selecting one offers Allow / Ignore / Block. The knock table
// carries the peer's FULL key, so Allow/Block need no lookup — the k+/kb cmdq
// verbs write the contact straight out.
static uint32_t req_sel_pk = 0;                 // partkey of the row being acted on
static char     req_sel_hex[KEY_LEN * 2 + 1];   // its full key, hex, for k+/kb
static void go_requests(void);

// Format a knock's wall-clock stamp. seen_secs is 0 if NTP had not set the clock
// when the knock arrived — show a dash rather than 1970.
static void req_when(const struct missed_request *m, char *out, int cap){
  if (!m->seen_secs) {
    snprintf(out, cap, "--");
    return;
  }
  time_t t = (time_t)m->seen_secs;
  struct tm *tm = gmtime(&t);
  if (tm)
    strftime(out, (size_t)cap, "%d %b %H:%M", tm);
  else
    snprintf(out, cap, "--");
}

// Step 2 of Allow: name the new contact. Prefilled with the partkey, because at
// this point the user usually does NOT know who it is — their first message is
// the introduction, and the name can be edited afterwards.
static int req_name_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // no list — just the prompt + the entry
    return -1;
  if (op == LIST_BACK) {
    go_requests();
    return 0;
  }
  if (op != EDIT_ENTER)
    return 0;
  const char *input = (const char *)data;
  bool has_char = false;
  for (const char *p = input; p && *p; p++)
    if (*p != ' ') {
      has_char = true;
      break;
    }
  if (!has_char)  // empty name: stay put
    return 0;
  char line[CMDQ_VERB_MAX + KEY_LEN * 2 + 1 + MAX_NAME + 2];
  snprintf(line, sizeof line, "knock-allow %s %s", req_sel_hex, input);
  if (!cmdq_post(&cmdq_ui_to_fs, line))
    Debug.println("request allow: cmdq full, dropped");
  cmdq_dispatch();                       // single-core: land it before we re-read
  req_sel_pk = 0;
  go_home();
  return 0;
}

// Per-request action menu.
static const char *req_action_items[4];
static int req_action_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op == LIST_BACK) {
    go_requests();
    return 0;
  }
  if (op != LIST_SELECTED)
    return 0;
  char line[3 + KEY_LEN * 2 + 2];
  switch (i){
    case 0: {                            // Allow contact... -> name screen
      char prompt[96];
      snprintf(prompt, sizeof prompt,
               "Add %08X as a contact.\nName it (the id will do for now).",
               (unsigned)req_sel_pk);
      char prefill[9];
      snprintf(prefill, sizeof prefill, "%08x", (unsigned)req_sel_pk);
      view_set(req_name_cb, "Allow Contact", prompt, NULL, "Contact name", prefill);
      return 0;
    }
    case 1:                              // Ignore — drop the knock, no record kept
      snprintf(line, sizeof line, "knock-ignore %08x", (unsigned)req_sel_pk);
      break;
    case 2:                              // Block — a contact slot flagged BLOCKED
      snprintf(line, sizeof line, "knock-block %s", req_sel_hex);
      break;
    default:
      go_requests();
      return 0;
  }
  if (!cmdq_post(&cmdq_ui_to_fs, line))
    Debug.println("request action: cmdq full, dropped");
  cmdq_dispatch();
  req_sel_pk = 0;
  go_home();
  return 0;
}

static void req_action_open(const struct missed_request *m){
  req_sel_pk = m->part_key;
  for (int b = 0; b < KEY_LEN; b++)
    snprintf(req_sel_hex + b * 2, 3, "%02x", m->key[b]);
  char when[24];
  req_when(m, when, sizeof when);
  static char prompt[96];
  snprintf(prompt, sizeof prompt, "%08X\nRequested %s", (unsigned)m->part_key, when);
  int n = 0;
  req_action_items[n++] = LV_SYMBOL_PLUS  "  Allow contact...";
  req_action_items[n++] = LV_SYMBOL_CLOSE "  Ignore";
  req_action_items[n++] = LV_SYMBOL_WARNING "  Block";
  req_action_items[n]   = NULL;
  view_set(req_action_cb, "Request", prompt, req_action_items, NULL, NULL);
}

// The list itself: one row per confirmed knock, newest first.
static int requests_cb(view_op_t op, int i, void *data){
  switch (op){
    case LIST_GET_ITEM: {
      if (i < 0)
        return -1;
      struct missed_request m;
      if (!missed_request_at(i, &m))
        return -1;
      view_item_t *it = (view_item_t *)data;
      static char buf[24], mbuf[32];
      snprintf(buf, sizeof buf, "%08X", (unsigned)m.part_key);
      req_when(&m, mbuf, sizeof mbuf);
      it->text        = buf;
      it->meta        = mbuf;
      it->meta_inline = true;
      it->dot         = VIEW_DOT_UNVERIFIED;   // known-registered, but not yet yours
      it->user        = (void *)(uintptr_t)m.part_key;
      return 0;
    }
    case LIST_SELECTED: {
      struct missed_request m;
      if (missed_request_at(i, &m))
        req_action_open(&m);
      return 0;
    }
    case LIST_BACK:
      go_home();
      return 0;
    default:
      return 0;
  }
}

static void go_requests(void){
  view_set(requests_cb, "Requests",
           "People who tried to reach you.\nAllow, ignore or block each.",
           NULL, NULL, NULL);
}

// ---- Add Contact — a two-step VIEW flow (userid first, then the name) -------
// Step 1 asks for the contact's 8-hex userid (their partkey). Step 2 is the SAME
// name-entry screen as rename (edit_name_cb + editing_uid): its c+ upserts, which
// for a new userid creates a PENDING contact and kicks contact_lookup. Promoting
// a stranger thread (home > stranger menu > Add Contact...) already holds the
// partkey, so it jumps straight to step 2.

static void add_name_open(const char *uid8){
  strcpy(editing_uid, uid8);
  char prompt[64];
  snprintf(prompt, sizeof prompt, "Name for %s\nType the name and press Go.", uid8);
  view_set(edit_name_cb, "Add Contact", prompt, NULL, "Contact name", NULL);
  view_set_input_max(MAX_NAME - 1);        // 29 chars; 29 * 16 px worst case = 464 <= 468
}

static int add_uid_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // no list — just the prompt + the entry
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *in = (const char *)data;
  while (*in == ' ')
    in++;
  char uid[9];
  int n = 0;
  for (; n < 8 && in[n] && isxdigit((unsigned char)in[n]); n++)
    uid[n] = (char)tolower((unsigned char)in[n]);
  uid[n] = 0;
  const char *rest = in + n;
  while (*rest == ' ')
    rest++;
  if (n != 8 || *rest){                  // not exactly 8 hex digits: stay on the screen
    Debug.printf("add contact: bad userid [%s]\n", in);
    return 0;
  }
  add_name_open(uid);                    // step 2 (view_set: the engine won't touch us after)
  return 0;
}

static void add_contact_open(void){
  view_set(add_uid_cb, "Add Contact",
           "Enter the contact's userid\n(8 hex characters) and press Go.",
           NULL, "userid", NULL);
}

// The chat thread, its message menu and the full-text reader are kernel
// screens now (app_chat.c: APP_CHAT / APP_MSG_MENU / APP_MSG_VIEW).
// What remains here is the navigation that launches them.

static uint32_t uid8_to_partkey(const char *uid8){
  uint32_t pk = 0;
  for (int j = 0; j < 8; j++){
    char d = uid8[j];
    uint8_t v = (d >= '0' && d <= '9') ? d - '0'
              : (d >= 'a' && d <= 'f') ? 10 + d - 'a'
              : (d >= 'A' && d <= 'F') ? 10 + d - 'A' : 0;
    pk = (pk << 4) | v;
  }
  return pk;
}




// HOME's inbound liveness, and home's alone now: the stack calls
// screen_invalidate() when a message arrives, a call ends, a delivery flips, or
// a contact changes, and each ui_slice checks the flag so home rebuilds its
// cached merge without renavigating. The chat screens stopped needing this —
// they receive NOTIFY_MSG_UPDATE with the peer named (app_chat.c) — so the
// peer-less flag retires when home becomes a kernel screen.
extern "C" void home_invalidate(void);   // app_home.c owns the home list now




// Contact action menu — a static-list VIEW, rebuilt per open so the Star/Blocked/
// Burner rows reflect the contact's current settings (like go_settings' ringer
// label). on_contact() stashes the row label in selected_userid; actions read it
// back (parse_selected_uid). Parallel action array (cmenu_act) since
// the item set is fixed but labels are stateful.
// The secure key for one contact, made from a passphrase. It is ONE WAY -- the
// phrase becomes the key and is not kept -- so there is nothing to prefill and
// no way to show what is set. Both sides type the same words.
//
// BOTH SIDES MUST HOLD THE SAME ONE. Set on one side only, that peer stops
// handshaking, which is the point of it and not a fault to chase.
static uint32_t seckey_uid;

static const char *seckey_on_text(const char *text) {
	int n = 0;
	if (text)
		n = (int)strlen(text);
	if (n > CONTACT_PSK_PHRASE_MAX)
		return "Too long. Enter:";
	if (!contact_psk_set(seckey_uid, text))
		return "Could not save it. Enter:";
	if (n == 0)
		Debug.printf("pqc: %08x cleared\n", (unsigned)seckey_uid);
	else
		Debug.printf("pqc: %08x set\n", (unsigned)seckey_uid);
	return NULL;
}

enum { CM_TEXT, CM_DELTEXTS, CM_CALL, CM_TALK, CM_TERM, CM_JOIN, CM_FIND, CM_STAR, CM_BLOCK, CM_PTT, CM_BURNER,
       CM_SECKEY, CM_EDIT, CM_DELETE };
// Room for every row PLUS the NULL the view engine terminates on.
static const char *cmenu_disp[16];
static uint8_t     cmenu_act[16];
static int         cmenu_n;
static const char *cmenu_notice;    // an error to show above the rows, once

static void contact_menu_show(void);

// ---- Join Channel — a two-step VIEW flow (id first, then the name) ----------
// The contact whose menu this is IS the host, so the id and the name are all
// that is left to say. An id already in the home list under this host is not a
// join: a second record would name the same log twice, so it says so and goes
// back to the menu.

static uint32_t join_channel_host;
static uint16_t join_channel_id;

static int join_name_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *name = (const char *)data;
  while (*name == ' ')
    name++;
  if (!*name)                      // empty name: stay on the screen
    return 0;
  if (!channel_create(join_channel_host, join_channel_id, name)){
    cmenu_notice = "Could not join that channel.";
    contact_menu_show();
    return 0;
  }
  home_invalidate();
  go_home();
  return 0;
}

static void join_name_open(void){
  static char prompt[64];
  snprintf(prompt, sizeof prompt,
           "Name for channel %u\nType the name and press Go.",
           (unsigned)join_channel_id);
  view_set(join_name_cb, "Join Channel", prompt, NULL, "Channel name", NULL);
  view_set_input_max(CHANNEL_NAME_MAX - 1);
}

static int join_id_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  int id = atoi((const char *)data);
  if (id < 1 || id > (int)CHANNEL_ID_MAX)   // out of range: stay on the screen
    return 0;
  struct channel_record have;
  if (channel_get(join_channel_host, (uint16_t)id, &have)){
    cmenu_notice = "Already on that channel.";
    contact_menu_show();
    return 0;
  }
  join_channel_id = (uint16_t)id;
  join_name_open();                // step 2 (view_set: the engine won't touch us after)
  return 0;
}

static void join_channel_open(void){
  view_set(join_id_cb, "Join Channel",
           "Enter the channel id and press Go.", NULL, "channel id", "1");
}

// Toggle a contact.settings bit via the cf cmdq verb, then re-render the menu so
// the row's On/Off label updates. Single-core: drain inline (like delete/rename).
static void contact_toggle_flag(uint32_t mask){
	char uid8[9];
	if (!parse_selected_uid(uid8))
		return;
	char line[CMDQ_VERB_MAX + 8 + 1 + 8 + 1 + 1 + 1];
	snprintf(line, sizeof line, "contact-flag %s %x t", uid8, (unsigned)mask);
	if (cmdq_post(&cmdq_ui_to_fs, line))
		cmdq_dispatch();
	else
		Debug.println("contact flag: cmdq full, dropped");
	contact_menu_show();
}

// ---- key-verification gate (THREAT_MODEL §9.5) ------------------------------
// A compromised directory server can hand back a full key that merely COLLIDES on
// the 32-bit partkey the user typed (grindable in ~hours). The wg handshake cannot
// catch that — it authenticates whatever key we were given. So the FIRST comms
// action (Text/Call/Talk/Terminal) to a resolved-but-unverified contact is gated:
// show the full 64-hex key and ask the user to confirm it out-of-band ("does yours
// end in 7f89ed?"). Yes -> mark CONTACT_VERIFIED (green dot) + proceed; No -> delete
// the contact + abort; Proceed -> run the action THIS ONCE (so the user can read the
// key to a friend over the very channel they're opening) but stay unverified so we
// ask again next time.
static int      vgate_action  = -1;    // CM_TEXT / CM_CALL / CM_TERM
static uint32_t vgate_partkey = 0;
static char     vgate_prompt[480];     // WHY + the key on two lines of four blocks

static const char *vgate_items[] = {
	LV_SYMBOL_OK    "  Confirmed! the key is correct",
	LV_SYMBOL_TRASH "  Delete, the key is not correct",
	LV_SYMBOL_RIGHT "  Proceed, I'll check later",
	NULL
};

// Run the deferred comms action once the gate has been answered/bypassed.
static void vgate_run(int action){
	switch (action){
		case CM_TEXT: screen_push(APP_CHAT, vgate_partkey); break;
		case CM_CALL: on_call_selected(NULL); break;
		case CM_TALK: screen_push(APP_PTT, vgate_partkey); break;
		case CM_TERM: {
			struct contact_record c;
			if (contact_get(&c, vgate_partkey) && c.status == CONTACT_KEY_VALID)
				screen_push(APP_TERM, contact_userid(&c));
			else
				Debug.println("terminal: contact key not resolved yet");
			break;
		}
	}
}

static int vgate_cb(view_op_t op, int i, void *data){
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	int      action = vgate_action;
	uint32_t pk     = vgate_partkey;
	if (i == 0){                                    // Yes -> trust + proceed
		char line[CMDQ_VERB_MAX + 8 + 1 + 8 + 1 + 1 + 1];
		snprintf(line, sizeof line, "contact-flag %08x %x s", (unsigned)pk, (unsigned)CONTACT_VERIFIED);
		if (cmdq_post(&cmdq_ui_to_fs, line))
			cmdq_dispatch();
		home_invalidate();
		vgate_run(action);
	} else if (i == 1){                             // No -> delete + home
		char line[CMDQ_VERB_MAX + 8 + 1];
		snprintf(line, sizeof line, "contact-del %08x", (unsigned)pk);
		if (cmdq_post(&cmdq_ui_to_fs, line))
			cmdq_dispatch();
		home_invalidate();
		go_home();
	} else {                                        // Proceed -> run once, stay unverified
		vgate_run(action);
	}
	return 0;
}

// If the selected contact is resolved (VALID) but its key is not yet user-verified,
// arm the gate and return true (caller must NOT run the action). False for a
// not-yet-resolved contact (let the action's own handling apply) or an already-
// verified one (straight through).
static bool vgate_needed(int action){
	char uid8[9];
	if (!parse_selected_uid(uid8))
		return false;
	uint32_t pk = uid8_to_partkey(uid8);
	struct contact_record c;
	if (!contact_get(&c, pk))
		return false;
	if (c.status != CONTACT_KEY_VALID)  // still resolving — action handles it
		return false;
	if (c.settings & CONTACT_VERIFIED)  // already green — no gate
		return false;
	// The full key as two lines of four 4-byte blocks: 8 hex per block, space
	// between blocks, newline after the 4th (byte 15).
	char kh[80];
	int o = 0;
	for (int b = 0; b < KEY_LEN; b++){
		o += snprintf(kh + o, sizeof kh - o, "%02x", c.key[b]);
		if (b == 15)  // break after the first four blocks
			kh[o++] = '\n';
		else if ((b & 3) == 3 && b != KEY_LEN - 1)
			kh[o++] = ' ';
	}
	kh[o] = 0;
	// A nameless contact shows its 8-hex partkey where the name would go.
	char dispname[MAX_NAME];
	if (c.name[0]){
		strncpy(dispname, c.name, sizeof dispname - 1);
		dispname[sizeof dispname - 1] = 0;
	} else {
		snprintf(dispname, sizeof dispname, "%08x", (unsigned)pk);
	}
	// WHY, in plain words: you only typed 8 digits (the ID); the server supplied the
	// rest of the key. Traffic stays end-to-end encrypted - the server reads nothing.
	// The risk is an IMPOSTOR whose key shares those first 8 digits. Confirm the whole
	// key with the human, out of band. Confirming silences this gate for the contact.
	snprintf(vgate_prompt, sizeof vgate_prompt,
	         "You added %s by an 8-letter ID. The server filled in the rest of the key. "
	         "An imposter's key could also have the same first 8-digits. So ask %s to read "
	         "their key aloud on the first call and check that the letters match:\n\n%s\n\n"
	         "If you choose \"Confirmed!\", you won't see this message again.",
	         dispname, dispname, kh);
	vgate_action  = action;
	vgate_partkey = pk;
	view_set(vgate_cb, "Verify key", vgate_prompt, vgate_items, NULL, NULL);
	return true;
}

// "Delete all Texts" — crypto-erases the whole thread with this contact.
//
// Confirmed, unlike the contact Delete directly below it in the same menu. That
// is not inconsistency: deleting a contact loses a name and a key you can be
// given again, while this destroys the messages themselves, in place, with
// nothing anywhere to restore them from. The contact survives either way.
static const char *deltexts_items[] = { "Delete all Texts", "Cancel", NULL };

// Which menu opened us. A stranger thread has no contact record to go back TO,
// and once its texts are erased the thread itself stops existing (home lists
// stranger rows straight off the logbook), so a successful delete lands home.
// Cancel/back still returns to the menu the user came from.
static bool deltexts_stranger = false;
static void deltexts_return(void){
  if (deltexts_stranger)
    go_home();
  else
    contact_menu_show();
}

static int deltexts_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op == LIST_BACK){
    deltexts_return();
    return 0;
  }
  if (op != LIST_SELECTED)
    return 0;
  if (i != 0){                       // Cancel
    deltexts_return();
    return 0;
  }
  char uid[9];
  if (!parse_selected_uid(uid)){
    Debug.printf("delete texts: can't parse uid from [%s]\n", selected_userid);
    go_home();
    return 0;
  }
  char line[CMDQ_VERB_MAX + 8 + 2];
  snprintf(line, sizeof line, "msg-delete-all %s", uid);
  if (!cmdq_post(&cmdq_ui_to_fs, line)){
    Debug.println("delete texts: cmdq full, dropped");
    deltexts_return();
    return 0;
  }
  // Single-core: drain now, so the thread is gone before the menu re-reads it.
  // Under the two-core split this reverts to post-and-let-core-0-drain.
  cmdq_dispatch();
  deltexts_return();
  return 0;
}

static void deltexts_confirm(void){
  deltexts_stranger = false;
  char name[MAX_NAME];
  selected_contact_name(name, sizeof name);
  static char prompt[220];
  snprintf(prompt, sizeof prompt,
           "\n"
           "Delete all Texts\n\n"
           "Every message to and from %s is erased from this device, "
           "including messages not yet sent.\n\n"
           "This cannot be undone. The contact itself is kept.",
           name[0] ? name : "this contact");
  view_set(deltexts_cb, "Delete all Texts", prompt, deltexts_items, NULL, NULL);
}

// Same confirm, from a stranger thread. Worded for the difference that matters:
// there is no contact record to keep, so erasing the texts removes the thread
// itself and its row disappears from home.
static void deltexts_confirm_stranger(void){
  deltexts_stranger = true;
  char uid[9];
  if (!parse_selected_uid(uid))
    uid[0] = 0;
  static char prompt[220];
  snprintf(prompt, sizeof prompt,
           "\n"
           "Delete all Texts\n\n"
           "Every message to and from %s is erased from this device, "
           "including messages not yet sent.\n\n"
           "This cannot be undone. The thread is removed.",
           uid[0] ? uid : "this sender");
  view_set(deltexts_cb, "Delete all Texts", prompt, deltexts_items, NULL, NULL);
}

static int contact_menu_cb(view_op_t op, int i, void *data){
	(void)data;
	if (op == LIST_KEY)
		return ui_volume_key(i);          // LIST_KEY carries the key in `i`
	if (op != LIST_SELECTED || i < 0 || i >= cmenu_n)
		return 0;
	switch (cmenu_act[i]){
		case CM_TEXT: {                                            // the chat thread screen
			char uid8[9];
			if (!vgate_needed(CM_TEXT) && parse_selected_uid(uid8))
				screen_push(APP_CHAT, uid8_to_partkey(uid8));
			break;
		}
		case CM_DELTEXTS: deltexts_confirm();              break;  // confirm, then erase the thread
		case CM_FIND: {                                            // re-query key + endpoint
			char uid[9];
			if (!parse_selected_uid(uid))
				break;
			char line[CMDQ_VERB_MAX + 8 + 2];
			snprintf(line, sizeof line, "contact-find %s", uid);
			if (cmdq_post(&cmdq_ui_to_fs, line)) {
				cmdq_dispatch();                                   // single-core: drain now
				Debug.printf("find: querying %s\n", uid);
			} else
				Debug.println("find: cmdq full, dropped");
			break;
		}
		case CM_CALL:   if (!vgate_needed(CM_CALL)) on_call_selected(NULL); break;  // opens the call view
		case CM_TALK: {                                            // push-to-talk screen
			char uid8[9];
			if (!vgate_needed(CM_TALK) && parse_selected_uid(uid8))
				screen_push(APP_PTT, uid8_to_partkey(uid8));
			break;
		}
		case CM_TERM: {                                            // remote terminal to this contact
			if (vgate_needed(CM_TERM))
				break;                                            // gate armed; runs on the user's Yes/Proceed
			char uid8[9];
			struct contact_record c;
			if (parse_selected_uid(uid8) && contact_get(&c, uid8_to_partkey(uid8))
			    && c.status == CONTACT_KEY_VALID)
				screen_push(APP_TERM, contact_userid(&c));     // the terminal is a screen
			else
				Debug.println("terminal: contact key not resolved yet");
			break;
		}
		case CM_JOIN: {                                            // a channel this contact hosts
			char uid8[9];
			if (!parse_selected_uid(uid8))
				break;
			join_channel_host = uid8_to_partkey(uid8);
			join_channel_open();
			break;
		}
		case CM_SECKEY: {                                          // set it, or clear it
			char uid8[9];
			if (!parse_selected_uid(uid8))
				break;
			seckey_uid = uid8_to_partkey(uid8);
			// Clearing needs nothing typed, so it happens here and the menu is
			// rebuilt to offer the other half.
			if (contact_has_psk(seckey_uid)) {
				if (contact_psk_set(seckey_uid, NULL))
					Debug.printf("pqc: %08x cleared\n", (unsigned)seckey_uid);
				contact_menu_show();
				break;
			}
			// No prefill: the phrase was never kept, so there is nothing to
			// show and nothing to edit.
			screen_ask("PQC Key", "Both sides type the same words:",
			           NULL, NULL, true, seckey_on_text);
			break;
		}
		case CM_STAR:   contact_toggle_flag(CONTACT_STAR);  break;
		case CM_BLOCK:  contact_toggle_flag(CONTACT_BLOCKED); break;
		case CM_PTT:    contact_toggle_flag(CONTACT_ALLOW_PTT); break;
		case CM_BURNER: contact_toggle_flag(CONTACT_BURNER); break;
		case CM_EDIT:   on_contact_edit(NULL);              break;  // Edit Name VIEW
		case CM_DELETE: on_contact_delete(NULL);            break;  // delete + go_home
	}
	return 0;
}

// Rebuild + show the menu from selected_userid (its current settings decide the
// On/Off labels). Row label strings are static literals (persistent — the engine
// borrows cmenu_disp).
static void contact_menu_show(void){
	uint32_t settings = 0;
	bool has_psk = false;
	char uid8[9];
	if (parse_selected_uid(uid8)){
		struct contact_record c;
		if (contact_get(&c, uid8_to_partkey(uid8)))
			settings = c.settings;
		has_psk = contact_has_psk(uid8_to_partkey(uid8));
	}
	char name[MAX_NAME];
	selected_contact_name(name, sizeof name);   // clean name for the title bar
	if (!name[0])
		return;

	cmenu_n = 0;
	#define CM_ADD(txt, act) do { cmenu_disp[cmenu_n] = (txt); cmenu_act[cmenu_n++] = (act); } while (0)
	CM_ADD(LV_SYMBOL_KEYBOARD "  Text...", CM_TEXT);
	CM_ADD(LV_SYMBOL_TRASH    "  Delete all Texts", CM_DELTEXTS);
	CM_ADD(LV_SYMBOL_CALL       "  Call...", CM_CALL);
	CM_ADD(LV_SYMBOL_VOLUME_MAX "  PTT...", CM_TALK);
	CM_ADD(LV_SYMBOL_LIST       "  Terminal...", CM_TERM);
	CM_ADD(LV_SYMBOL_PLUS       "  Join Channel...", CM_JOIN);
	// "Find..." re-asks the server for this contact's key + relay endpoint. It is
	// the ONLY non-Retry way to re-resolve, because nothing re-queries
	// automatically: a failed handshake cannot tell "offline" from "moved relay".
	CM_ADD(LV_SYMBOL_REFRESH    "  Find...", CM_FIND);
	CM_ADD((settings & CONTACT_STAR)    ? LV_SYMBOL_OK "  Star: On"    : "     Star: Off",    CM_STAR);
	CM_ADD((settings & CONTACT_BLOCKED) ? LV_SYMBOL_OK "  Blocked: On" : "     Blocked: Off", CM_BLOCK);
	// PTT plays with no ring and no accept, so it is granted per contact.
	CM_ADD((settings & CONTACT_ALLOW_PTT) ? LV_SYMBOL_OK "  PTT: On"    : "     PTT: Off",    CM_PTT);
	CM_ADD((settings & CONTACT_BURNER)  ? LV_SYMBOL_OK "  Burner: On"  : "     Burner: Off",  CM_BURNER);
	// Two states, not an editor: the key is one way, so it can be set or removed
	// and never shown. The row says which of those selecting it will do.
	if (has_psk)
		CM_ADD(LV_SYMBOL_TRASH    "  Clear PQC Key", CM_SECKEY);
	else
		CM_ADD(LV_SYMBOL_KEYBOARD "  Set PQC Key...", CM_SECKEY);
	CM_ADD(LV_SYMBOL_EDIT  "  Edit...", CM_EDIT);
	CM_ADD(LV_SYMBOL_TRASH "  Delete",  CM_DELETE);
	#undef CM_ADD
	cmenu_disp[cmenu_n] = NULL;
	view_set(contact_menu_cb, name, cmenu_notice, cmenu_disp, NULL, NULL);
	cmenu_notice = NULL;
}

static void on_contact(const char *contact_id){
	strcpy(selected_userid, contact_id);
	contact_menu_show();
}

// ---- stranger thread menu — a static-list VIEW ------------------------------
// A logbook thread with no contact behind it (a NOCONTACT sender). Fully two-way:
// each record carries the peer's full wg-authenticated key (the msg.c NOCONTACT
// payload contract), so messaging AND calling work without a contact entry —
// one-off exchanges never touch the contact ring. "Add Contact..." (partkey known
// → straight to the name step) remains the optional promote path.
//
// "Delete all Texts" is the ONLY way to get rid of a stranger thread, and home
// lists these rows straight off the logbook — so without it a thread was
// permanently undeletable. That bit worst after deleting a contact: the contact
// record went, its logbook thread stayed, and it reappeared as a stranger row
// with no delete anywhere (and unreadable, since deleting the contact destroys
// the contact_key its payloads were sealed under). Same confirm flow and same
// msg-delete-all verb as the contact menu; ordered second to match it.
static const char *stranger_menu_items[] = {
	LV_SYMBOL_TRASH    "  Delete all Texts",
	LV_SYMBOL_PLUS     "  Add Contact...",
	NULL,
};

static int stranger_menu_cb(view_op_t op, int i, void *data){
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	switch (i){
		case 0: deltexts_confirm_stranger();        break;  // confirm, then erase the thread
		case 1: {                                           // promote: partkey known — go straight to the name step
			char uid[9];
			if (parse_selected_uid(uid))
				add_name_open(uid);
			break;
		}
	}
	return 0;
}

static void on_stranger(uint32_t partkey){
	// " <name>  <8hex-uid>" shape (name = the hex uid) so parse_selected_uid /
	// the contact actions read it back exactly like a contact row's label.
	snprintf(selected_userid, sizeof selected_userid, " %08x  %08x",
	         (unsigned)partkey, (unsigned)partkey);
	char title[16];
	snprintf(title, sizeof title, "%08X", (unsigned)partkey);
	view_set(stranger_menu_cb, title, "Messages from an unknown sender", stranger_menu_items, NULL, NULL);
}

// Wipe Out — a VIEW: warning in the Prompt zone, a "yes" confirmation in the
// editor. Go (EDIT_ENTER) with exactly "yes" requests the wipe; anything else
// (or ESC) returns home. The erase itself — crypto-erase the volume key + clear
// contacts, then reboot — runs on core 0 via flag_wipe_device, since flash + the
// reboot must not run from this UI handler.

// (The old "Your Keys" fresh-device menu — Register / Sign In / Wipe Out — is
// retired: the step-0 welcome chooser covers New + Sign In on a fresh device, and
// Admin exposes Register / Sign In / Wipe Out on a configured one.)

// Progress text is rendered live from doh_stage by unblock_ui_pump() below.
static int last_unblock_stage = -1;
// After the new relay is set (DOH_APPLIED) the screen waits for the re-login to land
// before it can say "Connected". reconnect_deadline caps that wait; home_after_ms is
// the short "Connected." linger before auto-returning home. 0 = inactive. Wrap-safe
// (unsigned-elapsed compare), like the other timers here.
static uint32_t reconnect_deadline = 0;
static uint32_t home_after_ms      = 0;

// Onboarding relay gate: a fresh device (no identity) must set a relay before the
// welcome chooser. relay_step_done latches once the relay is chosen this setup
// session (resets on the wipe/reboot that starts a fresh setup). During that step
// the DoH/manual-entry completions route to the chooser instead of Settings/home.
static bool relay_step_done = false;
// The kernel-side relay entry (app_home.c) marks the onboarding step done here.
extern "C" void relay_step_mark_done(void){ relay_step_done = true; }
static bool identity_absent(void){
  for (int j = 0; j < KEY_LEN; j++)
    if (device_record.my_private_key[j])
      return false;
  return true;
}
static bool onboarding_relay_step(void){ return identity_absent() && !relay_step_done; }
// Defined below go_relay_ip(); forward-declared for unblock_ui_pump / go_home_setup.
static int relay_gate_cb(view_op_t op, int i, void *data);
static int relay_fail_cb(view_op_t op, int i, void *data);

// Unblock — a VIEW. The DoH resolve runs on core 0 (request_fetch_new_ip sets
// doh_result when done); the outcome is rendered by the deferred unblock_ui_pump
// (called from ui_slice, outside any LVGL event dispatch) — no busy-spin, the
// pattern wait_on_flag used to hand-roll. A single "Return" item on the result /
// offline screens; ESC also returns home.
static volatile bool unblock_wait_active = false;

static int unblock_cb(view_op_t op, int i, void *data){
  // Status screen with ONE "Return" row so BOTH keys go home: Enter selects the row
  // (LIST_SELECTED), Backspace hits it via the view engine's global back-fallback.
  // Every other index MUST return -1 (no item) -- returning 0 means "item exists",
  // which makes the view believe it has an infinite list and hangs the render (the
  // long-hunted Unblock freeze).
  if (op == LIST_GET_ITEM){
    if (i != 0)
      return -1;
    view_item_t *it = (view_item_t *)data;
    it->text  = "Return";
    it->style = TERMINAL_NORMAL;
    it->user  = NULL;
    return 0;
  }
  if (op == LIST_SELECTED || op == LIST_BACK){   // Enter on "Return", or Backspace
    unblock_wait_active = false; reconnect_deadline = 0; home_after_ms = 0; last_unblock_stage = -1;
    go_home();
    return 0;
  }
  return 0;   // LIST_COUNT (1 item) etc.
}

// Kick the DoH relay resolve and open the progress screen. Same code path for
// onboarding "Find a Relay" and Settings > Admin > "Find a Relay..." — no confirm.
static void start_unblock(){
  if (wifi_get_status() != WIFI_ONLINE){
    view_set(unblock_cb, "Find a Relay",
             "WiFi is not connected.\nConnect WiFi and try again.",
             NULL, NULL, NULL);
    return;
  }
  doh_result = 0;
  request_fetch_new_ip();               // -> doh_stage = DOH_FETCHING
  last_unblock_stage  = DOH_FETCHING;   // the "Fetching" prompt is shown just below
  unblock_wait_active = true;
  view_set(unblock_cb, "Find a Relay", "Finding a relay...", NULL, NULL, NULL);
}

// "Find a Relay..." from Admin runs the DoH directly (no confirm screen).
extern "C" void do_unblocking(){   // C linkage: launched from app_home.c's Admin
  start_unblock();
}

// Deferred outcome renderer for Unblock — polled from ui_slice (core 1), like
// registration_ui_pump / wifi_ui_pump. If the user navigated away from the
// Unblock screen meanwhile, just drop the wait (core 0 finishes the fetch
// harmlessly); otherwise render doh_strings[doh_result-1] + Return.
void unblock_ui_pump(){
  // "Connected." linger, then auto-return home. Runs independent of the wait flag;
  // only homes if we're still on the Unblock screen (don't yank a user who left).
  if (home_after_ms){
    if ((int32_t)(millis() - home_after_ms) >= 0){
      home_after_ms = 0;
      if (view_current() == unblock_cb)
        go_home();
    }
    return;
  }

  if (!unblock_wait_active)
    return;
  if (view_current() != unblock_cb){
    unblock_wait_active = false; last_unblock_stage = -1; reconnect_deadline = 0; return;
  }

  // Post-apply: the new relay is set; wait for the re-login to land, then show
  // "Connected." and auto-home. Falls back to home on timeout (the device keeps
  // retrying login in the background regardless). doh_stage stays DOH_APPLIED here,
  // so this is checked every tick, before the stage-change gate below.
  if (doh_stage == DOH_APPLIED && reconnect_deadline){
    if (ltp_is_online()){
      reconnect_deadline = 0; unblock_wait_active = false; last_unblock_stage = -1;
      home_after_ms = millis() + 1500;   // show "Connected." briefly, then go home
      view_set(unblock_cb, "Find a Relay", "Connected.", NULL, NULL, NULL);
      return;
    }
    if ((int32_t)(millis() - reconnect_deadline) >= 0){
      reconnect_deadline = 0; unblock_wait_active = false; last_unblock_stage = -1;
      go_home();   // login didn't confirm in time; return home, it keeps trying
    }
    return;   // keep showing "Reconnecting..." until online or timeout
  }

  int st = doh_stage;
  if (st == last_unblock_stage)  // no change since last render
    return;
  last_unblock_stage = st;
  const char *msg;
  switch (st){
    case DOH_FETCHING: msg = "Finding a relay...";  break;
    case DOH_RECEIVED: msg = "Relay found";         break;
    case DOH_APPLIED:
      // ONBOARDING: no identity yet, so there's nothing to log in / wait for --
      // the relay is set, advance straight to the welcome chooser.
      if (onboarding_relay_step()){
        relay_step_done = true; unblock_wait_active = false; last_unblock_stage = -1;
        go_home();         // -> welcome chooser (relay_step_done now true)
        return;
      }
      msg = "New relay is set.\nReconnecting...";
      reconnect_deadline = millis() + 15000;   // configured device: wait up to 15s for login
      break;
    case DOH_FAILED:
      // Couldn't reach the relay directory (Cloudflare/DoH). Offer retry or manual
      // entry -- one screen for both onboarding and Settings.
      unblock_wait_active = false; last_unblock_stage = -1;
      view_set(relay_fail_cb, "Find a Relay",
               "Couldn't reach the relay directory.\nTry again, or enter a relay IP.",
               NULL, NULL, NULL);
      return;
    default: return;
  }
  view_set(unblock_cb, "Find a Relay", msg, NULL, NULL, NULL);
}

// Settings — a static-list VIEW, rebuilt each open so stateful rows (ringer,
// presence, allow, audio) show their current value. A parallel action array
// (settings_act) drives dispatch so rows can be added/reordered without
// re-indexing a switch. Term... is parked here for now to keep it off home.
static void go_relay_ip();   // the onboarding gates below launch it

// ---- Settings > Admin: the rarely-changed items (keys, relay, backup, term) ----
// Its own static-list VIEW; Backspace returns to Settings. The "Your Keys" trio
// is flattened in here directly (Register/Sign In/Wipe Out) rather than nested.
enum { ADM_REGISTER, ADM_SIGNIN, ADM_DISKKEY, ADM_SETPIN, ADM_SETBURNER, ADM_RELAYIP,
       ADM_UNBLOCK, ADM_BACKUP, ADM_RESTORE, ADM_FWUPDATE, ADM_DEVMODE, ADM_ABOUT, ADM_WIPE };
// (No Admin "Term..." entry: a terminal needs a PEER, and that menu has no
// contact selected, so it could only ever open a target-less screen. Terminal
// lives on the CONTACT menu (CM_TERM), which resolves that contact's key.)
static const char *admin_items[15];
static uint8_t     admin_act[15];
static int         admin_n;

extern "C" void restore_confirm_push(void);
static void restore_confirm_open(void){
  restore_confirm_push();
}
void go_admin(){
  screen_push(APP_ADMIN, 0);
}

void go_security(){
  screen_push(APP_SECURITY, 0);
}



// Onboarding relay gate + the DoH-failure retry/manual screen. Both are dynamic-list
// views (cb serves LIST_GET_ITEM; -1 past the end -- see the unblock_cb note on the
// infinite-list wedge). "Find a relay" and "Enter IP" reuse the same paths as Admin.
static int relay_gate_cb(view_op_t op, int i, void *data){
  if (op == LIST_GET_ITEM){
    view_item_t *it = (view_item_t *)data;
    if (i == 0) {
      it->text = LV_SYMBOL_GPS   "  Find a relay IP";
      it->style = TERMINAL_NORMAL;
      it->user = NULL;
      return 0;
    }
    if (i == 1) {
      it->text = LV_SYMBOL_EDIT  "  Enter Relay's IP address";
      it->style = TERMINAL_NORMAL;
      it->user = NULL;
      return 0;
    }
    return -1;
  }
  if (op == LIST_SELECTED){
    if (i == 0)  // Find -> DoH (no confirm); onboarding routing on DOH_APPLIED
      start_unblock();
    else  // Enter -> relay IP screen
      go_relay_ip();
  }
  return 0;
}
static int relay_fail_cb(view_op_t op, int i, void *data){
  if (op == LIST_GET_ITEM){
    view_item_t *it = (view_item_t *)data;
    if (i == 0) {
      it->text = LV_SYMBOL_REFRESH "  Try again";
      it->style = TERMINAL_NORMAL;
      it->user = NULL;
      return 0;
    }
    if (i == 1) {
      it->text = LV_SYMBOL_GPS     "  Enter relay IP";
      it->style = TERMINAL_NORMAL;
      it->user = NULL;
      return 0;
    }
    return -1;
  }
  if (op == LIST_SELECTED){
    if (i == 0)  // retry the DoH (onboarding state preserved via identity_absent)
      start_unblock();
    else  // manual entry
      go_relay_ip();
  }
  return 0;
}

extern "C" void relay_ip_ask_open(void);
static void go_relay_ip(){
  relay_ip_ask_open();
}

void go_settings(){
  screen_push(APP_SETTINGS, 0);
}

// First-time / unconfigured setup screen — shown until BOTH WiFi and a private
// key are present. It offers only what's still missing: WiFi when no AP is
// The step-0 WELCOME CHOOSER for a fresh/wiped device (no private key yet): the
// three onboarding paths (New, Sign In, Restore). EVERY path needs WiFi first (New
// and Sign In reach the server; Restore uploads a backup), so a path that finds
// WiFi down routes to a Connect-WiFi step, after which the user returns and
// re-picks. (Endpoint/relay resolution is a later prereq step; Your Keys / Unblock
// stay reachable from Settings on a configured device.)
// Set true by welcome_wifi_pump on a failed connect (CONNECTING -> OFFLINE);
// cleared on a new attempt / success / retry. Distinguishes a failed connect from
// a fresh device (both read WIFI_OFFLINE) so the welcome shows the right screen.
static bool wifi_login_failed = false;
// The "Welcome to Xyfr" splash shows once per boot; after the user dismisses it
// (Enter -> WiFi setup), an idle-offline state drops straight to the AP list rather
// than re-showing the splash, so the flow just iterates WiFi setup until connected.
static bool welcome_shown = false;

static const char *welcome_disp[] = {
  LV_SYMBOL_PLUS    "  Set up a new phone",
  LV_SYMBOL_UPLOAD  "  Restore from a backup",
  LV_SYMBOL_SD_CARD "  Sign in with my key",
  NULL,
};

// The WiFi-first gate screen: a fresh device (a wipe clears the AP list) has no
// connection, and all three paths need one, so the welcome offers WiFi setup
// first. The single (auto-focused) row is the Enter target — pressing Enter opens
// WiFi; wifi_open() returns home when done, and go_home_setup re-checks.
static const char *welcome_wifi_items[] = { "Press ENTER to continue", NULL };
static int welcome_wifi_cb(view_op_t op, int i, void *data){
  (void)i;
  (void)data;
  if (op == LIST_SELECTED){
    welcome_shown = true;   // splash dismissed -> stay in the WiFi loop from here on
    wifi_open();            // Enter -> WiFi setup; returns home when done
  }
  return 0;
}

// The "connecting" screen — shown while WiFi is associating (after an AP + key were
// entered). Enter cancels back to the AP list; when the connect completes, the
// welcome flips to the three paths (welcome_wifi_pump re-renders on the state change).
static const char *welcome_wait_items[] = { "Press ENTER to Cancel", NULL };
static int welcome_wait_cb(view_op_t op, int i, void *data){
  (void)i;
  (void)data;
  if (op == LIST_SELECTED)  // Cancel -> back to the WiFi AP list
    wifi_open();
  return 0;
}

// The "connection failed" screen. Enter retries by returning to the AP list.
static const char *welcome_fail_items[] = { "Press ENTER to retry", NULL };
static int welcome_fail_cb(view_op_t op, int i, void *data){
  (void)i;
  (void)data;
  if (op == LIST_SELECTED){
    wifi_login_failed = false;   // retrying
    wifi_open();                 // back to the WiFi AP list
  }
  return 0;
}

static int welcome_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op != LIST_SELECTED || i < 0 || i > 2)
    return 0;
  if (wifi_get_status() != WIFI_ONLINE){   // WiFi dropped since the chooser drew -> re-gate
    go_home();
    return 0;
  }
  switch (i){
    case 0: registration_start();   break;   // Set up a new phone (register)
    case 1: restore_confirm_open(); break;   // Restore from a backup
    case 2: key_import_start();     break;   // Sign in (import an existing key)
  }
  return 0;
}

static void go_home_setup(bool wifi_is_empty, bool key_absent){
  (void)wifi_is_empty;
  (void)key_absent;
  // WiFi gates the chooser: all three onboarding paths need a connection. Show the
  // screen for the current WiFi state (offline -> gate, connecting -> waiting,
  // online -> the three paths); welcome_wifi_pump re-renders when the state changes.
  int st = wifi_get_status();
  if (st == WIFI_ONLINE){
    // Relay gate: before the onboarding chooser, the device must have a relay to
    // reach the server. Resolve it at config time (in case it moved since the
    // firmware shipped) or let the user type one. Latched by relay_step_done.
    if (onboarding_relay_step()){
      view_set(relay_gate_cb, "Find a Relay",
               "Xyfr needs a relay's IP address to communicate.",
               NULL, NULL, NULL);
      return;
    }
    view_set(welcome_cb, "Welcome",
             "Xyfr is now online.\nWhat would you like to do now?",
             welcome_disp, NULL, NULL);
    return;
  }
  if (st == WIFI_CONNECTING){
    view_set(welcome_wait_cb, "Welcome",
             "\n\n"
             "Waiting for WiFi...",
             welcome_wait_items, NULL, NULL);
    return;
  }
  if (wifi_login_failed){
    view_set(welcome_fail_cb, "Welcome",
             "\n\n"
             "WiFi connection failed.",
             welcome_fail_items, NULL, NULL);
    return;
  }
  if (welcome_shown){
    wifi_open();   // splash already seen -> keep iterating WiFi setup (the AP list)
    return;
  }
  view_set(welcome_wifi_cb, "Welcome",
           "\n\n"
           "Welcome to Xyfr\n\n"
           "You need an active WiFi connection to proceed.",
           welcome_wifi_items, NULL, NULL);
}

// Onboarding WiFi auto-flip. The WiFi flow returns home before the association
// completes, so re-render the welcome screen once the async connect state catches
// up: the gate flips to the three-path chooser when we come online, and the
// chooser drops back to the gate if WiFi is lost. Called each ui_slice; a no-op
// unless a welcome screen is showing (and it self-settles after one flip).
void welcome_wifi_pump(void){
  view_cb_t cur = view_current();
  if (cur != welcome_wifi_cb && cur != welcome_wait_cb &&
      cur != welcome_fail_cb && cur != welcome_cb)
    return;
  int st = wifi_get_status();
  if (st == WIFI_FAILED)
    wifi_login_failed = true;
  if (st == WIFI_CONNECTING || st == WIFI_ONLINE)
    wifi_login_failed = false;   // trying again / connected
  view_cb_t want = welcome_wifi_cb;    // nothing configured -> the WiFi gate
  if (st == WIFI_ONLINE)
    want = welcome_cb;                 // the three paths
  else if (st == WIFI_CONNECTING)
    want = welcome_wait_cb;
  else if (wifi_login_failed)
    want = welcome_fail_cb;
  if (cur != want)  // WiFi state changed -> render the matching screen
    go_home();
}

// The fully-configured home as a VIEW (the common screen library). Item 0 =
// Settings, item 1 = Add Contact, items 2.. = contacts (read live via
// contact_by_index — no cache). A contact row shows its status icon + name with
// the 8-hex userid as the small grey meta line. Selecting an item hands off to the
// its sub-screens, which are views too.
// The j-th logbook thread whose sender is NOT a contact (a stranger/NOCONTACT
// thread) — home lists these after the contacts so an unknown sender's message
// is visible, promotable, or ignorable. False past the last one (or before the
// logbook can mount). Contacts' own threads are skipped: they ARE the contact row.
// Home is a CONVERSATIONS list: Settings + Add Contact pinned, then all contacts
// AND stranger threads merged and sorted by newest logbook activity (newest
// first); contacts with no history sink to the bottom, by name. Each row carries a
// status dot: red = unread message waiting, green = a reachable (VALID) contact,
// hollow = a contact whose lookup hasn't resolved. Built once per open / repaint
// into a small RAM cache (contacts are few — a plain insertion sort), rendered
// straight from the cache so LIST_GET_ITEM touches no flash.
// The home screen lives in app_home.c (APP_HOME). What remains here is the
// legacy launch seam (the screens home opens that are not kernel screens yet),
// the deferred volume persist, and go_home()'s dispatcher below.
extern "C" void home_legacy_open(int what, uint32_t pk){
  switch (what){
    case 0: go_requests();      break;   // the knock list
    case 1: add_contact_open(); break;   // two-step add
    case 2: {                            // contact menu (" name  uid" label form)
      struct contact_record c;
      char label[48];
      if (contact_get(&c, pk))
        snprintf(label, sizeof label, " %s  %08X", c.name, (unsigned)pk);
      else
        snprintf(label, sizeof label, " %08x  %08x", (unsigned)pk, (unsigned)pk);
      on_contact(label);
      break;
    }
    case 3: on_stranger(pk);    break;   // stranger menu
  }
}

// Set by the home +/- keys (app_home.c) when the volume notch changes; the
// flash persist is held off until the speaker is idle (home_volume_save_pump).
static bool vol_save_pending = false;
extern "C" void home_vol_arm(void){ vol_save_pending = true; }

// THE VOLUME KEYS, for any screen that wants them: home, the contact menu, the
// call and the PTT screens. The physical +/- keys emit the LETTER in normal case
// and the SYMBOL in symbol case, so both are accepted. Returns 1 if the key was
// ours. The change is instant and touches no flash; the write is armed here and
// flushed by home_volume_save_pump() once audio goes quiet.
extern "C" int ui_volume_key(int key){
  if (key == '+' || key == 'c' || key == 'C')
    audio_set_speaker_level(speaker_level + 1);
  else if (key == '-' || key == 'x' || key == 'X')
    audio_set_speaker_level(speaker_level - 1);
  else
    return 0;
  home_vol_arm();
  return 1;
}

// Persist a home +/- volume change, but ONLY when the speaker is idle: a flash
// write pauses the audio DMA, so committing mid-playback would cut the very PTT/
// call the user is adjusting. Deferred from the keypress and flushed here the
// moment audio goes quiet. Runs every ui_slice; a cheap no-op when nothing is
// pending or while audio is still playing.
void home_volume_save_pump(void){
  if (!vol_save_pending || audio_is_active())
    return;
  if (device_record.volume_notch != (uint8_t)(speaker_level + 1)){
    device_record.volume_notch = (uint8_t)(speaker_level + 1);
    flag_save_block = 1;   // core 0's block_pump persists it — safe now, audio idle
  }
  vol_save_pending = false;
}

void go_home(void){

  editing_uid[0] = 0;   // leaving any contact-edit flow (Cancel, Save, or nav home)

  // A LOCKED store (a real disk key is set and not yet entered) must ALWAYS route
  // to the unlock screen -- NEVER to setup/welcome. While locked the private key
  // isn't decrypted, so key_absent below reads true and we'd otherwise show the
  // fresh-device welcome. Every "back" gesture (ESC chord, an unhandled backspace
  // on the unlock screen) funnels through go_home(), so a single stray keystroke
  // could put a provisioned phone one step from the wipe path. Gate it here, at
  // the one place all navigation-home passes through.
  if (store_needs_passphrase()) {
    disk_unlock_start();
    return;
  }

  // First-time users branch off to a separate setup screen until they have a
  // private key (an identity). WiFi does NOT gate the home screen — it's optional
  // and configured later from Settings > WiFi, so a keyed-but-offline phone still
  // shows its normal home (contacts, settings, etc.).
  bool wifi_is_empty = true;
  for (int i = 0; i < MAX_APS; i++)
    if (device_record.ap_list[i].ssid[0])
      wifi_is_empty = false;

  bool key_absent = true;
  for (int i = 0; i < KEY_LEN; i++)
    if (device_record.my_private_key[i]) {
      key_absent = false;
      break;
    }

  if (key_absent) {
    go_home_setup(wifi_is_empty, key_absent);   // setup is now a VIEW (offers WiFi too if also empty)
    return;
  }

  // ---- fully configured: home is a kernel screen (app_home.c) ----
  screen_push(APP_HOME, 0);
}

void user_input(const char *input){
  // Chat compose and the edit-name rename are now owned by their views'
  // EDIT_ENTER (the view holds input while open). user_input only serves the
  // remaining legacy list_view screens.
  Debug.println(input);
}
