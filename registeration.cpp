#include "debug.h"
#include "ui_symbols.h"       // LV_SYMBOL_* glyph strings (no lv_* calls here)
#include "bip39.h"
#include "diskkey.h"    // 8-word disk-key phrase generate/confirm
#include "ui.h"
#include "view.h"
#include "device_record.h"
#include "secure_store.h"      // store_keystate / KS_BLANK — key import only on a fresh device
#include "wg.h"        // struct peer, peer_response_process
#include "contacts.h"  // contact_by_index/delete/userid + CONTACT_BURNER — burner wipe
#include "msg.h"       // msg_recent/_delete_one/_flush — clear burner history

static void on_registration(const char *selection_text);
static char bip39_phrase[BIP39_MNEMONIC_BUFSZ];
static uint8_t new_private_key[KEY_LEN];
static uint8_t new_public_key[KEY_LEN];

// Bench toggle: skip re-typing the 24-word phrase to confirm, so failure paths
// (bad WiFi / bad code / reused code) can be exercised fast. MUST stay false in
// anything shipped -- the retype is what proves the user actually wrote the
// phrase down, and losing it means losing the identity for good.
// The seed-phrase retype is skipped in Developer Mode (device_record.dev_mode); production
// always requires the retype (proving the user wrote the phrase down). Was a
// standalone bench bool; folded into the Developer Mode toggle.

// Activation request state. The user types a 16-char code on core 1 and sets
// flag_send_activation; loop() on core 0 polls the flag and calls netif_setkey.
// The code buffer is file-static so it outlives the trigger.
//
// THERE IS NO SEPARATE ACTIVATION HANDSHAKE HERE ANY MORE. Activation IS the
// login with the code in mac2, so netif runs it against its own link: the peer,
// the msg1 buffer, the regen callback and the request slot this file used to
// keep are all netif's, and went with requests.c on 2026-08-12.
static char       pending_activation_code[20];
static volatile uint8_t flag_send_activation = 0;
#include "netif.h"   // netif_relogin, netif_setkey

// kernel.c holds the activation verdict in two statics that netif writes
// through on_identity_result and this screen polls: s_identity_ok (-1 no attempt
// this boot, 0 refused, 1 accepted) and s_identity_reason (the msg6 reason).
// They persist so a screen polling on its own tick cannot miss the answer.
extern "C" int  kernel_identity_result(int *reason);
// Clear both before a new attempt, or its first poll returns the previous
// attempt's answer.
extern "C" void kernel_identity_reset(void);

// Result code translated from netif's verdict (see the wait loop); polled by
// registration_ui_pump on core 1. 0 = pending, 1..N = outcome per
// activation_strings[].
static volatile int activation_result = 0;
// True between the "Accept" click (which kicks off core 0) and the moment
// registration_ui_pump() renders the outcome. Replaces the old in-event
// wait_on_flag busy-spin, which re-entered lv_timer_handler (a no-op in
// LVGL v9) and froze the screen — same hazard the wifi flow documents.
static volatile bool registration_wait_active = false;
// #1 WiFi/server-timeout handling: the "Submitting..." wait times out after this;
// on timeout we offer Retry / Choose-another-WiFi, keeping the key + code in RAM.
uint32_t        reg_activation_timeout_ms     = 15000;   // tunable
static uint32_t registration_wait_start_ms    = 0;
static bool     reg_pending_activation_resume = false;   // WiFi reselected mid-activation -> resume on reconnect

static const char *const activation_strings[] = {
  "Activation successful",                       // 1 = msg2 success
  "Unknown activation code",                     // 2 = REASON_UNKNOWN_CODE
  "This code has already been used",             // 3 = REASON_CODE_USED
  "User already exists",                         // 4 = REASON_USER_EXISTS
  "Server error - please try again later",       // 5 = REASON_INTERNAL
  "Activation failed (unrecognised reason)",     // 6 = fallback
  "No server endpoint - run Unblock first",      // 7 = no DoH endpoint
  NULL
};

void registration_send_to_server();
void registration_pump_send();

// ---- registration wizard UI (the view model) -------------------------------
// Each step renders a "Registration" view. Button steps list instruction/value
// text rows + action-button rows (dispatched via on_registration); the two entry
// steps put the typed phrase/code in the editor with Go = submit (reg_submit).
// ESC = Cancel on every step (global -> go_home). The core-0 activation logic
// below (send / pump / response) is unchanged.

// Rows are a plain const char*[] handed to view_set — the engine serves
// LIST_GET_ITEM/LIST_COUNT itself, so this file no longer implements a second
// list mechanism. Emphasis rides in the string (VIEW_MARK_HEADING "###"), which
// is why no per-row style field is needed. reg_actions[] maps a row index to its
// action token for on_registration(); a NULL entry is an inert text row.
#define REG_MAX_ROWS 8
static const char *reg_items[REG_MAX_ROWS + 1];
static const char *reg_actions[REG_MAX_ROWS];
static int  reg_nrows = 0;
static void (*reg_submit)(const char *text) = NULL;   // entry-step Go handler (NULL on button steps)

static char reg_userid[12];   // generated User ID, shown on the keygen step (row borrows it)
static char reg_hint[96];     // transient line (e.g. bad activation-code length / phrase mismatch)
static char reg_attempt[BIP39_MNEMONIC_BUFSZ + 8];                       // last raw phrase entry (Retry prefill)
static char reg_marked [BIP39_MNEMONIC_BUFSZ + BIP39_WORD_COUNT + 8];    // phrase with '*' error markers
static char reg_code_attempt[40];   // last raw activation-code entry (retry prefill, keeps the user's format)

static void on_phrase_submit(const char *text);
static void on_code_submit(const char *text);

static int reg_cb(view_op_t op, int i, void *data){
  switch (op){
    case LIST_SELECTED: {
      // Static items => `data` is the row index (view.cpp vcb).
      int idx = (int)(intptr_t)data;
      if (idx >= 0 && idx < reg_nrows && reg_actions[idx])
        on_registration(reg_actions[idx]);       // text rows (NULL action) are inert
      return 0;
    }
    case EDIT_ENTER:
      if (reg_submit)
        reg_submit((const char *)data);
      return 0;
    default:
      (void)i;
      return 0;
  }
}

static void reg_begin(void){ reg_nrows = 0; reg_submit = NULL; }
static void reg_add(const char *text, const char *action){
  if (reg_nrows < REG_MAX_ROWS){
    reg_items[reg_nrows]   = text;
    reg_actions[reg_nrows] = action;
    reg_nrows++;
  }
}

// A VALUE row — the thing the screen is actually showing (generated id, seed
// phrase). Marked as a heading so the engine renders it emphasised; the marker
// has to live in the string, so copy into scratch. One buffer is enough: no
// screen shows two value rows.
static char reg_value[BIP39_MNEMONIC_BUFSZ + BIP39_WORD_COUNT + 12];
static void reg_add_value(const char *text){
  snprintf(reg_value, sizeof reg_value, VIEW_MARK_HEADING "%s", text ? text : "");
  reg_add(reg_value, NULL);
}

// Render the assembled view. An entry step passes input_hint (the editor
// placeholder) and leaves the list empty -> the engine starts focus in the
// editor; a button step passes NULL hint and we land focus on its first
// actionable row.
static void reg_show(const char *prompt, const char *input_hint, const char *prefill){
  reg_items[reg_nrows] = NULL;                       // NULL-terminate for the engine
  view_set(reg_cb, "Registration", prompt, reg_items, input_hint, prefill);
  if (!input_hint)
    for (int i = 0; i < reg_nrows; i++)
      if (reg_actions[i]) {
        view_select(i);
        break;
      }
}

// Why Register refuses, in both cases. Return → home, which on a keyless device
// is the setup screen that offers WiFi.
//
// A status screen has NO rows, and -1 from LIST_GET_ITEM is the only thing that
// says so: answering 0 claims the row exists, the engine asks for the next one
// forever, and the render never returns.
static int reg_status_cb(view_op_t op, int /*i*/, void * /*data*/){
  if (op == LIST_GET_ITEM)
    return -1;
  return 0;   // Backspace exits (global back-to-home)
}

void registration_start(){
  // A new identity on a provisioned phone would keep the old one's volume key,
  // so its contacts and messages would survive under the new key and every
  // channel this device hosts would be left named under the old partkey. Sign In
  // refuses for the same reason (key_import_start); registering is the same act
  // with a fresh key instead of a typed one.
  if (store_keystate() != KS_BLANK){
    view_set(reg_status_cb, "Register",
             "This phone already has a key.\nWipe Out first to register a new one.",
             NULL, NULL, NULL);
    return;
  }
  // Registration is a live server round-trip, so it needs WiFi.
  if (wifi_get_status() != WIFI_ONLINE){
    view_set(reg_status_cb, "Register",
             "WiFi is not connected.\nConnect WiFi and try again.",
             NULL, NULL, NULL);
    return;
  }
  reg_begin();
  reg_add("Welcome! Let's set up your secure ID.\nTakes about 2 minutes. Ready?", NULL);
  reg_add(LV_SYMBOL_RIGHT "  Yes", "Yes");
  reg_add(LV_SYMBOL_CLOSE "  Cancel", "Cancel");
  reg_show(NULL, NULL, NULL);
}

// ---- Key import ("Sign In...") — type an EXISTING 24-word recovery phrase ------
// The phrase IS the 32-byte private key (bip39_decode), so importing is a decode +
// install. Lands only on a FRESH device (blank keystore): re-keying a provisioned
// device needs ks_wipe first (block_write only provisions when the keystore is
// blank), so on a configured phone we refuse and point the user at Wipe Out.
static char import_msg[112];
// Retry buffer: the typed phrase plus any '*' error markers. Must be a STABLE
// buffer -- never hand the textarea its own storage back as the prefill.
static char import_attempt[BIP39_MNEMONIC_BUFSZ + BIP39_WORD_COUNT + 8];
static const char *import_home_items[]  = { LV_SYMBOL_HOME "  Home", NULL };
static const char *import_retry_items[] = { LV_SYMBOL_REFRESH "  Retry",
                                            LV_SYMBOL_HOME    "  Home", NULL };

// Sign-in confirmation state. Importing a phrase only writes the key LOCALLY;
// "you are signed in" is a claim about the SERVER, so wait for the kernel to
// report PS_SIGNED_IN instead of asserting it. An unregistered or expired key
// decodes perfectly well and would otherwise look identical to success.
static bool     import_wait_active   = false;
static uint32_t import_wait_start_ms = 0;
uint32_t import_signin_timeout_ms    = 20000;   // tunable

static int key_import_result_cb(view_op_t op, int i, void *data){
  (void)i; (void)data;
  if (op == LIST_SELECTED)
    go_home();
  return 0;
}

// Install done -> ask the stack to log in, and WAIT for the answer.
static void key_import_begin_signin(void){
  netif_relogin();                       // our identity changed: re-join now
  phone_state_set(PS_SIGNING_IN);        // drop any stale SIGNED_IN from a prior identity
  import_wait_active   = true;
  import_wait_start_ms = millis();
  view_set(key_import_result_cb, "Sign In",
           "Key imported.\nSigning in to the server...", import_home_items, NULL, NULL);
}

static int key_import_fail_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op != LIST_SELECTED)
    return 0;
  if (i == 0)  // Retry
    key_import_begin_signin();
  else
    go_home();
  return 0;
}

// Polled from ui_slice: resolves the pending sign-in into success or a truthful
// failure. The key stays installed either way -- only the CLAIM is withheld.
void key_import_ui_pump(){
  if (!import_wait_active)
    return;
  if (phone_state_get() == PS_SIGNED_IN){
    import_wait_active = false;
    view_set(key_import_result_cb, "Sign In",
             "Key imported. You're signed in.", import_home_items, NULL, NULL);
    return;
  }
  if ((uint32_t)(millis() - import_wait_start_ms) < import_signin_timeout_ms)
    return;
  import_wait_active = false;
  view_set(key_import_fail_cb, "Sign In",
           "Key stored, but the server has not confirmed sign-in.\n"
           "This key may not be registered here, or the\nnetwork is down.",
           import_retry_items, NULL, NULL);
}

static int key_import_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // no list — prompt + editor
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *raw = (const char *)data ? (const char *)data : "";
  // Strip any '*' markers left from a previous attempt: the user corrects the
  // flagged word and presses Go, and a stale marker must not fail the decode by
  // itself (which would look like the fix didn't take).
  char text[BIP39_MNEMONIC_BUFSZ + BIP39_WORD_COUNT + 8];
  size_t ti = 0;
  for (const char *p = raw; *p && ti < sizeof text - 1; p++){
    if (*p == '*')
      continue;
    text[ti++] = *p;
  }
  text[ti] = 0;
  uint8_t key[KEY_LEN];
  int rc = bip39_decode(text, key);
  if (rc != BIP39_OK){
    const char *why = (rc == BIP39_ERR_WORD_COUNT) ? "Please enter all 24 words."
                    : (rc == BIP39_ERR_CHECKSUM)   ? "Checksum failed - a word is wrong."
                    : (rc == BIP39_ERR_BAD_WORD)   ? "A word isn't in the list."
                                                   : "That phrase isn't valid.";
    // Copy BEFORE re-showing: `text` aliases the textarea's OWN buffer, and
    // set_text wipes it before reading the source -- that is what produced the
    // garbage prefill ("K K l occur practice") instead of the typed phrase.
    strncpy(import_attempt, text, sizeof import_attempt - 1);
    import_attempt[sizeof import_attempt - 1] = 0;
    // No reference key here (we are importing an unknown phrase), so only words
    // absent from the wordlist can be flagged -- a valid-but-wrong word is
    // indistinguishable from the intended one. Marks go into the edit box so the
    // user can see and fix the offending word in place.
    bip39_mark_errors(NULL, import_attempt, sizeof import_attempt);
    snprintf(import_msg, sizeof import_msg, "%s\nErrors are marked with *. Fix it, then Go:", why);
    view_set(key_import_cb, "Sign In", import_msg, NULL, "Recovery phrase", import_attempt);
    view_set_input_multiline(true);        // 24-word phrase wraps across lines
    return 0;
  }
  memcpy(device_record.my_private_key, key, KEY_LEN);
  flag_save_block = 1;              // core-0 block_write installs + provisions the keystore
  Debug.println("key import: installed private key from recovery phrase");
  key_import_begin_signin();        // claim success only once the server confirms
  return 0;
}

void key_import_start(){
  if (store_keystate() != KS_BLANK){
    view_set(key_import_result_cb, "Sign In",
             "This phone already has a key.\nWipe Out first to import a different one.",
             import_home_items, NULL, NULL);
    return;
  }
  view_set(key_import_cb, "Sign In",
           "Type your 24-word recovery phrase, then Go.",
           NULL, "Recovery phrase", NULL);
  view_set_input_multiline(true);          // 24-word phrase wraps across lines
}

// ---- Disk Key setup — a system-generated 8-word phrase (the at-rest passphrase) --
// Flow mirrors the private-key wizard: generate → Try another (regenerate) → write
// it down → re-type to confirm (with '*' error marks) → commit via ks_change_
// passphrase (from the default). AFTER this, a cold boot needs the phrase — the
// unlock screen below handles that. WARNING: lose the phrase = lose the data.
static char disk_phrase[DISKKEY_BUFSZ];                              // canonical generated phrase
static char disk_marked[DISKKEY_BUFSZ + DISKKEY_WORDS + 8];         // confirm error display
static char disk_old[DISKKEY_BUFSZ];                                // verified CURRENT key (empty = first-time)
static char disk_typed[DISKKEY_BUFSZ];                              // user-typed candidate key
static const char *disk_home_items[] = { LV_SYMBOL_HOME "  Home", NULL };

#define DISKKEY_WEAK_MIN 30      // shorter than this -> "weak" warning (still allowed)

static void disk_key_show_phrase();
static void disk_key_confirm_gen();
static void disk_key_type();
static void disk_key_confirm_typed();
static void disk_key_choose();
static void disk_key_commit(const char *newkey);

static int disk_key_result_cb(view_op_t op, int i, void *data){
  (void)i; (void)data;
  if (op == LIST_SELECTED)
    go_home();
  return 0;
}

// ---- generated (8-word) path ----
static const char *disk_gen_items[] = {
  LV_SYMBOL_OK      "  Set the Disk Key",
  LV_SYMBOL_REFRESH "  Give me another key",
  NULL,
};
static int disk_gen_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op == LIST_BACK) {  // back to the choice
    disk_key_choose();
    return 0;
  }
  if (op != LIST_SELECTED)
    return 0;
  switch (i){
    case 0: disk_key_confirm_gen(); break;   // "Set" -> re-type to confirm
    case 1: disk_key_show_phrase(); break;   // "Give me another" -> regenerate
  }
  return 0;
}
static void disk_key_show_phrase(){
  diskkey_generate(disk_phrase, sizeof disk_phrase);
  static char prompt[DISKKEY_BUFSZ + 128];
  snprintf(prompt, sizeof prompt,
    "Your disk key - WRITE IT DOWN. It encrypts this phone and cannot be recovered.\n\n%s",
    disk_phrase);
  view_set(disk_gen_cb, "Disk Key", prompt, disk_gen_items, NULL, NULL);
}
static int disk_confirm_gen_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // no list — prompt + editor
    return -1;
  if (op == LIST_BACK) {  // ESC -> back to the shown key
    disk_key_show_phrase();
    return 0;
  }
  if (op != EDIT_ENTER)
    return 0;
  const char *typed = (const char *)data ? (const char *)data : "";
  strncpy(disk_marked, typed, sizeof disk_marked - 1); disk_marked[sizeof disk_marked - 1] = 0;
  if (diskkey_mark_errors(disk_phrase, disk_marked, sizeof disk_marked) != 0){
    static char msg[DISKKEY_BUFSZ + DISKKEY_WORDS + 128];
    snprintf(msg, sizeof msg,
      "That doesn't match (errors marked *). Type the 8 words again, then Go:\n\n%s", disk_marked);
    view_set(disk_confirm_gen_cb, "Disk Key", msg, NULL, "Disk key", typed);
    view_set_input_multiline(true);        // 8-word disk key wraps across lines
    return 0;
  }
  disk_key_commit(disk_phrase);   // re-type matched -> commit the generated phrase
  return 0;
}
static void disk_key_confirm_gen(){
  view_set(disk_confirm_gen_cb, "Disk Key",
    "Type the 8 words again to confirm you saved them, then Go.",
    NULL, "Disk key", NULL);
  view_set_input_multiline(true);          // 8-word disk key wraps across lines
}

// Changing an existing disk key: prove you know the CURRENT one first, so a
// briefly-unlocked device can't be silently re-keyed to an attacker's phrase
// (which would turn temporary access into persistent access after a reboot).
static int disk_key_old_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *typed = (const char *)data ? (const char *)data : "";
  if (!store_verify_disk_key(typed)){
    view_set(disk_key_old_cb, "Disk Key",
             "Wrong disk key.\nEnter your CURRENT disk key, then Go.", NULL, "Current disk key", NULL);
    view_set_input_multiline(true);        // 8-word disk key wraps across lines
    return 0;
  }
  strncpy(disk_old, typed, sizeof disk_old - 1); disk_old[sizeof disk_old - 1] = 0;
  disk_key_choose();                    // current key confirmed — now pick the new one
  return 0;
}

// Commit a chosen new disk key (typed or generated). disk_old set (verified
// earlier) => re-key from the old phrase; empty => first-time set from the
// factory default. Clears all key buffers afterwards.
static void disk_key_commit(const char *newkey){
  bool ok = disk_old[0] ? store_change_disk_key(disk_old, newkey)
                        : store_set_disk_key(newkey);
  memset(disk_phrase, 0, sizeof disk_phrase);
  memset(disk_marked, 0, sizeof disk_marked);
  memset(disk_old,    0, sizeof disk_old);
  memset(disk_typed,  0, sizeof disk_typed);
  view_set(disk_key_result_cb, "Disk Key",
           ok ? "Disk key set. You'll enter it each time you power on."
              : "Couldn't set the disk key. Please try again.",
           disk_home_items, NULL, NULL);
}

// ---- type-your-own path ----
// Re-type confirm — the shared endpoint for both the >=30 and the weak-accepted cases.
static int disk_confirm_typed_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op == LIST_BACK) {  // ESC -> back to edit
    disk_key_type();
    return 0;
  }
  if (op != EDIT_ENTER)
    return 0;
  const char *again = (const char *)data ? (const char *)data : "";
  if (strcmp(again, disk_typed) != 0){
    view_set(disk_confirm_typed_cb, "Disk Key",
      "That doesn't match. Type your disk key again, then Go.", NULL, "Disk key", again);
    return 0;
  }
  disk_key_commit(disk_typed);            // matched -> commit
  return 0;
}
static void disk_key_confirm_typed(){
  view_set(disk_confirm_typed_cb, "Disk Key",
    "Type your disk key again to confirm, then Go.", NULL, "Disk key", NULL);
}

// Too short -> confirm the weaker key, or go back and edit.
static const char *disk_weak_items[] = {
  LV_SYMBOL_WARNING "  Use this weaker key",
  LV_SYMBOL_EDIT    "  Go back and edit",
  NULL,
};
static int disk_weak_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op == LIST_BACK) {
    disk_key_type();
    return 0;
  }
  if (op != LIST_SELECTED)
    return 0;
  switch (i){
    case 0: disk_key_confirm_typed(); break;   // accept the weaker key -> re-type confirm
    case 1: disk_key_type();          break;   // edit more
  }
  return 0;
}

// Type-your-own entry. On Go: if too short -> weak warning; else re-type confirm.
static int disk_type_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // editor, no list
    return -1;
  if (op == LIST_BACK) {  // ESC -> back to the choice
    disk_key_choose();
    return 0;
  }
  if (op != EDIT_ENTER)
    return 0;
  const char *typed = (const char *)data ? (const char *)data : "";
  strncpy(disk_typed, typed, sizeof disk_typed - 1); disk_typed[sizeof disk_typed - 1] = 0;
  if ((int)strlen(disk_typed) < DISKKEY_WEAK_MIN){
    static char msg[208];
    snprintf(msg, sizeof msg,
      "That disk key is short (%d chars). 30+ letters, digits and punctuation is much "
      "stronger. Use it anyway, or edit?", (int)strlen(disk_typed));
    view_set(disk_weak_cb, "Disk Key", msg, disk_weak_items, NULL, NULL);
    return 0;
  }
  disk_key_confirm_typed();               // long enough -> re-type to confirm
  return 0;
}
static void disk_key_type(){
  view_set(disk_type_cb, "Disk Key",
    "Type your disk key (30+ letters, digits, punctuation - case-sensitive), then Go. "
    "It encrypts this phone and cannot be recovered.", NULL, "Disk key", NULL);
}

// ---- the choice: autogenerated (recommended) or type your own ----
static const char *disk_choose_items[] = {
  LV_SYMBOL_REFRESH "  Autogenerated 8-word key (recommended)",
  LV_SYMBOL_EDIT    "  Let me type my own key",
  NULL,
};
static int disk_choose_cb(view_op_t op, int i, void *data){
  (void)data;
  if (op == LIST_BACK) {  // back to the Security menu (where Disk Key lives now)
    go_security();
    return 0;
  }
  if (op != LIST_SELECTED)
    return 0;
  switch (i){
    case 0: disk_key_show_phrase(); break;   // autogenerated (recommended)
    case 1: disk_key_type();        break;   // type my own
  }
  return 0;
}
static void disk_key_choose(){
  view_set(disk_choose_cb, "Disk Key",
    "Set a disk key that encrypts this phone. You'll enter it on every power-on.",
    disk_choose_items, NULL, NULL);
}

void disk_key_start(){
  if (store_needs_passphrase()){        // locked — the unlock screen owns this, not setup
    view_set(disk_key_result_cb, "Disk Key", "Unlock the phone first.", disk_home_items, NULL, NULL);
    return;
  }
  disk_old[0] = 0;
  if (store_disk_key_is_custom()){
    // A disk key is already set — require the current one before changing it.
    view_set(disk_key_old_cb, "Disk Key",
             "Changing the disk key.\nEnter your CURRENT disk key, then Go.",
             NULL, "Current disk key", NULL);
    view_set_input_multiline(true);        // a phrase may wrap across lines
    return;
  }
  disk_key_choose();                    // first-time set (from the factory default)
}

// ---- Disk Key cold-boot unlock — shown from ui_setup when the store is LOCKED ----
// A user disk key is set, so the default boot-unlock failed. Prompt for the phrase;
// on success reload the block (settings + private key now decryptable) and go home.
static int disk_unlock_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *phrase = (const char *)data ? (const char *)data : "";
  if (store_unlock_disk_key(phrase)){
    block_read();          // reload settings + private key (volume_key now in RAM)
    go_home();        // the running pumps pick up WiFi/endpoints from the reloaded block
  } else {
    view_set(disk_unlock_cb, "Unlock",
             "Wrong disk key.\nType your disk key, then Go.", NULL, "Disk key", NULL);
    view_set_input_multiline(true);        // a phrase may wrap across lines
  }
  return 0;
}
void disk_unlock_start(){
  view_set(disk_unlock_cb, "Unlock",
    "This phone is locked.\nType your disk key, then Go.",
    NULL, "Disk key", NULL);
  view_set_input_multiline(true);          // a phrase may wrap across lines
}

// ---- UI screen-lock PIN ----
// A UI-LEVEL lock, NOT the crypto disk key: the volume_key stays in RAM, so the
// phone keeps receiving while locked; the PIN just gates the screen. Stored as a
// salted BLAKE2s hash in the settings block (encrypted at rest under the volume
// key). ui_locked (ui.cpp) is set on the backlight-off timeout / manual Lock and
// cleared here on the correct PIN.
extern "C" uint32_t hal_rand(void);

bool ui_pin_is_set(){ return device_record.ui_pin_len != 0; }

static void ui_pin_digest(const char *pin, const uint8_t salt[8], uint8_t out[16]){
  blake2s(out, 16, salt, 8, pin, strlen(pin));   // keyed (salted) BLAKE2s
}
static void ui_pin_set(const char *pin){
  uint32_t r0 = hal_rand(), r1 = hal_rand();
  memcpy(device_record.ui_pin_salt,     &r0, 4);
  memcpy(device_record.ui_pin_salt + 4, &r1, 4);
  ui_pin_digest(pin, device_record.ui_pin_salt, device_record.ui_pin_hash);
  device_record.ui_pin_len = (uint8_t)strlen(pin);       // length only (a hint; not the PIN)
  flag_save_block = 1;                            // persist via core-0 block_write
}
static bool ui_pin_verify(const char *pin){
  if (!ui_pin_is_set())
    return false;
  uint8_t h[16];
  ui_pin_digest(pin, device_record.ui_pin_salt, h);
  return memcmp(h, device_record.ui_pin_hash, sizeof h) == 0;
}

// ---- Burner (duress) code — a SECOND lock-screen code (storage.h burner_pin_*) --
// Same salted-BLAKE2s shape as the UI PIN. Entering it at the lock screen runs the
// duress sequence (burner_trigger): wipe every CONTACT_BURNER contact + its message
// history, promote the burner code to the normal ui_pin, erase the burner slot,
// then unlock exactly like a normal PIN — leaving no trace a second code existed.
bool burner_pin_is_set(){ return device_record.burner_pin_len != 0; }

static void burner_pin_set(const char *pin){
  uint32_t r0 = hal_rand(), r1 = hal_rand();
  memcpy(device_record.burner_pin_salt,     &r0, 4);
  memcpy(device_record.burner_pin_salt + 4, &r1, 4);
  ui_pin_digest(pin, device_record.burner_pin_salt, device_record.burner_pin_hash);
  device_record.burner_pin_len = (uint8_t)strlen(pin);
  flag_save_block = 1;
}
static bool burner_pin_verify(const char *pin){
  if (!burner_pin_is_set())
    return false;
  uint8_t h[16];
  ui_pin_digest(pin, device_record.burner_pin_salt, h);
  return memcmp(h, device_record.burner_pin_hash, sizeof h) == 0;
}

// The duress action. Runs on core 0 (single-thread UI); all storage lives here.
static void burner_trigger(){
  // 1) Wipe every burner-flagged contact and its message history. Re-scan from the
  //    top each pass (contact_delete shifts the ring's indices), deleting one
  //    burner contact per pass until none remain.
  for (;;){
    struct contact_record c;
    uint32_t cid = 0;
    bool found = false;
    for (int i = 0; contact_by_index(i, &c); i++){
      if (c.settings & CONTACT_BURNER){
        cid = contact_userid(&c);
        found = true;
        break;
      }
    }
    if (!found)
      break;
    // Tombstone every record for this contact (offset-only edit — no key needed).
    // msg_recent skips already-deleted messages, so batches drain to zero.
    struct msg_record recs[16];
    int n;
    while ((n = msg_recent(cid, recs, 16)) > 0)
      for (int k = 0; k < n; k++)
        msg_delete_one(cid, recs[k].record_id);
    contact_delete(cid);
  }
  file_storage_flush();

  // 2) Promote the burner code to the normal PIN (the code the attacker was handed
  //    keeps working as an ordinary PIN), then erase the burner slot — one code on
  //    disk, no evidence there were ever two.
  device_record.ui_pin_len = device_record.burner_pin_len;
  memcpy(device_record.ui_pin_salt, device_record.burner_pin_salt, sizeof device_record.ui_pin_salt);
  memcpy(device_record.ui_pin_hash, device_record.burner_pin_hash, sizeof device_record.ui_pin_hash);
  device_record.burner_pin_len = 0;
  memset(device_record.burner_pin_salt, 0, sizeof device_record.burner_pin_salt);
  memset(device_record.burner_pin_hash, 0, sizeof device_record.burner_pin_hash);
  flag_save_block = 1;

  // 3) Unlock exactly like a normal PIN success — indistinguishable to the attacker.
  ui_locked = false;
  go_home();
}

static int pin_result_cb(view_op_t op, int i, void *data){
  (void)i; (void)data;
  if (op == LIST_SELECTED)
    go_home();
  return 0;
}
static int pin_set_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // editor, no list
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *pin = (const char *)data ? (const char *)data : "";
  if (strlen(pin) < 4){
    view_set(pin_set_cb, "Set PIN",
      "Use at least 4 characters. Enter a PIN, then Go.", NULL, "PIN", NULL);
    return 0;
  }
  if (burner_pin_verify(pin)){    // else every normal unlock would fire the burner wipe
    view_set(pin_set_cb, "Set PIN",
      "That matches your burner code. Choose a different PIN, then Go.", NULL, "PIN", NULL);
    return 0;
  }
  ui_pin_set(pin);
  view_set(pin_result_cb, "Set PIN",
    "PIN set. The screen locks on timeout (or via Lock); enter this PIN to get back in.",
    disk_home_items, NULL, NULL);
  return 0;
}
void pin_set_start(){
  view_set(pin_set_cb, "Set PIN",
    "Set a screen-lock PIN. The phone keeps receiving while locked - the PIN only "
    "gates the screen. Enter a PIN, then Go.", NULL, "PIN", NULL);
}

// Set / change the burner (duress) code — same edit flow as Set PIN.
static int burner_set_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)  // editor, no list
    return -1;
  if (op != EDIT_ENTER)
    return 0;
  const char *pin = (const char *)data ? (const char *)data : "";
  if (strlen(pin) < 4){
    view_set(burner_set_cb, "Burner Code",
      "Use at least 4 characters. Enter a code, then Go.", NULL, "Code", NULL);
    return 0;
  }
  if (ui_pin_verify(pin)){                            // must differ from the normal PIN
    view_set(burner_set_cb, "Burner Code",
      "Must differ from your normal PIN. Enter a different code, then Go.", NULL, "Code", NULL);
    return 0;
  }
  burner_pin_set(pin);
  view_set(pin_result_cb, "Burner Code",
    "Burner code set. If forced to unlock, enter THIS at the lock screen: it wipes "
    "your Burner-marked contacts and their history, then unlocks normally - no sign "
    "a second code existed.",
    disk_home_items, NULL, NULL);
  return 0;
}
void burner_set_start(){
  if (!ui_pin_is_set()){
    view_set(pin_result_cb, "Burner Code",
      "Set a normal PIN first (Admin > Set PIN).", disk_home_items, NULL, NULL);
    return;
  }
  view_set(burner_set_cb, "Burner Code",
    "A DURESS code. If someone forces you to unlock, enter this instead of your PIN: "
    "it erases the contacts you marked Burner (and their messages/calls), then unlocks "
    "the phone normally. Enter a code, then Go.", NULL, "Code", NULL);
}

// The lock screen — traps until the correct PIN (LIST_BACK re-shows it, no escape).
static int pin_unlock_cb(view_op_t op, int i, void *data){
  (void)i;
  if (op == LIST_GET_ITEM)
    return -1;
  if (op == LIST_BACK) {  // trap
    pin_show_lock_screen();
    return 0;
  }
  if (op != EDIT_ENTER)
    return 0;
  const char *pin = (const char *)data ? (const char *)data : "";
  // Burner (duress) code FIRST — it's a distinct code, and a match must run the
  // wipe+collapse, not a normal unlock.
  if (burner_pin_verify(pin)) {
    burner_trigger();
    return 0;
  }
  if (ui_pin_verify(pin)) {
    ui_locked = false;
    go_home();
    return 0;
  }
  view_set(pin_unlock_cb, "Locked", "Wrong PIN.\nEnter your PIN, then Go.", NULL, "PIN", NULL);
  return 0;
}
void pin_show_lock_screen(){
  view_set(pin_unlock_cb, "Locked", "Screen locked.\nEnter your PIN, then Go.", NULL, "PIN", NULL);
}
void pin_lock(){
  if (!ui_pin_is_set()){
    view_set(pin_result_cb, "Lock", "Set a PIN first (Admin > Set PIN).",
             disk_home_items, NULL, NULL);
    return;
  }
  ui_locked = true;
  pin_show_lock_screen();
}

// ---- #3 partkey collision check + server-reachability probe -----------------
// Before the user can keep a freshly-generated key, ask the server whether the
// partkey is already registered (wg contact query msg7/msg8): registered ->
// regenerate; free -> proceed. No reply within the timeout => the server is
// unreachable (bad relay/DoH endpoint) => send the user to fix it.
//
// The query is netif's (remote_query). Its answer lands in contacts.c, which
// hands it here when the device has NO PRIVATE KEY: that state means onboarding,
// and an identity-less device has no contacts to resolve and is not logged in,
// so the only lookup that can be in flight is this one.
//
// A keyless device can ask at all because msg7 is ANONYMOUS by design — a fresh
// ephemeral keypair per query, ECDH straight to the server's static key, no
// enc_static (THREAT_MODEL 10.3). The static identity we are asking about does
// not exist yet, and the lookup never needed it.
static volatile int reg_query_result  = 0;      // 0 pending, 1 free, 2 registered
static bool         reg_query_active   = false;
static uint32_t     reg_query_start_ms = 0;
uint32_t reg_query_timeout_ms = 12000;          // tunable: no reply -> server unreachable
static void registration_show_keep_this(void);  // fwd (the Keep this / Try another step)

// Called from contacts.c on the no-private-key branch of the query answer.
// QUERY_TIMEOUT is deliberately ignored: netif has already spent its retries, and
// the pump's own reg_query_timeout_ms is what tells the user the server is
// unreachable -- two deadlines for one wait would race.
extern "C" void registration_query_answer(const uint8_t key[32], int status){
  if (!reg_query_active)
    return;
  if (get_part_key((uint8_t *)key) != get_part_key(new_public_key))
    return;                                     // not the probe we sent
  if (status == QUERY_FOUND)
    reg_query_result = 2;                       // partkey taken -> regenerate
  else if (status == QUERY_NOUSER)
    reg_query_result = 1;                       // free -> offer Keep this
  else
    return;                                     // timeout: let the pump decide
  reg_query_active = false;
}

// Fire the collision/reachability query for the current new_public_key partkey.
static void registration_check_partkey(){
  reg_query_result   = 0;
  reg_query_active   = true;
  reg_query_start_ms = millis();
  // remote_query reads the partkey from key[0..3] and the rest is what an answer
  // would fill in, so handing it the whole public key costs nothing and keeps the
  // match in registration_query_answer exact.
  if (!remote_query(new_public_key)){
    reg_query_active = false;
    reg_query_result = 1;   // couldn't ask -> best-effort proceed
    return;
  }
  // Deliberately NOT showing the key here: a taken one is silently regenerated,
  // so only a key confirmed available is ever put in front of the user.
  reg_begin();
  reg_add("Checking availability of a new key ...", NULL);
  reg_add(LV_SYMBOL_CLOSE "  Cancel", "Cancel");
  reg_show(NULL, NULL, NULL);
}

static void registration_generate_keys(){
  reg_attempt[0] = 0;        // fresh keypair -> no prior phrase attempt to prefill
  reg_begin();
  reg_add("Creating your key...", NULL);
  reg_show(NULL, NULL, NULL);
  for (int i = 0; i < 10; i++)  // let the "creating" line paint before the keygen
    ui_slice();

  fill_random(new_private_key, sizeof(new_private_key));
  curve25519(new_public_key, new_private_key, basepoint);
  sprintf(reg_userid, "%08X", get_part_key(new_public_key));
  Debug.println("new pvt and public keys:");
  phone_dump_key(new_private_key, sizeof(new_private_key));
  phone_dump_key(new_public_key,  sizeof(new_public_key));

  // Ask the server whether this partkey is free before offering to keep it (also
  // probes reachability). Shows "Checking..."; registration_ui_pump renders the outcome.
  registration_check_partkey();
}

// The "Keep this / Try another" step — shown once the collision query confirms the
// partkey is free.
static void registration_show_keep_this(void){
  reg_begin();
  reg_add("We created a key for you. New User ID:", NULL);
  reg_add_value(reg_userid);
  reg_add(LV_SYMBOL_RIGHT   "  Keep this", "Keep this");
  reg_add(LV_SYMBOL_REFRESH "  Try another", "Try another");
  reg_add(LV_SYMBOL_CLOSE   "  Cancel", "Cancel");
  reg_show(NULL, NULL, NULL);
}

static void registration_display_private_key(){
  bip39_encode(new_private_key, bip39_phrase, sizeof(bip39_phrase));
  reg_begin();
  reg_add("Your 24-word recovery phrase. WRITE IT ON PAPER! It's the only way to restore your account.", NULL);
  reg_add_value(bip39_phrase);
  reg_add(LV_SYMBOL_RIGHT "  I've written it", "I've written it");
  reg_add(LV_SYMBOL_CLOSE "  Cancel", "Cancel");
  reg_show(NULL, NULL, NULL);
}

static void registration_ask_private_key(){
  reg_begin();
  reg_submit = on_phrase_submit;
  // On a Retry, prefill the editor with the previous attempt so the user can fix
  // the marked words rather than retype all 24 from scratch.
  reg_show("Re-enter your 24 words, then Go:", "Recovery phrase",
           reg_attempt[0] ? reg_attempt : NULL);
  view_set_input_multiline(true);          // 24-word phrase wraps across lines
}

// Reusable "type the 16-letter activation code" entry step — used after a phrase
// confirmation (retry=false) and after a failed attempt (retry=true).
static void registration_show_activation_prompt(bool retry){
  reg_begin();
  reg_submit = on_code_submit;
  snprintf(reg_hint, sizeof reg_hint,
           retry ? "Enter the activation code for %s again, then Go:"
                 : "Enter the activation code for %s, then Go:",
           reg_userid);
  reg_show(reg_hint, "Activation Code", (retry && reg_code_attempt[0]) ? reg_code_attempt : NULL);
}

// Fire the activation send (fresh submit or a Retry) and show the submit spinner.
// Records the start time so registration_ui_pump can time out an unreachable server.
static void registration_kick_activation(){
  activation_result          = 0;
  flag_send_activation       = 1;
  registration_wait_active   = true;
  registration_wait_start_ms = millis();
  reg_begin();
  reg_add("Submitting activation request...", NULL);
  reg_add(LV_SYMBOL_CLOSE "  Cancel", "Abort");
  reg_show(NULL, NULL, NULL);
}

// Count whitespace-separated words in a string.
static int reg_word_count(const char *s){
  int n = 0;
  while (*s){
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r')
      s++;
    if (!*s)
      break;
    n++;
    while (*s && *s != ' ' && *s != '\t' && *s != '\n' && *s != '\r')
      s++;
  }
  return n;
}

// Go on the phrase step. A correct re-entry advances to activation; a wrong one
// shows the phrase with '*' markers before each unrecognised word and before the
// first word that diverges from the original (bip39_mark_errors), plus Retry/Cancel.
// ============================================================================
// BENCH ONLY -- REVERT BEFORE COMMIT. Shows the phrase-confirm screen as normal
// but accepts ANY input, so a UI pass doesn't cost 24 typed words. This defeats
// the one check that proves the user actually wrote the phrase down; shipping it
// true means people lose their identity with no way back. Also gated on
// dev_mode so a production build can't honour it even if this is left set.
#define REG_BENCH_ACCEPT_ANY_PHRASE 0
// ============================================================================

static void on_phrase_submit(const char *text){
  const char *t = text ? text : "";
#if REG_BENCH_ACCEPT_ANY_PHRASE
  // NOTE: deliberately NOT gated on device_record.dev_mode -- a wipe clears dev_mode, and
  // a freshly wiped device is exactly when this bench path is needed. The #define
  // is the only gate, so it MUST go back to 0 before commit.
  Debug.println("*** BENCH: phrase confirmation BYPASSED (any input accepted) ***");
  reg_attempt[0] = 0;
  registration_show_activation_prompt(false);
  return;
#endif
  strncpy(reg_attempt, t, sizeof reg_attempt - 1); reg_attempt[sizeof reg_attempt - 1] = 0;

  // Authoritative pass/fail (exact word count + every word), on a scratch copy
  // so the canonical comparison isn't affected by the markers we add below.
  char chk[BIP39_MNEMONIC_BUFSZ + BIP39_WORD_COUNT + 8];
  strncpy(chk, t, sizeof chk - 1); chk[sizeof chk - 1] = 0;
  if (bip39_check(new_private_key, chk, sizeof chk) == BIP39_OK){
    reg_attempt[0] = 0;                            // matched — drop the retry buffer
    registration_show_activation_prompt(false);
    return;
  }

  // Build the marked phrase for display.
  strncpy(reg_marked, t, sizeof reg_marked - 1); reg_marked[sizeof reg_marked - 1] = 0;
  bip39_mark_errors(new_private_key, reg_marked, sizeof reg_marked);

  int wc = reg_word_count(t);
  if (wc != BIP39_WORD_COUNT)
    snprintf(reg_hint, sizeof reg_hint,
             "Expected 24 words, you entered %d. Errors are marked with *:", wc);
  else
    snprintf(reg_hint, sizeof reg_hint,
             "Your phrase doesn't match the original. Errors are marked with *:");

  reg_begin();
  reg_add(reg_hint, NULL);
  reg_add_value(reg_marked);
  reg_add(LV_SYMBOL_REFRESH   "  Retry?", "Retype");
  reg_add(LV_SYMBOL_EYE_OPEN  "  See the phrase again", "Show Phrase");
  reg_add(LV_SYMBOL_CLOSE     "  Cancel", "Cancel");
  reg_show(NULL, NULL, NULL);
}

// Go on the activation-code step: accept 4-letter groups separated by spaces or
// dashes and normalise to exactly 16 lowercase letters, then kick core 0 and
// show the "submitting" spinner. We RETURN immediately (no busy-spin on this
// core); registration_ui_pump() renders the outcome from ui_slice() once core 0
// writes activation_result.
static void on_code_submit(const char *text){
  char raw[40];
  strncpy(raw, text ? text : "", sizeof raw - 1); raw[sizeof raw - 1] = 0;
  strncpy(reg_code_attempt, raw, sizeof reg_code_attempt - 1);   // keep for a retry prefill
  reg_code_attempt[sizeof reg_code_attempt - 1] = 0;
  int n = 0;
  for (int i = 0; raw[i]; i++){
    unsigned char c = (unsigned char)raw[i];
    if (isalpha(c) && n < (int)sizeof(pending_activation_code) - 1)
      pending_activation_code[n++] = (char)tolower(c);
    // digits, dashes, spaces, punctuation silently dropped
  }
  pending_activation_code[n] = 0;

  if (n != 16){
    snprintf(reg_hint, sizeof reg_hint, "Code must be 16 letters (got %d). Try again, then Go:", n);
    reg_begin();
    reg_submit = on_code_submit;
    // Prefill from the stable copy, NOT `text` (which aliases the textarea's own
    // buffer; set_text would wipe it before reading and blank the box).
    reg_show(reg_hint, "Activation Code", reg_code_attempt);   // keep what they typed
    return;
  }

  registration_kick_activation();
}

// The spinner's Cancel: abort an in-flight activation (stop core 0 sending,
// free any scheduled request) and offer Return.
static void registration_abort_activation(){
  flag_send_activation = 0;
  registration_wait_active = false;
  // Keep the generated identity: go back to the activation-code editor (previous
  // entry prefilled). Backspace/ESC from there abandons registration (-> Home).
  registration_show_activation_prompt(true);
}

// Core 1, polled from ui_slice() after lv_timer_handler returns (so the view_set
// here is outside any LVGL event dispatch). Renders the activation outcome once
// core 0 writes activation_result.
void registration_ui_pump(){
  // #1 resume: after "Choose another WiFi", return to the activation step once WiFi
  // is back online (the key + code stayed in RAM the whole time).
  if (reg_pending_activation_resume && wifi_get_status() == WIFI_ONLINE){
    reg_pending_activation_resume = false;
    registration_show_activation_prompt(true);
    return;
  }
  // #3: partkey collision-check outcome (fired at key-gen; polled each slice).
  if (reg_query_active || reg_query_result){
    if (reg_query_result == 2){                 // partkey taken -> silently regenerate
      reg_query_result = 0;
      registration_generate_keys();
      return;
    }
    if (reg_query_result == 1){                 // free -> offer Keep this
      reg_query_result = 0;
      registration_show_keep_this();
      return;
    }
    if ((uint32_t)(millis() - reg_query_start_ms) > reg_query_timeout_ms){
      // No reply -> server unreachable. Nothing to retire: netif owns the query's
      // one in-flight slot and frees it on its own timeout, and clearing this flag
      // is what makes a late answer land in registration_query_answer's early out.
      reg_query_active = false;
      reg_begin();
      reg_add("Couldn't reach the server.\nCheck WiFi or the server address.", NULL);
      reg_add(LV_SYMBOL_REFRESH "  Retry", "Recheck Key");
      reg_add(LV_SYMBOL_CLOSE   "  Cancel", "Cancel");
      reg_show(NULL, NULL, NULL);
    }
    return;
  }

  if (!registration_wait_active)
    return;
  // Translate netif's verdict. ACTIVATION_REASON_* are 1..4 and map to
  // activation_strings[] 2..5; anything else falls in the generic bucket.
  if (activation_result == 0){
    int reason = 0;
    int verdict = kernel_identity_result(&reason);
    if (verdict == 1)
      activation_result = 1;
    else if (verdict == 0) {
      if (reason >= 1 && reason <= 4)
        activation_result = reason + 1;
      else
        activation_result = 6;
    }
  }
  // #1: activation-send timeout -> server unreachable; offer Retry / Choose WiFi.
  if (activation_result == 0){
    if ((uint32_t)(millis() - registration_wait_start_ms) < reg_activation_timeout_ms)
      return;
    flag_send_activation = 0;
    registration_wait_active = false;
    reg_begin();
    reg_add("Couldn't reach the server.\nCheck your WiFi connection.", NULL);
    reg_add(LV_SYMBOL_REFRESH "  Retry?", "Retry Activation");
    reg_add(LV_SYMBOL_WIFI    "  Choose another WiFi", "Choose WiFi");
    reg_show(NULL, NULL, NULL);
    return;
  }
  int rc = activation_result;
  registration_wait_active = false;

  reg_begin();
  if (rc == 1){
    // Success — new_private_key was persisted on core 0. No button here: the
    // closing line IS the actionable row (plain text, no icon), so it reads as
    // a sign-off and ENTER on it returns home. reg_show auto-selects the first
    // row carrying an action, which is that line.
    reg_add(activation_strings[0], NULL);
    reg_add("Your new Xyfr phone is ready\n"
            "You can now add contacts and call them!\n"
            "Press ENTER to return", "Home");
    reg_show(NULL, NULL, NULL);
    return;
  }
  // Recoverable failure (rc 2..7) — re-ask for the activation code, keeping the
  // generated keypair and prefilling the previous entry so the user can fix it.
  // Backspace/ESC from the editor abandons registration (-> Home).
  int nstr = 0;
  while (activation_strings[nstr])
    nstr++;
  const char *reason = (rc >= 1 && rc <= nstr) ? activation_strings[rc - 1] : "Activation failed.";
  snprintf(reg_hint, sizeof reg_hint, "%s\nEnter the activation code for %s again, then Go:", reason, reg_userid);
  reg_submit = on_code_submit;
  reg_show(reg_hint, "Activation Code", reg_code_attempt[0] ? reg_code_attempt : NULL);
}

static void on_registration(const char *selection_text){
  Debug.printf("selected [%s]\n", selection_text);
  if (!strcmp(selection_text, "Cancel") || !strcmp(selection_text, "Home"))
    go_home();
  else if (!strcmp(selection_text, "Yes") || !strcmp(selection_text, "Try another"))
    registration_generate_keys();
  else if (!strcmp(selection_text, "Keep this") || !strcmp(selection_text, "Show Phrase"))
    registration_display_private_key();
  else if (!strcmp(selection_text, "I've written it") || !strcmp(selection_text, "Retype")){
    if (device_record.dev_mode)
      registration_show_activation_prompt(false);
    else
      registration_ask_private_key();
  }
  else if (!strcmp(selection_text, "Try Again"))
    registration_show_activation_prompt(true);
  else if (!strcmp(selection_text, "Abort"))
    registration_abort_activation();
  else if (!strcmp(selection_text, "Recheck Key"))
    registration_check_partkey();                 // re-probe the SAME key (server unreachable retry)
  else if (!strcmp(selection_text, "Retry Activation"))
    registration_kick_activation();               // re-send the activation (same key + code)
  else if (!strcmp(selection_text, "Choose WiFi")){
    reg_pending_activation_resume = true;         // resume at the activation step once WiFi is back
    wifi_open();
  }
  else
    Debug.printf("Didn't match any: [%s]\n", selection_text);
}

// Build the activation msg1 (a normal handshake msg1 with msg_type flipped
// to MSG_REQUEST_ACTIVATE and the 16-byte activation code stuffed into
// mac2 — see secserver/client.c:client_activate). Hands the buffer to
// send_handshake_msg1 for retry-driven delivery. Runs on core 0 only.
void registration_send_to_server(){
  if (device_record.endpoints[1].ip4 == 0) {
    Debug.println("activation: no server endpoint (DoH bootstrap not done)");
    activation_result = 7;     // surface as "run Unblock first" to the wait
    return;
  }

  // ACTIVATION IS THE LOGIN with the code in mac2, so there is no separate
  // protocol to run here: netif becomes the new identity and reports the verdict
  // through on_identity_result — success is the login coming up, failure is a
  // msg6 reason. The peer, msg1 buffer, request slot and response handler this
  // used to need are all netif's now.
  kernel_identity_reset();          // discard any earlier attempt's verdict
  if (!netif_setkey(new_private_key, pending_activation_code)) {
    Debug.println("activation: netif refused the identity change");
    activation_result = 6;     // surface as a generic "failed" to the wait
  }
}

// Polled from core 0 loop(). UI sets flag_send_activation when the user
// hits Accept; we pick it up here so UDP I/O happens on the right core.
void registration_pump_send(){
  if (!flag_send_activation)
    return;
  flag_send_activation = 0;
  registration_send_to_server();
}
