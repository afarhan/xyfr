#include "debug.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include "audio.h"      // platform audio HAL (PWM/ADC drivers live in audio.cpp)
#include "ui.h"
#include "device_record.h"
#include "secure_store.h"       // store_needs_passphrase — cold-boot disk-key lock check
#include "hal.h"         // hal_malloc/hal_free — the shared scratch arena (mb filler)

// Set by Wipe Out (UI, core 1); consumed on core 0 in loop() — flash erase +
// reboot must not run from a UI handler. Crypto-erases the volume key so all
// at-rest data (settings, contacts, messages) becomes unrecoverable.
volatile uint8_t flag_wipe_device = 0;

// Set by Admin > Compact Storage, consumed on core 0 in loop(). Compaction MOVES
// entries, so every entry id held anywhere goes stale; the reboot on the far side
// is what makes that safe, because the RAM holding them does not survive it.
volatile uint8_t flag_compact_store = 0;
#include "contacts.h"
#include "ota.h"
#include "netif.h"      // frame_write — the netif-open test hook
#include "policy.h"     // admit_handshake — the inbound accept gate (validate_public_key)
#include "cmdq.h"
#include "call.h"
#include "wg.h"        // curve25519, get_part_key, KEY_LEN
#include "msg.h"
#include "config.h"   // kernel_alloc_total — what this build costs in RAM
#include "channel_log.h"   // channel_admits — this build's answer to allow_into_channel
#include "filesystem.h"  // fsdump / fswipe / logstat bench commands
#include "terminal.h"
#include "kernel.h"     // screen_push, APP_TERM, kernel_slice
#include "peer_data.h"
#include "webbackup.h"
#include "restore_net.h"
#include "bootstrap.h"          // DoH endpoint resolution (Unblock)
#include "display_backend.h"   // display_test_pattern (serial `disptest` diagnostic)

// ---- Restore entry. Normal entry is the reboot-surviving watchdog-scratch flag
// (restore_boot_requested()): the Settings>Restore action / serial `restore` sets
// it + warm-reboots, and setup() branches here. RESTORE_BOOT_TEST=1 force-boots
// restore for bench testing (skips normal boot); 0 = flag-driven (production). ----
#define RESTORE_BOOT_TEST 0
static bool g_restore_mode = false;

extern "C" {
#include "pico.h"
#include "pico/time.h"
#include "pico/bootrom.h"
}

//https://datatracker.ietf.org/doc/html/rfc5683


// arduino-pico: give core 1 its own 8KB stack instead of sharing core 0's.
// This must be a global so the core boot code picks it up.
bool core1_separate_stack = true;

//OSS level network
//
bool wifi_online = false;
// UI/keyboard slice period (ms). The matrix keyboard is polled by ui_loop's LVGL
// indev, so this is also the keystroke latency; ~30 ms (≈33 Hz) keeps up with
// typing. Runtime-tunable (raise to throttle the UI, lower for snappier input).
uint32_t ui_loop_period_ms = 30;
IPAddress server_ip(104,131,75,201);
// Bind ephemeral. Pre-call we used 5004, which collides with the relay
// when phone+relay run on the same LAN — the WG layer doesn't care
// what our source port is (the relay learns it from msg1's UDP source
// and stamps it into the route's a_port), so any free port works.
const int udp_port = 0;
IPAddress server_p;

//flags
// `flag_save_block` lives in storage.cpp; the persistence pump
// (block_pump) does too. UI handlers still set it directly.
//

// validate_public_key is the hook wg.c calls inside
// peer_handshake_request_process to decide whether to accept an inbound
// msg1. Only fires on the responder path — our outbound login msg1 to
// the server uses peer_handshake_request_generate and does NOT consult
// this hook. So gating here affects inbound peer calls only; the
// server-login flow is untouched.
//
// Policy now lives in policy.c (admit_handshake): presence==Offline rejects all,
// a Blocked contact is refused, and allow_policy==Contacts requires a VALID
// contact with a byte-exact key (partkey lookup + full 32-byte compare, so a
// 4-byte prefix collision can't slip through). Both settings are user-editable in
// Settings — this replaces the old promiscuous `validate_accept_all` load-test flag.
//
// NOTHING is promiscuous any more. Under the open setting (ALLOW_REGISTERED) a
// STRANGER — a peer with no contact record — is admitted only once the SERVER has
// confirmed that partkey is a registered user and its registered key matches
// byte-exact. A keypair is free; a registration costs an activation code, so that
// check is what makes stranger admission (and blocking) mean anything. The check
// is asynchronous — this hook must never block — so the first msg1 from a stranger
// is always discarded silently and merely REQUESTS the check; the peer's own
// handshake retries bring it back once the answer lands. One verification in
// flight and one parked result, so a flood of fresh keypairs can neither amplify
// into server queries nor reach flash. See contacts.h (stranger_verify_*).
extern "C" int validate_public_key(const uint8_t *public_key, void *ctx) {
  (void)ctx;   // device is responder-only here; no per-call admission context
  return admit_handshake(public_key);
}

// THIS BUILD'S ANSWER to "who may enter a channel we host" (channel_log.h). A
// handheld keeps a CLOSED list, and keeps it in the channel's own inode where
// CHANNEL_MEMBERS_MAX of them fit — so the list is destroyed with the channel
// and needs nothing to keep it in step.
//
// A desktop build answers from a database or a flat file and ignores those
// fields entirely, which is why the question is asked here and not looked up
// inside channel_log.c. See secserver/phone_host.c.
extern "C" int allow_into_channel(uint16_t channel_id, uint32_t contact_id) {
  struct contact_record c;
  if (!contact_get(&c, contact_id))
    return 0;
  if (c.settings & CONTACT_BLOCKED)
    return 0;
  return channel_admits(channel_log_owner(channel_id, contact_id), channel_id, contact_id);
}

// THIS BUILD'S ANSWER to "under whose name is a member's log filed"
// (channel_log.h). Every channel a handheld hosts is a group chat: one log that
// all its members read, so we name it and the member does not. A build that also
// ran a per-user proxy would answer by id.
extern "C" uint32_t channel_log_owner(uint16_t channel_id, uint32_t member) {
  (void)channel_id;
  (void)member;
  return channel_my_partkey();
}

// The login lives in netif.c and frame_pump() reports it; the kernel latches the
// last reported state. This no longer infers online-ness from a timestamp: the
// old form asked "is the last server msg2 younger than two login cycles?", which
// needed the slack precisely because it was guessing from a clock. netif answers
// directly, and treats a rekey as still-online, so there is nothing to flap.
extern "C" int kernel_online(void);

bool ltp_is_online() {
  return kernel_online() != 0;
}

// NTP server (dotted-quad). Cloudflare's anycast NTP is the default;
// will be made user-editable later via Settings.
char ntp_server[40] = "162.159.200.1";

//char temp_ssid[32], temp_key[32];

// Audio (PWM speaker, ADC mics, sample queues, callbacks, handsfree
// routing, ringback) now lives behind the platform HAL in audio.cpp /
// audio.h. setup() calls audio_init(); the call layer uses the HAL.

// ---- kernel (portable stack loop) -------------------------------------
// The server login / NAT-keepalive / UDP receive+dispatch core moved to
// kernel.c so the device and the host CLI run the same sources. This
// file keeps only the device-side glue around it: the non-wg datagram hook
// (NTP) below, plus the device loop()/setup() that drive kernel_init/pump.
extern "C" void kernel_init(void);
extern "C" void kernel_pump(void);
extern "C" void kernel_slice(void);
void flash_guard_pump(void);   // rawflash_arduino.cpp — lazy-resume audio DMA after flash writes

// Non-wg datagram hook, called by the kernel's UDP dispatch for any packet that
// isn't a wg message (mt outside 1..8). On the device that's the NTP reply;
// reconstruct an IPAddress (octet0-low, matching net_recv) for the existing ntp
// helpers. Returns true if the packet was consumed. The host CLI stubs this.
volatile int debug_line_counter = 0;   // core1 checkpoint: last __LINE__ reached in setup1/loop1
volatile int debug_line0       = 0;    // core0 checkpoint: last __LINE__ reached in loop()
// SINGLE-CORE EXPERIMENT: these were setup1()/loop1() (auto-run on core1). Renamed
// so core1 stays idle; setup()/loop() (core0) now call them directly. Ordering:
// called AFTER kernel_init() so block_read + the contact cache are ready.
void ui_setup(){
	debug_line_counter = __LINE__;
  // ui_init() already ran early in setup() (display + boot splash). Here, after the
  // mount, swap the splash for the home screen.
  while (!block_ready)  // home reads block; already set in single-thread
    delay(1);
	debug_line_counter = __LINE__;
  ui_splash_clear();
  // If a user disk key is set, the default boot-unlock failed and the store is
  // LOCKED (block couldn't decrypt) — prompt for the 8-word disk key before home.
  if (store_needs_passphrase()) {
    disk_unlock_start();
    ui_force_refresh();
    return;
  }
  go_home();
	debug_line_counter = __LINE__;
  ui_force_refresh();   // finish painting the home screen before loop() starts
}

void ui_loop(){
	// Cross-core hang trace (~2x/s, throttled so it never floods/blocks the
	// CDC): prints both core checkpoints. If core0 hangs, debug_line0 freezes
	// while core1 keeps advancing here — the frozen value names the loop()
	// call that wedged. If core1 hangs, loop1 stops printing (and core0's
	// own trace, below, keeps reporting). If output stops entirely with both
	// cores fine, that's a USB-CDC wedge, not a code hang.
	static uint32_t cp_last1 = 0;
	if ((uint32_t)(millis() - cp_last1) >= 500) {
		cp_last1 = millis();
		//Debug.printf("CP1 core0=%d core1=%d\n", debug_line0, debug_line_counter);  // muted: heartbeat noise
	}
	debug_line_counter = __LINE__;
  // (The on-screen hang readout went with list_view: it painted the core
  // checkpoints into the legacy screen's title bar, which the view layer has
  // occluded since the migration. debug_line0/debug_line_counter are still
  // maintained and readable over serial / a debugger.)
  // The terminal is a screen like any other now: it paints from its own
  // APP_PUMP and the view engine stands down while it owns the panel, so there
  // is no grid branch here.
  ui_slice();
  // The Sym2 picker overlays whoever just painted, so it is pumped after, not
  // from inside.
  { extern void te_legend_pump(void); te_legend_pump(); }
  kernel_slice();                                    // the app tick
	debug_line_counter = __LINE__;
  // The home list reads contacts live via contact_by_index on every go_home, so
  // there's no background "redraw home" here — the core never drives the UI.
  // (delay(100) removed for the single-core merge — loop() throttles the UI.)
}

// ---- on-device storage acceptance test (test_storage.cpp). When enabled,
// setup() runs ONLY the storage test and skips the normal boot — so LittleFS is
// never mounted and the keystore/filesystem own the reserved FS region (_FS_start).
// Set to 0 for the normal firmware. ----
#define STORAGE_DEVICE_TEST 0
#if STORAGE_DEVICE_TEST
extern "C" void test_storage(void);
extern "C" void test_storage_report(void);
#endif

// ---- Same idea for filesystem.c. DESTROYS this unit's contacts and messages:
// it owns the whole filesystem region. Two-phase — flash it, read phase 1,
// power-cycle, read phase 2. Set to 0 for the normal firmware. ----
#define FILESYSTEM_DEVICE_TEST 0
#if FILESYSTEM_DEVICE_TEST
extern "C" void test_filesystem_device(void);
extern "C" void test_filesystem_device_report(void);
#endif

// ---- first-cut test provisioning ----------------------------------------
// Compile-time seeding so a bench device boots ready to test (WiFi + identity
// + a peer contact) without going through the WiFi dialog / BIP39 registration
// every flash. Runs once per boot on core 0, after kernel_init() has loaded
// `block` and mounted LittleFS; persists via block_write() + rebuilds the
// contact cache. Set to 0 to disable for a clean/production build.
// The seeded values live in bench_seed.h, which is not tracked: no identity,
// endpoint or access point belongs in this file.
#define SEED_TEST_DEFAULTS 0   // clean device: no seeded identity/WiFi (first-boot setup on the TFT)
#if SEED_TEST_DEFAULTS
#include "bench_seed.h"   // untracked; copy bench_seed.h.example and fill in
static void seed_hex(uint8_t *dst, const char *hex, int n) {
  for (int i = 0; i < n; i++) {
    auto nib = [](char c) -> int {
      if ((c >= '0' && c <= '9'))
        return c - '0';
      return (c | 0x20) - 'a' + 10;
    };
    dst[i] = (uint8_t)((nib(hex[2*i]) << 4) | nib(hex[2*i + 1]));
  }
}

static void seed_test_defaults() {
  // 1+2. Two known APs, in priority order (wc_begin_next tries ap_list[0] first).
  strncpy(device_record.ap_list[0].ssid, BENCH_AP0_SSID, sizeof(device_record.ap_list[0].ssid) - 1);
  strncpy(device_record.ap_list[0].key,  BENCH_AP0_KEY,  sizeof(device_record.ap_list[0].key)  - 1);
  strncpy(device_record.ap_list[1].ssid, BENCH_AP1_SSID, sizeof(device_record.ap_list[1].ssid) - 1);
  strncpy(device_record.ap_list[1].key,  BENCH_AP1_KEY,  sizeof(device_record.ap_list[1].key)  - 1);

  // 3. Device wg static private key. Used lazily by
  //    wireguard_init(device_record.my_private_key) on login/session.
  seed_hex(device_record.my_private_key, BENCH_DEVICE_PRIVATE_HEX, KEY_LEN);

  // Server/relay endpoint (normally filled by the "Unblock" DoH lookup). login
  // and keepalive read device_record.endpoints[1]. ip4 packs octet-0 in the low byte.
  device_record.endpoints[1].ip4  = BENCH_RELAY_IP4;
  device_record.endpoints[1].port = BENCH_RELAY_PORT;

  block_write();   // core 0 — persist ap_list + my_private_key + endpoint

  // 4. A bench peer as a VALID contact. Build a PENDING contact for the correct
  //    flag/version + name, then upgrade to VALID with the full 32-byte key
  //    (mirrors the lookup path).
  uint32_t peer_userid = BENCH_PEER_USERID;   // get_part_key(pubkey) = first 4 bytes BE
  struct contact_record c;
  if (!contact_get(&c, peer_userid) || c.status != CONTACT_KEY_VALID) {
    contact_create_pending(&c, BENCH_PEER_NAME, peer_userid);
    seed_hex(c.key, BENCH_PEER_PUBKEY_HEX, KEY_LEN);
    c.status = CONTACT_KEY_VALID;
    contact_save(&c);   // home renders it live via contact_by_index
  }
  Debug.println("seed_test_defaults: APs + private key + bench contact provisioned");
}
#endif

void setup() {

  Serial.begin(115200);
  while (!Serial && millis() < 3000)
		NULL;

  // FIRST: if a firmware apply is pending (warm-reboot flag), copy the staged image
  // over the live firmware and reset. Re-verifies the staged hash first; a no-op if
  // nothing is pending or the stage fails re-verify. Runs before any other bring-up.
  ota_apply_run();

#if RESTORE_BOOT_TEST
  g_restore_mode = true;
#else
  if (restore_boot_requested())  // warm-reboot flag set by `restore`
    g_restore_mode = true;
  if (firmware_boot_requested())  // warm-reboot flag set by Firmware Update (fw-staging mode)
    g_restore_mode = true;
#endif
  if (g_restore_mode) {
    restore_boot();   // tsb->poll switch + connect + :80 server; loop() runs restore_loop()
    return;           // skip the entire normal boot
  }

#if STORAGE_DEVICE_TEST
  test_storage();     // run the storage test on real flash; skip the normal boot
  return;
#endif

#if FILESYSTEM_DEVICE_TEST
  test_filesystem_device();   // run the filesystem test on real flash; skip the normal boot
  return;
#endif

  Debug.println("Initializing the WiFi");
  wifi_init();

  // Bring up the display + boot splash BEFORE the (slow) volume mount below, so
  // the panel isn't dead during boot. ui_init touches no flash / no block.
  ui_init();

  Debug.println("phone v0.01");

  // Portable stack init: requests / contacts / block_read / block_ready /
  // contact_lookup / session / call / cmdq + wireguard_ask_mac2. block_read runs
  // on core 0 (settings, at-rest store), then block_ready signals core 1 it can
  // render. The UI reads the contact list live via contact_by_index (see the
  // cross-core note there). See kernel.c; the host CLI calls the same
  // kernel_init().
  kernel_init();
  Debug.printf("config: %u bytes of capacity\n", (unsigned)kernel_alloc_total());

#if SEED_TEST_DEFAULTS
  seed_test_defaults();   // bench provisioning: WiFi APs + private key + CLI contact
#endif

  // Dump LittleFS contents at boot so we can confirm what is surviving
  // reboots without needing picotool. (Contacts live in the encrypted
  // filesystem now, not LittleFS — inspect via the UI or `fsdump`.)
  fs_ls();

  // Before the first key is read. The scan runs from loop(), which is after
  // setup() returns, so the mapping is always in force by then.
  keyboard_set_layout(device_record.keyboard_layout);

  // What is held at boot decides two things, checked in this order because the
  // escape hatch has to win.
  //
  // Space on a dev-mode unit goes straight to the UF2 bootloader: the 1200-baud
  // touch is not honoured while the app runs, and a keyboard reading through the
  // wrong layout cannot reach the menu item.
  if (device_record.dev_mode && keyboard_boot_space_held()) {
    Debug.println("boot: space held, rebooting to BOOTSEL...");
    delay(50);
    reset_usb_boot(0, 0);
  }
  // Otherwise: no stored layout means we do not know this board, so ask. A board
  // we DO know asks again only if a key is held, which is how a wrong answer
  // gets corrected without a wipe.
  if (device_record.keyboard_layout == KBD_LAYOUT_UNKNOWN || keyboard_raw_down() >= 0)
    keyboard_probe_run();
  Debug.println("starting audio");
  audio_init();
  audio_set_mode(device_record.audio_mode);   // apply the user's saved route (Normal/Handsfree) from the settings block
  if (device_record.volume_notch)             // persisted call playback level (stored as notch+1; 0 = unset -> keep default)
    audio_set_speaker_level(device_record.volume_notch - 1);
  Debug.println("started audio");
  // LVGL/TFT lives on core 1 (see setup1/loop1) — do not call list_open / go_home / ui_slice from here.

  // SINGLE-CORE EXPERIMENT: bring up the UI here (was core1's setup1), now that
  // kernel_init() has loaded block + built the contact cache.
  ui_setup();
}

// Serial-monitor command harness. Currently:
//   call <8hex-userid>   originate a peer call to a contact
//   sm <message>         send <message> as a MSG datagram to the first ALIVE peer
//   hangup               send DATA_BYE on the audio-active session and tear down
//   wipe confirm        ERASE keys/settings/contacts + reboot (bench recovery when
//                       the UI is unreachable, e.g. stuck on the disk-key screen)
//   bootsel              reboot into the UF2 bootloader (hands-free reflash)
//   restore              warm-reboot into restore mode (= Settings > Restore)
// Parsed greedily on each newline; non-matching input is echoed.

// An UNCONFIGURED device — no private key, the same `key_absent` test go_home()
// uses to route to the setup screen — always gets the serial harness, whatever
// dev_mode says. Bring-up needs it: a freshly wiped unit has dev_mode off, so the
// harness was dead exactly when you need `wifi`, `key` and `bootsel` to configure
// it, and `bootsel` in particular is the only reliable reflash path when the
// 1200-baud auto-reset misbehaves. It costs nothing to protect: with no private
// key there is no identity, no contacts and no messages on the device — the
// keystore has not even been provisioned. The moment a key exists the device has
// something worth protecting, and the harness goes back behind dev_mode.
static bool device_unconfigured() {
  for (int i = 0; i < KEY_LEN; i++)
    if (device_record.my_private_key[i])
      return false;
  return true;
}

static void serial_command_pump() {
  // Production is serial-silent: once the device HAS an identity the command
  // harness is live ONLY in Developer Mode. Either way the block must be up first,
  // or neither dev_mode nor the key is known yet. See storage.h dev_mode.
  if (!block_ready)
    return;
  if (!device_record.dev_mode && !device_unconfigured())
    return;
  // Rate-limited VOX telemetry (bench): mirror the HUD to serial at ~2/s while
  // it's active. Via the non-blocking Debug (drops on full TX — never wedges);
  // deliberately low-rate so a couple of lines/sec can't back up the CDC pipe.
  {
    extern volatile bool vox_telem;
    extern int32_t spk_env, mic_env, vox_ne_attack; extern int mic_vox_gain, spk_gate;
    extern bool fe_speech, ne_speech;
    static uint32_t vt_last = 0;
    uint32_t now = millis();
    if (vox_telem && (uint32_t)(now - vt_last) >= 500) {
      vt_last = now;
      Debug.printf("vox fe=%d ne=%d micg=%d spkg=%d [se=%ld me=%ld atk=%ld]\n",
                   fe_speech, ne_speech, mic_vox_gain, spk_gate,
                   (long)spk_env, (long)mic_env, (long)vox_ne_attack);
    }
  }

  static char line[320];
  static uint16_t pos = 0;

  while (Serial.available() > 0) {
    int c = Serial.read();
    if (c < 0)
      break;
    if (c == '\r')
      continue;
    if (c == '\n') {
      line[pos] = 0;
      uint8_t n = pos;
      pos = 0;
      if (n == 0)
        continue;

      if (n > 5 && !memcmp(line, "call ", 5)) {
        const char *hx = line + 5;
        // Skip leading spaces.
        while (*hx == ' ')
          hx++;
        // Parse exactly 8 hex chars into userid.
        uint32_t userid = 0;
        int i;
        for (i = 0; i < 8 && hx[i]; i++) {
          char d = hx[i];
          uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          userid = (userid << 4) | v;
        }
        if (i != 8) {
          Debug.println("call: usage: call <8hex-userid>");
          continue;
        }
        struct contact_record c;
        if (!contact_get(&c, userid)) {
          Debug.printf("call: no contact for userid %08x\n", (unsigned)userid);
          continue;
        }
        if (contact_key_status(&c) != CONTACT_KEY_VALID) {
          Debug.printf("call: contact %08x key not VALID (status=%d)\n",
            (unsigned)userid, contact_key_status(&c));
          continue;
        }
        call_originate(contact_userid(&c));
        continue;
      }

      if ((n == 4 && !memcmp(line, "help", 4)) || (n == 1 && line[0] == '?')) {
        Debug.println("serial commands (type + Enter):");
        Debug.println("  help / ?                   this list");
        Debug.println("  pub                        print this device's public key + userid");
        Debug.println("  key <64hex>                write a NEW private key permanently (re-provisions; old contacts/settings crypto-erased)");
        Debug.println("  contact <8hex> <name...>   add/rename a contact by partkey (name may contain spaces)");
        Debug.println("  wifi <ssid> <key>          set + save the primary WiFi AP (ssid = 1st token, key = rest)");
        Debug.println("  sdiag                      dump boot store diagnostics (settings load / epoch)");
        Debug.println("  call <8hex>                call a VALID contact");
        Debug.println("  msg <8hex> <text>          send a message to a contact");
        Debug.println("  msg-key <64hex> <text>     send a message by raw public key");
        Debug.println("  msg-list <8hex>            dump a stored message thread");
        Debug.println("  msg-delete-all <8hex>      ERASE every message in that thread");
        Debug.println("  msg-bulk <64hex> <size>    TEST: send a generated <size>-byte message");
        Debug.println("  wipe confirm               ERASE keys/settings/contacts, then reboot");
        Debug.println("  bootsel                    reboot into the UF2 bootloader");
        Debug.println("  wifi-drop                  disconnect WiFi, as walking out of range");
        Debug.println("  reset                      reboot");
        continue;
      }

      // key <64hex> — write a NEW private key permanently. The keystore provisions
      // blank-only, so this wipes it (KS_BLANK) then re-provisions under the new key;
      // the RAM settings image (e.g. seeded Wi-Fi) is re-saved under the fresh volume
      // key, but old contacts (encrypted under the previous volume key) are crypto-erased.
      if (n > 4 && !memcmp(line, "key ", 4)) {
        const char *p = line + 4;
        while (*p == ' ')
          p++;
        uint8_t nk[KEY_LEN]; int i;
        for (i = 0; i < KEY_LEN; i++) {
          char a = p[i*2], b = p[i*2+1];
          uint8_t hi, lo; bool ok = true;
          if      (a>='0'&&a<='9')
            hi=a-'0';
          else if (a>='a'&&a<='f')
            hi=10+a-'a';
          else if (a>='A'&&a<='F')
            hi=10+a-'A';
          else
            ok=false;
          if      (b>='0'&&b<='9')
            lo=b-'0';
          else if (b>='a'&&b<='f')
            lo=10+b-'a';
          else if (b>='A'&&b<='F')
            lo=10+b-'A';
          else
            ok=false;
          if (!ok)
            break;
          nk[i] = (uint8_t)((hi << 4) | lo);
        }
        if (i != KEY_LEN) {
          Debug.println("usage: key <64 hex chars>");
          continue;
        }
        store_wipe();          // erases the keystore, the settings AND the whole
                               // filesystem region — contacts and messages go with
                               // the volume key they were sealed under
        memcpy(device_record.my_private_key, nk, KEY_LEN);
        block_write();                                // provisions the keystore with the new key + persists
        uint8_t pub[KEY_LEN];
        static const uint8_t basepoint[KEY_LEN] = { 9 };
        curve25519(pub, device_record.my_private_key, basepoint);
        Debug.printf("key: set — userid %08x (reboot to confirm it stuck)\n", (unsigned)get_part_key(pub));
        continue;
      }

      // contact <8hex-partkey> <name...> — add or rename a contact by partkey. The name
      // is the rest of the line (spaces allowed). Full key is resolved later by lookup.
      // contact-del <8hex> — remove a contact (crypto-erase: destroys its
      // contact_key, so the record AND its whole message thread go). The harness
      // could add but not remove; `contact ` can't swallow this because index 7
      // is '-', not a space.
      if (n > 12 && !memcmp(line, "contact-del ", 12)) {
        const char *p = line + 12;
        while (*p == ' ')
          p++;
        uint32_t uid = 0; int i;
        for (i = 0; i < 8 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d>='0'&&d<='9')
            v=d-'0';
          else if (d>='a'&&d<='f')
            v=10+d-'a';
          else if (d>='A'&&d<='F')
            v=10+d-'A';
          else
            break;
          uid = (uid << 4) | v;
        }
        if (i != 8 || p[8]) {
          Debug.println("usage: contact-del <8hex-partkey>");
          continue;
        }
        if (contact_delete(uid))
          Debug.printf("contact-del: %08x removed (crypto-erased)\n", (unsigned)uid);
        else
          Debug.printf("contact-del: %08x not found\n", (unsigned)uid);
        continue;
      }
      if (n > 8 && !memcmp(line, "contact ", 8)) {
        const char *p = line + 8;
        while (*p == ' ')
          p++;
        uint32_t uid = 0; int i;
        for (i = 0; i < 8 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d>='0'&&d<='9')
            v=d-'0';
          else if (d>='a'&&d<='f')
            v=10+d-'a';
          else if (d>='A'&&d<='F')
            v=10+d-'A';
          else
            break;
          uid = (uid << 4) | v;
        }
        if (i != 8 || p[8] != ' ') {
          Debug.println("usage: contact <8hex-partkey> <name>");
          continue;
        }
        const char *name = p + 9;   // rest of the line verbatim (spaces preserved)
        struct contact_record c;
        if (contact_get(&c, uid)) {
          strncpy(c.name, name, MAX_NAME - 1); c.name[MAX_NAME - 1] = 0;   // rename in place
        } else {
          contact_create_pending(&c, name, uid);
        }
        contact_save(&c);
        contact_lookup_request(uid);   // resolve now (parity with the cmdq contact-add path)
        Debug.printf("contact: %08x = \"%s\"\n", (unsigned)uid, c.name);
        continue;
      }

      // wifi <ssid> <key> — set + persist the primary WiFi AP and reconnect. The
      // ssid is the first token; the key is the rest of the line (spaces allowed).
      // Overwrites ap_list[0]; block_write() persists it, WiFi.disconnect() makes
      // wifi_poll re-associate to it.
      if (n > 5 && !memcmp(line, "wifi ", 5)) {
        const char *p = line + 5;
        while (*p == ' ')
          p++;
        const char *sp = p;
        while (*sp && *sp != ' ')
          sp++;
        int slen = (int)(sp - p);
        if (*sp != ' ' || slen == 0 || slen >= (int)sizeof(device_record.ap_list[0].ssid)) {
          Debug.println("usage: wifi <ssid> <key>"); continue;
        }
        const char *key = sp + 1;                     // rest of the line (spaces preserved)
        if (*key == 0) {
          Debug.println("usage: wifi <ssid> <key>");
          continue;
        }
        memcpy(device_record.ap_list[0].ssid, p, slen); device_record.ap_list[0].ssid[slen] = 0;
        strncpy(device_record.ap_list[0].key, key, sizeof(device_record.ap_list[0].key) - 1);
        device_record.ap_list[0].key[sizeof(device_record.ap_list[0].key) - 1] = 0;
        block_write();                                 // persist
        WiFi.disconnect();                             // wifi_poll re-associates to ap_list[0]
        Debug.printf("wifi: ap0 = \"%s\" (saved, connecting)\n", device_record.ap_list[0].ssid);
        continue;
      }

      // relay <a.b.c.d> <port> — point this device at a relay, the same field
      // Admin > Relay IP writes. Bench provisioning: a demo runs its own server
      // and relay on a laptop, and typing an address on two handhelds is worse
      // than typing it here. Set it AFTER `key`, which wipes the settings.
      if (n > 6 && !memcmp(line, "relay ", 6)) {
        unsigned a = 0, b = 0, c = 0, d = 0, port = 0;
        if (sscanf(line + 6, "%u.%u.%u.%u %u", &a, &b, &c, &d, &port) != 5 ||
            a > 255 || b > 255 || c > 255 || d > 255 || port == 0 || port > 65535) {
          Debug.println("usage: relay <a.b.c.d> <port>");
          continue;
        }
        device_record.endpoints[1].ip4  = a | (b << 8) | (c << 16) | (d << 24);
        device_record.endpoints[1].port = (uint16_t)port;
        block_write();
        netif_relogin();                 // drop the old link, log in at the new address
        Debug.printf("relay: %u.%u.%u.%u:%u (saved)\n", a, b, c, d, port);
        continue;
      }

      // sdiag — dump the boot-store diagnostics captured on the boot path (settings
      // load result + which A/B slot won + whether store_boot_epoch wrote empty), for
      // the settings-persistence investigation. See store.h / settingsblock.h.
      if (n == 5 && !memcmp(line, "sdiag", 5)) {
        Debug.printf("sdiag load : store_load n=%d decrypt=%d  ap0_after_read=%d\n",
                     g_store_diag.settings_load_bytes, g_store_diag.settings_load_decrypt_ok, g_store_diag.aplist_0_ssid_length_at_load);
        Debug.printf("sdiag slots: nslots=%d winner=%d wseq=%u | A valid=%d seq=%u | B valid=%d seq=%u\n",
                     g_sb_diag.nslots, g_sb_diag.winner, g_sb_diag.winner_seq,
                     g_sb_diag.slot_valid[0], g_sb_diag.slot_seq[0],
                     g_sb_diag.slot_valid[1], g_sb_diag.slot_seq[1]);
        Debug.printf("sdiag epoch: ran=%d old=%u new=%u  ap0_at_write=%d\n",
                     g_store_diag.epoch_write_ran, g_store_diag.epoch_before, g_store_diag.epoch_after, g_store_diag.aplist_0_ssid_length_at_epoch_write);
        Debug.printf("sdiag write: last block_write ap0=%d commit=%d calls=%u\n",
                     g_store_diag.aplist_0_ssid_length, g_store_diag.block_write_commit_success, g_store_diag.block_write_count);
        Debug.printf("sdiag now  : ap0=[%s] keystate=%d\n", device_record.ap_list[0].ssid, (int)store_keystate());
        continue;
      }

      // bdump — dump the LIVE RAM settings image (magic, userid, every AP slot,
      // endpoints) via block_dump(). The wipe-investigation companion to sdiag:
      // run it AT the failure, before any reboot, to see the wipe's exact scope.
      if (n == 5 && !memcmp(line, "bdump", 5)) {
        block_dump();
        continue;
      }

      // reread — re-load the settings image straight from flash into `block` (no
      // reboot) and report the AP + identity. Isolates block_write durability from a
      // reboot: if the AP shows here right after a `wifi` save, the write persisted.
      if (n == 6 && !memcmp(line, "reread", 6)) {
        bool ok = block_read();
        uint8_t pub[KEY_LEN];
        static const uint8_t basepoint[KEY_LEN] = { 9 };
        curve25519(pub, device_record.my_private_key, basepoint);
        Debug.printf("reread: block_read=%d ap0=[%s] userid=%08x\n",
                     ok ? 1 : 0, device_record.ap_list[0].ssid, (unsigned)get_part_key(pub));
        continue;
      }

      // otatest — exercise the firmware-staging flash primitives (erase/program/read
      // /blake2s the STAGING region, no network, no apply). Dev-mode only (this whole
      // pump is dev-gated). Cross-check the printed hash against python:
      //   hashlib.blake2s(bytes((i*7+0x5a)&0xff for i in range(512)),digest_size=32).hexdigest()
      if (n == 7 && !memcmp(line, "otatest", 7)) {
        ota_selftest();
        continue;
      }

      // m+ <8hex-uid> <text> — send a direct message to a contact (persists + delivers)
      if (n > 4 && !memcmp(line, "msg ", 4)) {
        const char *p = line + 4;
        while (*p == ' ')
          p++;
        uint32_t uid = 0; int i;
        for (i = 0; i < 8 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          uid = (uid << 4) | v;
        }
        if (i != 8 || p[8] != ' ') {
          Debug.println("usage: m+ <8hex-uid> <text>");
          continue;
        }
        msg_post(uid, p + 9);
        continue;
      }

      // mk <64hex-pubkey> <text> — send a message by raw public key (mirrors the
      // cmdq `mk` verb: upserts a VALID contact + sends, no contact_lookup needed)
      if (n > 8 && !memcmp(line, "msg-key ", 8)) {
        const char *p = line + 8;
        while (*p == ' ')
          p++;
        uint8_t key[KEY_LEN];
        int i;
        for (i = 0; i < KEY_LEN * 2 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          if (i & 1)
            key[i / 2] |= v;
          else
            key[i / 2] = (uint8_t)(v << 4);
        }
        if (i != KEY_LEN * 2 || p[KEY_LEN * 2] != ' ') {
          Debug.println("usage: mk <64hex-pubkey> <text>");
          continue;
        }
        msg_post_to_key(key, p + KEY_LEN * 2 + 1);
        continue;
      }

      // netif-open <64hex-pubkey> — TEST: make netif ORIGINATE a peer link.
      // The one way to provoke a crossing handshake before a real tenant calls
      // frame_write (step 3): fire this on both ends inside the handshake
      // window and exactly one must yield the tie-break. The payload is a single
      // byte and is DROPPED — frame_write returns FRAME_PENDING and starts
      // bring-up, which is all this exercises.
      if (n > 11 && !memcmp(line, "netif-open ", 11)) {
        const char *p = line + 11;
        while (*p == ' ')
          p++;
        uint8_t key[KEY_LEN];
        int i;
        for (i = 0; i < KEY_LEN * 2 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          if (i & 1)
            key[i / 2] |= v;
          else
            key[i / 2] = (uint8_t)(v << 4);
        }
        if (i != KEY_LEN * 2) {
          Debug.println("usage: netif-open <64hex-pubkey>");
          continue;
        }
        uint8_t probe = 0;
        int st = frame_write(key, &probe, 1);
        Debug.printf("netif-open %08x -> %s\n", (unsigned)get_part_key(key),
                     st == FRAME_SENT ? "SENT" : (st == FRAME_PENDING ? "PENDING (bringing up)" : "FAILED"));
        continue;
      }

      // mb <64hex-pubkey> <size> — TEST: send a generated <size>-byte message
      // (verifies multi-chunk streaming past the 320-byte serial line cap).
      if (n > 9 && !memcmp(line, "msg-bulk ", 9)) {
        const char *p = line + 9;
        while (*p == ' ')
          p++;
        uint8_t key[KEY_LEN]; int i;
        for (i = 0; i < KEY_LEN * 2 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          if (i & 1)
            key[i / 2] |= v;
          else
            key[i / 2] = (uint8_t)(v << 4);
        }
        if (i != KEY_LEN * 2 || p[KEY_LEN * 2] != ' ') {
          Debug.println("usage: mb <64hex> <size>");
          continue;
        }
        // Two INDEPENDENT clamps. They were nested once — the upper bound sat
        // inside `if (size < 1)`, where it could never fire, so `mb <key> 50000`
        // wrote 50000 bytes into a 10001-byte buffer. Now that the buffer is
        // sized to `size` rather than being a fixed static, this clamp is what
        // keeps the request inside the arena, so it is load-bearing twice over.
        int size = atoi(p + KEY_LEN * 2 + 1);
        if (size < 1)
          size = 1;
        if (size > 10000)
          size = 10000;
        // Real-world-shaped filler: words, spaces and sentence stops. An unbroken
        // A-Z run was one `size`-character WORD, which only ever exercised the
        // hard-break path and told us nothing about ordinary word wrapping.
        static const char *W[] = {
          "the","relay","forwards","every","packet","without","reading","any","of","it",
          "and","a","session","rekeys","quietly","in","the","background","while","the",
          "storage","seals","each","message","to","flash","before","the","peer","is",
          "told","that","anything","arrived","which","is","what","makes","delivery","mean",
          "something","rather","than","being","a","hopeful","guess","about","the","network"
        };
        const int NW = (int)(sizeof W / sizeof W[0]);
        // Borrowed from the shared scratch arena, not a 10 KB static: this is a
        // bench command that runs for the length of one msg_post_to_key, which
        // consumes the text before it returns (msg.c streams it into the
        // storage). Exactly the arena's contract — big, transient, foreground,
        // one holder.
        char *big = (char *)hal_malloc((size_t)size + 1);
        if (!big) {
          Debug.printf("mb: scratch arena busy\n");
          continue;
        }
        int k = 0, wi = 0, words = 0;
        while (k < size) {
          if (k && k < size)
            big[k++] = ' ';
          const char *w = W[wi++ % NW];
          bool cap = (words == 0) || (k >= 2 && big[k - 2] == '.');
          for (int j = 0; w[j] && k < size; j++)
            big[k++] = (j == 0 && cap) ? (char)(w[j] - 'a' + 'A') : w[j];
          if (++words % 11 == 0 && k < size)
            big[k++] = '.';
        }
        big[size] = 0;
        Debug.printf("mb: sending %d-byte message\n", size);
        msg_post_to_key(key, big);
        hal_free(big);
        continue;
      }

      // term <64hex-pubkey> — open the on-device terminal to a peer TERM server
      // (originates a wg session + opens a "TERM" stream; core 1 shows it).
      if (n > 5 && !memcmp(line, "term ", 5)) {
        const char *p = line + 5;
        while (*p == ' ')
          p++;
        uint8_t key[KEY_LEN];
        int i;
        for (i = 0; i < KEY_LEN * 2 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          if (i & 1)
            key[i / 2] |= v;
          else
            key[i / 2] = (uint8_t)(v << 4);
        }
        if (i != KEY_LEN * 2) {
          Debug.println("usage: term <64hex-pubkey>");
          continue;
        }
        screen_push(APP_TERM, get_part_key((uint8_t *)key));
        Debug.println("term: opening terminal ...");
        continue;
      }

      // term-key <text> — type into whatever screen is up, one char at a time,
      // through the same door a real keypress uses. The terminal is driven by
      // the keyboard and nothing else, so without this it cannot be exercised
      // from the bench at all. "\r" sends Enter, "\t" Tab, "\e" Escape.
      if (!strncmp(line, "term-key ", 9)) {
        const char *p = line + 9;
        int sent = 0;
        while (*p) {
          char c = *p++;
          if (c == '\\' && *p) {          // an escape for the keys that are not printable
            char e = *p++;
            if      (e == 'r') c = '\r';
            else if (e == 'n') c = '\n';
            else if (e == 't') c = '\t';
            else if (e == 'e') c = 0x1b;
            else if (e == 'b') c = '\b';
            else               c = e;
          }
          screen_key((int)(unsigned char)c);
          sent++;
        }
        Debug.printf("term-key: %d\n", sent);
        continue;
      }

      // ml <8hex-uid> — dump the stored message log for a contact
      // msg-delete-all <8hex> — crypto-erase a whole thread. Mirrors the contact
      // menu's "Delete all Texts"; here so the thread delete can be exercised
      // against real on-device data without driving the UI by hand.
      if (n > 15 && !memcmp(line, "msg-delete-all ", 15)) {
        const char *p = line + 15;
        while (*p == ' ')
          p++;
        uint32_t uid = 0; int i;
        for (i = 0; i < 8 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          uid = (uid << 4) | v;
        }
        if (i != 8) {
          Debug.println("usage: msg-delete-all <8hex-uid>");
          continue;
        }
        int gone = msg_delete_thread(uid);
        Debug.printf("msg-delete-all %08x: %d record(s) erased\n", (unsigned)uid, gone);
        continue;
      }

      if (n > 9 && !memcmp(line, "msg-list ", 9)) {
        const char *p = line + 9;
        while (*p == ' ')
          p++;
        uint32_t uid = 0; int i;
        for (i = 0; i < 8 && p[i]; i++) {
          char d = p[i]; uint8_t v;
          if      (d >= '0' && d <= '9')
            v = d - '0';
          else if (d >= 'a' && d <= 'f')
            v = 10 + d - 'a';
          else if (d >= 'A' && d <= 'F')
            v = 10 + d - 'A';
          else
            break;
          uid = (uid << 4) | v;
        }
        if (i != 8) {
          Debug.println("usage: ml <8hex-uid>");
          continue;
        }
        msg_list(uid);
        continue;
      }

      // loss <pct> — simulated inbound packet loss, for soak testing. Runtime,
      // not compiled in, so it can be turned on and off during a run and a
      // reboot always comes back with the radio honest.
      if (n >= 4 && !memcmp(line, "loss", 4)) {
        if (n == 4) {
          Debug.printf("loss: %d%% inbound\n", net_loss_pct);
          continue;
        }
        int pct = atoi(line + 5);
        if (pct < 0 || pct > 100) {
          Debug.println("usage: loss <0..100>");
          continue;
        }
        net_loss_pct = pct;
        Debug.printf("loss: inbound now %d%%\n", net_loss_pct);
        continue;
      }

      // wifi-drop — walk out of range without touching anything else. The only
      // way to take a DEVICE off the air: bootsel needs a reflash to come back.
      if (n == 9 && !memcmp(line, "wifi-drop", 9)) {
        WiFi.disconnect();
        Debug.println("wifi: dropped on request");
        continue;
      }

      // reset — reboot, for the churn the soak cannot otherwise produce.
      if (n == 5 && !memcmp(line, "reset", 5)) {
        Debug.println("reset: rebooting");
        Debug.flush();
        delay(50);
        rp2040.reboot();
        continue;
      }

      if (n == 8 && !memcmp(line, "msgcache", 8)) {
        msg_cache_dump();
        continue;
      }

      // The same work Admin > Compact Storage does, reachable without a person
      // at the screen. A store fills in hours under a soak and nothing reclaims
      // until someone opens a menu, so without this every long run ends the same
      // way: three devices deaf, and every later lap measuring storage rather
      // than whatever it was meant to measure.
      if (n == 7 && !memcmp(line, "compact", 7)) {
        flag_compact_store = 1;   // consumed in loop(): compact with progress, then reboot
        Debug.println("compact: requested; the device reboots when it finishes");
        continue;
      }

      if (n == 7 && !memcmp(line, "logstat", 7)) {
        if (msg_ensure_log())
          Debug.printf("filesystem: %d%% full, %d contacts\n",
                       file_storage_usage(), contact_count());
        else
          Debug.println("filesystem: not mounted");
        continue;
      }
      // cbdump — read-only post-mortem of the contact ring region. Prints every
      // non-erased slot's magic/record_id/epoch + a decrypt check. Writes nothing.
      if (n == 6 && !memcmp(line, "fsdump", 6)) {
        struct contact_record probe;
        contact_get(&probe, 0);   // force the lazy mount
        file_storage_dump();
        continue;
      }
      // fswipe — erase the filesystem region (settings/WiFi/endpoints/keys kept).
      // Contacts and messages go TOGETHER now: they are one region under one key,
      // so the old cbwipe/logwipe split no longer describes anything real.
      if (n == 6 && !memcmp(line, "fswipe", 6)) {
        struct contact_record probe;
        contact_get(&probe, 0);   // force the lazy mount
        if (file_storage_wipe()) {
          Debug.println("filesystem: WIPED (contacts + messages erased)");
          // Home draws its rows from contact_by_index, but only when something
          // asks it to repaint. Without this the panel keeps showing contacts
          // that no longer exist -- three devices reported 0 contacts over
          // serial while still listing six on screen.
          screen_invalidate();
        } else {
          Debug.println("filesystem: wipe failed (not mounted?)");
        }
        continue;
      }

      if (n >= 12 && !memcmp(line, "msg-accept ", 11)) {
        msg_accept = (line[11] != '0');
        Debug.printf("msg: accept = %d\n", msg_accept);
        continue;
      }

      // wscan — DEBUG: scan + dump every AP the radio can see (SSID/RSSI/chan/enc).
      // The definitive "can this 2.4GHz-only radio see the target AP" check.
      // BLOCKING (~2-4s, freezes the UI briefly) — a diagnostic command only.
      if (n == 5 && !memcmp(line, "wscan", 5)) {
        Debug.println("wifi: scanning...");
        int nap = WiFi.scanNetworks();
        Debug.printf("wifi: %d AP(s) visible:\n", nap);
        for (int i = 0; i < nap; i++) {
          Debug.printf("  [%2d] rssi=%4d ch=%2d enc=%d  ssid=[%s]\n",
                       i, (int)WiFi.RSSI(i), (int)WiFi.channel(i),
                       (int)WiFi.encryptionType(i), WiFi.SSID(i));
        }
        Debug.printf("wifi: current status=%d (3=CONNECTED)\n", (int)WiFi.status());
        continue;
      }

      if (n == 6 && !memcmp(line, "hangup", 6)) {
        call_handle call = call_holding_audio();
        if (!call_hangup(call))
          Debug.println("call: no active call to hang up");
        continue;
      }

      // pub — print this device's PUBLIC key (64 hex) + userid, for pointing a
      // host `phone msg <key>` test at it. Public only; the private key never prints.
      if (n == 3 && !memcmp(line, "pub", 3)) {
        // REFUSE while the key is still zeros (store not yet unlocked/loaded):
        // curve25519 of a zero scalar is a CONSTANT, so an early pub printed the
        // same phantom identity (2fe57da3) on every locked device — which sent a
        // whole debugging session chasing a unit that did not exist.
        bool have_key = false;
        for (int i = 0; i < KEY_LEN; i++)
          if (device_record.my_private_key[i]) {
            have_key = true;
            break;
          }
        if (!have_key) {
          Debug.printf("pub: no identity yet (store locked or unconfigured)\n");
          continue;
        }
        static const uint8_t basepoint[KEY_LEN] = { 9 };
        uint8_t pub[KEY_LEN];
        curve25519(pub, device_record.my_private_key, basepoint);
        Debug.printf("pub: ");
        for (int i = 0; i < KEY_LEN; i++)
          Debug.printf("%02x", pub[i]);
        Debug.printf("  userid: %08x\n", (unsigned)get_part_key(pub));
        continue;
      }

      // (PTT playback now shares the speakerphone gain — speaker_volume *
      // speakerphone_boost — so it is tuned via `sv`/`sp`, not a separate knob.)

      // sv <n> — set speaker_volume (call earpiece/speaker playback gain, Q8;
      // 256 = unity, 128 = -6 dB default, >256 amplifies and eventually clips).
      // Live-tune device-side playback loudness by feel without reflashing.
      if (n >= 12 && !memcmp(line, "spk-volume ", 11)) {
        extern int speaker_volume;
        speaker_volume = atoi(line + 11);
        Debug.printf("speaker_volume = %d\n", speaker_volume);
        continue;
      }

      // sp <n> — set speakerphone_boost (Q8 multiplier on the notch volume in
      // SPEAKERPHONE mode; 256 = no boost, 1024 = 4x). Volume notch still applies.
      if (n >= 11 && !memcmp(line, "spk-boost ", 10)) {
        extern int speakerphone_boost;
        speakerphone_boost = atoi(line + 10);
        Debug.printf("speakerphone_boost = %d\n", speakerphone_boost);
        continue;
      }

      // bv <n> — set batt_fullscale_mv (pack mV at raw 4095). Trim until the title
      // battery voltage matches a VOM reading of the pack, no reflash needed.
      if (n >= 12 && !memcmp(line, "batt-scale ", 11)) {
        extern int batt_fullscale_mv;
        extern volatile int batt_adc_raw;
        batt_fullscale_mv = atoi(line + 11);
        Debug.printf("batt_fullscale_mv = %d (raw %d -> %d mV)\n",
                     batt_fullscale_mv, batt_adc_raw,
                     (int)(batt_adc_raw * batt_fullscale_mv / 4095));
        continue;
      }


      // vh — toggle the low-rate (2/s) VOX telemetry line to serial (spk_env /
      // mic_vox_gain). Bench tool for eyeing the envelope/gate; no screen HUD.
      if (n == 7 && !memcmp(line, "vox-log", 7)) {
        extern volatile bool vox_telem;
        vox_telem = !vox_telem;
        Debug.printf("vox_telem = %d\n", vox_telem);
        continue;
      }

      // vx <open> [close] [hang] [att] [rel] [floor] — live-tune the VOX gate.
      // open/close = spk_env thresholds; hang = hangover samples; att/rel = ramp
      // shifts (smaller att = faster close); floor = Q8 gate floor. Omit trailing
      // args to leave them unchanged.
      if (n >= 9 && !memcmp(line, "vox-far ", 8)) {
        extern int vox_spk_open, vox_spk_close, vox_hang_samples, vox_att_shift, vox_rel_shift, vox_mic_floor;
        int o = 0, c = 0, h = 0, a = -1, r = -1, f = -1;
        int got = sscanf(line + 8, "%d %d %d %d %d %d", &o, &c, &h, &a, &r, &f);
        if (got >= 1 && o > 0)
          vox_spk_open     = o;
        if (got >= 2 && c > 0)
          vox_spk_close    = c;
        if (got >= 3 && h > 0)
          vox_hang_samples = h;
        if (got >= 4 && a >= 0)
          vox_att_shift   = a;
        if (got >= 5 && r >= 0)
          vox_rel_shift   = r;
        if (got >= 6 && f >= 0)
          vox_mic_floor   = f;
        Debug.printf("vox FE open=%d close=%d hang=%d att=%d rel=%d floor=%d\n",
                     vox_spk_open, vox_spk_close, vox_hang_samples, vox_att_shift, vox_rel_shift, vox_mic_floor);
        continue;
      }

      // vn <open> [close] [hold_ms] — near-end (mic_env) attack/hold/release for
      // the VOX. open = attack (your voice opens the mic); close = release (LOWER;
      // below the mid-sentence drop); hold_ms = stay open after dropping below
      // release (~200 ms bridges word gaps). Omit trailing args to leave them.
      if (n >= 10 && !memcmp(line, "vox-near ", 9)) {
        extern int vox_mic_open, vox_mic_close, vox_ne_hold, vox_mic_slope;
        int o = 0, c = 0, h = 0, s = -1;
        int got = sscanf(line + 9, "%d %d %d %d", &o, &c, &h, &s);
        if (got >= 1 && o > 0)
          vox_mic_open  = o;
        if (got >= 2 && c > 0)
          vox_mic_close = c;
        if (got >= 3 && h > 0)  // ms -> samples @ 8 kHz
          vox_ne_hold   = h * 8;
        if (got >= 4 && s >= 0)  // Q8 echo-aware slope (0 = flat)
          vox_mic_slope = s;
        Debug.printf("vox NE base=%d slope=%d close=%d hold=%dms\n",
                     vox_mic_open, vox_mic_slope, vox_mic_close, vox_ne_hold / 8);
        continue;
      }

      // am <0|1|2> — set the audio route (0=Normal, 1=Handsfree, 2=Speakerphone).
      // Bench hook to reach SPEAKERPHONE (and engage its VOX gate) before the
      // Settings>Audio menu item exists (Step D); mirrors what the menu will do.
      if (n >= 12 && !memcmp(line, "audio-mode ", 11)) {
        int m = atoi(line + 11);
        audio_set_mode(m);
        device_record.audio_mode = (uint8_t)audio_mode;
        Debug.printf("audio_mode = %d\n", audio_mode);
        continue;
      }

      // disptest b|w|f — display diagnostic: draw a test pattern straight through
      // the panel driver (below the text engine) to isolate edge/offset issues. 'f' = white +
      // 1px frame at the extreme edges + centre cross.
      if (n == 10 && !memcmp(line, "disptest ", 9)) {
        display_test_pattern(line[9]);
        Debug.printf("display test pattern '%c' drawn (the UI repaints on the next slice)\n", line[9]);
        continue;
      }

      // Destructive bench recovery: crypto-erase the store + contacts, then reboot.
      // The UI's Wipe Out is unreachable when a unit is stuck on the cold-boot disk
      // key screen (e.g. it carries an older storage layout whose passphrase we
      // cannot satisfy), and reflashing does NOT clear the storage region -- so this
      // is the escape hatch. Guarded by an explicit "confirm" word.
      if (n == 12 && !memcmp(line, "wipe confirm", 12)) {
        Debug.println("wipe: crypto-erasing store + contacts, then rebooting...");
        flag_wipe_device = 1;   // consumed in loop(): store_wipe + reboot
        continue;
      }
      if (n == 4 && !memcmp(line, "wipe", 4)) {
        Debug.println("wipe: DESTRUCTIVE. type 'wipe confirm' to erase keys, settings and contacts.");
        continue;
      }

      // kbdlayout [v2|v3] — which keyboard this unit has. With no argument it
      // reports. The layout probe sets this from the UI; this is the way in when
      // the probe is ambiguous or the screen cannot be read.
      if (n >= 9 && !memcmp(line, "kbdlayout", 9)) {
        const char *arg = line + 9;
        while (*arg == ' ')
          arg++;
        if (!memcmp(arg, "v2", 2))
          device_record.keyboard_layout = KBD_LAYOUT_V2;
        else if (!memcmp(arg, "v3", 2))
          device_record.keyboard_layout = KBD_LAYOUT_V3;
        else if (*arg) {
          Debug.println("usage: kbdlayout [v2|v3]");
          continue;
        }
        if (*arg) {
          keyboard_set_layout(device_record.keyboard_layout);
          flag_save_block = 1;
        }
        Debug.printf("kbdlayout: %u (0=unknown, 1=v2, 2=v3)\n",
                     (unsigned)device_record.keyboard_layout);
        continue;
      }

      // kbdraw [secs] — print the matrix position of each key as it is pressed,
      // mapping nothing. This is how a board's table is built and checked against
      // the hardware rather than trusted from a transcription.
      if (n >= 6 && !memcmp(line, "kbdraw", 6)) {
        unsigned secs = 20;
        const char *arg = line + 6;
        while (*arg == ' ')
          arg++;
        if (*arg)
          secs = (unsigned)atoi(arg);
        Debug.printf("kbdraw: press keys for %us -- reporting row:col and the flat position\n", secs);
        uint32_t until = millis() + secs * 1000u;
        int last = -1;
        while ((int32_t)(millis() - until) < 0) {
          int pos = keyboard_raw_down();
          if (pos != last && pos >= 0)
            Debug.printf("  raw %d%d  flat %d\n", pos / 6, pos % 6, pos);
          last = pos;
          delay(20);
        }
        Debug.println("kbdraw: done");
        continue;
      }

      if (n == 6 && !memcmp(line, "reboot", 6)) {
        // A PLAIN reset, which bootsel is not: that one stops in the bootloader
        // and the unit stays there until something reflashes it. This one comes
        // back on the firmware it already has, which is what timing a boot needs.
        Debug.println("rebooting...");
        delay(50);
        watchdog_reboot(0, 0, 0);
        continue;
      }

      if (n == 7 && !memcmp(line, "bootsel", 7)) {
        // Reboot into the UF2 bootloader so the host can reflash hands-free
        // (the 1200-baud touch isn't honored while the full app runs).
        Debug.println("rebooting to BOOTSEL...");
        delay(50);
        reset_usb_boot(0, 0);
        continue;
      }
      if (n == 7 && !memcmp(line, "restore", 7)) {
        // Set the reboot-surviving flag + warm-reboot into restore mode. This is
        // what the Settings>Restore menu action will call. Power-cycle = escape.
        Debug.println("entering restore mode (warm reboot)...");
        restore_request_reboot();   // does not return
        continue;
      }

      // fwupdate — warm-reboot into FIRMWARE-UPDATE staging mode (Admin > Firmware
      // Update does the same). Prints an access code + IP; POST a .bin to /firmware.
      if (n == 8 && !memcmp(line, "fwupdate", 8)) {
        Debug.println("entering firmware-update mode (warm reboot)...");
        firmware_request_reboot();   // does not return
        continue;
      }

      // Not one of ours: hand it to cmdq, which is where every UI action goes.
      // That makes the whole cmdq verb table reachable from serial for bench
      // work — call, call-key, contact-flag — without listing each one twice.
      if (cmdq_post(&cmdq_ui_to_fs, line)) {
        Debug.printf("cmdq: %s\n", line);
        continue;
      }
      Debug.printf("cmd? %s\n", line);
      continue;
    }
    if (pos < sizeof(line) - 1)
      line[pos++] = (char)c;
  }
}

// ---- Admin > Compact Storage ------------------------------------------------
// Compaction is the ONLY thing that frees space: a delete leaves a tombstone and
// the append head only goes forward, so a store fills once and stays full, and a
// device at 100% stops accepting messages from every peer.
//
// It blocks core 0 for as long as it runs -- a full-region pass erased in 17 s on
// this hardware -- so the view engine cannot paint while it works. panel_* draws
// straight to the panel, which is what restore mode and the updater use for the
// same reason.
//
// IT MOVES EVERY ENTRY, so every entry id held anywhere goes stale. The reboot at
// the end is not a courtesy: it is what makes that safe, because the RAM holding
// those ids does not survive it.
static void compact_progress(uint32_t done, uint32_t total) {
  int w = panel_width();
  int h = panel_height();
  int bx = w / 8;
  int bw = w - 2 * bx;
  int by = h / 2;
  int bh = 18;
  uint32_t pct = 0;
  if (total)
    pct = (uint32_t)(((uint64_t)done * 100) / total);
  char line[32];
  snprintf(line, sizeof line, "%lu%%", (unsigned long)pct);
  panel_fill(bx + 1, by + 1, bw - 2, bh - 2, false);
  panel_fill(bx + 1, by + 1, (int)((bw - 2) * pct / 100), bh - 2, true);
  panel_fill(bx, by + bh + 8, bw, 16, false);
  panel_text(bx, by + bh + 8, 1, line);
  panel_present();
}

static void compact_store_now(void) {
  Debug.println("compact: starting; the store is unusable until this finishes");
  panel_begin();
  panel_clear();
  int w = panel_width();
  int h = panel_height();
  panel_text(w / 8, h / 2 - 40, 2, "Compacting storage");
  panel_text(w / 8, h / 2 - 18, 1, "Keep the power connected");
  panel_frame(w / 8, h / 2, w - 2 * (w / 8), 18);
  panel_present();

  bool ok = file_storage_compact(compact_progress);
  if (ok) {
    // Entry ids moved, and a channel member's cursor IS an entry id. A fresh
    // epoch on every channel we host is what tells those members to start over.
    int renewed = channel_epochs_renew();
    Debug.printf("compact: done; %d hosted channel(s) renumbered\n", renewed);
  } else {
    Debug.println("compact: FAILED");
  }

  panel_clear();
  if (ok)
    panel_text(w / 8, h / 2 - 10, 2, "Done - restarting");
  else
    panel_text(w / 8, h / 2 - 10, 2, "Compaction failed");
  panel_present();
  delay(1200);              // long enough to read, and to drain the Debug lines
  watchdog_reboot(0, 0, 0);
}

void loop() {
  // Developer Mode drives serial visibility: output flows during boot (block not
  // yet decrypted), whenever dev_mode is on, and on an UNCONFIGURED device (no
  // private key) so bring-up is possible at all; a production device (keyed,
  // dev_mode off) goes silent once the block is up. The unconfigured exemption
  // must match serial_command_pump's — enabling the command parser while this
  // line still routed every reply to the null sink made the harness look dead
  // when it was in fact parsing input correctly. Serial "enabled" means BOTH
  // directions. See storage.h dev_mode.
  Debug.enabled = (!block_ready) || (device_record.dev_mode != 0) || device_unconfigured();
  if (g_restore_mode) {
    restore_loop();
    return;
  }
#if STORAGE_DEVICE_TEST
  test_storage_report();   // reprint the result every second so any monitor catches it
  delay(1000);
  return;
#endif

#if FILESYSTEM_DEVICE_TEST
  test_filesystem_device_report();
  delay(1000);
  return;
#endif
  // Core0 hang trace (throttled ~2x/s): catches a CORE1 hang (core1 frozen
  // while core0 keeps printing). loop1 prints "CP1" from core1 to catch a
  // CORE0 hang. If CP0 stops but CP1 continues -> core0 hung at debug_line0.
  // If both stop with cores fine -> USB-CDC wedge, not a code hang.
  static uint32_t cp_last0 = 0;
  if ((uint32_t)(millis() - cp_last0) >= 500) {
    cp_last0 = millis();
    // TEMP HANG TRACE (2026-08-11) — remove once the wedge is found. Prints the
    // phase marker every 500 ms; the last line before silence names what hung.
    Debug.printf("CP0 line=%d ui=%lu\n", debug_line0,
                 (unsigned long)ui_slice_ticks);
  }

  // CANARY (wipe investigation, 2026-08-15): one line per minute pinning the
  // settings image's health in the continuous log. When the ap_list "wipes",
  // the transition minute — and whatever the log shows just before it — is the
  // evidence that names the mechanism. Remove with the investigation.
  {
    extern volatile uint32_t block_write_calls;
    static uint32_t canary_last_ms = 0;
    if ((uint32_t)(millis() - canary_last_ms) >= 60000) {
      canary_last_ms = millis();
      Debug.printf("canary: aplist_0_ssid_length=%d keystate=%d block_write_count=%u\n",
                   (int)strlen(device_record.ap_list[0].ssid), (int)store_keystate(),
                   (unsigned)block_write_calls);
    }
  }

  // Backup maintenance mode: the on-device web server owns the device — run only
  // it + the UI, suspending the network/store pumps so nothing writes the store
  // underneath the restore. Exit (on the screen) clears the flag and goes home.
  if (backup_mode_active()) {
    keyboard_scan();         // matrix poll: latches kbd_pending for the LVGL indev AND fires
                             // display_kick() (backlight-wake is inside the scan). Omitting it
                             // here left Exit dead and the screen unable to wake in backup mode.
    serial_command_pump();   // keep the bench serial harness alive (e.g. `rok`) in backup mode
    backup_pump();
    static uint32_t ui_last_b = 0;
    if ((uint32_t)(millis() - ui_last_b) >= ui_loop_period_ms) {
      ui_last_b = millis();
      ui_loop();
    }
    return;
  }

  // Device-only pumps (Serial/WiFi/NTP/keys/registration + UI live on core 1).
  debug_line0 = __LINE__;  keyboard_scan();   // fast matrix poll (~5 ms, outside LVGL) → latches kbd_pending
  debug_line0 = __LINE__;  keys_pump();
  debug_line0 = __LINE__;  serial_command_pump();
  debug_line0 = __LINE__;  wifi_poll();
  debug_line0 = __LINE__;  registration_pump_send();

  // The portable network/session/call/transport stack — udp_read, request_poll,
  // server_login_pump, nat_keepalive_pump, contact_query_pump, session_pump,
  // call_slot_pump, call_voice_tx_pump, cmdq_dispatch, block_pump,
  // terminal_net_pump — now lives in kernel_pump(), shared with the CLI.
  debug_line0 = __LINE__;
  kernel_pump();
  debug_line0 = __LINE__;
  audio_qspk_report();  // q_speaker jitter-buffer health (silent when idle)
  debug_line0 = __LINE__;
  flash_guard_pump();   // resume audio DMA once flash writes go idle
  debug_line0 = __LINE__;
  if (flag_compact_store) {                       // Admin > Compact Storage (deferred from UI)
    flag_compact_store = 0;
    compact_store_now();
  }
  if (flag_wipe_device) {                         // Wipe Out: crypto-erase + reboot (deferred from UI)
    flag_wipe_device = 0;
    Debug.println("wipe: crypto-erasing (keystore + settings + contacts + messages), then rebooting");
    store_wipe();            // settingsblock_erase_all + ks_wipe (destroys the wrapped
                             // volume key) AND erases the whole filesystem region
    delay(80);               // let the Debug line drain before we reset
    watchdog_reboot(0, 0, 0);
  }

  // SINGLE-CORE (time-sliced): run the UI (was core1's loop1) at ~30 Hz so the
  // matrix keyboard (polled by ui_loop's LVGL indev) keeps up with typing — at the
  // old 100 ms cadence a keystroke waited up to 100 ms and fast presses merged.
  // lv_timer_handler only redraws invalidated regions, so an idle frame is cheap;
  // each call still returns well inside the 200 ms q_speaker jitter buffer, and the
  // network/voice pumps above run every loop() iteration regardless. Tunable.
  // Keeping ui_loop() a distinct function means loop1() can be split back to core1.
  static uint32_t ui_last_ms = 0;
  if ((uint32_t)(millis() - ui_last_ms) >= ui_loop_period_ms) {
    ui_last_ms = millis();
    debug_line0 = __LINE__;   // the UI runs on core 0 here, so it needs a marker too
    ui_loop();
    debug_line0 = __LINE__;
  }

  // 5ms keeps the voice tx pump tight: at 8 kHz with 320-sample frames,
  // q_microphone hits the 320 threshold every ~40 ms — a 5ms loop
  // ensures the pump catches each frame within ~5 ms of it being ready,
  // smoothing the 25 fps wire spacing. 50 ms (the old value) caused
  // bursty 1-2-frame clumps that overran q_speaker on the rx side.
  delay(5);
}
