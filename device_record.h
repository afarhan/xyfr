#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>       // wg.h uses time_t without including it

#include "wg.h"     // KEY_LEN lives there and NOWHERE ELSE

#pragma pack(1)
#define MAX_APS 5


// 32-byte server static public key, as 64 hex chars. Seeded into
// device_record.server_static_public by block_read() when the on-disk copy is
// all-zeros (fresh device, or upgrading from a pre-extension /device_record.bin).
// Replaceable later via a settings UI without firmware reflash.
#define DEFAULT_SERVER "a35f055dbd6a7574c6268a80295b74fda7fa3f3457e7ecc8522ef345a87b927d"

struct ap {
	char ssid[32];
	char key[32];
};

#define MAX_DOH_ENDPOINTS 256
#define MAX_SERVER_ENDPOINTS 5
struct server_endpoint {
	uint32_t ip4;   // octet 0 in lowest byte (matches IPAddress raw layout)
	uint16_t port;
};
// The device's persistent state — one struct, the whole "device-state block"
// (formerly `struct saved` / "the settings" or "fixed" block). It is MORE than user
// settings, which is why the old name misled: it also carries the device's wg static
// keypair (the private key is a RAM-only mirror of the keystore, filled by block_read
// — it is NOT persisted in this image) AND the store's per-boot AEAD-nonce epoch
// (boot_epoch). block_read/block_write pack this <-> the encrypted A/B image in
// store.c; `block` (below) is the single live instance. Every write of it goes
// through block_write() — so anything that triggers a write (e.g. store_begin_session)
// touches ALL of this, not just "settings".
struct device_record {
	uint32_t magic;
	uint64_t my_id;
	uint16_t calibration_data[10];
	struct ap ap_list[MAX_APS];
	uint8_t ringer;
	char doh_endpoints[MAX_DOH_ENDPOINTS]; // cached TXT from fetch_new_ip(); empty = unresolved
	struct server_endpoint endpoints[MAX_SERVER_ENDPOINTS]; // parsed from doh_endpoints
	// --- appended fields (block_read tolerates short files) ---
	uint8_t my_private_key[KEY_LEN];      // device's wg static private key, written on activation success
	uint8_t server_static_public[KEY_LEN];// server's wg static public key; defaults to DEFAULT_SERVER (wg.h)
	uint8_t audio_mode;                   // 0=Normal(earpiece) 1=Handsfree 2=Speakerphone (appended; 0 for old images)
	// --- presence + allow policy (appended; 0 for old images = Normal / Allow all, today's behaviour) ---
	uint8_t presence;                     // PRESENCE_* : 0=Normal 1=Busy 2=NoCalls 3=Offline (reachability)
	uint8_t allow_policy;                 // ALLOW_* : 0=AllowAll 1=Contacts (handshake admission)
	uint32_t boot_epoch;                  // monotonic per-boot counter folded into the contactsblock + logbook
	                                      // AEAD nonces (with a per-store domain byte) so a record_id reused
	                                      // after a delete/compaction can't reuse a (volume_key,nonce) across
	                                      // boots. Bumped+persisted once per boot by store_begin_session();
	                                      // tenants read it via store_current_epoch() (a pure reader).
	uint8_t volume_notch;                 // call playback level, stored as (notch 0..10)+1 (appended; 0 for
	                                      // old images / blank device -> unset -> boot applies the default).
	// --- UI screen-lock PIN (appended; 0 = unset). A SALTED HASH only. This is a
	// UI-level lock that KEEPS the volume_key in RAM (so the phone keeps receiving
	// while locked) — NOT the crypto disk key. See registeration.cpp:ui_pin_*. ---
	uint8_t ui_pin_len;                   // 0 = no PIN; else salt+hash below are valid
	uint8_t ui_pin_salt[8];               // random salt (hal_rand)
	uint8_t ui_pin_hash[16];              // blake2s(key=salt, msg=PIN)
	// --- terminal screen size, chosen on the terminal welcome screen and remembered
	// (appended; 0 for old images). 0 = unset (default 60x18 / 8x16 font); 1 = 80x25
	// / 6x12 font; 2 = 60x18 / 8x16 font. See terminal.cpp term_{load,save}_font. ---
	uint8_t term_font;
	// --- Burner (duress) code (appended; 0 = unset). SAME shape/derivation as the
	// UI PIN above (salted BLAKE2s), a SECOND lock-screen code. Entering it at the
	// lock screen wipes every CONTACT_BURNER contact + its logbook history, promotes
	// itself to the normal ui_pin, then erases this slot and unlocks — so a coerced
	// unlock leaves no sign a second code ever existed. See registeration.cpp
	// burner_*. THREAT_MODEL §10.2 duress. ---
	uint8_t burner_pin_len;               // 0 = no burner code; else salt+hash below valid
	uint8_t burner_pin_salt[8];           // random salt (hal_rand)
	uint8_t burner_pin_hash[16];          // blake2s(key=salt, msg=code)
	// --- Developer Mode (appended; 0 = OFF = PRODUCTION default). A device/dev split
	// toggled from Admin > Developer Mode. ON: serial output + the serial command
	// harness are live, and the seed-phrase retype is skipped. OFF (production):
	// serial goes silent (telemetry will move to the stream layer) and the command harness is
	// dead. Does NOT touch the PIN lock or disk key — those stay enforced either way. ---
	uint8_t dev_mode;
	// --- Last OTA-verified build checksum (appended; all-zero = unset / flashed
	// directly, never via OTA). The firmware updater hashes the image incrementally
	// as it streams into staging; when the running BLAKE2s matches the uploader's
	// published checksum the image is proven intact, and THAT checksum is persisted
	// here + the image marked valid for apply. The About screen displays it. ---
	uint8_t ota_checksum[32];
	// --- PTT Conference (appended; 0 = OFF). A global mode, not a per-contact
	// one: it changes what push-to-talk DOES rather than who may use it. What it
	// does is not built yet -- this is the setting it will read. ---
	uint8_t ptt_conference;
	// --- Which keyboard this unit has (appended; KBD_LAYOUT_* in ui.h). The two
	// hardware revisions carry the same keycaps but connect them to different
	// matrix positions, so the mapping cannot be compiled in. 0 = not yet
	// established: keyboard.cpp assumes v2 so the device stays usable, and the
	// setup flow asks for two keys by physical position to settle it. ---
	uint8_t keyboard_layout;
};

// device_record.presence — device reachability, enforced in the accept path (policy.c).
// Normal: all calls ring + all messages ping. Busy: only Star contacts ring
// (messages still flow). NoCalls: calls refused, messages flow. Offline: reject
// every inbound handshake (calls AND messages).
#define PRESENCE_NORMAL   0
#define PRESENCE_BUSY     1
#define PRESENCE_NOCALLS  2
#define PRESENCE_OFFLINE  3

// device_record.allow_policy — who may complete an inbound handshake at all (policy.c),
// orthogonal to presence (except Offline, which rejects everyone).
// NOTE: value 0 is NOT promiscuous. A non-contact handshake is still REFUSED
// (a stranger never gets a session, so nothing they send reaches the logbook);
// what it allows is the KNOCK being filed for the user to approve — see
// contacts.h contact_knock / "Requests from (N) users".
#define ALLOW_ALL         0   // strangers may knock; the user approves them
#define ALLOW_CONTACTS    1   // only a VALID contact may handshake

#pragma pack()

extern struct device_record device_record;

// Diagnostic counters. Incremented at the top of each fn so the other
// core can witness that block_read / block_write actually executed —
// without depending on Serial output (which races with Serial.begin
// during early boot).
extern volatile uint32_t block_read_calls;
extern volatile uint32_t block_write_calls;

bool block_read();
void block_write();
void block_dump();

// Set to 1 by core 0 (setup) once block_read() has populated `block`. core 1
// (UI) waits on this instead of calling block_read() itself — so ALL LittleFS
// access stays on core 0 and can never race a core-0 block_write (the deadlock
// that wiped the block). `block` is plain RAM after that; core 1 just reads it.
extern volatile uint8_t block_ready;

// Polled from loop() (core 0). When `flag_save_block` is set by a UI
// handler or background pump, persist `block` to flash and clear the
// flag. See [[project_block_save_path]] for why writes are deferred to
// core 0 rather than done inline from core 1.
extern uint8_t flag_save_block;
void block_pump();

// One-shot diagnostic: once `device_record.my_private_key` is populated, print
// the private key, derived public key, and partkey to Serial. Self-
// disables after the first successful print; cheap to call every loop.
void keys_pump();

// Walk LittleFS root and print every file name + size to Serial.
// Intended for boot-time / on-demand inspection: prove what files are
// actually on the FS without needing picotool. Safe to call from
// either core (no mutation), but call it on the same core that did
// LittleFS.begin() if you can — the arduino-pico LittleFS isn't
// documented to be re-entrant across cores.
void fs_ls();


#ifdef __cplusplus
}
#endif
