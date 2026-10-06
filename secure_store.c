//
// secure_store.c — the storage block: the RP2350/flash implementation of
// persistence.
// ===========================================================================
// This is a higher-level HAL. The rest of the system (the keystore, the
// settings and the filesystem that holds contacts and their message threads)
// asks this layer for durable storage and does not care how it works — it just
// happens that on this hardware "how" is A/B-redundant flash images (bootblock
// + settingsblock) over raw sectors.
//
// PORTING CONTRACT:
//   * To port to other flash hardware, reimplement the sector HALs only —
//     rawflash (sector read/erase/program + sector count) and bootflash (the
//     boot/keystore sectors). Nothing in this block or above it changes.
//   * To port to a non-flash platform (say a Linux phone backed by sqlite or a
//     filesystem), reswap this block's upper interface: store_* plus
//     block_read/block_write below, and the bootblock, settingsblock and
//     filesystem backends. The tenants above are untouched.
//
// What lives here:
//   * store_*        — region map + keystore bring-up + the encrypted settings
//                      image (one live buffer; A/B via settingsblock).
//   * block_read/    — pack and unpack `struct device_record` against that
//     block_write      image.
//
// Portable C, core 0 only. See secure_store.h / STORAGE_SECURITY.md.
//

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "secure_store.h"
#include "device_record.h"    // struct device_record, MAX_APS, DEFAULT_SERVER, endpoints
#include "rawflash.h"
#include "settingsblock.h"
#include "keystore.h"
#include "hal.h"        // hal_debug (pulls <time.h> for wg.h)
#include "wg.h"         // xchacha20poly1305_*, fill_random, crypto_zero, AUTHTAG_LEN, curve25519, basepoint

// The settings image is stored encrypted: the slot payload holds
// [nonce:24][ciphertext + Poly1305 tag] under the keystore volume_key
// (XChaCha20-Poly1305), so the usable plaintext is the slot payload minus the
// nonce and the authentication tag.
#define STORE_NONCE_LEN  24
#define STORE_SB_PAYLOAD (STORE_SB_SLOT_SECTORS * RAWFLASH_SECTOR - FB_FRAME_LEN)  // 40 KB flash slot
#define STORE_CRYPTO_OVH (STORE_NONCE_LEN + AUTHTAG_LEN)

// The live settings image is just `struct device_record`, under 1 KB. The RAM
// scratch is sized to that, not to the 40 KB flash slot (STORE_SB_PAYLOAD) —
// the slot stays as big as it is because flash is not scarce and shrinking it
// would move CONTACTSBLOCK_BASE_SECTOR. The asserts near DEVICE_STATE_LEN below
// keep the image within this cap and its encrypted form within the slot.
#define STORE_IMG_CAP    4096u

// The single live PLAINTEXT settings image (`struct device_record`). Core-0.
static uint8_t s_image[STORE_IMG_CAP];
// Scratch for the on-flash [nonce||ciphertext] form. Same lifetime/core as above.
static uint8_t s_ciphertext[STORE_IMG_CAP + STORE_CRYPTO_OVH];
_Static_assert(STORE_IMG_CAP + STORE_CRYPTO_OVH <= STORE_SB_PAYLOAD, "encrypted image exceeds the flash slot");

// Known placeholder passphrase used to wrap the volume_key until the user sets
// their own (via the not-yet-built passphrase UI). Provides no secrecy on its
// own — it just turns encryption ON so a later user passphrase is a re-wrap.
#define STORE_DEFAULT_PASSPHRASE "scramler-default-0000"

bool store_init(void) {
	if (!rawflash_init())
		return false;
	if (!ks_init())  // reads the keystore bootblock state
		return false;
	if (!settingsblock_init(RAWFLASH_DEV_INTERNAL, STORE_SB_BASE_SECTOR, STORE_SB_SLOT_SECTORS))
		return false;
	return true;
}

ks_state store_keystate(void) { return ks_state_get(); }

bool store_provision(const uint8_t priv[32]) {
	if (!ks_provision(priv))  // BLANK -> NOENC
		return false;
	if (!ks_enable_passphrase(STORE_DEFAULT_PASSPHRASE)) {  // NOENC -> UNLOCKED (wrapped)
		hal_debug(LOG_ERROR, "store: enable default passphrase failed\n");
		return false;
	}
	return true;
}

bool store_unlock_default(void) {
	if (ks_state_get() == KS_LOCKED)
		ks_unlock_passphrase(STORE_DEFAULT_PASSPHRASE);   // LOCKED -> UNLOCKED on success
	return store_unlocked();
}

// True once a user (non-default) disk key is in effect: set when boot required the
// user passphrase, when the cold-boot unlock ran, or when the user sets one. Drives
// the "prompt for the CURRENT disk key before changing it" flow (an unlocked device
// must not be silently re-keyed to an attacker's phrase → persistent access).
static bool s_diskkey_custom = false;
bool store_disk_key_is_custom(void) { return s_diskkey_custom; }

// First-time set: re-wrap the volume_key from the default passphrase to `phrase`
// (volume_key unchanged → no data migration). After this a cold boot needs `phrase`.
bool store_set_disk_key(const char *phrase) {
	bool ok = ks_change_passphrase(STORE_DEFAULT_PASSPHRASE, phrase);
	if (ok)
		s_diskkey_custom = true;
	return ok;
}

// Change an existing disk key: verifies `old_phrase` (ks_change_passphrase checks it
// against the current EDEK) before re-wrapping under `new_phrase`.
bool store_change_disk_key(const char *old_phrase, const char *new_phrase) {
	return ks_change_passphrase(old_phrase, new_phrase);   // s_diskkey_custom already true
}

// Non-destructive: is `phrase` the current disk key? (Gate the change flow.)
bool store_verify_disk_key(const char *phrase) {
	return ks_verify_passphrase(phrase);
}

// Cold-boot unlock with the user's disk key (LOCKED -> UNLOCKED). Returns true on
// success (volume_key now in RAM; the caller should re-run block_read()).
bool store_unlock_disk_key(const char *phrase) {
	if (ks_state_get() == KS_LOCKED)
		ks_unlock_passphrase(phrase);
	bool ok = store_unlocked();
	if (ok)  // we unlocked with a user phrase → custom key in effect
		s_diskkey_custom = true;
	return ok;
}

bool store_needs_passphrase(void) { return ks_state_get() == KS_LOCKED; }

void store_boot_unlock(void) {
	switch (ks_state_get()) {
	case KS_LOCKED:
		if (store_unlock_default())
			hal_debug(LOG_EVERYTHING, "store: unlocked (default passphrase)\n");
		else
			hal_debug(LOG_WARNING, "store: default passphrase failed — user passphrase required\n");
		break;
	case KS_NOENC:
		// Device provisioned by older firmware (plaintext volume_key). Upgrade in
		// place to default-passphrase encryption (NOENC -> UNLOCKED, no data move).
		if (ks_enable_passphrase(STORE_DEFAULT_PASSPHRASE))
			hal_debug(LOG_WARNING, "store: upgraded NOENC -> encrypted (default passphrase)\n");
		else
			hal_debug(LOG_ERROR, "store: NOENC upgrade failed\n");
		break;
	default:
		break;   // BLANK (provision on first save) / UNLOCKED (already open)
	}
}

bool store_unlocked(void) {
	ks_state st = ks_state_get();
	return st == KS_NOENC || st == KS_UNLOCKED;
}

uint8_t *store_image(void) { return s_image; }
int      store_image_cap(void) { return (int)STORE_IMG_CAP; }

struct store_diag g_store_diag = { -2, -2, -2, 0, 0, 0, -2, -2, -2, 0 };   // TEMP diagnostic (secure_store.h)

int store_load(void) {
	int n = settingsblock_load(s_ciphertext, (int)sizeof s_ciphertext);
	g_store_diag.settings_load_bytes = n;
	g_store_diag.settings_load_decrypt_ok = -2;
	if (n < 0)  // blank settings block
		return -1;
	if (n < (int)STORE_CRYPTO_OVH) {
		hal_debug(LOG_ERROR, "store: image too short (%d)\n", n);
		return -1;
	}
	uint8_t vk[KS_KEY_LEN];
	if (!ks_get_volume_key(vk)) {                         // not unlocked → can't read
		hal_debug(LOG_WARNING, "store: load while locked (no volume_key)\n");
		return -1;
	}
	// s_ciphertext = [nonce][ciphertext + authentication tag]; decrypt into s_image.
	bool ok = xchacha20poly1305_decrypt(s_image, s_ciphertext + STORE_NONCE_LEN,
	                                    (size_t)(n - STORE_NONCE_LEN),
	                                    NULL, 0, s_ciphertext, vk);
	if (ok)
		g_store_diag.settings_load_decrypt_ok = 1;
	else
		g_store_diag.settings_load_decrypt_ok = 0;
	crypto_zero(vk, sizeof vk);
	if (!ok) {
		hal_debug(LOG_ERROR, "store: decrypt failed (wrong key or corrupt)\n");
		return -1;
	}
	return n - (int)STORE_CRYPTO_OVH;                     // plaintext length
}

bool store_commit(int len) {
	if (len < 0 || len > (int)STORE_IMG_CAP)
		return false;
	uint8_t vk[KS_KEY_LEN];
	if (!ks_get_volume_key(vk)) {                         // not unlocked → can't write
		hal_debug(LOG_ERROR, "store: commit while locked (no volume_key)\n");
		return false;
	}
	// s_ciphertext = [fresh nonce][ciphertext + authentication tag] under the volume_key.
	fill_random(s_ciphertext, STORE_NONCE_LEN);
	xchacha20poly1305_encrypt(s_ciphertext + STORE_NONCE_LEN, s_image, (size_t)len,
	                          NULL, 0, s_ciphertext, vk);
	crypto_zero(vk, sizeof vk);
	return settingsblock_save(s_ciphertext, (int)STORE_NONCE_LEN + len + AUTHTAG_LEN);
}

// Destroying the volume_key crypto-erases every tenant that encrypts under it,
// so this must take their flash with it. Leaving a tenant's sectors behind
// strands its ciphertext while its RAM mount keeps writing under a key that no
// longer exists, and those writes are unreadable at the next boot. There is no
// "wipe the key only" caller: losing the key IS the erase, and the sector erase
// only reclaims the space.
bool store_wipe(void) {
	bool ok = settingsblock_erase_all();
	uint32_t total = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	for (uint32_t s = CONTACTSBLOCK_BASE_SECTOR; s < CONTACTSBLOCK_BASE_SECTOR + CONTACTSBLOCK_SECTORS; s++)
		if (!rawflash_erase(RAWFLASH_DEV_INTERNAL, s))
			ok = false;
	for (uint32_t s = STORE_LOG_BASE_SECTOR; s < total; s++)
		if (!rawflash_erase(RAWFLASH_DEV_INTERNAL, s))
			ok = false;
	ks_wipe();   // last: bumps ks_key_generation(), forcing every tenant to re-mount
	return ok;
}

// ======================================================================
// block_read / block_write — pack and unpack `struct device_record` against the
// encrypted settings image above. The wg private key is not in the image: it
// lives in the keystore and is filled in on read. Core 0.
// ======================================================================
#define BLOCK_MAGIC 0x00C0FFEE

// Octet 0 in the lowest byte, matching struct server_endpoint.ip4.
#define IP4(a,b,c,d) ((uint32_t)(a) | ((uint32_t)(b)<<8) | ((uint32_t)(c)<<16) | ((uint32_t)(d)<<24))

static int hex_nybble(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

// Decode `len` hex chars from `hex` into `out` (len/2 bytes). Returns false on
// any malformed nybble. Used once at boot to seed server_static_public.
static bool hex_decode(const char *hex, uint8_t *out, size_t len) {
	if (len & 1)
		return false;
	for (size_t i = 0; i < len; i += 2) {
		int hi = hex_nybble(hex[i]);
		int lo = hex_nybble(hex[i + 1]);
		if (hi < 0 || lo < 0)
			return false;
		out[i / 2] = (uint8_t)((hi << 4) | lo);
	}
	return true;
}

static bool is_all_zero(const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++)
		if (p[i])
			return false;
	return true;
}

// Fill appended fields the on-disk image was too short to contain (or unset on a
// fresh device). Called on every block_read regardless of success.
static void block_apply_defaults(void) {
	if (is_all_zero(device_record.server_static_public, KEY_LEN)) {
		if (hex_decode(DEFAULT_SERVER, device_record.server_static_public, 2 * KEY_LEN))
			hal_debug(LOG_EVERYTHING, "storage: server_static_public seeded from DEFAULT_SERVER\n");
		else
			hal_debug(LOG_ERROR, "storage: DEFAULT_SERVER hex malformed\n");
	}
	// Relay default: seed endpoints[1] ONLY when unset, so a user-entered relay IP
	// (Settings > Relay IP… / onboarding "Find a Relay") persists and is NEVER
	// clobbered on boot. This is a SAFE FALLBACK pointing at the CURRENT production
	// relay; onboarding still resolves the live relay via DoH before registration
	// (in case it moved since the firmware was built).
	if (device_record.endpoints[1].ip4 == 0) {
		device_record.endpoints[1].ip4  = IP4(147, 182, 170, 128);   // new droplet (xyfr.io) relay
		device_record.endpoints[1].port = 50004;
	}
}

struct device_record device_record;
uint8_t flag_save_block = 0;
volatile uint8_t block_ready = 0;
volatile uint32_t block_read_calls  = 0;
volatile uint32_t block_write_calls = 0;

#define DEVICE_STATE_LEN ((int)sizeof(struct device_record))
_Static_assert(sizeof(struct device_record) <= STORE_IMG_CAP, "struct device_record exceeds STORE_IMG_CAP - grow the cap");

// Refill device_record.my_private_key from the keystore, which holds the
// authoritative copy. The key IS also in the settings image, being a field of
// struct device_record, and block_read memcpy's that copy in a few lines before
// this call overwrites it -- the same bytes, and both are sealed under the volume
// key, so the second copy costs no secrecy a flash dump did not already have.
// Does nothing while the store is locked, which block_read never reaches: a
// locked store cannot decrypt the image, so store_load() fails first.
static void block_load_private_key(void) {
	if (store_unlocked())
		ks_get_private_key(device_record.my_private_key);
	// else: locked — the private key stays zero until unlocked
}

bool block_read(void) {
	block_read_calls++;
	memset(&device_record, 0, sizeof(device_record));

	int n = store_load();   // newest settings image into store_image()
	if (n < 0) {
		hal_debug(LOG_EVERYTHING, "storage: no saved block (blank fixed block)\n");
		block_apply_defaults();
		block_load_private_key();
		return false;
	}

	const uint8_t *img = store_image();
	int copy_len = DEVICE_STATE_LEN;
	if (n < DEVICE_STATE_LEN)
		copy_len = n;                    // tolerate a shorter (older) image
	memcpy(&device_record, img, (size_t)copy_len);

	if (device_record.magic != BLOCK_MAGIC) {
		hal_debug(LOG_ERROR, "storage: bad block (read %d, magic %08x), reset\n",
			n, (unsigned)device_record.magic);
		memset(&device_record, 0, sizeof(device_record));
		block_apply_defaults();
		block_load_private_key();
		return false;
	}

	block_apply_defaults();   // seeds endpoints[1] only when unset (see there) — the
	                          // manual/DoH-set relay now survives reboots
	block_load_private_key();
	hal_debug(LOG_EVERYTHING, "storage: read %d byte settings image\n", n);
	if (device_record.ap_list[0].ssid[0])
		g_store_diag.aplist_0_ssid_length_at_load = (int)strlen(device_record.ap_list[0].ssid);
	else
		g_store_diag.aplist_0_ssid_length_at_load = 0;

	block_dump();
	return true;
}


void block_write(void) {
	block_write_calls++;
	device_record.magic = BLOCK_MAGIC;

	// Centralized keystore provisioning: if we have a private key (from the seed
	// or a successful registration) but the keystore is still blank, provision it
	// now (NOENC). The keystore holds the authoritative copy; every boot refills
	// device_record.my_private_key from it (block_load_private_key), whatever the
	// image carries. Runs on core 0
	// (block_write is core-0 only). Re-keying an already-provisioned device is a
	// Stage 2 concern (needs ks_wipe + re-provision, which drops the volume_key).
	if (store_keystate() == KS_BLANK && !is_all_zero(device_record.my_private_key, KEY_LEN)) {
		if (store_provision(device_record.my_private_key))
			hal_debug(LOG_EVERYTHING, "storage: keystore provisioned (default passphrase) from my_private_key\n");
		else
			hal_debug(LOG_ERROR, "storage: keystore provision failed\n");
	}

	// The settings image holds only `struct device_record`; contacts and their
	// message threads live in the filesystem region and persist independently.
	uint8_t *img = store_image();
	memcpy(img, &device_record, DEVICE_STATE_LEN);
	bool committed = store_commit(DEVICE_STATE_LEN);
	if (device_record.ap_list[0].ssid[0])
		g_store_diag.aplist_0_ssid_length = (int)strlen(device_record.ap_list[0].ssid);
	else
		g_store_diag.aplist_0_ssid_length = 0;
	if (committed)
		g_store_diag.block_write_commit_success = 1;
	else
		g_store_diag.block_write_commit_success = 0;
	g_store_diag.block_write_count  = (unsigned)block_write_calls;
	if (!committed)
		hal_debug(LOG_ERROR, "storage: store_commit failed\n");
	else
		hal_debug(LOG_EVERYTHING, "storage: wrote %d byte settings image\n", DEVICE_STATE_LEN);
	block_dump();
}

// Per-boot AEAD-nonce epoch (see secure_store.h). Bumped once on first use each
// boot and persisted (block_write) BEFORE it stamps any record, so a crash
// mid-bump can never leave records carrying an unpersisted epoch — the worst
// case is reusing the same epoch next boot, having written nothing under it.
// The stores only mount once the volume_key is up, so the first call is always
// post-unlock and the guard below is belt and braces.
static uint32_t s_epoch = 0;
static bool     s_session_begun = false;

void store_begin_session(void) {
	if (s_session_begun)  // once per boot
		return;
	if (!store_unlocked())  // locked/blank — defer; begins next boot post-provision
		return;
	// Never bump and persist the epoch onto an unconfigured record. If block_read
	// failed or reset, device_record holds the magic and zeros with no private
	// key; writing that would overwrite a good A/B slot with an empty image and,
	// across reboots, wipe the store. A keyless device has no records to protect,
	// so defer — and say so, because it also means block_read loaded nothing real.
	bool has_key = false;
	for (int i = 0; i < KEY_LEN; i++)
		if (device_record.my_private_key[i]) {
			has_key = true;
			break;
		}
	if (!has_key) {
		hal_debug(LOG_CRITICAL, "store: session begin on KEYLESS block — SKIP epoch write (protect A/B slots)\n");
		return;
	}
	g_store_diag.epoch_write_ran = 1;
	g_store_diag.epoch_before = device_record.boot_epoch;
	if (device_record.ap_list[0].ssid[0])
		g_store_diag.aplist_0_ssid_length_at_epoch_write = (int)strlen(device_record.ap_list[0].ssid);
	else
		g_store_diag.aplist_0_ssid_length_at_epoch_write = 0;
	s_epoch = device_record.boot_epoch + 1;                       // a fresh nonce subspace for this session
	device_record.boot_epoch = s_epoch;
	g_store_diag.epoch_after = s_epoch;
	s_session_begun = true;
	block_write();                                        // durable before any record uses the new epoch
}

uint32_t store_current_epoch(void) {
	if (s_session_begun)  // PURE reader — never writes flash
		return s_epoch;
	return device_record.boot_epoch;
}

// A one-line store status for the boot log.
void fs_ls(void) {
	hal_debug(LOG_EVERYTHING, "store: keystate=%d block_read_calls=%u block_write_calls=%u\n",
		(int)store_keystate(), (unsigned)block_read_calls, (unsigned)block_write_calls);
}

void block_pump(void) {
	if (!flag_save_block)
		return;
	hal_debug(LOG_EVERYTHING, "writing the block\n");
	block_dump();
	block_write();
	flag_save_block = 0;
}

void keys_pump(void) {
	static bool printed = false;
	if (printed)
		return;
	if (is_all_zero(device_record.my_private_key, KEY_LEN))
		return;

	uint8_t pub[KEY_LEN];
	curve25519(pub, device_record.my_private_key, basepoint);

	hal_debug(LOG_EVERYTHING, "my private: ");
	for (int i = 0; i < KEY_LEN; i++)
		hal_debug(LOG_EVERYTHING, "%02x", device_record.my_private_key[i]);
	hal_debug(LOG_EVERYTHING, "\n");
	hal_debug(LOG_EVERYTHING, "my public:  ");
	for (int i = 0; i < KEY_LEN; i++)
		hal_debug(LOG_EVERYTHING, "%02x", pub[i]);
	hal_debug(LOG_EVERYTHING, "\n");
	hal_debug(LOG_EVERYTHING, "my partkey: %08x\n",
		(unsigned)((pub[0] << 24) | (pub[1] << 16) | (pub[2] << 8) | pub[3]));

	printed = true;
}

// The touch calibration array is longer than this, but only the first points
// were ever populated, so the dump stays short.
#define CALIBRATION_DUMP_POINTS 6

void block_dump(void) {
	hal_debug(LOG_EVERYTHING, "block magic id %x\n", device_record.magic);
	hal_debug(LOG_EVERYTHING, "userid : %u\n", (unsigned)device_record.my_id);
	for (int i = 0; i < CALIBRATION_DUMP_POINTS; i++)
		hal_debug(LOG_EVERYTHING, "%d ", device_record.calibration_data[i]);
	hal_debug(LOG_EVERYTHING, "\nAPs:\n");
	for (int i = 0; i < MAX_APS; i++)
		hal_debug(LOG_EVERYTHING, "%d. [%s]->[%s]\n", i+1, device_record.ap_list[i].ssid, device_record.ap_list[i].key);
	hal_debug(LOG_EVERYTHING, "Endpoints:\n");
	for (int i = 0; i < MAX_SERVER_ENDPOINTS; i++) {
		uint32_t ip = device_record.endpoints[i].ip4;
		hal_debug(LOG_EVERYTHING, "%d. %u.%u.%u.%u:%u\n", i+1,
			(unsigned)(ip & 0xff),
			(unsigned)((ip >> 8) & 0xff),
			(unsigned)((ip >> 16) & 0xff),
			(unsigned)((ip >> 24) & 0xff),
			(unsigned)device_record.endpoints[i].port);
	}
}
