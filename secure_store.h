#pragma once
//
// store.h — the at-rest storage integration point. Brings up the keystore +
// the fixed block (settings + contact table) over the rawflash region, and owns
// the single live plaintext image buffer that storage.cpp / contacts.cpp pack
// and unpack. This is what replaces LittleFS for `block` and contacts.
//
// Region layout (sectors of the internal rawflash device):
//   [0 .. BOOTBLOCK_SECTORS)                          keystore bootblock   (A/B EDEK)
//   [STORE_SB_BASE .. +SB_SLOTS*FB_SLOT_SECTORS)      fixed block          (A/B)
//   [CONTACTSBLOCK_BASE .. +CONTACTSBLOCK_SECTORS)      contact ring         (page-slot log)
//   [STORE_LOG_BASE .. end)                           logbook message log
//
// The contact ring is the dedicated per-record contact store (256 B/record =
// one page, 16/sector, per-record AEAD under the volume_key, GC). It is
// RESERVED here now; contacts still serialize into the fixed block until the
// cutover, after which the fixed block shrinks to just `struct device_record` settings
// and this map compacts (see the storage.* -> settings.* split).
//
// The fixed block is ENCRYPTED: the slot holds [nonce:24][ciphertext+tag] under
// the keystore volume_key (XChaCha20-Poly1305), so the Wi-Fi list, settings and
// contacts are encrypted at rest. The volume_key itself is wrapped under a
// passphrase (default placeholder until the user sets their own — see
// store_provision / store_boot_unlock). Real at-rest secrecy arrives when the
// user replaces the default passphrase (a cheap re-wrap; the data stays put,
// already encrypted under the same volume_key). Core 0 only.
//

#include <stdint.h>
#include <stdbool.h>
#include "bootblock.h"   // BOOTBLOCK_SECTORS
#include "keystore.h"    // ks_state
#include "settingsblock.h"  // SB_SLOTS

#ifdef __cplusplus
extern "C" {
#endif

#define STORE_SB_BASE_SECTOR   ((uint32_t)BOOTBLOCK_SECTORS)
#define STORE_SB_SLOT_SECTORS   10u   // 40 KB/slot — holds settings + contacts TODAY; shrinks to settings-only post-cutover

// Contact ring: the dedicated per-record contact store. MAX_INODES * 256 B =
// 128 KB = 32 live sectors; + ~8 spare sectors for GC copy-forward / write-ahead
// headroom. Reserved now, consumed by the contact ring backend; the backend
// enforces MAX_INODES (filesystem.h) on the live count.
#define CONTACTSBLOCK_BASE_SECTOR (STORE_SB_BASE_SECTOR + (uint32_t)SB_SLOTS * STORE_SB_SLOT_SECTORS)
#define CONTACTSBLOCK_SECTORS     40u

#define STORE_LOG_BASE_SECTOR  (CONTACTSBLOCK_BASE_SECTOR + CONTACTSBLOCK_SECTORS)

// Bring up rawflash + keystore + fixed block. Does NOT provision (no key yet).
// Returns true if the storage HAL is ready. Call once at boot, before block_read.
bool store_init(void);

// Keystore state (KS_BLANK on a fresh device → caller must provision).
ks_state store_keystate(void);

// Provision a fresh device: store the wg private key AND immediately wrap the
// volume_key under the DEFAULT passphrase (BLANK → NOENC → UNLOCKED, encryption
// ON). The default is a known placeholder — it gives no secrecy until the user
// sets their own passphrase, but it means doing so later is a cheap re-wrap (no
// data migration) and exercises the real crypto path now.
bool store_provision(const uint8_t priv[32]);

// Cold-boot unlock: if the keystore is LOCKED, try the DEFAULT passphrase.
// Returns true if usable afterwards. If it fails, the device has a user-set
// passphrase → store_needs_passphrase() goes true and the (future) UI must
// prompt for it before block_read can proceed.
bool store_unlock_default(void);

// Boot-time key management, called once after store_init (before block_read):
//   LOCKED  -> try the default passphrase (store_unlock_default).
//   NOENC   -> upgrade in place to default-passphrase encryption (migrates a
//              device provisioned by an older, pre-passphrase firmware).
//   BLANK   -> nothing (provisioned later on first block_write).
//   UNLOCKED-> nothing (already open).
void store_boot_unlock(void);

// True if the keystore is provisioned but not unlocked (the default passphrase
// didn't open it) — i.e. a user passphrase is required.
bool store_needs_passphrase(void);

// Disk-key (user passphrase) UI hooks.
//   store_disk_key_is_custom() — true if a user (non-default) disk key is in effect;
//     the UI must prompt for the CURRENT key before allowing a change.
//   store_set_disk_key(new)    — FIRST-TIME set (re-wrap from the default).
//   store_change_disk_key(old,new) — change an existing key (verifies old first).
//   store_verify_disk_key(phrase)  — non-destructive check of the current key.
//   store_unlock_disk_key(phrase)  — cold-boot LOCKED->UNLOCKED; caller re-runs block_read().
bool store_disk_key_is_custom(void);
bool store_set_disk_key(const char *phrase);
bool store_change_disk_key(const char *old_phrase, const char *new_phrase);
bool store_verify_disk_key(const char *phrase);
bool store_unlock_disk_key(const char *phrase);

// True once key material is usable (NOENC or UNLOCKED).
bool store_unlocked(void);

// The per-boot store session epoch, folded into the contactsblock + logbook AEAD
// nonces (alongside record_id and a per-store domain byte) so a record_id that
// regresses after a delete/compaction cannot reuse a (volume_key, nonce) pair
// across boots.
//
// Split into an explicit establish + a pure read so the WRITE it entails can't hide
// inside a tenant mount (the meta-bug: contacts_init() -> ensure_ring() ->
// store_boot_epoch() did a full device-state block_write; run before block_read it
// persisted an empty image that then won the load, wiping settings every boot):
//   store_begin_session() — bump the epoch and PERSIST it (a device-state write),
//     once per boot. MUST run right after block_read (so it saves the loaded state,
//     not an empty one); kernel_init calls it there. Defers while locked/blank.
//   store_current_epoch()  — PURE reader for the tenants (contactsblock/logbook);
//     never writes flash, so a ring/logbook mount can never clobber device state.
void     store_begin_session(void);
uint32_t store_current_epoch(void);

// The single live plaintext image buffer (settings + contact table). storage.cpp
// owns its byte layout; store.c just persists it verbatim.
uint8_t *store_image(void);
int      store_image_cap(void);

// Load the newest fixed-block image into store_image(). Returns the byte length,
// or -1 if the fixed block is blank (fresh device).
int store_load(void);

// Persist store_image()[0..len) to the fixed block (A/B atomic).
bool store_commit(int len);

// Crypto-erase everything: wipe the fixed block and the keystore → blank device.
bool store_wipe(void);

// TEMP boot diagnostic (`sdiag` serial cmd): the settings load + per-boot epoch
// write on the boot path, to explain settings-persistence failures.
struct store_diag {
	int      settings_load_bytes;        // store_load(): settingsblock_load byte count (-1 = no valid slot)
	int      settings_load_decrypt_ok;  // 1 = image decrypted OK, 0 = decrypt failed, -2 = not reached
	int      aplist_0_ssid_length_at_load;      // strlen(device_record.ap_list[0].ssid) right after block_read
	int      epoch_write_ran;     // did store_boot_epoch() bump+write this boot?
	unsigned epoch_before, epoch_after;
	int      aplist_0_ssid_length_at_epoch_write;     // strlen(device_record.ap_list[0].ssid) at the store_boot_epoch write
	int      aplist_0_ssid_length;        // strlen(device_record.ap_list[0].ssid) at the last block_write
	int      block_write_commit_success;     // last block_write's store_commit() result (1 ok, 0 fail, -2 none)
	unsigned block_write_count;      // block_write() call count this boot
};
extern struct store_diag g_store_diag;

#ifdef __cplusplus
}
#endif
