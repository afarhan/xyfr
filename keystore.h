#pragma once
//
// keystore.h — the at-rest key schedule (see STORAGE_SECURITY.md Part II). Sits
// on top of the bootblock (bootblock.h) and uses ONLY crypto.c primitives via
// wg.h (keyed BLAKE2s for the KDF, xchacha20poly1305 for wrapping, crypto_zero /
// crypto_equal). No edit to wg.c / crypto.c. Core 0 only.
//
// Two-level schedule (LUKS-style):
//
//     passphrase + salt --KDF(BLAKE2s,PBKDF2)--> KEK --unwrap--> volume_key (DEK)
//                                                                  |
//                          decrypts: the private key + per-contact keys
//                          (and, later, the LittleFS bulk)
//
// The volume_key is random and never changes; the passphrase only wraps it
// (EDEK), so a passphrase change re-wraps one small key and a wipe destroys one
// small key. The decrypted volume_key lives in RAM only and is re-derived from
// the passphrase each boot. A short session PIN gates the powered-on session by
// re-wrapping the in-RAM volume_key — it never protects the at-rest disk.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KS_KEY_LEN 32   // wg static key / volume key / contact key size

typedef enum {
	KS_BLANK = 0,    // no bootblock yet (fresh device)
	KS_NOENC,        // provisioned, but volume_key is plaintext on flash (encryption OFF)
	KS_LOCKED,       // EDEK on flash, no volume_key in RAM — needs the passphrase
	KS_SESSION,      // powered-on but screen-locked — only a PIN-wrapped blob in RAM
	KS_UNLOCKED,     // volume_key in RAM — keys + data accessible
} ks_state;

// Mount the bootblock and classify state. Call once at boot (core 0).
bool     ks_init(void);
ks_state ks_state_get(void);

// --- provisioning (STORAGE_SECURITY.md §II.4) ---
// Step 1+2: create the bootblock with a fresh random volume_key (stored
// PLAINTEXT — encryption OFF) and store the device private key wrapped under it.
// BLANK -> NOENC.
bool ks_provision(const uint8_t priv[KS_KEY_LEN]);
// Step 3: derive KEK from the passphrase, wrap the volume_key (EDEK -> flash),
// and securely erase the plaintext volume_key. NOENC -> UNLOCKED (encryption ON).
bool ks_enable_passphrase(const char *phrase);
// Step 4: configure the session PIN (stores only a salt; the PIN itself and any
// verifier never touch flash). Requires UNLOCKED. Arms the session key in RAM.
bool ks_set_pin(const char *pin);

// --- unlock / lock ---
bool ks_unlock_passphrase(const char *phrase);  // LOCKED  -> UNLOCKED (cold)
bool ks_lock_session(void);                      // UNLOCKED-> SESSION (needs armed PIN key)
bool ks_unlock_pin(const char *pin);             // SESSION -> UNLOCKED
void ks_evict(void);                             // drop all key material from RAM -> LOCKED (cold)

// --- key access (UNLOCKED only) ---
bool ks_get_private_key(uint8_t out[KS_KEY_LEN]);
bool ks_get_volume_key(uint8_t out[KS_KEY_LEN]);          // the at-rest encryption seam (contact ring, fixed block)
// Monotonic counter of volume_key IDENTITY changes this boot (provision mints a
// new key, wipe destroys it; unlocking recovers the same key and does not bump).
// A tenant that caches a mount under the volume_key must re-check this — see
// contacts.c ensure_ring(). RAM-only; not persisted.
uint32_t ks_key_generation(void);
// Per-contact keys are NOT in the keystore anymore — they live inside each
// contact's record in the contact ring, wrapped under the volume_key obtained
// from ks_get_volume_key(). See contactsblock.c.

// --- maintenance ---
// Non-destructive check: does `phrase` unwrap the current EDEK? (UNLOCKED + ENC
// only.) No state change — used to confirm the CURRENT disk key before a change.
bool ks_verify_passphrase(const char *phrase);
bool ks_change_passphrase(const char *old_phrase, const char *new_phrase);
void ks_wipe(void);   // crypto-erase: destroy the wrapped volume_key -> blank device

// Failed-unlock attempt counter (in-RAM for now; persistent anti-rollback
// counter is a TODO — see STORAGE_SECURITY.md §II.6).
int  ks_fail_count(void);

// Test-only: clear the in-RAM state WITHOUT touching the bootblock, to simulate
// a power cycle in the host harness. Not used by firmware.
void ks_test_reset_ram(void);

#ifdef __cplusplus
}
#endif
