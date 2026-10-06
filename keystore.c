//
// keystore.c — the at-rest key schedule. See keystore.h + STORAGE_SECURITY.md
// Part II. Portable C; uses crypto.c primitives via wg.h (BLAKE2s, xchacha,
// crypto_zero/equal) and the bootblock A/B store. Core 0 only.
//

#include <string.h>
#include "hal.h"        // hal_rand, hal_debug
#include "wg.h"         // blake2s, xchacha20poly1305_*, crypto_zero, crypto_equal, AUTHTAG_LEN
#include "bootblock.h"
#include "keystore.h"

#define KS_NONCE_LEN 24                          // xchacha nonce
#define KS_TAG_LEN   AUTHTAG_LEN                 // 16
#define KS_WRAP_LEN  (KS_KEY_LEN + KS_TAG_LEN)   // 48: a wrapped 32-byte key
#define KS_SALT_LEN  16
#define KS_KDF_ITERS_DEFAULT 16384               // ~1-2s on device (defense-in-depth for the disk key);
                                                 // stored per-image so only fresh provisions use the new value

#define KSF_ENC 0x01   // EDEK valid, volume_key NOT plaintext (encryption ON)
#define KSF_PIN 0x02   // a session PIN is configured

// The persisted image (payload of the bootblock A/B frame). Plaintext fields are
// public; the wrapped fields are ciphertext. Layout is versioned for forward
// compatibility; keep it append-only.
//
// It holds only the fixed key schedule, which is what keeps it inside a single
// bootblock sector. A per-contact key lives in that contact's own file header
// (filesystem.c) so it can be crypto-erased with the contact.
struct ks_image {
	uint16_t version;
	uint8_t  flags;
	uint8_t  _pad;
	uint32_t kdf_iters;
	uint8_t  salt[KS_SALT_LEN];          // passphrase KDF salt
	uint8_t  pin_salt[KS_SALT_LEN];      // session-PIN KDF salt (not secret)
	uint8_t  edek_nonce[KS_NONCE_LEN];
	uint8_t  edek[KS_WRAP_LEN];          // xwrap(KEK, volume_key)         (valid iff KSF_ENC)
	uint8_t  dek_plain[KS_KEY_LEN];      // plaintext volume_key           (valid iff !KSF_ENC)
	uint8_t  priv_nonce[KS_NONCE_LEN];
	uint8_t  priv_wrap[KS_WRAP_LEN];     // xwrap(volume_key, private_key)
};

#define KS_IMAGE_VERSION 2   // v2 dropped the per-contact key slab

// ---- RAM state ----
static struct ks_image img;
static ks_state state = KS_BLANK;

static uint8_t  volkey[KS_KEY_LEN];        // the decrypted volume key (DEK)
static bool     have_volkey = false;
static uint8_t  pinkey[KS_KEY_LEN];        // the armed PIN-derived key
static bool     have_pinkey = false;
static uint8_t  sess_nonce[KS_NONCE_LEN];
static uint8_t  sess_blob[KS_WRAP_LEN];    // PIN-wrapped DEK while SESSION-locked
static int      fail_count = 0;

// ---- small helpers ----

static void rand_bytes(uint8_t *p, int n) {
	int i = 0;
	while (i < n) {
		uint32_t r = hal_rand();
		for (int k = 0; k < 4 && i < n; k++, i++)
			p[i] = (uint8_t)(r >> (8 * k));
	}
}

// Derive a 32-byte key from a secret via PBKDF2 with keyed BLAKE2s as the PRF.
// The secret is pre-hashed to 32 bytes first (BLAKE2s keys are <=32 bytes, but
// passphrases can be longer) — the standard HMAC-style key prehash. U and T are
// PBKDF2's own names for the per-iteration block and the running xor.
static void derive_key(uint8_t out[KS_KEY_LEN], const char *secret,
                       const uint8_t salt[KS_SALT_LEN], uint32_t iters) {
	uint8_t prf_key[KS_KEY_LEN], U[KS_KEY_LEN], T[KS_KEY_LEN];
	uint8_t msg[KS_SALT_LEN + 4];
	size_t slen = strlen(secret);

	blake2s(prf_key, KS_KEY_LEN, NULL, 0, secret, slen);   // prehash -> PRF key

	// U1 = PRF(prf_key, salt || BE32(1))
	memcpy(msg, salt, KS_SALT_LEN);
	msg[KS_SALT_LEN + 0] = 0;
	msg[KS_SALT_LEN + 1] = 0;
	msg[KS_SALT_LEN + 2] = 0;
	msg[KS_SALT_LEN + 3] = 1;
	blake2s(U, KS_KEY_LEN, prf_key, KS_KEY_LEN, msg, sizeof msg);
	memcpy(T, U, KS_KEY_LEN);

	for (uint32_t i = 1; i < iters; i++) {
		blake2s(U, KS_KEY_LEN, prf_key, KS_KEY_LEN, U, KS_KEY_LEN);
		for (int j = 0; j < KS_KEY_LEN; j++)
			T[j] ^= U[j];
	}
	memcpy(out, T, KS_KEY_LEN);
	crypto_zero(prf_key, sizeof prf_key);
	crypto_zero(U, sizeof U);
	crypto_zero(T, sizeof T);
}

// Wrap a 32-byte key into a 48-byte blob (ciphertext || Poly1305 tag) under
// `wrapkey` + nonce.
static void wrap_key(uint8_t out[KS_WRAP_LEN], const uint8_t key[KS_KEY_LEN],
                     const uint8_t wrapkey[KS_KEY_LEN], const uint8_t nonce[KS_NONCE_LEN]) {
	xchacha20poly1305_encrypt(out, key, KS_KEY_LEN, NULL, 0, nonce, wrapkey);
}

// Unwrap a 48-byte blob back to a 32-byte key. False if the authentication tag
// does not match.
static bool unwrap_key(uint8_t out[KS_KEY_LEN], const uint8_t blob[KS_WRAP_LEN],
                       const uint8_t wrapkey[KS_KEY_LEN], const uint8_t nonce[KS_NONCE_LEN]) {
	return xchacha20poly1305_decrypt(out, blob, KS_WRAP_LEN, NULL, 0, nonce, wrapkey);
}

// Bumped whenever the volume_key's identity changes: a provision mints a new one
// and a wipe destroys it, while the unlock paths recover the same key and do not
// bump. A tenant that caches a mount under the volume_key compares this to spot a
// stale mount — see contacts.c ensure_store(). RAM-only: a reboot re-mounts
// everything anyway.
static uint32_t key_generation = 0;

uint32_t ks_key_generation(void) { return key_generation; }

static bool persist_image(void) {
	return bootblock_save(&img, (int)sizeof img);
}

// ---- public API ----

bool ks_init(void) {
	if (!bootblock_init())
		return false;
	int n = bootblock_load(&img, (int)sizeof img);
	if (n < 0) {
		state = KS_BLANK;
		return true;
	}
	if ((size_t)n != sizeof img || img.version != KS_IMAGE_VERSION) {
		hal_debug(LOG_ERROR, "keystore: image size/version mismatch (%d)\n", n);
		state = KS_BLANK;       // treat as blank rather than risk a wrong parse
		return true;
	}
	if (img.flags & KSF_ENC) {
		state = KS_LOCKED;      // need the passphrase to recover the volume_key
	} else {
		// encryption OFF: the volume_key is plaintext on flash — load it directly.
		memcpy(volkey, img.dek_plain, KS_KEY_LEN);
		have_volkey = true;
		state = KS_NOENC;
	}
	return true;
}

ks_state ks_state_get(void) { return state; }

bool ks_provision(const uint8_t priv[KS_KEY_LEN]) {
	if (state != KS_BLANK)
		return false;
	memset(&img, 0, sizeof img);
	img.version   = KS_IMAGE_VERSION;
	img.flags     = 0;                       // encryption OFF until a passphrase is set
	img.kdf_iters = KS_KDF_ITERS_DEFAULT;
	rand_bytes(img.salt, KS_SALT_LEN);
	rand_bytes(img.pin_salt, KS_SALT_LEN);

	rand_bytes(volkey, KS_KEY_LEN);              // the volume_key (DEK)
	key_generation++;                            // a new key identity — invalidate cached mounts
	memcpy(img.dek_plain, volkey, KS_KEY_LEN);   // stored plaintext for now
	have_volkey = true;

	rand_bytes(img.priv_nonce, KS_NONCE_LEN);
	wrap_key(img.priv_wrap, priv, volkey, img.priv_nonce);

	if (!persist_image()) {
		crypto_zero(volkey, sizeof volkey);
		have_volkey = false;
		return false;
	}
	state = KS_NOENC;
	return true;
}

bool ks_enable_passphrase(const char *phrase) {
	if (state != KS_NOENC || !have_volkey)
		return false;
	uint8_t kek[KS_KEY_LEN];
	rand_bytes(img.salt, KS_SALT_LEN);
	img.kdf_iters = KS_KDF_ITERS_DEFAULT;
	derive_key(kek, phrase, img.salt, img.kdf_iters);

	rand_bytes(img.edek_nonce, KS_NONCE_LEN);
	wrap_key(img.edek, volkey, kek, img.edek_nonce);
	crypto_zero(kek, sizeof kek);

	img.flags |= KSF_ENC;
	crypto_zero(img.dek_plain, KS_KEY_LEN);   // securely erase the plaintext volume_key

	// Double-write: the first save lands the encrypted image in the inactive
	// slot; the second overwrites the OTHER slot — which still held the plaintext
	// volume_key — so neither slot retains it. (Residual window: if power is lost
	// between the two writes, the plaintext copy survives in one slot until the
	// next save. A power-safe scrub can't erase the only valid copy first; this
	// is the accepted compromise — see STORAGE_SECURITY.md / threat notes.)
	if (!persist_image()) {  // best-effort rollback in RAM
		img.flags &= ~KSF_ENC;
		return false;
	}
	persist_image();                                                 // scrub the stale plaintext slot
	state = KS_UNLOCKED;
	return true;
}

bool ks_set_pin(const char *pin) {
	if (state != KS_UNLOCKED)
		return false;
	// pin_salt was randomised at provision; keep it stable. Mark configured and
	// arm the session key (so an auto-lock can wrap without re-prompting).
	img.flags |= KSF_PIN;
	if (!persist_image()) {
		img.flags &= ~KSF_PIN;
		return false;
	}
	derive_key(pinkey, pin, img.pin_salt, img.kdf_iters);
	have_pinkey = true;
	return true;
}

bool ks_unlock_passphrase(const char *phrase) {
	if (state != KS_LOCKED)
		return false;
	uint8_t kek[KS_KEY_LEN], vk[KS_KEY_LEN];
	derive_key(kek, phrase, img.salt, img.kdf_iters);
	bool ok = unwrap_key(vk, img.edek, kek, img.edek_nonce);
	crypto_zero(kek, sizeof kek);
	if (!ok) {
		fail_count++;
		crypto_zero(vk, sizeof vk);
		return false;
	}
	memcpy(volkey, vk, KS_KEY_LEN);
	crypto_zero(vk, sizeof vk);
	have_volkey = true;
	fail_count = 0;
	state = KS_UNLOCKED;
	return true;
}

bool ks_lock_session(void) {
	if (state != KS_UNLOCKED || !have_volkey)
		return false;
	if (!have_pinkey)  // no armed PIN key — caller should ks_evict()
		return false;
	rand_bytes(sess_nonce, KS_NONCE_LEN);
	wrap_key(sess_blob, volkey, pinkey, sess_nonce);
	crypto_zero(volkey, sizeof volkey);
	have_volkey = false;
	crypto_zero(pinkey, sizeof pinkey);
	have_pinkey = false;
	state = KS_SESSION;
	return true;
}

bool ks_unlock_pin(const char *pin) {
	if (state != KS_SESSION)
		return false;
	uint8_t k[KS_KEY_LEN], vk[KS_KEY_LEN];
	derive_key(k, pin, img.pin_salt, img.kdf_iters);
	bool ok = unwrap_key(vk, sess_blob, k, sess_nonce);
	if (!ok) {
		fail_count++;
		crypto_zero(k, sizeof k);
		crypto_zero(vk, sizeof vk);
		return false;
	}
	memcpy(volkey, vk, KS_KEY_LEN);
	have_volkey = true;
	memcpy(pinkey, k, KS_KEY_LEN);   // re-arm for the next lock
	have_pinkey = true;
	crypto_zero(vk, sizeof vk);
	crypto_zero(k, sizeof k);
	crypto_zero(sess_blob, sizeof sess_blob);
	fail_count = 0;
	state = KS_UNLOCKED;
	return true;
}

void ks_evict(void) {
	crypto_zero(volkey, sizeof volkey);
	crypto_zero(pinkey, sizeof pinkey);
	crypto_zero(sess_blob, sizeof sess_blob);
	have_pinkey = false;
	if (img.flags & KSF_ENC) {
		have_volkey = false;
		state = KS_LOCKED;
	} else {
		// encryption OFF: there is nothing to lock to — reload the plaintext key.
		memcpy(volkey, img.dek_plain, KS_KEY_LEN);
		have_volkey = true;
		state = KS_NOENC;
	}
}

bool ks_get_private_key(uint8_t out[KS_KEY_LEN]) {
	if (!have_volkey)
		return false;
	return unwrap_key(out, img.priv_wrap, volkey, img.priv_nonce);
}

bool ks_get_volume_key(uint8_t out[KS_KEY_LEN]) {
	if (!have_volkey)
		return false;
	memcpy(out, volkey, KS_KEY_LEN);
	return true;
}

bool ks_verify_passphrase(const char *phrase) {
	if (state != KS_UNLOCKED || !(img.flags & KSF_ENC))
		return false;
	uint8_t kek[KS_KEY_LEN], vk[KS_KEY_LEN];
	derive_key(kek, phrase, img.salt, img.kdf_iters);
	bool ok = unwrap_key(vk, img.edek, kek, img.edek_nonce);
	crypto_zero(kek, sizeof kek);
	crypto_zero(vk, sizeof vk);
	return ok;
}

bool ks_change_passphrase(const char *old_phrase, const char *new_phrase) {
	if (state != KS_UNLOCKED || !(img.flags & KSF_ENC))
		return false;
	// Verify the old passphrase against the current EDEK before re-wrapping.
	uint8_t kek[KS_KEY_LEN], vk[KS_KEY_LEN];
	derive_key(kek, old_phrase, img.salt, img.kdf_iters);
	bool ok = unwrap_key(vk, img.edek, kek, img.edek_nonce);
	crypto_zero(kek, sizeof kek);
	if (!ok) {
		crypto_zero(vk, sizeof vk);
		return false;
	}
	crypto_zero(vk, sizeof vk);        // we already hold volkey in RAM

	// Fresh salt + re-wrap the (unchanged) volume_key under the new passphrase.
	uint8_t new_kek[KS_KEY_LEN];
	uint8_t old_salt[KS_SALT_LEN], old_nonce[KS_NONCE_LEN], old_edek[KS_WRAP_LEN];
	memcpy(old_salt, img.salt, KS_SALT_LEN);
	memcpy(old_nonce, img.edek_nonce, KS_NONCE_LEN);
	memcpy(old_edek, img.edek, KS_WRAP_LEN);

	rand_bytes(img.salt, KS_SALT_LEN);
	derive_key(new_kek, new_phrase, img.salt, img.kdf_iters);
	rand_bytes(img.edek_nonce, KS_NONCE_LEN);
	wrap_key(img.edek, volkey, new_kek, img.edek_nonce);
	crypto_zero(new_kek, sizeof new_kek);

	if (!persist_image()) {                  // roll back in RAM on persist failure
		memcpy(img.salt, old_salt, KS_SALT_LEN);
		memcpy(img.edek_nonce, old_nonce, KS_NONCE_LEN);
		memcpy(img.edek, old_edek, KS_WRAP_LEN);
		return false;
	}
	return true;
}

void ks_wipe(void) {
	// Crypto-erase / duress wipe: erase BOTH slots so neither retains the wrapped
	// volume_key. A single image-write would leave the key intact in the other
	// slot. With no key material on flash, every ciphertext sealed under the
	// volume_key becomes undecryptable noise and the device is back to blank.
	bootblock_erase_all();
	memset(&img, 0, sizeof img);
	key_generation++;                       // the volume_key is gone — invalidate cached mounts
	crypto_zero(volkey, sizeof volkey);
	have_volkey = false;
	crypto_zero(pinkey, sizeof pinkey);
	have_pinkey = false;
	crypto_zero(sess_blob, sizeof sess_blob);
	state = KS_BLANK;
}

int ks_fail_count(void) { return fail_count; }

void ks_test_reset_ram(void) {
	crypto_zero(volkey, sizeof volkey);
	have_volkey = false;
	crypto_zero(pinkey, sizeof pinkey);
	have_pinkey = false;
	crypto_zero(sess_blob, sizeof sess_blob);
	memset(&img, 0, sizeof img);
	fail_count = 0;
	state = KS_BLANK;
}
