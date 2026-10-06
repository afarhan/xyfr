//
// test_store.c — HOST test for store.c, the at-rest integration point: keystore
// (key schedule, over bootflash_posix) + fixed block (settings+contacts, over
// rawflash_posix) composed together. Proves: blank device, provision (NOENC),
// image round-trip, persistence across a re-init ("reboot") including the
// private key recovered from the keystore, and wipe. Verifies the sector layout
// (keystore / fixed block / logbook) doesn't overlap by exercising both stores.
//
// Build/run: cd secserver && make store_test && ./store_test
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include "secure_store.h"
#include "keystore.h"

// wg.c references these (it's linked for the keystore's crypto). Stubs, same as
// test_keystore.c — the store test exercises no handshake path.
int    validate_public_key(const uint8_t *pk, void *ctx) { (void)pk; (void)ctx; return 1; }
time_t get_current_time_seconds(void) { return time(NULL); }

static int passed = 0, failed = 0;
#define CHECK(c, m) do { if (c) { printf("  PASS  %s\n", m); passed++; } \
                         else  { printf("  FAIL  %s\n", m); failed++; } } while (0)

int main(void) {
	unlink("fsroot/bootblock.img");
	unlink("fsroot/rawflash.img");
	printf("==== store host test ====\n");

	uint8_t priv[32]; for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(0x40 + i);

	CHECK(store_init(), "store_init (fresh)");
	CHECK(store_keystate() == KS_BLANK, "fresh device -> KS_BLANK");
	CHECK(store_load() == -1, "blank fixed block -> load -1");

	CHECK(store_provision(priv), "provision (default passphrase)");
	CHECK(store_keystate() == KS_UNLOCKED, "provisioned -> UNLOCKED (encryption on)");
	CHECK(store_unlocked(), "unlocked after provision");
	CHECK(!store_needs_passphrase(), "no passphrase prompt while unlocked");

	uint8_t gp[32];
	CHECK(ks_get_private_key(gp) && memcmp(gp, priv, 32) == 0, "private key readable");

	// Write an image (settings only now — contacts moved to contactsblock, so the
	// image cap shrank from ~40 KB to STORE_IMG_CAP=4096, reclaiming RAM).
	int cap = store_image_cap();
	CHECK(cap >= 4000, "image cap holds the settings image");
	uint8_t *img = store_image();
	int len = 4000;
	for (int i = 0; i < len; i++) img[i] = (uint8_t)(i * 13 + 7);
	CHECK(store_commit(len), "commit image");

	// Corrupt RAM, reload from flash.
	memset(img, 0, cap);
	CHECK(store_load() == len, "load returns committed length");
	bool ok = true; for (int i = 0; i < len; i++) if (img[i] != (uint8_t)(i * 13 + 7)) { ok = false; break; }
	CHECK(ok, "image round-trips");

	// "Reboot": cold boot is LOCKED (volume_key wrapped); default unlocks it.
	CHECK(store_init(), "store_init (reboot)");
	CHECK(store_keystate() == KS_LOCKED, "LOCKED on cold boot (passphrase wrap)");
	CHECK(!store_unlocked(), "not unlocked before passphrase");
	CHECK(store_needs_passphrase(), "needs passphrase before unlock");
	CHECK(store_unlock_default(), "default passphrase unlocks");
	CHECK(store_keystate() == KS_UNLOCKED, "UNLOCKED after default unlock");
	CHECK(ks_get_private_key(gp) && memcmp(gp, priv, 32) == 0, "private key survives reboot");
	memset(store_image(), 0, cap);
	CHECK(store_load() == len, "image length survives reboot");
	ok = true; img = store_image(); for (int i = 0; i < len; i++) if (img[i] != (uint8_t)(i * 13 + 7)) { ok = false; break; }
	CHECK(ok, "image content survives reboot");

	// Prove the fixed block is actually ENCRYPTED: drop the key material and the
	// image becomes unreadable; it only comes back after re-unlocking.
	ks_evict();
	CHECK(store_keystate() == KS_LOCKED, "evict -> LOCKED");
	CHECK(store_load() == -1, "load fails while locked (data is encrypted at rest)");
	CHECK(store_unlock_default(), "re-unlock with default");
	memset(store_image(), 0, cap);
	CHECK(store_load() == len, "load works again after unlock");
	ok = true; img = store_image(); for (int i = 0; i < len; i++) if (img[i] != (uint8_t)(i * 13 + 7)) { ok = false; break; }
	CHECK(ok, "decrypted content correct after re-unlock");

	// Update + re-persist (A/B alternation under the hood).
	for (int i = 0; i < len; i++) img[i] = (uint8_t)(i * 5 + 1);
	CHECK(store_commit(len), "commit updated image");
	memset(img, 0, cap);
	CHECK(store_load() == len, "reload updated");
	ok = true; img = store_image(); for (int i = 0; i < len; i++) if (img[i] != (uint8_t)(i * 5 + 1)) { ok = false; break; }
	CHECK(ok, "updated image round-trips");

	// Wipe.
	CHECK(store_wipe(), "wipe");
	CHECK(store_load() == -1, "fixed block blank after wipe");
	CHECK(store_init() && store_keystate() == KS_BLANK, "keystore blank after wipe");

	printf("==== %d passed, %d failed ====\n", passed, failed);
	return failed ? 1 : 0;
}
