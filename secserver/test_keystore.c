//
// test_keystore.c — HOST simulation of the at-rest key schedule (keystore.c +
// bootblock.c) over the file-backed bootflash_posix backend. Proves the full
// lifecycle on Linux before any device flash code runs:
//   provision -> contact keys -> enable passphrase -> power cycle -> cold unlock
//   -> session PIN lock/unlock -> change passphrase -> A/B torn-write recovery
//   -> crypto-erase wipe.
// Also reads the raw image file to verify, independently of the API, that
// secrets are not sitting in cleartext.
//
// Build/run: cd secserver && make keystore_test && ./keystore_test
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include "keystore.h"
#include "bootblock.h"
#include "hal.h"

extern int bootflash_test_truncate_next;   // fault injection in bootflash_posix.c

// wg.c references these (defined per-binary); no handshake here, so stubs.
int validate_public_key(const uint8_t *pk, void *ctx) { (void)pk; (void)ctx; return 1; }
time_t get_current_time_seconds(void) { return now_seconds(); }

static int passed = 0, failed = 0;
#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS  %s\n", msg); passed++; } \
	else      { printf("  FAIL  %s\n", msg); failed++; } \
} while (0)

// Scan the raw image file for a byte pattern (independent "is it encrypted?" check).
static bool image_contains(const uint8_t *needle, int n) {
	FILE *f = fopen("fsroot/bootblock.img", "rb");
	if (!f) return false;
	static uint8_t buf[2 * ZB_SECTOR_SIZE];
	size_t got = fread(buf, 1, sizeof buf, f);
	fclose(f);
	if (got < (size_t)n) return false;
	for (size_t i = 0; i + n <= got; i++)
		if (memcmp(buf + i, needle, n) == 0) return true;
	return false;
}

int main(void) {
	unlink("fsroot/bootblock.img");   // fresh device every run

	uint8_t priv[32], vol1[32], out[32];
	for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(0xA0 + i);

	const char *PASS = "correct horse battery staple";
	const char *PASS2 = "trombone marigold velvet anchor";
	const char *PIN  = "zt7q9p";

	printf("==== keystore host simulation ====\n");

	// --- blank -> provision ---
	CHECK(ks_init(), "ks_init on blank device");
	CHECK(ks_state_get() == KS_BLANK, "fresh device is BLANK");
	CHECK(ks_provision(priv), "provision");
	CHECK(ks_state_get() == KS_NOENC, "after provision: NOENC (encryption off)");
	CHECK(ks_get_private_key(out) && memcmp(out, priv, 32) == 0, "private key round-trips");
	CHECK(ks_get_volume_key(vol1), "read volume key");

	// independent: the private key is wrapped (absent in cleartext) even in NOENC,
	// but the volume key IS plaintext on flash (encryption off).
	CHECK(!image_contains(priv, 32), "NOENC: private key NOT in cleartext on flash");
	CHECK(image_contains(vol1, 32),  "NOENC: volume key IS plaintext on flash (enc off)");

	// --- enable passphrase (encryption ON) ---
	CHECK(ks_enable_passphrase(PASS), "enable passphrase");
	CHECK(ks_state_get() == KS_UNLOCKED, "after enable: UNLOCKED");
	CHECK(ks_get_private_key(out) && memcmp(out, priv, 32) == 0, "private key still readable (volkey in RAM)");
	CHECK(!image_contains(vol1, 32), "ENC: plaintext volume key REMOVED from flash");
	CHECK(!image_contains(priv, 32), "ENC: private key still not in cleartext");

	// --- power cycle: drop RAM, reload from flash ---
	ks_test_reset_ram();
	CHECK(ks_init(), "re-init after power cycle");
	CHECK(ks_state_get() == KS_LOCKED, "after power cycle: LOCKED (need passphrase)");
	CHECK(!ks_get_private_key(out), "locked: no key access");

	CHECK(!ks_unlock_passphrase("wrong passphrase here now"), "wrong passphrase rejected");
	CHECK(ks_state_get() == KS_LOCKED, "still LOCKED after wrong passphrase");
	CHECK(ks_fail_count() == 1, "failed attempt counted");
	CHECK(ks_unlock_passphrase(PASS), "correct passphrase unlocks");
	CHECK(ks_state_get() == KS_UNLOCKED, "now UNLOCKED");
	CHECK(ks_get_private_key(out) && memcmp(out, priv, 32) == 0, "private key recovered across reboot");
	CHECK(ks_fail_count() == 0, "fail count reset on success");

	// --- session PIN lock/unlock ---
	CHECK(ks_set_pin(PIN), "set session PIN");
	CHECK(ks_lock_session(), "screen-lock (wrap volkey under PIN)");
	CHECK(ks_state_get() == KS_SESSION, "SESSION-locked");
	CHECK(!ks_get_private_key(out), "session-locked: no key access");
	CHECK(!ks_get_volume_key(out), "session-locked: volume key not in RAM");
	CHECK(!ks_unlock_pin("000000"), "wrong PIN rejected");
	CHECK(ks_unlock_pin(PIN), "correct PIN unlocks session");
	CHECK(ks_state_get() == KS_UNLOCKED && ks_get_private_key(out) && memcmp(out, priv, 32) == 0,
	      "private key back after PIN unlock");

	// --- change passphrase ---
	CHECK(!ks_change_passphrase("not the old one", PASS2), "change rejects wrong old passphrase");
	CHECK(ks_change_passphrase(PASS, PASS2), "change passphrase");
	ks_test_reset_ram();
	ks_init();
	CHECK(!ks_unlock_passphrase(PASS),  "old passphrase no longer works");
	CHECK(ks_unlock_passphrase(PASS2),  "new passphrase works");
	CHECK(ks_get_private_key(out) && memcmp(out, priv, 32) == 0, "key intact after passphrase change");

	// --- A/B torn-write recovery (power loss mid-save) ---
	{
		bootflash_test_truncate_next = 40;            // next program writes only 40 bytes then "power loss"
		bool saved = ks_change_passphrase(PASS2, PASS);   // re-wrap back to PASS, torn mid-save
		CHECK(!saved, "torn write reports failure");
		ks_test_reset_ram();
		ks_init();
		CHECK(ks_state_get() == KS_LOCKED, "after torn write + reboot: LOCKED (prior image survived)");
		CHECK(!ks_unlock_passphrase(PASS),  "torn passphrase change did NOT persist");
		CHECK(ks_unlock_passphrase(PASS2),  "prior passphrase still works after torn write");
		CHECK(ks_get_private_key(out) && memcmp(out, priv, 32) == 0, "key intact after torn write");
	}

	// --- crypto-erase wipe ---
	ks_wipe();
	CHECK(ks_state_get() == KS_BLANK, "after wipe: BLANK");
	ks_test_reset_ram();
	ks_init();
	CHECK(ks_state_get() == KS_BLANK, "wipe persists across reboot");
	CHECK(!ks_unlock_passphrase(PASS2), "no unlock after wipe");

	printf("==== %d passed, %d failed ====\n", passed, failed);
	return failed ? 1 : 0;
}
