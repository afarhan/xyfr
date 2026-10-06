//
// test_storage.cpp — ON-DEVICE acceptance test for the at-rest storage stack
// (bootblock keystore + filesystem) on REAL RP2350 flash, in the reserved
// FS region (_FS_start). Mirrors the host suites but proves the things only
// hardware shows: real flash_range erase/program, XIP reads, and — crucially —
// that the in-place NOR bit-clears (delete / mark-delivered / secure-erase) work
// AND persist across a power cycle (the multi-partial-page-program assumption).
//
// Two-phase, keyed off the bootblock state:
//   first boot (blank)  → erase region, provision, write, in-place edit, verify.
//                         then: POWER-CYCLE the device.
//   next boot (present)  → unlock, mount, verify everything survived.
//
// NOT wired by default — runs only under -DSTORAGE_DEVICE_TEST (the .ino skips
// the normal boot, so LittleFS is never mounted and the store owns the region).
//

#include <Arduino.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "rawflash.h"
#include "bootblock.h"
#include "keystore.h"
#include "filesystem.h"
#include "msg.h"      // the status bits (no msg.c calls: see below)

#define TS_PASSPHRASE "device-test-pass-77"
#define TS_CONTACT    (0x00C0FFEEull << 32)   // a contact: peer, group 0

static int ts_pass = 0, ts_fail = 0;
#define TCHECK(c, m) do { if (c) { Debug.printf("  PASS  %s\n", m); ts_pass++; } \
                          else  { Debug.printf("  FAIL  %s\n", m); ts_fail++; } } while (0)

static uint8_t TPRIV[32];
static void ts_keys(void) { for (int i = 0; i < 32; i++) TPRIV[i] = (uint8_t)(0xA0 + i); }

// Result summary, reprinted from loop() so it's capturable whenever a monitor
// connects (the on-device Serial drops output if no monitor is attached during
// the brief boot window).
static char ts_summary[160] = "test_storage: not run yet";
extern "C" void test_storage_report(void) { Debug.println(ts_summary); }

// THE TEST OWNS ITS REGION, so it talks to the filesystem directly and never
// through contacts.c/msg.c -- their lazy mount would re-mount at the real
// device's base sector and clobber the region under us.
static bool payeq(uint32_t entry, const char *exp) {
	char b[128];
	int n = file_entry_read(TS_CONTACT, entry, 0, b, sizeof b - 1);
	if (n < 0)
		return false;
	b[n] = 0;
	return strcmp(b, exp) == 0;
}

// Newest-first walk of this contact's log, skipping deleted entries.
static int ts_recent(uint32_t out[], int max) {
	int n = 0;
	uint32_t id = file_log_newest(TS_CONTACT);
	while (id != FILE_NONE && n < max) {
		struct file_entry_info info;
		if (file_entry_stat(TS_CONTACT, id, &info) &&
		    (info.flags & FILE_DELETED))
			out[n++] = id;
		id = file_log_older(TS_CONTACT, id);
	}
	return n;
}

static bool ts_delivered(uint32_t entry) {
	struct file_entry_info info;
	if (!file_entry_stat(TS_CONTACT, entry, &info))
		return false;
	return (info.flags & MSG_ST_DELIVERED) == 0;
}

// A message lives in its contact's log, so the contact file has to exist before
// anything can be written for it. Creating it is what mints the data key.
static bool ts_make_contact(void) {
	struct file_header h;
	memset(&h, 0, sizeof h);
	h.file_id   = TS_CONTACT;
	h.file_type = FILE_TYPE_CONTACT;
	return file_create(&h);
}

// Create + fill + seal, the one-shot form.
static uint32_t ts_put(const char *text, uint8_t kind, uint16_t msg_id) {
	uint16_t len = (uint16_t)strlen(text);
	uint8_t meta[FILE_META] = { kind, 0, (uint8_t)msg_id, (uint8_t)(msg_id >> 8) };
	uint32_t id = file_entry_create(TS_CONTACT, len, 0, meta);
	if (id == FILE_NONE)
		return 0;
	if (len && file_entry_write(TS_CONTACT, id, text, len) != len)
		return 0;
	if (!file_entry_commit(TS_CONTACT, id))
		return 0;
	return id;
}

static void erase_region(void) {
	uint32_t n = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	for (uint32_t s = 0; s < n; s++)
		rawflash_erase(RAWFLASH_DEV_INTERNAL, s);
}

extern "C" void test_storage(void) {
	Debug.println("\n==== test_storage (device, real flash @ _FS_start) ====");
	ts_keys();
	uint32_t nsec = rawflash_sector_count(RAWFLASH_DEV_INTERNAL);
	Debug.printf("  FS region: %u sectors (~%u KB); bootblock=%d, filesystem=%u\n",
	             (unsigned)nsec, (unsigned)(nsec * 4), (int)BOOTBLOCK_SECTORS, (unsigned)(nsec - BOOTBLOCK_SECTORS));

	ks_init();
	if (ks_state_get() == KS_BLANK) {
		// -------- FIRST BOOT: provision + write + in-place edit on real flash --------
		Debug.println("  [first boot] region blank -> erase, provision, write, edit");
		erase_region();
		ks_init();
		TCHECK(ks_provision(TPRIV), "provision keystore");
		TCHECK(ks_enable_passphrase(TS_PASSPHRASE), "enable passphrase");

		uint8_t vol[32];
		TCHECK(ks_get_volume_key(vol), "get volume key");
		TCHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BOOTBLOCK_SECTORS,
		                          nsec - BOOTBLOCK_SECTORS, vol, 1), "filesystem mount (blank)");
		TCHECK(ts_make_contact(), "test contact file (its creation mints the data key)");

		ts_put("msg one",    ENTRY_MSG_IN,  1);
		ts_put("DELETE ME",  ENTRY_MSG_IN,  2);
		ts_put("DELIVER ME", ENTRY_MSG_OUT, 1);
		ts_put("msg four",   ENTRY_MSG_IN,  3);
		TCHECK(file_storage_flush(), "flush 4 messages");

		uint32_t rs[8];
		int n = ts_recent(rs, 8);   // newest-first: four, DELIVER, DELETE, one
		TCHECK(n == 4, "recent==4 before edits");
		TCHECK(payeq(rs[0], "msg four") && payeq(rs[3], "msg one"), "payloads round-trip on real flash");
		TCHECK(file_entry_flag_clear(TS_CONTACT, rs[2], FILE_DELETED),
		       "delete DELETE ME (in-place)");
		TCHECK(file_entry_flag_clear(TS_CONTACT, rs[1], MSG_ST_DELIVERED),
		       "mark DELIVER ME delivered (in-place)");

		n = ts_recent(rs, 8);       // newest-first: four, DELIVER, one
		TCHECK(n == 3, "recent==3 after delete");
		TCHECK(ts_delivered(rs[1]), "DELIVER ME shows delivered");
		TCHECK(payeq(rs[1], "DELIVER ME"), "delivered message still reads");

		Debug.printf("  ==== FIRST BOOT: %d pass, %d fail ====\n", ts_pass, ts_fail);
		Debug.println("  >>> POWER-CYCLE the device now to verify persistence <<<");
		snprintf(ts_summary, sizeof ts_summary,
		         "test_storage FIRST BOOT: %d pass, %d fail -- power-cycle to verify persistence",
		         ts_pass, ts_fail);
	} else {
		// -------- LATER BOOT: verify everything survived the power cycle --------
		Debug.println("  [reboot] bootblock present -> unlock + verify persistence");
		TCHECK(ks_unlock_passphrase(TS_PASSPHRASE), "unlock passphrase after reboot");
		uint8_t vol[32];
		TCHECK(ks_get_volume_key(vol), "recover volume key");
		// epoch 2 = "reboot"; epoch-1 entries still decrypt via their stored epoch
		TCHECK(file_storage_mount(RAWFLASH_DEV_INTERNAL, BOOTBLOCK_SECTORS,
		                          nsec - BOOTBLOCK_SECTORS, vol, 2), "filesystem mount (recover)");

		uint32_t rs[8];
		int n = ts_recent(rs, 8);
		TCHECK(n == 3, "recent==3 survived reboot (delete held)");
		TCHECK(payeq(rs[0], "msg four"), "payload decrypts after reboot (full key chain)");
		TCHECK(ts_delivered(rs[1]), "delivered flag survived reboot (NOR bit-clear persisted)");
		uint32_t hd = file_log_newest(TS_CONTACT);
		TCHECK(hd != FILE_NONE && payeq(hd, "msg four"), "head resolves to newest live after reboot");

		Debug.printf("  ==== REBOOT PERSISTENCE: %d pass, %d fail ====\n", ts_pass, ts_fail);
		Debug.println(ts_fail == 0 ? "  >>> ALL GOOD — storage stack verified on device <<<"
		                           : "  >>> *** FAILURES — see above *** <<<");
		snprintf(ts_summary, sizeof ts_summary,
		         "test_storage PERSISTENCE: %d pass, %d fail -- %s",
		         ts_pass, ts_fail, ts_fail == 0 ? "ALL GOOD (verified on device)" : "*** FAILURES ***");
	}
}
