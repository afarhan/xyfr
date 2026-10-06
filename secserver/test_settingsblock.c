//
// test_fixedblock.c — HOST test for the multi-sector A/B image store
// (settingsblock.c over the rawflash file backend). Proves: blank load, small +
// multi-sector-spanning payloads round-trip, A/B alternation with newest-seq
// wins, persistence across a re-init ("reboot"), power-loss atomicity (a torn
// write leaves the PRIOR image intact), and erase_all.
//
// Build/run: cd secserver && make settingsblock_test && ./settingsblock_test
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "rawflash.h"
#include "settingsblock.h"

extern int rawflash_test_fail_after_pages;   // rawflash_posix fault injection (one-shot)

static int passed = 0, failed = 0;
#define CHECK(c, m) do { if (c) { printf("  PASS  %s\n", m); passed++; } \
                         else  { printf("  FAIL  %s\n", m); failed++; } } while (0)

#define BASE        2
#define SLOT_SECS   3           // 12 KB per slot, A/B = 6 sectors

static void fill(uint8_t *b, uint32_t n, uint8_t seed) { for (uint32_t i = 0; i < n; i++) b[i] = (uint8_t)(seed * 31 + i * 7); }
static bool same(const uint8_t *b, uint32_t n, uint8_t seed) { for (uint32_t i = 0; i < n; i++) if (b[i] != (uint8_t)(seed * 31 + i * 7)) return false; return true; }

int main(void) {
	unlink("fsroot/rawflash.img");
	printf("==== settingsblock host test ====\n");

	CHECK(settingsblock_init(RAWFLASH_DEV_INTERNAL, BASE, SLOT_SECS), "init");
	CHECK(settingsblock_max_payload() == SLOT_SECS * 4096u - 16u, "max_payload = slot*4096 - frame");

	uint8_t wbuf[16000], rbuf[16000];

	// blank region
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == -1, "load on blank region -> -1");

	// small payload round-trip
	fill(wbuf, 200, 1);
	CHECK(settingsblock_save(wbuf, 200), "save small");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 200 && same(rbuf, 200, 1), "load small round-trips");

	// payload spanning multiple sectors (8 KB > 1 sector, < slot)
	fill(wbuf, 8000, 2);
	CHECK(settingsblock_save(wbuf, 8000), "save multi-sector (8 KB)");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 8000 && same(rbuf, 8000, 2), "load multi-sector round-trips");

	// near-max payload
	uint32_t mx = settingsblock_max_payload();
	fill(wbuf, mx, 3);
	CHECK(settingsblock_save(wbuf, (int)mx), "save near-max payload");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == (int)mx && same(rbuf, mx, 3), "load near-max round-trips");
	CHECK(!settingsblock_save(wbuf, (int)mx + 1), "over-max payload rejected");

	// A/B alternation: several saves; newest always wins, persists across re-init
	for (int i = 0; i < 5; i++) { fill(wbuf, 1000 + i, (uint8_t)(10 + i)); CHECK(settingsblock_save(wbuf, 1000 + i), "save iter"); }
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 1004 && same(rbuf, 1004, 14), "newest-seq wins after alternation");

	// "reboot": re-init and confirm the newest image survives
	CHECK(settingsblock_init(RAWFLASH_DEV_INTERNAL, BASE, SLOT_SECS), "re-init (reboot)");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 1004 && same(rbuf, 1004, 14), "image persists across re-init");

	// Power-loss atomicity: a torn write must leave the PRIOR image intact.
	fill(wbuf, 2222, 99);
	rawflash_test_fail_after_pages = 1;        // fail mid-program of the inactive slot
	bool torn = settingsblock_save(wbuf, 2222);
	CHECK(!torn, "torn save reports failure");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 1004 && same(rbuf, 1004, 14), "prior image intact after torn write");

	// A clean save after the torn one still works (writes the other/again).
	CHECK(settingsblock_save(wbuf, 2222), "clean save after torn write");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == 2222 && same(rbuf, 2222, 99), "new image after recovery");

	// erase_all wipes everything
	CHECK(settingsblock_erase_all(), "erase_all");
	CHECK(settingsblock_load(rbuf, sizeof rbuf) == -1, "load -1 after erase_all");

	printf("==== %d passed, %d failed ====\n", passed, failed);
	return failed ? 1 : 0;
}
