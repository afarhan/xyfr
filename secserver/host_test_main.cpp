// host_test_main.cpp — Linux driver for the SHARED test_contacts() acceptance
// test. Runs the device's verbatim contacts.cpp + test_contacts.cpp against the
// POSIX fs backend (fs_posix.c, rooted at ./fsroot) — proving the fs HAL on host
// and giving us test_contacts() under gdb/valgrind/ASan. Same test, both targets.

#include <ctime>
#include "debug.h"   // host-aware: provides the host DebugClass (printf→stdout)
#include "hal.h"     // now_seconds()
#include "secure_store.h"   // the keystore bring-up contacts.c needs

DebugClass Debug;    // the one definition of the host Debug object

// test_contacts.cpp (shared) still calls get_current_time_seconds(); map it to
// the host time HAL.
extern "C" time_t get_current_time_seconds(void) { return now_seconds(); }

// The stamp clock lives in kernel.c, which this test does not link. Same logic:
// a stamp is strictly above every one seen or issued, so entries created inside
// one second still sort by the order they were written.
static uint32_t stamp_floor;

extern "C" void kernel_time_seen(uint32_t stamp) {
	if (stamp > stamp_floor)
		stamp_floor = stamp;
}

extern "C" uint32_t kernel_time_mint(void) {
	uint32_t stamp = (uint32_t)get_current_time_seconds();
	if (stamp <= stamp_floor)
		stamp = stamp_floor + 1;
	stamp_floor = stamp;
	return stamp;
}

extern "C" void test_contacts();   // C linkage: contacts.h wraps it

// wg.c references validate_public_key (defined per-binary, not in wg.c). The
// contacts test never runs a handshake, so this is an unused link stub.
extern "C" int validate_public_key(const uint8_t *public_key, void *ctx) { (void)public_key; (void)ctx; return 1; }

// contacts.c reaches the network and the screen; this test exercises neither, so
// these are link stubs. They exist because contacts.c owns the lookup pump as
// well as the CRUD -- see the note on contact_query_pump.
extern "C" {
void netif_addr_from_ip4(uint8_t *addr, int *addr_len, uint32_t ip4, uint16_t port) {
	(void)addr; (void)ip4; (void)port;
	if (addr_len)
		*addr_len = 0;
}
bool netif_addr_to_ip4(const uint8_t *addr, int addr_len, uint32_t *ip4, uint16_t *port) {
	(void)addr; (void)addr_len; (void)ip4; (void)port;
	return false;
}
bool remote_query(const uint8_t *key) { (void)key; return false; }
void registration_query_answer(const uint8_t key[32], int status) { (void)key; (void)status; }
void screen_invalidate(void) { }
int  wifi_get_status(void) { return 0; }
}

int main(void) {
	// contacts.c mounts the filesystem under the keystore's volume key, so the
	// keystore has to exist before a single contact can be saved. On device this
	// happens in kernel_init; here it is the test's job.
	static const uint8_t TEST_PRIV[32] = {
		0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
		0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF,
	};
	store_init();
	if (store_keystate() == KS_BLANK)
		store_provision(TEST_PRIV);
	if (!store_unlocked())
		store_unlock_default();

	test_contacts();
	return 0;
}
