// hal_posix.c — host (Linux) backend for the non-net HAL primitives in ../hal.h:
// time, debug, and the cryptographic RNG. (UDP lives in net_posix.c; files in
// fs_posix.c.) Linked into the host CLI and the host test harnesses.

#include "hal.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

// getrandom(2)/<sys/random.h> needs glibc >= 2.25. Older hosts (the deployment
// droplet is one) read /dev/urandom directly instead -- the SAME kernel CSPRNG
// via its device node, not a weaker source.
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#include <sys/random.h>
#define HAL_HAVE_GETRANDOM 1
#endif

// Monotonic milliseconds since PROCESS START. Wraps at 2^32 like the device's
// millis(); all timer math uses (int32_t)(a-b), which is only wrap-safe while
// the two operands are within 2^31 of each other. CLOCK_MONOTONIC counts from
// MACHINE boot, so on a long-uptime host it is already > 2^31 (a 829-day droplet
// read 2.94e9 ms); compared against a 0-initialised deadline the wrap-safe check
// reads "not yet" forever and pumps (e.g. the login pump) never fire. Anchoring
// to the first call keeps now_ms() near 0 at start-up -- matching the device,
// whose millis() resets every reboot -- so it stays < 2^31 for ~24.8 days of
// process uptime, which no host process reaches.
uint32_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
	static uint64_t base = 0;
	static int      inited = 0;
	if (!inited) { base = ms; inited = 1; }
	return (uint32_t)(ms - base);
}

time_t now_seconds(void) {
	return time(NULL);
}

void hal_delay_ms(uint32_t ms) {
	usleep((useconds_t)ms * 1000u);
}

// Verbosity floor (LOG_*). Tunable at runtime; default = emit everything.
int hal_log_level = LOG_EVERYTHING;

void hal_debug(int debug_level, const char *fmt, ...) {
	if (debug_level < hal_log_level) return;
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

// CSPRNG: the kernel random source (getrandom → /dev/urandom CSPRNG). This is
// what closes J-1 for the Linux relay/server/CLI — NEVER libc rand().
uint32_t hal_rand(void) {
	uint32_t v = 0;
#ifdef HAL_HAVE_GETRANDOM
	ssize_t n = getrandom(&v, sizeof(v), 0);
	if (n == (ssize_t)sizeof(v)) return v;
#endif
	// Same kernel CSPRNG through the device node; the only path on pre-2.25 glibc.
	FILE *f = fopen("/dev/urandom", "rb");
	if (f) {
		size_t got = fread(&v, 1, sizeof(v), f);
		fclose(f);
		if (got == sizeof(v)) return v;
	}
	// Both paths failed. Returning 0 here would silently feed wg.c's fill_random
	// a constant "random" stream -- colliding session ids and ephemeral keys, with
	// no visible symptom. Refuse to run instead.
	fprintf(stderr, "hal_rand: no CSPRNG available (getrandom and /dev/urandom both failed)\n");
	abort();
}

// ---- scratch arena (hal.h): host is not RAM-bound, so use the real allocator ----
void *hal_malloc(size_t n) { return malloc(n); }
void  hal_free(void *p)    { free(p); }
