// hal_arduino.cpp — device (RP2350) backend for the non-fs HAL primitives in
// hal.h: time, debug, and the cryptographic RNG. (Files live in fs_littlefs.cpp;
// UDP will live in net_arduino.cpp.) Counterpart of the host hal_posix.c.

#include <Arduino.h>
#include <pico/rand.h>
#include "debug.h"      // the non-blocking Debug object (device branch)
#include "hal.h"

#include <stdarg.h>
#include <stdio.h>

// get_current_time_seconds() lives in ui.cpp (millis()/1000 + NTP correction).
extern "C" time_t get_current_time_seconds();

uint32_t now_ms(void)          { return millis(); }
time_t   now_seconds(void)     { return get_current_time_seconds(); }
void     hal_delay_ms(uint32_t ms) { delay(ms); }

// Verbosity floor (LOG_*). Tunable at runtime; default = emit everything.
int hal_log_level = LOG_EVERYTHING;

// Route to the non-blocking Debug object (drops, never wedges on a full Serial
// TX buffer). Format into a stack buffer since Debug has no vprintf. Gated by
// debug_level so raising hal_log_level quiets the lower-severity lines.
void hal_debug(int debug_level, const char *fmt, ...) {
	if (debug_level < hal_log_level)
		return;
	char buf[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	Debug.print(buf);
}

// RP2350 hardware RNG (the same source ui.cpp's rand() override draws from).
uint32_t hal_rand(void) { return get_rand_32(); }

// ---- scratch arena (hal.h): ONE shared static buffer, one holder at a time ----
static uint8_t hal_scratch[HAL_SCRATCH_SIZE];
static bool    hal_scratch_busy = false;
void *hal_malloc(size_t n) {
	if (hal_scratch_busy || n > HAL_SCRATCH_SIZE)  // busy or too big
		return nullptr;
	hal_scratch_busy = true;
	return hal_scratch;
}
void hal_free(void *p) {
	(void)p;                        // always the one buffer
	hal_scratch_busy = false;
}
