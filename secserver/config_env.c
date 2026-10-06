// config_env.c — the host's way to run the same binary at a different size.
//
// The portable core takes its capacities from a struct; this fills that struct
// from the environment so one build can be exercised at handheld sizes and at
// host sizes without a rebuild. Host only: the device sets its config in the
// sketch, where the numbers are a property of the board.
//
//   XYFR_MAX_FILES XYFR_STREAM_SLOTS XYFR_CALL_SLOTS XYFR_CHAT_RECORDS
//   XYFR_MISSED_REQUESTS XYFR_SCREEN_STACK XYFR_CHANNEL_RING
//
// An unset variable keeps the default. A variable that is not a positive number
// is a mistake worth stopping for, not worth guessing past.

#include "config.h"
#include "config_env.h"
#include <stdio.h>
#include <stdlib.h>

static int from_env(const char *name, int fallback) {
	const char *s = getenv(name);
	if (!s || !*s)
		return fallback;
	char *end = NULL;
	long v = strtol(s, &end, 10);
	if (*end || v <= 0) {
		fprintf(stderr, "%s=%s is not a positive number\n", name, s);
		exit(2);
	}
	return (int)v;
}

void config_from_env(void) {
	struct kernel_config cfg = *kernel_cfg;
	cfg.max_files          = from_env("XYFR_MAX_FILES",       cfg.max_files);
	cfg.stream_slots       = from_env("XYFR_STREAM_SLOTS",    cfg.stream_slots);
	cfg.call_slots         = from_env("XYFR_CALL_SLOTS",      cfg.call_slots);
	cfg.chat_records       = from_env("XYFR_CHAT_RECORDS",    cfg.chat_records);
	cfg.missed_requests    = from_env("XYFR_MISSED_REQUESTS", cfg.missed_requests);
	cfg.screen_stack       = from_env("XYFR_SCREEN_STACK",    cfg.screen_stack);
	cfg.channel_ring_bytes = from_env("XYFR_CHANNEL_RING",    cfg.channel_ring_bytes);
	if (!kernel_config_set(&cfg))
		exit(2);
	fprintf(stderr, "config: %d files, %d streams, %d calls, %d chat, %d ring\n",
	        cfg.max_files, cfg.stream_slots, cfg.call_slots,
	        cfg.chat_records, cfg.channel_ring_bytes);
}
