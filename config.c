// config.c — the live capacities, and the one allocator the core uses.
//
// The defaults are what the handheld has always had, so a build that sets
// nothing behaves exactly as it did when these were #defines. kernel_config_set
// replaces them wholesale; there is no merging, because a half-applied config
// is harder to reason about than a wrong one.
//
// Portable C, core 0.

#include "config.h"
#include "hal.h"
#include <stdlib.h>
#include <string.h>

static const struct kernel_config defaults = {
	.max_files          = 500,
	.stream_slots       = 10,
	.call_slots         = 3,
	.chat_records       = 100,
	.missed_requests    = 10,
	.screen_stack       = 6,
	.channel_ring_bytes = 10240,
	.alloc              = NULL,
};

const struct kernel_config *kernel_cfg = &defaults;

static struct kernel_config live;
static size_t alloc_total;

bool kernel_config_set(const struct kernel_config *cfg) {
	if (!cfg)
		return false;
	const struct {
		const char *name;
		int value;
	} counts[] = {
		{ "max_files",          cfg->max_files },
		{ "stream_slots",       cfg->stream_slots },
		{ "call_slots",         cfg->call_slots },
		{ "chat_records",       cfg->chat_records },
		{ "missed_requests",    cfg->missed_requests },
		{ "screen_stack",       cfg->screen_stack },
		{ "channel_ring_bytes", cfg->channel_ring_bytes },
	};
	for (unsigned i = 0; i < sizeof counts / sizeof counts[0]; i++) {
		if (counts[i].value <= 0) {
			hal_debug(LOG_CRITICAL, "config: %s is %d\n",
			          counts[i].name, counts[i].value);
			return false;
		}
	}
	live = *cfg;
	kernel_cfg = &live;
	return true;
}

void *kernel_alloc(size_t bytes) {
	void *p;
	if (kernel_cfg->alloc) {
		p = kernel_cfg->alloc(bytes);
		if (p)
			memset(p, 0, bytes);
	} else {
		p = calloc(1, bytes);
	}
	if (!p) {
		hal_debug(LOG_CRITICAL, "config: no room for %u bytes\n", (unsigned)bytes);
		return NULL;
	}
	alloc_total += bytes;
	return p;
}

size_t kernel_alloc_total(void) {
	return alloc_total;
}
