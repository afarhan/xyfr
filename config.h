#pragma once
//
// config.h — the capacities the portable core is built with.
//
// Every number here is LOCAL: no peer can see it, so two builds may differ and
// still talk to each other. A number the two ends must agree on is NOT here and
// stays compile-time — FILE_INODE_DATA, FILE_ENTRY_MAX, CHANNEL_TEXT_MAX,
// STREAM_SEG_MAX and struct msg_header. Making one of those settable would turn
// it into a compatibility matrix between builds.
//
// `alloc` is how a module gets its one block, at init, never freed. NULL means
// calloc. A platform that wants its RAM in BSS instead passes an allocator that
// hands out slices of a static arena, which keeps the link-time size check; the
// core never learns which it got. Every block comes back zeroed either way,
// because the arrays these replace were zeroed by BSS and callers rely on it.

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct kernel_config {
	int max_files;           // files: contacts and channels share the cap
	int stream_slots;        // concurrent reliable streams
	int call_slots;          // concurrent calls
	int chat_records;        // the chat window's resident record metadata
	int missed_requests;     // knocks held in RAM
	int screen_stack;        // nested screens
	int channel_ring_bytes;  // a channel's scrollback ring

	void *(*alloc)(size_t bytes);
};

// What the core uses until kernel_config_set says otherwise. Never NULL, so a
// test that links one module and calls no init still reads sane numbers.
extern const struct kernel_config *kernel_cfg;

// Before kernel_init. Refuses a config with a non-positive count, keeping the
// previous one, and says which field was wrong.
bool kernel_config_set(const struct kernel_config *cfg);

// Zeroed, permanent, never freed. NULL if the platform has no room.
void *kernel_alloc(size_t bytes);

// Total handed out so far, for the boot line that says what this build costs.
size_t kernel_alloc_total(void);

#ifdef __cplusplus
}
#endif
