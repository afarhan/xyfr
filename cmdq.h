#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Single-producer / single-consumer byte ring used to ferry user-initiated
// contact changes from LVGL handlers on core 1 to the loop() dispatcher on
// core 0 (LittleFS access stays on core 0). Modeled on queue.cpp's
// non-blocking pattern: drops on full, returns 0 on empty.
//
// Commands are framed by a NUL ('\0'), NOT a newline — so a trailing message
// field can contain newlines (multi-line text messages). The payload is ASCII/
// UTF-8 text, which never contains a NUL. cmdq_post() strips any trailing
// newline a caller appended (legacy callers wrote "...\n") before framing.
//
// Format (ASCII, NUL-framed):
//   c+ <8hex-userid> <name>\0       add or update contact
//   c- <8hex-userid>\0              delete contact
//   cl <8hex-userid>\0              originate a call to userid
//   m+ <8hex-userid> <text>\0       send a message (text MAY contain newlines)
//   ca | cr | ce \0                 answer / refuse / end the current call
//
// In c+, the userid is redundant with the first 4 bytes of the key (see
// contact_userid()) — the dispatcher cross-checks them and rejects on
// mismatch. The trailing field (name / message text) is preserved verbatim,
// including spaces and newlines, up to the NUL.
//
// The single-letter call-control verbs (ca/cr/ce) carry no payload —
// the consumer (cmdq.cpp:dispatch_ca / dispatch_call_end) picks the
// session the user's UI button refers to: the audio-holding slot
// (session_audio_idx) for in-call actions, else the single RINGING_IN
// slot for Answer/Refuse. The "Ignore" UI button has no cmdq verb:
// it's a pure core-1 view dismiss that leaves the session to age out
// via the inactivity timer on core 0 (silent — no DATA_BYE).

// SIZED FOR OUTBOUND ONLY, and that is why 600 is enough forever. An INBOUND
// message never crosses this ferry: it arrives on core 0 over a stream and goes
// straight into the logbook, and the UI reads it back from there -- which is how
// a multi-chunk message displays in full while this line stays short. What
// crosses here is only what the user TYPED, and that is capped at 512 characters
// at the editor (view_set_input_max), so it cannot silently truncate here.
// Do not widen this to "support long messages" -- long messages already work.
#define CMDQ_SIZE     1024   // room for a full outbound message + queued commands
#define CMD_MAX_LINE  600    // max single command length (incl. the message field)
// Room a producer must reserve for the verb and its trailing space before the
// payload. Producers used to hard-code 3 ("two-character verb, then a space"),
// which is how the verb names ended up unrenameable: every line[] in the UI
// silently encoded their length. Longest verb today is "ptt-open-key" (12).
#define CMDQ_VERB_MAX 16
#define CMDQ_SEP      '\0'   // command framing byte (text payloads never contain NUL)

struct ByteQueue {
	int     head;
	int     tail;
	int     count;
	uint8_t data[CMDQ_SIZE];
};

void cmdq_init(struct ByteQueue *q);

// Producer (core 1). Frames `line` with a trailing NUL (CMDQ_SEP), stripping
// any trailing newline the caller appended first (so legacy "...\n" callers and
// multi-line message fields both work). Either the whole command lands in the
// queue or none of it does — no partial writes. Returns true on success, false
// if the queue can't fit the whole command right now.
bool cmdq_post(struct ByteQueue *q, const char *line);

// Consumer (core 0). Pops the next NUL-framed command into `out` (NUL-
// terminated). Returns the command length (0 if none buffered), or -1 if it
// exceeds out_max-1 bytes — in that case the bytes are discarded to resync.
int cmdq_pop_line(struct ByteQueue *q, char *out, size_t out_max);

// .ino glue: drains cmdq_ui_to_fs and dispatches each command. Polled
// from loop() on core 0.
void cmdq_dispatch(void);

extern struct ByteQueue cmdq_ui_to_fs;

// THE REVERSE DIRECTION of the ferry: one core-0 -> UI repaint flag, raised by
// kernel.c's screen_invalidate() and cleared by the UI when it repaints. Single
// writer, single reader; a second event before the poll is absorbed, because the
// repaint reads live data and the flag only says that something moved.
//
// It is needed because home renders from a CACHED sorted merge of contacts and
// stranger threads, rebuilt on nav-to-home: a change landing after that rebuild
// is invisible until the flag forces another one. Rebuilding on a timer instead
// would be the brute-force alternative.
extern volatile uint8_t home_needs_refresh;

#ifdef __cplusplus
}
#endif
