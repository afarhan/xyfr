// termg.h — the TERMG grid transmission format: encoder (host) + decoder (device/CLI).
//
// Deliberately dependency-free: plain arrays in, bytes out. It knows nothing
// about libvterm, the transport or the PTY, so the SAME file compiles on the device for
// the decode side and unit-tests with no network.
//
// WHY A DIFF AND NOT A FRAME DUMP: the transport is stop-and-wait over a
// relayed link, so it carries one segment per RTT. A whole 80x25 grid is 2000
// bytes and would cost several round trips; a diff of a typical edit is a few
// dozen bytes.
//
// PACING: there is none, deliberately. The caller sends whenever the window has
// room, sized to that room (see termg_build's `cap`). A fixed frame rate would
// only ADD latency on top of the RTT the link already imposes.

#pragma once

#include <stdint.h>
#include <stdbool.h>

// termg.c is plain C (it is shared verbatim with the host build); the device's
// C++ TUs need the unmangled symbols. Same convention as stream.h / contacts.h.
#ifdef __cplusplus
extern "C" {
#endif

#define TG_COLS_MAX  80
#define TG_ROWS_MAX  25
#define TG_CELLS_MAX (TG_COLS_MAX * TG_ROWS_MAX)   // 2000

// Envelope: type(1) len(2 BE) payload. Every message is length-prefixed because
// the transport delivers segments at ARBITRARY split points with no reassembly,
// so a receiver cannot otherwise tell where a message ends.
#define TG_HDR_LEN      3
#define TG_PAYLOAD_MAX  500
#define TG_MSG_MAX      (TG_HDR_LEN + TG_PAYLOAD_MAX)   // 503 -- always < the 512 window,
                                                        // so a message is never split across
                                                        // windows nor half-written in transmission.
// Opcodes
#define TG_HELLO   0x01   // H->D  cols(1) rows(1) ver(1)
#define TG_FRAME   0x02   // H->D  see below
#define TG_RESET   0x03   // H->D  cols(1) rows(1) -- geometry changed, clear
#define TG_KEYS    0x10   // D->H  raw bytes -> PTY
#define TG_RESYNC  0x11   // D->H  reason(1): 0=attach 1=desync
#define TG_SIZE    0x12   // D->H  cols(1) rows(1)

#define TG_VERSION 1

// TG_FRAME payload: flags(1) seq(1) cursor(2 BE) [top(1) bot(1) delta(i8)] runs...
// run: pos(2 BE) n(1) attr(1) chars(n)
#define TG_F_CURSOR_VIS 0x01
#define TG_F_BELL       0x02
#define TG_F_HAS_SCROLL 0x04

#define TG_CURSOR_NONE  0xFFFF

// Cell attributes -- only what a 1-bit panel can actually render.
#define TG_ATTR_REVERSE   0x01
#define TG_ATTR_BOLD      0x02
#define TG_ATTR_UNDERLINE 0x04
// Foreground colour as a 4-bit ANSI index in the spare attr bits. The ILI9488
// is RGB565, so colour is real there; the 1-bit Sharp simply ignores it. Only
// the FOREGROUND is carried -- backgrounds in a terminal are overwhelmingly
// default-or-reverse, and a second nibble would not have fit.
#define TG_ATTR_FG_SHIFT  3
#define TG_ATTR_FG_MASK   0x78
#define TG_FG_DEFAULT     7          // ANSI white == "no colour set"

// Box drawing rides a PRIVATE character range, the DEC Special Graphics trick:
// transmission stays one byte per cell instead of growing to UTF-8, and the device
// font carries 15 generated glyphs for these. Anything else non-ASCII becomes
// '?'. TG_BOX_BASE..TG_BOX_BASE+TG_BOX_COUNT-1.
#define TG_BOX_BASE  0x80
#define TG_BOX_COUNT 34

// ---------------------------------------------------------------------------
// Encoder (host)
// ---------------------------------------------------------------------------

// What the emulator currently shows. Borrowed pointers; valid for the call.
struct termg_src {
	const uint8_t *chars;      // ncells, ASCII 0x20..0x7E
	const uint8_t *attrs;      // ncells, TG_ATTR_*
	int  cols;
	int  rows;
	int  ncells;               // cols * rows
	int  cursor;               // flat index, or -1 hidden
	bool bell;
	bool has_scroll;           // hint: rows [top,bot] moved by delta (>0 = up)
	int  top;                  // first row of the moved band
	int  bot;                  // last row of the moved band
	int  delta;                // rows moved; >0 = up
};

struct termg {
	uint8_t  shadow[TG_CELLS_MAX];        // what the device is believed to show
	uint8_t  shadow_attr[TG_CELLS_MAX];
	uint16_t shadow_cursor;
	uint16_t scan_start;                  // round-robin fairness cursor
	uint8_t  seq;

	// Scratch: shadow with the scroll hint pre-applied, so build() can diff
	// against what the device WILL show without mutating shadow (which must
	// only advance on a fully-accepted message).
	uint8_t  work[TG_CELLS_MAX];
	uint8_t  work_attr[TG_CELLS_MAX];
};

void termg_init(struct termg *f);

// Forget everything the device is believed to show, so the next builds repaint
// the whole screen progressively. Used on attach and on an explicit TG_RESYNC.
void termg_resync(struct termg *f);

// Encode one message of at most `cap` bytes (cap should be min(window room,
// TG_MSG_MAX)). Returns bytes written, or 0 if there is nothing to send.
// PURE: does not touch shadow -- call termg_commit only once the bytes were
// accepted IN FULL, or the device and shadow diverge.
int termg_build(struct termg *f, const struct termg_src *src, uint8_t *out, int cap);

// Advance shadow to match a message that was accepted in full. Re-walks the
// encoded bytes, so build and commit cannot drift apart.
void termg_commit(struct termg *f, const struct termg_src *src, const uint8_t *msg, int n);

// ---------------------------------------------------------------------------
// Decoder (device / CLI client)
// ---------------------------------------------------------------------------

// Apply one TG_FRAME message to a caller-owned grid. Returns 0 on success, -1
// if the message is malformed or would write out of bounds (rejected whole --
// a partial apply would desync silently).
// `cursor` and `bell` are optional out-params.
int termg_apply(const uint8_t *msg, int n,
                uint8_t *chars, uint8_t *attrs, int ncells, int cols,
                int *cursor, bool *bell);

// Envelope helpers, shared by both ends.
int  tg_put_hdr(uint8_t *out, int cap, uint8_t type, int payload_len);
int  tg_msg_len(const uint8_t *buf, int have);   // total message size, or -1 if incomplete

#ifdef __cplusplus
}
#endif
