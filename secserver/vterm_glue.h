// vterm_glue.h — the host's terminal emulator, wrapping libvterm.
//
// WHY A LIBRARY AND NOT OUR OWN: a PTY is a pipe with a line discipline; it
// does echo, line editing and signals, but it has no screen and never
// interprets an escape sequence. Something must turn "ESC[5;1H" into a screen
// image, and since the device is a dumb cell-painter, that something lives
// here. Doing it for real xterm (256-colour SGR, the alternate screen that
// vi/less rely on, scroll regions, UTF-8) is a large job done properly, so we
// use libvterm — the emulator neovim embeds — rather than hand-rolling a
// subset and calling it an Ubuntu terminal.
//
// What this wrapper adds on top of libvterm is only what transmission needs:
//   - a flat ASCII cell grid (libvterm cells are UTF-8 codepoints + colour)
//   - collapsed damage tracking, so the differ inspects only changed cells
//   - a scroll hint, taken straight from libvterm's moverect callback
//
// Colour is deliberately dropped: the panel is 1-bit. Only what mono can show
// (reverse / bold / underline) survives into VG_ATTR_*.

#pragma once

#include <stdint.h>
#include <stdbool.h>

#define VG_COLS_MAX  80
#define VG_ROWS_MAX  25
#define VG_CELLS_MAX (VG_COLS_MAX * VG_ROWS_MAX)   // 2000

// Attribute bits — what a monochrome 6x12 cell can actually render.
#define VG_ATTR_REVERSE   0x01
#define VG_ATTR_BOLD      0x02
#define VG_ATTR_UNDERLINE 0x04

struct vterm_glue;

struct vterm_glue *vg_new(int cols, int rows);
void               vg_free(struct vterm_glue *g);

// Feed PTY output. ALWAYS consumes every byte — the emulator never applies
// backpressure, which is what makes it impossible to lose PTY output the way
// the raw-byte path did (bytes were read from the master fd and then dropped
// when the send window was full).
void vg_write(struct vterm_glue *g, const uint8_t *b, int len);

// Grid accessors. `chars` is the live grid, one ASCII byte per cell, always
// 0x20..0x7E (anything libvterm reports that we cannot draw becomes '?').
const uint8_t *vg_chars(const struct vterm_glue *g);
const uint8_t *vg_attrs(const struct vterm_glue *g);
int  vg_cols(const struct vterm_glue *g);
int  vg_rows(const struct vterm_glue *g);
int  vg_ncells(const struct vterm_glue *g);

// Cursor: flat cell index, or -1 when hidden (DECTCEM).
int  vg_cursor(const struct vterm_glue *g);

// Sticky bell, cleared by the reader.
bool vg_take_bell(struct vterm_glue *g);

// Scroll hint for the framer, straight from libvterm's moverect. Valid only if
// vg_take_scroll returns true; *delta > 0 means content moved UP by that many
// rows within rows [*top, *bot]. Consumed (cleared) by the call. Correctness
// never depends on this — it is an optimisation that lets a full-screen scroll
// cost ~50 bytes instead of ~2000; the diff in the same frame repairs any
// mismatch.
bool vg_take_scroll(struct vterm_glue *g, int *top, int *bot, int *delta);

// Resize the emulated screen (device told us its geometry changed).
void vg_resize(struct vterm_glue *g, int cols, int rows);
