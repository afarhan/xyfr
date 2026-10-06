#pragma once
//
// text_engine.h — draw text by composing a whole line into one coverage band
// and blitting it once.
//
// WHY A BAND. The panel takes 3 bytes per pixel over SPI at 37.5 MHz, measured
// at 4.28 MB/s. Every transfer also pays a fixed setup (the address window is 15
// bytes of command traffic), so drawing glyph-by-glyph pays that per character.
// Composing the line in RAM and issuing ONE transfer amortises it over the whole
// string. The band is 4bpp coverage — the same layout as the font — so a glyph
// row moves with a shift-and-OR of whole bytes, never a per-pixel loop.
//
// Measured: a 421 px line is 5.88 ms, i.e. 872 us/1000px against 700 for a flat
// fill. Composition costs ~25% on top of the transfer; SPI still dominates 4:1.
//
#include <stdint.h>
#include "tfont.h"

typedef struct { int16_t x, y, w, h; } trect_t;

// Colours are RGB565 throughout; the panel expands to RGB666 at the blit.
static inline uint16_t rgb(uint8_t r, uint8_t g, uint8_t b) {
	return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

// draw_string style flags.
#define TEXT_MULTILINE  0x01   // word-wrap within the rect; else one line
#define TEXT_ELLIPSES   0x02   // append "..." when the text does not fit
#define ALIGN_LEFT      0x00
#define ALIGN_CENTER    0x04
#define ALIGN_RIGHT     0x08
#define ALIGN_MASK      0x0C
#define TEXT_INDENT     0x10   // indent the first line
#define TEXT_UNDERLINE  0x20   // underline the text itself

// A flat rectangle. The one non-text thing the engine draws, and the reason it
// exists here rather than in the caller: it keeps the panel API out of the
// layers above, so `draw_rect` + the coverage-band push are the ONLY two calls
// that touch hardware. A port reimplements those two and nothing else.
//
// x/y may be negative or off-panel; the rect is clipped, never wrapped. Signed
// on purpose — the whole engine allows off-screen coordinates, and an unsigned
// x would turn -4 into 65532 and drop the rect instead of clipping it.
void draw_rect(int x, int y, int w, int h, uint16_t color);

// Pixel width of `s` (whole string, or the first `len` bytes). ASCII; codepoints
// outside the font are skipped.
int text_width(const tfont_t *f, const char *s);
int text_width_n(const tfont_t *f, const char *s, int len);

// Draw `s` with its LEFT edge at x and TOP at y, clipped hard to the panel. x/y
// may be negative or past the edge; anything outside is dropped at a pixel
// boundary, never wrapped. A fully off-screen string draws nothing.
void text_draw(int x, int y, const char *s, const tfont_t *f,
               uint16_t fg, uint16_t bg);

// THE WRAP RULE, once. Advances ONE wrapped line of `s` at `width` pixels and
// returns the bytes consumed (0 at the end of the string); *show, if given, is
// how many of those bytes to DRAW -- it excludes the space or newline the break
// happened on, and the run-on spaces the advance swallows.
//
// draw_string and measure_text are both built on this, deliberately: a measure
// that carried its own copy of the greedy-on-whitespace rule would agree with
// the renderer right up until one of them was edited.
int text_wrap_next(const tfont_t *f, const char *s, int width, int *show);

// MEASURE WITHOUT DRAWING. The height `s` occupies wrapped to `width`, stopping
// once another line would exceed `max_h` -- the same cutoff draw_string applies,
// so a rect of the returned height renders exactly these lines and no more.
//
// Deliberately knows nothing about colour, alignment or ellipsis: none of them
// change the answer. The one flag that would is TEXT_INDENT, which narrows the
// first line and can therefore move a break; no caller uses it on a wrapped
// string today, so it is not a parameter. Add one if that changes.
int measure_text(const tfont_t *f, const char *s, int width, int max_h);

// THE WORKHORSE. Renders `s` inside `r`, honouring the style flags. Every line
// is composed and blitted as one full-rect-width band, so the background is
// painted as a side effect and needs no separate clear; any rows left below the
// last line are filled once at the end.
//
// Returns the pixel height actually used (<= r->h).
//
// Wrapping is greedy on whitespace. A single word wider than the rect is broken
// at the last character that fits and continues on the next line — the same rule
// the editor's reflow uses, so wrapped display and wrapped editing agree.
// THE SCISSOR. A hard bound on where any primitive may write, independent of the
// geometry it was handed.
//
// draw_string's rect says where text is LAID OUT; it does not say where the text
// may LAND. Those are usually the same and the distinction never came up -- until
// a list row TALLER than its viewport, which must be positioned with its top
// ABOVE the viewport for its lower half to be visible. Told only the rect, the
// engine correctly painted the hidden lines, over whatever was above (a title
// bar). Clamping the rect instead would not do: that stops the row scrolling.
//
// Set it, draw, clear it (NULL restores the full panel). Clearing is the
// caller's job; a scissor left set is invisible until something quietly fails to
// paint, so treat it like a lock. Covers both hardware paths -- text and
// draw_rect.
void text_set_clip(const trect_t *r);

int draw_string(const trect_t *r, const char *s, const tfont_t *f, int style,
                uint16_t fg, uint16_t bg);

// Bring-up self-check: arm canaries around the compose band, then verify after
// drawing. 0 = intact, -1 = wrote before the band, +1 = wrote past it.
void     text_guard_arm(void);
int      text_guard_check(void);
uint32_t text_guard_fails(void);
