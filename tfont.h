#pragma once
//
// tfont.h — the text engine's font table.
//
// Produced by tools/lvfont2tfont.py from an LVGL generated font. LVGL stays the
// SOURCE of glyphs (its .c files ship with the library and the conversion is
// pixel-exact), but the storage layout is changed to the one the blitter wants:
//
//   * every glyph the SAME height (a uniform cell), so vertical placement is a
//     straight row copy instead of per-glyph offset arithmetic
//   * each glyph row padded to a BYTE BOUNDARY, so a row can be moved with a
//     shift-and-OR of whole bytes rather than extracting pixels one at a time
//
// LVGL's own layout has neither: glyphs are tight boxes with offsets, and rows
// are packed contiguously (row `py` starts at bit py*box_w*bpp), so at 4bpp a
// row lands on a byte boundary only when box_w happens to be even.
//
// bpp is 4: Montserrat is a fine-stroked geometric sans and thresholding it to
// 1bpp breaks the thin strokes. Coverage also makes "bold" work as a brighter
// colour rather than needing a second table.
//
#include <stdint.h>

typedef struct {
	uint8_t  height;          // uniform cell height, rows
	uint8_t  base;            // baseline, rows up from the cell BOTTOM
	uint8_t  bpp;             // 1 or 4
	uint8_t  first;           // first codepoint of the dense block (0x20)
	uint8_t  count;           // glyphs in the dense block (95 = ASCII)
	uint16_t sym_count;       // glyphs in the SPARSE block that follows it
	const uint16_t *sym_cp;   // their codepoints, ASCENDING (NULL if none)
	const uint8_t  *bitmap;   // row-major, rows padded to a byte boundary
	const uint16_t *offset;   // per-glyph byte offset into bitmap
	const uint8_t  *width;    // per-glyph cell width in pixels (== advance)
} tfont_t;

// Bytes per glyph row for a given cell width.
static inline int tfont_row_bytes(const tfont_t *f, int w) {
	return (w * f->bpp + 7) / 8;
}

// The widest glyph in the font. A single-line field is bounded by a CHARACTER
// count, not a pixel width -- a pixel cap on a proportional face would hold 28
// of '1' and 18 of 'W', so "this field takes an IP address" could not be stated
// as a fact. The caller sizes the field so that max_len * this <= its width, and
// then no input can ever overflow it whatever the user types. Checking that at
// the point the field is DECLARED turns a layout mistake into a startup warning
// instead of a caret that silently walks off the end.
// The DENSE block only, deliberately: the sparse tier is the LV_SYMBOL_* icons,
// which are rendered but can never be TYPED -- the matrix keyboard emits ASCII,
// which is the same fact that lets the editor stay byte-oriented. Including them
// would raise the answer from 16 to 18 (the wifi glyph) and falsely condemn the
// 29-character contact-name field: 29*18 = 522 > 468, where 29*16 = 464 fits.
static inline int tfont_max_width(const tfont_t *f) {
	int mx = 0;
	for (int i = 0; i < (int)f->count; i++) {
		if (f->width[i] > mx)
			mx = f->width[i];
	}
	return mx;
}

// The row an underline sits on: one below the last row a non-descending glyph
// can reach, so it clears the baseline and still leaves the cell's own descender
// rows as spacing. Font-relative on purpose — a fixed "second row from the
// bottom" is right for one size and wrong for the next (mont14 base 3, mont10
// base 2), which is why `base` is carried at all.
static inline int tfont_underline_row(const tfont_t *f) {
	return f->height - f->base;
}

// Glyph index for a codepoint, or -1 if the font has no such glyph.
//
// TWO TIERS. ASCII is a dense block indexed by subtraction — the hot path, one
// compare and one subtract, unchanged from before. The LV_SYMBOL_* icons are
// SPARSE (62 codepoints scattered through U+00B0..U+F8FF), so they get a binary
// search over ~6 steps. Keeping them out of the dense block is what stops a
// 63,000-entry range from becoming a 63,000-entry table.
static inline int tfont_index(const tfont_t *f, uint32_t cp) {
	if (cp >= f->first && cp < (uint32_t)(f->first + f->count))
		return (int)(cp - f->first);
	if (!f->sym_cp || cp > 0xFFFF)
		return -1;
	int lo = 0, hi = (int)f->sym_count - 1;
	while (lo <= hi) {
		int mid = (lo + hi) >> 1;
		uint32_t v = f->sym_cp[mid];
		if (v == cp)
			return (int)f->count + mid;
		if (v < cp)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	return -1;
}

// Decode one UTF-8 sequence, advancing *p past it. A malformed lead or a broken
// continuation consumes exactly ONE byte and returns it, so bad input can never
// stall a loop or read past `end` — the decoder is a text renderer's, not a
// validator's. (LV_SYMBOL_* strings are already UTF-8; this is what reads them.)
static inline uint32_t tfont_utf8(const unsigned char **p, const unsigned char *end) {
	const unsigned char *s = *p;
	unsigned char c = s[0];
	uint32_t cp;
	int n;
	if (c < 0x80) {
		*p = s + 1;
		return c;
	}
	else if ((c & 0xE0) == 0xC0) {
		n = 1;
		cp = c & 0x1Fu;
	}
	else if ((c & 0xF0) == 0xE0) {
		n = 2;
		cp = c & 0x0Fu;
	}
	else if ((c & 0xF8) == 0xF0) {
		n = 3;
		cp = c & 0x07u;
	}
	else {
		*p = s + 1;
		return c;
	}
	if (s + n >= end) {
		*p = s + 1;
		return c;
	}
	for (int i = 1; i <= n; i++) {
		if ((s[i] & 0xC0) != 0x80) {
			*p = s + 1;
			return c;
		}
		cp = (cp << 6) | (uint32_t)(s[i] & 0x3F);
	}
	*p = s + n + 1;
	return cp;
}
