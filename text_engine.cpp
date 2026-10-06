// text_engine.cpp — see text_engine.h.

#include <string.h>
#include "text_engine.h"
#include "ili9488.h"

// One line band, 4bpp coverage, full panel width. 480/2 * 32 = 7,680 B — sized
// for a cell height up to 32 so a larger font drops in without a resize.
#define BAND_MAX_H   32
#define BAND_STRIDE  (ILI_W / 2)
// Canary bytes either side of the band. A clipping bug that computes a stride or
// a run length wrong writes past the end of a row and lands here; checking them
// turns "does it look right on the panel" into a definite yes/no. Cheap enough
// to leave in for the whole bring-up.
#define BAND_GUARD   64
static uint8_t band_mem[BAND_GUARD + BAND_STRIDE * BAND_MAX_H + BAND_GUARD];
static uint8_t *const band = band_mem + BAND_GUARD;

static uint32_t band_guard_fails = 0;

void text_guard_arm(void) {
	memset(band_mem, 0xA5, BAND_GUARD);
	memset(band_mem + BAND_GUARD + BAND_STRIDE * BAND_MAX_H, 0xA5, BAND_GUARD);
}

int text_guard_check(void) {
	for (int i = 0; i < BAND_GUARD; i++) {
		if (band_mem[i] != 0xA5) {
			band_guard_fails++;
			return -1;
		}
		if (band_mem[BAND_GUARD + BAND_STRIDE * BAND_MAX_H + i] != 0xA5) {
			band_guard_fails++; return 1;
		}
	}
	return 0;
}

uint32_t text_guard_fails(void) { return band_guard_fails; }

// ---- measurement ------------------------------------------------------------

int text_width_n(const tfont_t *f, const char *s, int len) {
	int w = 0;
	const unsigned char *p = (const unsigned char *)s;
	const unsigned char *e = p + len;
	while (p < e && *p) {
		int gi = tfont_index(f, tfont_utf8(&p, e));
		if (gi >= 0)
			w += f->width[gi];
	}
	return w;
}

int text_width(const tfont_t *f, const char *s) {
	return text_width_n(f, s, 0x7FFF);
}

// ---- glyph row move ---------------------------------------------------------
// The hot path, and the reason the font is stored byte-aligned. When dx is EVEN
// the source and destination nibble boundaries coincide, so it is a plain byte
// OR. When ODD each source byte straddles two destination bytes and needs a
// 4-bit shift. Both walk whole bytes; neither touches a pixel individually.

static inline void blit_row(uint8_t *dst, const uint8_t *src,
                            int dx, int skip_px, int n_px) {
	if (n_px <= 0)
		return;

	if (((dx & 1) == 0) && ((skip_px & 1) == 0)) {
		uint8_t *d = dst + (dx >> 1);
		const uint8_t *s = src + (skip_px >> 1);
		int whole = n_px >> 1;
		while (whole--)
			*d++ |= *s++;
		if (n_px & 1)
			*d |= (uint8_t)(*s & 0xF0);
		return;
	}

	for (int i = 0; i < n_px; i++) {
		int sp = skip_px + i;
		uint8_t v = (sp & 1) ? (src[sp >> 1] & 0x0F) : (uint8_t)(src[sp >> 1] >> 4);
		if (!v)
			continue;
		int dp = dx + i;
		if (dp & 1)
			dst[dp >> 1] |= v;
		else
			dst[dp >> 1] |= (uint8_t)(v << 4);
	}
}

// ---- one run of text --------------------------------------------------------
// Composes s[0..len) at pen x/y into a band spanning [cx0,cx1) and blits it.
// Everything is clipped to that span and to the panel; nothing else is touched.

// ---- the scissor -------------------------------------------------------------
//
// draw_string's rect says where text is LAID OUT. That is not always where it
// may LAND, and conflating the two is a real bug: a list row TALLER than its
// viewport has to be positioned with its top above that viewport for its lower
// half to be on screen, and the engine -- told only the rect -- faithfully
// painted the hidden lines over whatever sat above. In Xyfr that was the title
// bar, reached by opening a chat containing one very long message.
//
// So the clip is separated out. It is a hard bound on where ANY primitive may
// write, independent of the geometry it was asked to draw.
//
// Module state rather than a parameter on every entry point, deliberately:
// there is ONE panel and one drawing thread, and threading a clip through
// draw_string / text_draw / draw_rect would change every call site to serve the
// few that need it. The contract is set-draw-clear, and it is the caller's job
// to clear -- a scissor left set is invisible until something silently fails to
// paint, so treat it like a lock.
static int clip_x0 = 0;
static int clip_y0 = 0;
static int clip_x1 = ILI_W;
static int clip_y1 = ILI_H;

void text_set_clip(const trect_t *r) {
	if (!r) {
		clip_x0 = 0;
		clip_y0 = 0;
		clip_x1 = ILI_W;
		clip_y1 = ILI_H;
		return;
	}
	clip_x0 = r->x;
	clip_y0 = r->y;
	clip_x1 = r->x + r->w;
	clip_y1 = r->y + r->h;
	if (clip_x0 < 0)
		clip_x0 = 0;
	if (clip_y0 < 0)
		clip_y0 = 0;
	if (clip_x1 > ILI_W)
		clip_x1 = ILI_W;
	if (clip_y1 > ILI_H)
		clip_y1 = ILI_H;
}

static void draw_run(int x, int y, const char *s, int len, const tfont_t *f,
                     uint16_t fg, uint16_t bg, int style,
                     int cx0, int cx1, int cy0, int cy1) {
	int h = f->height;
	if (h > BAND_MAX_H)
		return;

	// The panel bound and the scissor are the same kind of limit, so they are
	// applied together: whichever is tighter wins.
	if (cx0 < clip_x0)
		cx0 = clip_x0;
	if (cx1 > clip_x1)
		cx1 = clip_x1;
	if (cy0 < clip_y0)
		cy0 = clip_y0;
	if (cy1 > clip_y1)
		cy1 = clip_y1;
	if (cx1 <= cx0 || cy1 <= cy0)
		return;

	int y0 = y, y1 = y + h;
	if (y1 <= cy0 || y0 >= cy1)
		return;
	int top_skip = (y0 < cy0) ? (cy0 - y0) : 0;
	int py       = (y0 < cy0) ? cy0 : y0;
	int vis_h    = ((y1 > cy1) ? cy1 : y1) - py;
	if (vis_h <= 0)
		return;

	int band_w = cx1 - cx0;
	int stride = (band_w + 1) / 2;
	for (int r = 0; r < vis_h; r++)
		memset(band + (size_t)r * stride, 0, stride);

	const unsigned char *p = (const unsigned char *)s;
	const unsigned char *e = p + len;
	int pen_x = x;
	while (p < e && *p) {
		int gi = tfont_index(f, tfont_utf8(&p, e));
		if (gi < 0)
			continue;
		int gw = f->width[gi];

		if (pen_x + gw > cx0 && pen_x < cx1) {
			int skip_px = (pen_x < cx0) ? (cx0 - pen_x) : 0;
			int run     = gw - skip_px;
			if (pen_x + gw > cx1)
				run -= (pen_x + gw - cx1);
			if (run > 0) {
				int dx  = (pen_x + skip_px) - cx0;
				int srb = tfont_row_bytes(f, gw);
				const uint8_t *g = f->bitmap + f->offset[gi];
				for (int r = 0; r < vis_h; r++)
					blit_row(band + (size_t)r * stride,
					         g + (size_t)(r + top_skip) * srb, dx, skip_px, run);
			}
		}
		pen_x += gw;
		if (pen_x >= cx1)
			break;
	}

	// TEXT_UNDERLINE is written INTO the band at full coverage, so it costs no
	// extra transfer and takes the text's own colour with no parameter. That is
	// why underline is a text STYLE and a row rule is not: the rule needs a
	// colour of its own, the underline cannot have one.
	if (style & TEXT_UNDERLINE) {
		int ur = tfont_underline_row(f) - top_skip;
		if (ur >= 0 && ur < vis_h) {
			int ux0 = (x     < cx0) ? cx0 : x;         // only under the glyphs,
			int ux1 = (pen_x > cx1) ? cx1 : pen_x;     // never the whole band
			uint8_t *row = band + (size_t)ur * stride;
			for (int px = ux0; px < ux1; px++) {
				int dp = px - cx0;
				if (dp & 1)
					row[dp >> 1] |= 0x0F;
				else
					row[dp >> 1] |= 0xF0;
			}
		}
	}

	ili_push_cov4(cx0, py, band_w, vis_h, band, stride, fg, bg);
}

void text_draw(int x, int y, const char *s, const tfont_t *f,
               uint16_t fg, uint16_t bg) {
	int w = text_width(f, s);
	if (w <= 0)
		return;
	int cx0 = x < 0 ? 0 : x;
	int cx1 = x + w;
	draw_run(x, y, s, 0x7FFF, f, fg, bg, 0, cx0, cx1, 0, ILI_H);
}

// ---- the one non-text primitive ---------------------------------------------

void draw_rect(int x, int y, int w, int h, uint16_t color) {
	if (w <= 0 || h <= 0)
		return;
	if (x < 0) {  // clip, never wrap — same
		w += x;
		x = 0;
	}
	if (y < 0) {  // contract as the text path
		h += y;
		y = 0;
	}
	// Same scissor as the text path -- draw_rect is the OTHER call that reaches
	// the panel, so a clip that did not cover it would leak row backgrounds over
	// the very chrome the text was clipped away from.
	if (x < clip_x0) {
		w -= clip_x0 - x;
		x = clip_x0;
	}
	if (y < clip_y0) {
		h -= clip_y0 - y;
		y = clip_y0;
	}
	if (x + w > clip_x1)
		w = clip_x1 - x;
	if (y + h > clip_y1)
		h = clip_y1 - y;
	if (w <= 0 || h <= 0)
		return;
	ili_fill_rect(x, y, w, h, color);
}

// ---- draw_string ------------------------------------------------------------

#define ELLIPSIS "..."

// Longest prefix of s[0..len) that fits in `avail`. Returns the byte count.
static int fit_chars(const tfont_t *f, const char *s, int len, int avail, int *out_w) {
	const unsigned char *b = (const unsigned char *)s;
	const unsigned char *p = b, *e = b + len;
	int w = 0;
	while (p < e && *p) {
		const unsigned char *q = p;
		int gi = tfont_index(f, tfont_utf8(&q, e));
		int gw = (gi >= 0) ? f->width[gi] : 0;
		if (w + gw > avail)
			break;
		w += gw;
		p = q;                          // advance only on a WHOLE sequence
	}
	if (out_w)
		*out_w = w;
	return (int)(p - b);
}

// Draw one already-chosen line, aligned inside [rx, rx+rw), ellipsised if asked
// and it does not fit. The band always spans the FULL rect width, so the
// background is painted here and needs no separate clear.
static void draw_one_line(const trect_t *r, int y, const char *s, int len,
                          const tfont_t *f, int style, int indent,
                          uint16_t fg, uint16_t bg, bool may_ellipsis) {
	int avail = r->w - indent;
	int w     = text_width_n(f, s, len);

	char tmp[160];
	if (may_ellipsis && (style & TEXT_ELLIPSES) && w > avail) {
		int ew = text_width(f, ELLIPSIS);
		int keep_w = 0;
		int keep = fit_chars(f, s, len, avail - ew, &keep_w);
		if (keep > (int)sizeof tmp - 4)
			keep = (int)sizeof tmp - 4;
		memcpy(tmp, s, keep);
		memcpy(tmp + keep, ELLIPSIS, sizeof ELLIPSIS);
		s = tmp; len = keep + 3; w = keep_w + ew;
	} else if (w > avail) {
		len = fit_chars(f, s, len, avail, &w);       // hard clip, no ellipsis
	}

	int x = r->x + indent;
	switch (style & ALIGN_MASK) {
		case ALIGN_CENTER: x = r->x + indent + (avail - w) / 2; break;
		case ALIGN_RIGHT:  x = r->x + indent + (avail - w);     break;
		default: break;
	}
	draw_run(x, y, s, len, f, fg, bg, style, r->x, r->x + r->w, r->y, r->y + r->h);
}

// ---- the wrap rule, once ----------------------------------------------------
// Greedy on whitespace: extend to the last space that still fits, fall back to
// it, and hard-break a single word wider than the line. The advance swallows the
// break character and any run-on spaces; `show` is what actually gets drawn.

int text_wrap_next(const tfont_t *f, const char *s, int width, int *show) {
	const unsigned char *b = (const unsigned char *)s, *q = b;
	int take = 0, w = 0, last_break = -1;

	while (*q) {
		if (*q == '\n')
			break;
		const unsigned char *q0 = q;
		uint32_t cp = tfont_utf8(&q, q + 4);
		int gi = tfont_index(f, cp);
		int gw = (gi >= 0) ? f->width[gi] : 0;
		if (w + gw > width) {
			q = q0;
			break;
		}
		w += gw;
		take = (int)(q - b);
		if (cp == ' ')
			last_break = take;
	}

	int drawn, advance;
	if (!b[take] || b[take] == '\n') {           // whole remainder fits
		drawn   = take;
		advance = take + (b[take] == '\n' ? 1 : 0);
	} else if (last_break > 0) {                  // break at the last space
		drawn   = last_break - 1;                 // drop the space itself
		advance = last_break;
	} else {                                      // one word wider than the line
		if (take > 0)  // hard-break it
			drawn = take;
		else
			drawn = 1;
		advance = drawn;
	}
	while (b[advance] == ' ')  // swallow run-on spaces
		advance++;
	if (show)
		*show = drawn;
	return advance;
}

int measure_text(const tfont_t *f, const char *s, int width, int max_h) {
	if (!s || !*s || width <= 0 || max_h <= 0)
		return 0;
	int h = f->height, y = 0;
	while (*s && y + h <= max_h) {
		int advance = text_wrap_next(f, s, width, NULL);
		if (advance <= 0)  // defensive: never spin
			break;
		s += advance;
		y += h;
	}
	return y;
}

int draw_string(const trect_t *r, const char *s, const tfont_t *f, int style,
                uint16_t fg, uint16_t bg) {
	int h = f->height;
	if (!s || !*s || r->w <= 0 || r->h <= 0)
		return 0;

	// Indent is two spaces' worth — proportional to the font rather than a magic
	// pixel count, so it scales when the font does.
	int indent0 = 0;
	if (style & TEXT_INDENT) {
		int gi = tfont_index(f, ' ');
		if ((gi >= 0))
			indent0 = f->width[gi] * 2;
		else
			indent0 = 0;
	}

	if (!(style & TEXT_MULTILINE)) {
		draw_one_line(r, r->y, s, 0x7FFF, f, style, indent0, fg, bg, true);
		if (h < r->h)
			return h;
		return r->h;
	}

	int y = r->y;
	int line_no = 0;
	const char *p = s;

	while (*p && y + h <= r->y + r->h) {
		int indent = (line_no == 0) ? indent0 : 0;
		int show = 0;
		int advance = text_wrap_next(f, p, r->w - indent, &show);
		if (advance <= 0)
			break;

		// If this is the last line that fits and text remains, ellipsise it.
		bool last_line = (y + 2 * h > r->y + r->h);
		bool more      = (p[advance] != 0);
		draw_one_line(r, y, p, show, f, style, indent, fg, bg,
		              last_line && more);

		p += advance;
		y += h;
		line_no++;
	}

	// Any rows left below the last line: one fill, so the caller's rect is fully
	// painted without a separate clear pass.
	int used = y - r->y;
	if (used < r->h)
		draw_rect(r->x, y, r->w, r->h - used, bg);
	return used;
}
