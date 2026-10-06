// termg.c - the TERMG grid protocol. See termg.h for the design rationale.

#include "termg.h"
#include <string.h>

// The fixed part of a TG_FRAME payload, past the 3-byte header: flags(1),
// seq(1), cursor(2), and the scroll triple (top, bot, delta) when present.
#define TG_FIXED_LEN   4
#define TG_SCROLL_LEN  3

// One run: position(2), length(1), attribute(1), then `length` character bytes.
#define TG_RUN_HDR_LEN 4
#define TG_RUN_MAX     255   // the run length is a u8

// Clean cells a run may swallow before ending it. Merging across k clean cells
// costs k characters and saves one run header, so it pays while k < 4.
#define TG_RUN_MERGE_GAP 3

// ---- envelope -------------------------------------------------------------

int tg_put_hdr(uint8_t *out, int cap, uint8_t type, int payload_len)
{
	if (cap < TG_HDR_LEN)
		return -1;
	out[0] = type;
	out[1] = (uint8_t)(payload_len >> 8);
	out[2] = (uint8_t)(payload_len & 0xFF);
	return TG_HDR_LEN;
}

int tg_msg_len(const uint8_t *buf, int have)
{
	if (have < TG_HDR_LEN)
		return -1;
	int payload = ((int)buf[1] << 8) | buf[2];
	if (payload < 0 || payload > TG_PAYLOAD_MAX)
		return -1;
	return TG_HDR_LEN + payload;
}

// ---- shared: apply a scroll to a grid -------------------------------------

// Move rows [top,bot] by `delta` (>0 = content moves up), blanking what scrolls
// in. Used identically on the host's shadow and the device's grid, so the two
// stay in step, which is the whole point of sending a scroll op instead of
// a screenful of re-sent text.
static void grid_scroll(uint8_t *chars, uint8_t *attrs, int cols,
                        int top, int bot, int delta)
{
	if (delta == 0)
		return;
	int n = bot - top + 1;
	if (n <= 0)
		return;
	if (delta >= n || -delta >= n) {                 // scrolled entirely away
		memset(chars + (size_t)top * cols, ' ', (size_t)n * cols);
		memset(attrs + (size_t)top * cols, 0,   (size_t)n * cols);
		return;
	}
	if (delta > 0) {
		int move = n - delta;
		memmove(chars + (size_t)top * cols,
		        chars + (size_t)(top + delta) * cols, (size_t)move * cols);
		memmove(attrs + (size_t)top * cols,
		        attrs + (size_t)(top + delta) * cols, (size_t)move * cols);
		memset(chars + (size_t)(top + move) * cols, ' ', (size_t)delta * cols);
		memset(attrs + (size_t)(top + move) * cols, 0,   (size_t)delta * cols);
	} else {
		int d = -delta;
		int move = n - d;
		memmove(chars + (size_t)(top + d) * cols,
		        chars + (size_t)top * cols, (size_t)move * cols);
		memmove(attrs + (size_t)(top + d) * cols,
		        attrs + (size_t)top * cols, (size_t)move * cols);
		memset(chars + (size_t)top * cols, ' ', (size_t)d * cols);
		memset(attrs + (size_t)top * cols, 0,   (size_t)d * cols);
	}
}

// Is this scroll hint usable against a grid of these dimensions?
static bool scroll_ok(const struct termg_src *s)
{
	if (!s->has_scroll)
		return false;
	if (s->top < 0 || s->bot >= s->rows || s->top > s->bot)
		return false;
	if (s->delta == 0)
		return false;
	return true;
}

// ---- encoder --------------------------------------------------------------

void termg_init(struct termg *f)
{
	memset(f, 0, sizeof *f);
	memset(f->shadow, ' ', sizeof f->shadow);
	f->shadow_cursor = TG_CURSOR_NONE;
	f->scan_start = 0;
}

void termg_resync(struct termg *f)
{
	// 0x00 is never a valid cell (cells are 0x20..0x7E), so every cell compares
	// unequal and the differ repaints the screen progressively. No special
	// "full frame" opcode is needed -- which is good, because a full frame
	// could not fit one window anyway.
	memset(f->shadow, 0, sizeof f->shadow);
	memset(f->shadow_attr, 0xFF, sizeof f->shadow_attr);
	f->shadow_cursor = TG_CURSOR_NONE;
	f->scan_start = 0;
}

// Emit runs over [from,to) of the work grid, appending to out. Returns bytes
// written; stops cleanly when the cap is reached (the rest stays dirty and is
// re-offered next call, merged with anything newer).
static int emit_runs(struct termg *f, const struct termg_src *s,
                     int from, int to, uint8_t *out, int cap, int *last_end)
{
	int used = 0;
	int i = from;
	while (i < to) {
		if (s->chars[i] == f->work[i] && s->attrs[i] == f->work_attr[i]) {
			i++;
			continue;
		}

		int start = i;
		uint8_t attr = s->attrs[i];
		int end = i;                       // last differing cell in this run
		int j = i;
		while (j < to) {
			if (s->attrs[j] != attr)  // an attribute change ends the run
				break;
			if (s->chars[j] != f->work[j] || s->attrs[j] != f->work_attr[j]) {
				end = j;
			} else if (j - end > TG_RUN_MERGE_GAP) {
				break;
			}
			if (end - start + 1 >= TG_RUN_MAX)
				break;
			j++;
		}
		int n = end - start + 1;
		if (n > TG_RUN_MAX)
			n = TG_RUN_MAX;

		int need = TG_RUN_HDR_LEN + n;
		if (used + need > cap) {
			// Not enough room for the whole run. Shorten it if a useful piece
			// fits; otherwise stop, and never emit a truncated run.
			int avail = cap - used - TG_RUN_HDR_LEN;
			if (avail < 1)
				break;
			n = avail;
		}
		out[used++] = (uint8_t)(start >> 8);
		out[used++] = (uint8_t)(start & 0xFF);
		out[used++] = (uint8_t)n;
		out[used++] = attr;
		memcpy(out + used, s->chars + start, (size_t)n);
		used += n;
		*last_end = start + n;
		i = start + n;
		if (used >= cap)
			break;
	}
	return used;
}

int termg_build(struct termg *f, const struct termg_src *src, uint8_t *out, int cap)
{
	if (cap > TG_MSG_MAX)
		cap = TG_MSG_MAX;
	int ncells = src->ncells;
	if (ncells <= 0 || ncells > TG_CELLS_MAX)
		return 0;

	bool use_scroll = scroll_ok(src);
	int fixed = TG_HDR_LEN + TG_FIXED_LEN;
	if (use_scroll)
		fixed += TG_SCROLL_LEN;
	if (cap < fixed + TG_RUN_HDR_LEN + 1)  // no room for even a 1-cell run
		return 0;

	// Build the view the device will have: shadow + the scroll we are about to
	// send. Diffing against this rather than the raw shadow is what makes the
	// scroll op safe: if the prediction is wrong, the runs in this same message
	// fix it.
	memcpy(f->work,      f->shadow,      (size_t)ncells);
	memcpy(f->work_attr, f->shadow_attr, (size_t)ncells);
	if (use_scroll)
		grid_scroll(f->work, f->work_attr, src->cols, src->top, src->bot, src->delta);

	uint16_t cursor = TG_CURSOR_NONE;
	if (src->cursor >= 0 && src->cursor < ncells)
		cursor = (uint16_t)src->cursor;

	// Nothing to say? Then say nothing: an idle screen costs zero bytes, which
	// is what lets a user read for ten minutes on a 512-byte window.
	bool cursor_moved = (cursor != f->shadow_cursor);
	bool any_dirty = false;
	for (int i = 0; i < ncells; i++) {
		if (src->chars[i] != f->work[i] || src->attrs[i] != f->work_attr[i]) {
			any_dirty = true;
			break;
		}
	}
	if (!any_dirty && !cursor_moved && !src->bell && !use_scroll)
		return 0;

	int used = fixed;
	int last_end = -1;

	// Round-robin from scan_start so a screen that churns at the top can never
	// starve the bottom rows: [scan_start,ncells) then [0,scan_start).
	int start = f->scan_start;
	if (start >= ncells)
		start = 0;
	used += emit_runs(f, src, start, ncells, out + used, cap - used, &last_end);
	if (used < cap)
		used += emit_runs(f, src, 0, start, out + used, cap - used, &last_end);

	int payload = used - TG_HDR_LEN;
	tg_put_hdr(out, cap, TG_FRAME, payload);
	uint8_t flags = 0;
	if (cursor != TG_CURSOR_NONE)
		flags |= TG_F_CURSOR_VIS;
	if (src->bell)
		flags |= TG_F_BELL;
	if (use_scroll)
		flags |= TG_F_HAS_SCROLL;
	uint8_t *fixed_part = out + TG_HDR_LEN;
	fixed_part[0] = flags;
	fixed_part[1] = f->seq;
	fixed_part[2] = (uint8_t)(cursor >> 8);
	fixed_part[3] = (uint8_t)(cursor & 0xFF);
	if (use_scroll) {
		uint8_t *scroll = fixed_part + TG_FIXED_LEN;
		scroll[0] = (uint8_t)src->top;
		scroll[1] = (uint8_t)src->bot;
		scroll[2] = (uint8_t)(int8_t)src->delta;
	}
	return used;
}

void termg_commit(struct termg *f, const struct termg_src *src, const uint8_t *msg, int n)
{
	if (n < TG_HDR_LEN + TG_FIXED_LEN || msg[0] != TG_FRAME)
		return;
	int payload = ((int)msg[1] << 8) | msg[2];
	if (payload != n - TG_HDR_LEN)
		return;

	uint8_t flags = msg[TG_HDR_LEN];
	uint16_t cursor = (uint16_t)((msg[TG_HDR_LEN + 2] << 8) | msg[TG_HDR_LEN + 3]);
	int p = TG_HDR_LEN + TG_FIXED_LEN;

	// Same order the device applies: scroll first, then the runs on top.
	if (flags & TG_F_HAS_SCROLL) {
		if (p + TG_SCROLL_LEN > n)
			return;
		int top = msg[p];
		int bot = msg[p + 1];
		int delta = (int8_t)msg[p + 2];
		p += TG_SCROLL_LEN;
		grid_scroll(f->shadow, f->shadow_attr, src->cols, top, bot, delta);
	}
	while (p + TG_RUN_HDR_LEN <= n) {
		int pos  = ((int)msg[p] << 8) | msg[p + 1];
		int len  = msg[p + 2];
		uint8_t attr = msg[p + 3];
		p += TG_RUN_HDR_LEN;
		if (p + len > n)
			break;
		if (pos >= 0 && pos + len <= TG_CELLS_MAX) {
			memcpy(f->shadow + pos, msg + p, (size_t)len);
			memset(f->shadow_attr + pos, attr, (size_t)len);
			f->scan_start = (uint16_t)(pos + len);      // fairness: resume past what we sent
		}
		p += len;
	}
	if (f->scan_start >= src->ncells)
		f->scan_start = 0;
	f->shadow_cursor = cursor;
	f->seq++;
}

// ---- decoder --------------------------------------------------------------

int termg_apply(const uint8_t *msg, int n,
                uint8_t *chars, uint8_t *attrs, int ncells, int cols,
                int *cursor, bool *bell)
{
	if (n < TG_HDR_LEN + TG_FIXED_LEN)
		return -1;
	if (msg[0] != TG_FRAME)
		return -1;
	int payload = ((int)msg[1] << 8) | msg[2];
	if (payload != n - TG_HDR_LEN)
		return -1;

	uint8_t flags = msg[TG_HDR_LEN];
	uint16_t frame_cursor = (uint16_t)((msg[TG_HDR_LEN + 2] << 8) | msg[TG_HDR_LEN + 3]);
	int p = TG_HDR_LEN + TG_FIXED_LEN;

	if (flags & TG_F_HAS_SCROLL) {
		if (p + TG_SCROLL_LEN > n)
			return -1;
		int top = msg[p];
		int bot = msg[p + 1];
		int delta = (int8_t)msg[p + 2];
		p += TG_SCROLL_LEN;
		if (top < 0 || bot >= ncells / cols || top > bot)
			return -1;
		grid_scroll(chars, attrs, cols, top, bot, delta);
	}

	// Validate the whole message before mutating anything: a half-applied frame
	// would desync the screen silently, which is worse than dropping it.
	int q = p;
	while (q + TG_RUN_HDR_LEN <= n) {
		int pos = ((int)msg[q] << 8) | msg[q + 1];
		int len = msg[q + 2];
		q += TG_RUN_HDR_LEN;
		if (q + len > n)
			return -1;
		if (pos < 0 || pos + len > ncells)
			return -1;
		q += len;
	}
	if (q != n)
		return -1;

	while (p + TG_RUN_HDR_LEN <= n) {
		int pos = ((int)msg[p] << 8) | msg[p + 1];
		int len = msg[p + 2];
		uint8_t attr = msg[p + 3];
		p += TG_RUN_HDR_LEN;
		memcpy(chars + pos, msg + p, (size_t)len);
		memset(attrs + pos, attr, (size_t)len);
		p += len;
	}

	if (cursor) {
		*cursor = (int)frame_cursor;
		if (frame_cursor == TG_CURSOR_NONE)
			*cursor = -1;
	}
	if (bell) {
		*bell = false;
		if (flags & TG_F_BELL)
			*bell = true;
	}
	return 0;
}
