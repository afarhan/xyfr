// text_edit.cpp — see text_edit.h.

#include <string.h>
#include "text_edit.h"
#include "text_engine.h"

static char      buf[EDIT_BUF_MAX];
static int       len;
static int       cursor, mark;

// Per-line CHARACTER counts. A line's start offset is the prefix sum, so the
// table is the only line bookkeeping needed — no per-line pointers to keep in
// step with edits.
static uint16_t  line_len[EDIT_MAX_LINES];
static uint8_t   line_dirty[EDIT_MAX_LINES];
static int       nlines;

static trect_t        rect;
static const tfont_t *font;
static bool           multi;
static const char    *filt;
static int            max_len;      // character cap, 0 = buffer cap only
static uint16_t       c_fg, c_bg;
static int            row_h, rows_vis, top_line;
static bool           finished;
static bool           focused = true;   // draw the caret? (see edit_set_focus)

// What is currently ON the panel per visible slot, so a repaint can be skipped
// when a line's content is unchanged (same scheme as the list box).
static int drawn_line[EDIT_MAX_LINES];

// The single mutation primitive; defined below edit_open, used by the cursor
// and word operations above it.
static bool replace_span(const char *ins, int ins_len);

static int line_start(int li) {
	int off = 0;
	for (int i = 0; i < li && i < nlines; i++)
		off += line_len[i];
	return off;
}

void edit_invalidate(void) {
	memset(line_dirty, 1, sizeof line_dirty);
	for (int i = 0; i < EDIT_MAX_LINES; i++)
		drawn_line[i] = -1;
}

// Rebuild the line table from `from_line` onward.
//
// Word rule, per the spec: a word runs between non-printing characters,
// INCLUDING the terminating NUL. A word longer than the line is broken at the
// line edge and continues on the next — so an unbreakable token degrades
// gracefully instead of vanishing or overflowing.
static void reflow(int from_line) {
	if (from_line < 0)
		from_line = 0;
	if (from_line > nlines)
		from_line = nlines;

	int off = line_start(from_line);
	int li  = from_line;
	int avail = rect.w;

	while (li < EDIT_MAX_LINES) {
		int w = 0, i = off, last_break = -1;
		bool hard = false;

		while (i < len) {
			unsigned char c = (unsigned char)buf[i];
			if (c == '\n') {
				hard = true;
				break;
			}
			int gi = tfont_index(font, c);
			int gw = (gi >= 0) ? font->width[gi] : 0;
			if (w + gw > avail)
				break;
			w += gw; i++;
			if (c == ' ')  // break AFTER the space
				last_break = i;
		}

		int end;
		if (hard)  // consume the newline
			end = i + 1;
		else if (i >= len)  // remainder fits
			end = len;
		else if (last_break > off)  // wrap at last space
			end = last_break;
		else { // hard-break a long word
			if ((i > off))
				end = i;
			else
				end = off + 1;
		}

		// Every line this pass VISITS is repainted: content can shift even when
		// the length does not (an insert mid-line moves characters without
		// changing the count). Only visited lines are marked, which is what keeps
		// an edit cheap — the pass covers one paragraph, not the document.
		int nl = end - off;
		line_dirty[li] = 1;
		line_len[li] = (uint16_t)nl;
		li++;
		off = end;

		if (off >= len) {
			// A trailing newline opens a NEW, EMPTY line. Without this the pass
			// stops on the line the newline closed, and cursor_line() leaves the
			// caret at the end of it -- so pressing Enter appeared to do nothing
			// until the next character arrived. A newline IS a character; the line
			// it opens simply has zero length.
			if (hard && li < EDIT_MAX_LINES) {
				line_dirty[li] = 1;
				line_len[li]   = 0;
				li++;
			}
			break;
		}
	}

	int old_lines = nlines;
	nlines = li;
	// If the document got SHORTER, the slots it vacated still show stale text.
	for (int k = nlines; k < old_lines && k < EDIT_MAX_LINES; k++)
		line_dirty[k] = 1;
	if (nlines == 0) {
		nlines = 1;
		line_len[0] = 0;
	}
	for (int k = nlines; k < EDIT_MAX_LINES; k++)
		line_len[k] = 0;
}

// The display line the caret was last PAINTED on. Moving the cursor has to
// repaint both the line it left (to erase the caret) and the line it arrived on
// — nothing else changes, so a cursor move costs two lines at most.
static int caret_line_drawn = -1;

static int cursor_line(void) {
	int li = 0, acc = 0;
	while (li + 1 < nlines && acc + line_len[li] <= cursor) {
		acc += line_len[li];
		li++;
	}
	return li;
}

// Bring the caret's line into the visible window by the MINIMUM scroll needed.
// Any change to top_line shifts every slot's content, so it invalidates the
// whole box — which is why scrolling is the expensive move and a plain cursor
// step is not.
static void scroll_into_view(void) {
	int cl = cursor_line();
	int old = top_line;
	if (cl < top_line)
		top_line = cl;
	else if (cl >= top_line + rows_vis)
		top_line = cl - rows_vis + 1;
	if (top_line < 0)
		top_line = 0;
	if (top_line != old)
		edit_invalidate();
}

// Mark the caret's old and new lines for repaint, then follow it with the view.
static void caret_moved(void) {
	int cl = cursor_line();
	if (caret_line_drawn >= 0 && caret_line_drawn < EDIT_MAX_LINES)
		line_dirty[caret_line_drawn] = 1;
	if (cl < EDIT_MAX_LINES)
		line_dirty[cl] = 1;
	scroll_into_view();
}

void edit_move(int delta) {
	cursor += delta;
	if (cursor < 0)
		cursor = 0;
	if (cursor > len)
		cursor = len;
	mark = cursor;                    // mark tracks the cursor: next edit inserts
	caret_moved();
}

void edit_move_line(int delta) {
	int cl = cursor_line();
	int col = cursor - line_start(cl);
	int nl = cl + delta;
	if (nl < 0)
		nl = 0;
	if (nl >= nlines)
		nl = nlines - 1;
	int nstart = line_start(nl);
	int nlen   = line_len[nl];
	// Do not land ON a trailing newline — that would put the caret past the
	// visible end of the line.
	if (nlen > 0 && buf[nstart + nlen - 1] == '\n')
		nlen--;
	cursor = nstart + (col < nlen ? col : nlen);
	mark = cursor;
	caret_moved();
}

void edit_home(void) { cursor = line_start(cursor_line()); mark = cursor; caret_moved(); }

void edit_end(void) {
	int cl = cursor_line();
	int n = line_len[cl];
	if (n > 0 && buf[line_start(cl) + n - 1] == '\n')
		n--;
	cursor = line_start(cl) + n;
	mark = cursor;
	caret_moved();
}

static bool is_wordsep(char ch) { return ch == ' ' || ch == '\n'; }

void edit_move_word(int delta) {
	if (delta > 0) {
		while (cursor < len && !is_wordsep(buf[cursor]))
			cursor++;
		while (cursor < len &&  is_wordsep(buf[cursor]))
			cursor++;
	} else if (delta < 0) {
		while (cursor > 0 &&  is_wordsep(buf[cursor - 1]))
			cursor--;
		while (cursor > 0 && !is_wordsep(buf[cursor - 1]))
			cursor--;
	}
	mark = cursor;
	caret_moved();
}

bool edit_delete_forward(void) {
	if (finished || cursor >= len)
		return false;
	mark = cursor + 1;                       // span [cursor, cursor+1)
	return replace_span(NULL, 0);
}

bool edit_delete_word(void) {
	if (finished || cursor == 0)
		return false;
	int c0 = cursor;
	while (c0 > 0 &&  is_wordsep(buf[c0 - 1]))
		c0--;
	while (c0 > 0 && !is_wordsep(buf[c0 - 1]))
		c0--;
	mark = c0;                               // span [c0, cursor)
	return replace_span(NULL, 0);
}

int edit_cursor(void)      { return cursor; }
int edit_cursor_line(void) { return cursor_line(); }
int edit_top_line(void)    { return top_line; }

void edit_open(const trect_t *r, const tfont_t *f, bool multiline,
               const char *filter, int maxlen, uint16_t fg, uint16_t bg) {
	rect = *r; font = f; multi = multiline; filt = filter; max_len = maxlen;
	c_fg = fg; c_bg = bg;
	row_h    = f->height;
	rows_vis = rect.h / row_h;
	len = cursor = mark = 0;
	top_line = 0;
	finished = false;
	buf[0] = 0;
	memset(line_len, 0, sizeof line_len);
	nlines = 1;
	edit_invalidate();
	draw_rect(rect.x, rect.y, rect.w, rect.h, c_bg);
}

// The one mutation primitive: replace buf[mark..cursor) with `ins` (0..1 chars).
static bool replace_span(const char *ins, int ins_len) {
	int a = mark < cursor ? mark : cursor;
	int b = mark < cursor ? cursor : mark;
	int delta = ins_len - (b - a);
	if (len + delta > EDIT_BUF_MAX - 1)
		return false;
	if (max_len > 0 && len + delta > max_len)  // the declared field cap
		return false;

	memmove(buf + a + ins_len, buf + b, (size_t)(len - b));
	if (ins_len)
		memcpy(buf + a, ins, (size_t)ins_len);
	len += delta;
	buf[len] = 0;
	cursor = mark = a + ins_len;

	// Reflow from the start of the edited PARAGRAPH — not from the edited line,
	// and not from 0.
	//
	// Why the paragraph and not the line: wrapping is a property of the whole
	// paragraph. Type "comfortable" at a line end and "able" wraps to the next
	// line, correctly. Now delete "able" — "comfort" must slip BACK up. A reflow
	// that starts at the current line never reconsiders the line above, so the
	// word would stay orphaned. Starting at the paragraph makes text flow both
	// ways. A hard newline ends a line, so a paragraph start is always a line
	// start, and the pass stays bounded by the paragraph's length.
	int p = a;
	while (p > 0 && buf[p - 1] != '\n')
		p--;

	int li = 0, acc = 0;
	while (li + 1 < nlines && acc + line_len[li] <= p) {
		acc += line_len[li];
		li++;
	}
	reflow(li);
	scroll_into_view();               // typing past the bottom must follow the caret
	return true;
}

bool edit_insert(char c) {
	if (finished)
		return false;
	if (c == '\n' && !multi) {
		finished = true;
		return true;
	}
	if (c != '\n') {
		if ((unsigned char)c < 0x20)  // non-printing
			return false;
		if (filt && !strchr(filt, c))  // filtered out
			return false;
	}
	return replace_span(&c, 1);
}

bool edit_backspace(void) {
	if (finished || cursor == 0)
		return false;
	mark = cursor - 1;                       // one-char span, replaced by nothing
	return replace_span(NULL, 0);
}

void edit_set_focus(bool on) {
	if (focused == on)
		return;
	focused = on;
	int cl = cursor_line();
	if (cl >= 0 && cl < EDIT_MAX_LINES)  // repaint it: that erases the caret
		line_dirty[cl] = 1;
}

int edit_draw(void) {
	int painted = 0;
	for (int s = 0; s < rows_vis; s++) {
		int li = top_line + s;
		bool has = (li < nlines);
		if (!line_dirty[li] && drawn_line[s] == (has ? li : -1))
			continue;

		trect_t r = { (int16_t)rect.x, (int16_t)(rect.y + s * row_h),
		              (int16_t)rect.w, (int16_t)row_h };
		if (!has) {
			draw_rect(r.x, r.y, r.w, r.h, c_bg);
		} else {
			int off = line_start(li);
			int n   = line_len[li];
			// Strip a trailing newline so it is not measured as a glyph.
			if (n > 0 && buf[off + n - 1] == '\n')
				n--;
			char tmp[256];
			if (n > (int)sizeof tmp - 1)
				n = (int)sizeof tmp - 1;
			memcpy(tmp, buf + off, (size_t)n);
			tmp[n] = 0;
			draw_string(&r, tmp[0] ? tmp : " ", font, ALIGN_LEFT, c_fg, c_bg);

			// Caret at the CURSOR's column, measured by summing glyph advances up
			// to it — the same widths the reflow used, so the caret cannot drift
			// away from where the text actually breaks.
			if (focused && li == cursor_line()) {
				int col = cursor - off;
				if (col < 0)
					col = 0;
				if (col > n)
					col = n;
				int cx = rect.x + text_width_n(font, tmp, col);
				// A BLOCK with the character under it reversed, not a thin bar --
				// a 2px bar is indistinguishable from a lowercase 'l'. Drawing the
				// glyph with fg/bg swapped fills the cell and inverts the letter in
				// one call, so it reads as a caret at any glyph width.
				char cch[2] = { (col < n) ? tmp[col] : ' ', 0 };
				int cgi = tfont_index(font, (unsigned char)cch[0]);
				int cw  = (cgi >= 0) ? font->width[cgi] : 0;
				if (cw < 4)  // visible even on 'i' or a space
					cw = 4;
				if (cx + cw > rect.x + rect.w)
					cw = rect.x + rect.w - cx;
				if (cw > 0) {
					trect_t cr = { (int16_t)cx, (int16_t)r.y, (int16_t)cw, (int16_t)row_h };
					draw_string(&cr, cch, font, ALIGN_LEFT, c_bg, c_fg);   // reversed
				}
				caret_line_drawn = li;
			}
		}
		line_dirty[li] = 0;
		if (has)
			drawn_line[s] = li;
		else
			drawn_line[s] = -1;
		painted++;
	}
	return painted;
}

const char *edit_text(void) { return buf; }
int  edit_len(void)         { return len; }
int  edit_lines(void)       { return nlines; }
bool edit_done(void)        { return finished; }
