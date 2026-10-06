// vterm_glue.c — libvterm -> flat ASCII cell grid. See vterm_glue.h for why.

#include "vterm_glue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vterm.h>

#include "termg.h"   // TG_BOX_BASE — the private box-drawing range

struct vterm_glue {
	VTerm       *vt;
	VTermScreen *screen;

	int cols, rows;

	uint8_t chars[VG_CELLS_MAX];
	uint8_t attrs[VG_CELLS_MAX];

	int  cursor;            // flat index, -1 = hidden
	bool cursor_vis;
	int  cursor_row, cursor_col;

	bool bell;

	// Scroll hint accumulated from moverect between reads.
	bool scroll_valid;
	int  scroll_top, scroll_bot, scroll_delta;

	// Set by any damage/moverect/resize; tells vg_sync it must re-read libvterm.
	bool dirty;
};

// ---------------------------------------------------------------------------

// One libvterm cell -> one transmitted byte. libvterm gives UTF-8 codepoints; the
// device can draw ASCII 0x20..0x7E plus a private box-drawing range, so
// everything else falls back to an ASCII lookalike or, failing that, '?' -- a
// visible placeholder is more honest than silently swallowing the character.
//
// Box-drawing codepoints we can actually draw, in the order the device's
// font6x12_box table expects. TUIs (Claude Code, vi, dialog) frame everything
// with these, and without them the whole UI collapses into a field of '?'.
static const uint32_t box_cps[] = {
	// MUST match the order in tools/gen_gfx.py -- the transmitted byte is the index.
	0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518,   // lines + corners
	0x251C, 0x2524, 0x252C, 0x2534, 0x253C,           // tees + cross
	0x256D, 0x256E, 0x256F, 0x2570,                   // rounded corners
	0x2588, 0x2580, 0x2584, 0x258C, 0x2590,           // block elements
	0x2591, 0x2592, 0x2593,                           // shades
	0x2190, 0x2192, 0x2191, 0x2193,                   // arrows
	0x2713, 0x2717,                                   // tick / cross
	0x2022, 0x25CF, 0x25CB,                           // bullets
	0x276F, 0x00B7,                                   // chevron, middle dot
};

static uint8_t cell_char(const VTermScreenCell *c)
{
	uint32_t cp = c->chars[0];
	if (cp == 0)                 return ' ';        // empty cell
	if (cp >= 0x20 && cp < 0x7F) return (uint8_t)cp;
	for (unsigned i = 0; i < sizeof box_cps / sizeof box_cps[0]; i++)
		if (cp == box_cps[i]) return (uint8_t)(TG_BOX_BASE + i);

	// Plain-ASCII lookalikes for what we still cannot draw. A readable
	// substitute beats a '?'; anything with a real glyph is handled above.
	switch (cp) {
	case 0x2013: case 0x2014: return '-';   // en/em dash
	case 0x2018: case 0x2019: return '\'';
	case 0x201C: case 0x201D: return '"';
	case 0x2026: return '.';                // ellipsis
	case 0x00A0: return ' ';                // no-break space
	case 0x00D7: return 'x';
	case 0x2212: return '-';
	case 0x276E: return '<';
	case 0x203A: return '>';
	case 0x2039: return '<';
	case 0x2714: return (uint8_t)(TG_BOX_BASE + 27);   // heavy tick -> the tick glyph
	case 0x2718: return (uint8_t)(TG_BOX_BASE + 28);   // heavy cross -> the cross glyph
	default: break;
	}
	return '?';
}

// libvterm hands back either a palette index or a real RGB triple (a program
// may emit 24-bit colour). Reduce both to the 16-colour ANSI index the format
// carries: the panel is 480x320 at 6x12, where fine colour distinctions are
// invisible anyway.
static uint8_t fg_index(VTermState *state, VTermColor col)
{
	if (VTERM_COLOR_IS_DEFAULT_FG(&col)) return TG_FG_DEFAULT;
	if (VTERM_COLOR_IS_INDEXED(&col)) {
		if (col.indexed.idx < 16) return (uint8_t)col.indexed.idx;
		vterm_state_convert_color_to_rgb(state, &col);      // 256-colour cube -> rgb
	}
	if (!VTERM_COLOR_IS_RGB(&col)) return TG_FG_DEFAULT;
	// Nearest of the 8 base hues, then bright if it is light overall.
	int r = col.rgb.red, g = col.rgb.green, b = col.rgb.blue;
	int hi = (r > g ? r : g) > b ? (r > g ? r : g) : b;
	if (hi < 64) return 0;                                   // black
	int thr = hi / 2;
	int idx = ((r >= thr) ? 1 : 0) | ((g >= thr) ? 2 : 0) | ((b >= thr) ? 4 : 0);
	if (hi >= 170) idx |= 8;                                 // bright variant
	return (uint8_t)idx;
}

static uint8_t cell_attr(struct vterm_glue *g, const VTermScreenCell *c)
{
	uint8_t a = 0;
	if (c->attrs.reverse)   a |= VG_ATTR_REVERSE;
	if (c->attrs.bold)      a |= VG_ATTR_BOLD;
	if (c->attrs.underline) a |= VG_ATTR_UNDERLINE;
	uint8_t fg = fg_index(vterm_obtain_state(g->vt), c->fg);
	a |= (uint8_t)((fg << TG_ATTR_FG_SHIFT) & TG_ATTR_FG_MASK);
	return a;
}

// Re-read the damaged region out of libvterm into our flat grid. Called lazily
// from the accessors so a burst of output costs one sync, not one per damage
// callback.
static void vg_sync(struct vterm_glue *g)
{
	if (!g->dirty) return;
	g->dirty = false;
	for (int r = 0; r < g->rows; r++) {
		for (int c = 0; c < g->cols; c++) {
			VTermPos pos = { .row = r, .col = c };
			VTermScreenCell cell;
			if (!vterm_screen_get_cell(g->screen, pos, &cell)) continue;
			int i = r * g->cols + c;
			g->chars[i] = cell_char(&cell);
			g->attrs[i] = cell_attr(g, &cell);
		}
	}
}

// ---- libvterm callbacks ---------------------------------------------------

static int cb_damage(VTermRect rect, void *user)
{
	(void)rect;
	((struct vterm_glue *)user)->dirty = true;
	return 1;
}

// libvterm reports a scroll as "this rect moved to there". Turn it into the
// (top, bot, delta) hint the format carries. Only a pure VERTICAL move of a
// full-width region is usable; anything else we ignore and let the plain diff
// handle it (correctness never depends on the hint).
static int cb_moverect(VTermRect dest, VTermRect src, void *user)
{
	struct vterm_glue *g = (struct vterm_glue *)user;
	g->dirty = true;

	if (src.start_col != dest.start_col || src.end_col != dest.end_col) return 1;
	if ((src.end_row - src.start_row) != (dest.end_row - dest.start_row)) return 1;

	int delta = src.start_row - dest.start_row;      // >0 = content moved up
	if (delta == 0) return 1;

	int top = dest.start_row < src.start_row ? dest.start_row : src.start_row;
	int bot = (dest.end_row > src.end_row ? dest.end_row : src.end_row) - 1;

	if (g->scroll_valid && g->scroll_top == top && g->scroll_bot == bot) {
		g->scroll_delta += delta;                    // same region again: accumulate
	} else if (g->scroll_valid) {
		g->scroll_valid = false;                     // two different regions: give up
	} else {
		g->scroll_valid = true;
		g->scroll_top = top;
		g->scroll_bot = bot;
		g->scroll_delta = delta;
	}
	return 1;
}

static int cb_movecursor(VTermPos pos, VTermPos oldpos, int visible, void *user)
{
	struct vterm_glue *g = (struct vterm_glue *)user;
	(void)oldpos;
	g->cursor_row = pos.row;
	g->cursor_col = pos.col;
	g->cursor_vis = visible ? true : false;
	return 1;
}

static int cb_settermprop(VTermProp prop, VTermValue *val, void *user)
{
	struct vterm_glue *g = (struct vterm_glue *)user;
	if (prop == VTERM_PROP_CURSORVISIBLE) g->cursor_vis = val->boolean ? true : false;
	// VTERM_PROP_ALTSCREEN needs no handling here: libvterm raises a full-screen
	// damage rect on the switch (verified), so the grid re-reads via cb_damage.
	return 1;      // titles (VTERM_PROP_TITLE) etc. are accepted and ignored
}

static int cb_bell(void *user)
{
	((struct vterm_glue *)user)->bell = true;
	return 1;
}

static int cb_resize(int rows, int cols, void *user)
{
	struct vterm_glue *g = (struct vterm_glue *)user;
	g->rows = rows;
	g->cols = cols;
	g->dirty = true;
	return 1;
}

static const VTermScreenCallbacks vg_cbs = {
	.damage      = cb_damage,
	.moverect    = cb_moverect,
	.movecursor  = cb_movecursor,
	.settermprop = cb_settermprop,
	.bell        = cb_bell,
	.resize      = cb_resize,
};

// ---- public ---------------------------------------------------------------

struct vterm_glue *vg_new(int cols, int rows)
{
	if (cols < 1) cols = 1;
	if (rows < 1) rows = 1;
	if (cols > VG_COLS_MAX) cols = VG_COLS_MAX;
	if (rows > VG_ROWS_MAX) rows = VG_ROWS_MAX;

	struct vterm_glue *g = calloc(1, sizeof *g);
	if (!g) return NULL;

	g->vt = vterm_new(rows, cols);
	if (!g->vt) { free(g); return NULL; }
	vterm_set_utf8(g->vt, 1);

	g->screen = vterm_obtain_screen(g->vt);
	vterm_screen_set_callbacks(g->screen, &vg_cbs, g);
	// Allocate the ALTERNATE buffer. libvterm does not by default, and without
	// it ESC[?1049h/l is accepted but there is nothing to switch to -- so vi and
	// less paint over the primary screen and leave it wrecked on exit, which is
	// precisely the behaviour we moved off vt100 to avoid.
	vterm_screen_enable_altscreen(g->screen, 1);
	vterm_screen_reset(g->screen, 1);

	g->cols = cols;
	g->rows = rows;
	g->cursor_vis = true;
	memset(g->chars, ' ', sizeof g->chars);
	g->dirty = true;
	return g;
}

void vg_free(struct vterm_glue *g)
{
	if (!g) return;
	if (g->vt) vterm_free(g->vt);
	free(g);
}

void vg_write(struct vterm_glue *g, const uint8_t *b, int len)
{
	if (!g || !b || len <= 0) return;
	vterm_input_write(g->vt, (const char *)b, (size_t)len);   // consumes ALL of it
}

const uint8_t *vg_chars(const struct vterm_glue *g)
{
	vg_sync((struct vterm_glue *)g);
	return g->chars;
}

const uint8_t *vg_attrs(const struct vterm_glue *g)
{
	vg_sync((struct vterm_glue *)g);
	return g->attrs;
}

int vg_cols(const struct vterm_glue *g)   { return g->cols; }
int vg_rows(const struct vterm_glue *g)   { return g->rows; }
int vg_ncells(const struct vterm_glue *g) { return g->cols * g->rows; }

int vg_cursor(const struct vterm_glue *g)
{
	if (!g->cursor_vis) return -1;
	if (g->cursor_row < 0 || g->cursor_row >= g->rows) return -1;
	if (g->cursor_col < 0 || g->cursor_col >= g->cols) return -1;
	return g->cursor_row * g->cols + g->cursor_col;
}

bool vg_take_bell(struct vterm_glue *g)
{
	bool b = g->bell;
	g->bell = false;
	return b;
}

bool vg_take_scroll(struct vterm_glue *g, int *top, int *bot, int *delta)
{
	if (!g->scroll_valid) return false;
	g->scroll_valid = false;
	// A scroll of a whole screen-height or more is not worth encoding -- the
	// diff will be sending every cell anyway.
	if (g->scroll_delta <= -g->rows || g->scroll_delta >= g->rows) return false;
	*top   = g->scroll_top;
	*bot   = g->scroll_bot;
	*delta = g->scroll_delta;
	return true;
}

void vg_resize(struct vterm_glue *g, int cols, int rows)
{
	if (cols < 1 || rows < 1) return;
	if (cols > VG_COLS_MAX) cols = VG_COLS_MAX;
	if (rows > VG_ROWS_MAX) rows = VG_ROWS_MAX;
	if (cols == g->cols && rows == g->rows) return;
	vterm_set_size(g->vt, rows, cols);      // fires cb_resize
	g->dirty = true;
}
