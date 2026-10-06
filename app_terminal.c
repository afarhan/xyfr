// app_terminal.c - the terminal app: the ANSI parser, the cell grid, and the
// screen, in one file behind one handler.
//
// Raw bytes both ways on a PORT_TERM stream: keystrokes up, PTY output down,
// no framing. The host runs the shell. One terminal per contact, and the
// stream is the session: switching contacts is switching which stream is
// read, and a backgrounded terminal is not read at all, so stream.c withholds
// the ack and the far shell blocks. Coming back sends Ctrl-L and the shell
// repaints.
//
// The parser (ansi_feed) is a VT100 subset covering the xyfr terminfo entry.
// It pokes cells into the grid: cells[] holds one uint16 per cell (character
// plus attribute bits, tui.h), each row remembers its dirty span, and
// tui_pump repaints dirty rows within a time budget so a full-screen blit
// never stalls the voice pump. The font profile fixes the grid size (80x25 or
// 60x18) and its glyph tables.
//
// Keystrokes go through a transmit ring: the stream is stop-and-wait, so a
// write is refused while a segment is in flight, and without the ring every
// character typed within an RTT of the last would be dropped. APP_PUMP drains
// the ring as the window opens.
//
// The screen is a view with no list: the engine paints the title bar and the
// body is painted from APP_PUMP, never from FOREGROUND, because the engine
// clears the panel on the tick after view_set. A fresh open shows the key help
// and swallows one key; B or W there picks the grid size. Backspace is the
// leave gesture and is declined so ui.cpp acts on it. The panel is reached
// only through display_backend.h's panel_* calls.
//
// Core 0.

#include <string.h>
#include <stdio.h>
#include "kernel.h"
#include "stream.h"
#include "peer_data.h"
#include "ui.h"
#include "ui_symbols.h"
#include "view.h"
#include "display_backend.h"
#include "device_record.h"
#include "call.h"
#include "hal.h"
#include "display_select.h"
#include "tui.h"
#include "ansi.h"

#define GLYPH_FIRST_ASCII  0x20
#define GLYPH_LAST_ASCII   0x7E
#define GLYPH_ASCII_COUNT  95
#define GLYPH_BOX_BASE     0x80
#define GLYPH_BOX_COUNT    34
#define GLYPH_BITS_PER_ROW 8      // one byte per glyph row, MSB leftmost

#define TAB_STOP           8
#define CSI_PARAM_MAX      8

#define TUI_BUDGET_US         15000   // per pump; tighter in a call, which needs a frame every 40 ms
#define TUI_BUDGET_IN_CALL_US 8000
#define TUI_PALETTE_SIZE        16
#define TUI_PALETTE_BRIGHT_BASE 8
#define TUI_X0 ((TFT_VER_RES - font->cols * font->cw) / 2)   // centres the grid

#define TERM_FONT_STORED_6X12 1   // device_record.term_font; 0 (wiped) = the default
#define TERM_FONT_STORED_8X16 2
#define TERM_TX_RING          512
#define TERM_TX_SEGMENT       256   // the most one stream_write is offered

// ---- structs ---------------------------------------------------------------

// The current graphic rendition, applied to every cell written.
struct pen {
	uint8_t fg;
	uint8_t bold;
	uint8_t reverse;
	uint8_t underline;
	uint8_t acs;        // DEC Special Graphics active (ESC(0)
};

struct font_profile {
	const uint8_t *text;   // 95 glyphs of `ch` bytes each
	const uint8_t *box;    // GLYPH_BOX_COUNT glyphs of `ch` bytes each
	int cols;
	int rows;
	int cw;                // cell width in pixels
	int ch;                // cell height in pixels
};

enum parser_state {
	P_GROUND,
	P_ESC,
	P_CSI,
	P_CHARSET,
};

// Arduino.h is C++-only; this file is C.
extern unsigned long millis(void);
extern unsigned long micros(void);

// The glyph tables (gfx6x12.c / gfx8x16.c).
extern const uint8_t font6x12[GLYPH_ASCII_COUNT][12];
extern const uint8_t font6x12_box[GLYPH_BOX_COUNT][12];
extern const uint8_t font8x16[GLYPH_ASCII_COUNT][16];
extern const uint8_t font8x16_box[GLYPH_BOX_COUNT][16];

static const struct font_profile profiles[TUI_FONT_COUNT] = {
	{ (const uint8_t *)font6x12, (const uint8_t *)font6x12_box, 80, 25, 6, 12 },
	{ (const uint8_t *)font8x16, (const uint8_t *)font8x16_box, 60, 18, 8, 16 },
};

// RGB565 for the sixteen ANSI foreground colours, dim 0-7 then bright 8-15.
static const uint16_t tui_pal[TUI_PALETTE_SIZE] = {
	0x0000, 0xA000, 0x0500, 0xA540, 0x0014, 0xA014, 0x0514, 0xAD55,
	0x52AA, 0xF800, 0x07E0, 0xFFE0, 0x001F, 0xF81F, 0x07FF, 0xFFFF,
};

// The parser.
static int  cur_row, cur_col;
static int  wrap_pending;                 // autowrap deferred past the last column
static int  scroll_top, scroll_bot;       // 0-based inclusive region
static struct pen pen;
static int  cursor_visible = 1;
static int  saved_row, saved_col;         // DECSC/DECRC and the alt-screen
static struct pen saved_pen;
static int  alt_active;
static int  pstate = P_GROUND;
static int  parm[CSI_PARAM_MAX], nparm;
static int  csi_priv;                     // '?' prefix

// The grid.
static int      font_index = TUI_FONT_6X12;
static const struct font_profile *font = &profiles[TUI_FONT_6X12];
static uint16_t cells[TUI_CELLS_MAX];
static uint8_t  row_dirty[TUI_ROWS_MAX];
static uint8_t  row_first_dirty_col[TUI_ROWS_MAX];
static uint8_t  row_last_dirty_col[TUI_ROWS_MAX];
static int32_t  cur_off = -1;
static int      scan_row = 0;             // where the budget ran out
static bool     cur_blink_on = true;
static uint32_t cur_blink_last = 0;
uint32_t        tui_cursor_blink_ms = 500;

// The screen.
static uint32_t      term_peer;           // 0 = not foreground; nobody's stream is read
static stream_handle term_stream;
static bool          term_help;           // the help screen is up; the next key is swallowed
static uint8_t       term_tx_buf[TERM_TX_RING];
static uint16_t      term_tx_head, term_tx_tail;

// ---- the parser ------------------------------------------------------------

static void clamp_cursor(void) {
	if (cur_row < 0)
		cur_row = 0;
	else if (cur_row >= tui_rows())
		cur_row = tui_rows() - 1;
	if (cur_col < 0)
		cur_col = 0;
	else if (cur_col >= tui_cols())
		cur_col = tui_cols() - 1;
}

// Parameter i; absent or 0 gives `fallback`.
static int csi_param(int i, int fallback) {
	int v = 0;
	if (i < nparm)
		v = parm[i];
	if (v == 0)
		return fallback;
	return v;
}

static uint16_t cell_of(uint8_t ch) {
	uint16_t c = ch;
	if (pen.bold)
		c |= TC_BOLD;
	if (pen.reverse)
		c |= TC_REVERSE;
	if (pen.underline)
		c |= TC_UNDERLINE;
	c |= (uint16_t)((pen.fg & 0x0F) << TC_FG_SHIFT);
	return c;
}

static void set_cursor(void) {
	int32_t off = -1;
	if (cursor_visible)
		off = (int32_t)(cur_row * tui_cols() + cur_col);
	tui_cursor(off);
}

// DEC Special Graphics: the box glyphs sit from GLYPH_BOX_BASE in the order
// gfx6x12.c fixes; symbols we lack fall back to ASCII.
static uint8_t dec_glyph(uint8_t ch) {
	switch (ch) {
		case 'q': return GLYPH_BOX_BASE + 0;   // ─
		case 'x': return GLYPH_BOX_BASE + 1;   // │
		case 'l': return GLYPH_BOX_BASE + 2;   // ┌
		case 'k': return GLYPH_BOX_BASE + 3;   // ┐
		case 'm': return GLYPH_BOX_BASE + 4;   // └
		case 'j': return GLYPH_BOX_BASE + 5;   // ┘
		case 't': return GLYPH_BOX_BASE + 6;   // ├
		case 'u': return GLYPH_BOX_BASE + 7;   // ┤
		case 'w': return GLYPH_BOX_BASE + 8;   // ┬
		case 'v': return GLYPH_BOX_BASE + 9;   // ┴
		case 'n': return GLYPH_BOX_BASE + 10;  // ┼
		case '`': return GLYPH_BOX_BASE + 29;  // ◆ -> •
		case 'a': return GLYPH_BOX_BASE + 21;  // ▒
		case '~': return GLYPH_BOX_BASE + 33;  // ·
		case 'o': case 'p': case 'r': case 's': return GLYPH_BOX_BASE + 0;  // scan lines -> ─
		case 'y': return '<';        // ≤
		case 'z': return '>';        // ≥
		case '|': return '!';        // ≠
		case 'f': return 'o';        // °
		case 'g': return '+';        // ±
		default:  return ch;
	}
}

static void line_feed(void) {
	if (cur_row == scroll_bot)
		tui_scroll(scroll_top, scroll_bot, 1);
	else if (cur_row < tui_rows() - 1)
		cur_row++;
}

static void rev_line_feed(void) {
	if (cur_row == scroll_top)
		tui_scroll(scroll_top, scroll_bot, -1);
	else if (cur_row > 0)
		cur_row--;
}

static void put_char(uint8_t ch) {
	if (wrap_pending) {
		cur_col = 0;
		line_feed();
		wrap_pending = 0;
	}
	if (pen.acs)
		ch = dec_glyph(ch);
	tui_poke((uint16_t)(cur_row * tui_cols() + cur_col), cell_of(ch));
	if (cur_col + 1 >= tui_cols())  // deferred, so the last column stays usable
		wrap_pending = 1;
	else
		cur_col++;
}

static void erase_line(int mode) {   // K: 0 to EOL, 1 from BOL, 2 whole line
	int r = cur_row * tui_cols();
	if (mode == 1)
		tui_fill((uint16_t)r, (uint16_t)(cur_col + 1), TC_BLANK);
	else if (mode == 2)
		tui_fill((uint16_t)r, tui_cols(), TC_BLANK);
	else
		tui_fill((uint16_t)(r + cur_col), (uint16_t)(tui_cols() - cur_col), TC_BLANK);
}

static void erase_display(int mode) {   // J: 0 to end, 1 from start, 2/3 all
	if (mode == 2 || mode == 3) {
		tui_fill(0, tui_cells(), TC_BLANK);
		return;
	}
	if (mode == 1) {
		if (cur_row > 0)
			tui_fill(0, (uint16_t)(cur_row * tui_cols()), TC_BLANK);
		tui_fill((uint16_t)(cur_row * tui_cols()), (uint16_t)(cur_col + 1), TC_BLANK);
	} else {
		tui_fill((uint16_t)(cur_row * tui_cols() + cur_col),
		         (uint16_t)(tui_cells() - (cur_row * tui_cols() + cur_col)), TC_BLANK);
	}
}

static void sgr(void) {
	if (nparm == 0) {  // ESC[m == ESC[0m
		parm[0] = 0;
		nparm = 1;
	}
	for (int i = 0; i < nparm; i++) {
		int p = parm[i];
		if      (p == 0) {
			pen.fg = TC_FG_DEFAULT;
			pen.bold = 0;
			pen.reverse = 0;
			pen.underline = 0;
		}
		else if (p == 1)
			pen.bold = 1;
		else if (p == 4)
			pen.underline = 1;
		else if (p == 7)
			pen.reverse = 1;
		else if (p == 22)
			pen.bold = 0;
		else if (p == 24)
			pen.underline = 0;
		else if (p == 27)
			pen.reverse = 0;
		else if (p >= 30 && p <= 37)
			pen.fg = (uint8_t)(p - 30);
		else if (p == 39)
			pen.fg = TC_FG_DEFAULT;
		else if (p >= 90 && p <= 97)  // bright
			pen.fg = (uint8_t)(p - 90 + 8);
		else if (p == 38 || p == 48)  // 256-colour and truecolour: not supported
			break;
		// 40-47 and the rest: ignored; the cell carries no background colour.
	}
}

// ?25 cursor, ?1049/47/1047 alt-screen.
static void set_mode(int on) {
	if (!csi_priv)
		return;
	int m = csi_param(0, 0);
	if (m == 25) {
		cursor_visible = on;
	}
	else if (m == 1049 || m == 47 || m == 1047) {
		if (on && !alt_active) {
			saved_row = cur_row;
			saved_col = cur_col;
			saved_pen = pen;
			alt_active = 1;
			tui_fill(0, tui_cells(), TC_BLANK);
			cur_row = 0;
			cur_col = 0;
			wrap_pending = 0;
		} else if (!on && alt_active) {
			alt_active = 0;
			tui_fill(0, tui_cells(), TC_BLANK);
			cur_row = saved_row;
			cur_col = saved_col;
			pen = saved_pen;
			wrap_pending = 0;
			clamp_cursor();
		}
	}
}

static void csi(uint8_t final) {
	// Any cursor move cancels a pending wrap, or the next character lands a
	// row below where it was addressed.
	switch (final) {
		case 'A': case 'B': case 'C': case 'D': case 'E':
		case 'F': case 'G': case '`': case 'd': case 'H': case 'f':
			wrap_pending = 0;
			break;
		default:
			break;
	}
	switch (final) {
		case 'A':
			cur_row -= csi_param(0, 1);
			clamp_cursor();
			break;
		case 'B':
			cur_row += csi_param(0, 1);
			clamp_cursor();
			break;
		case 'C':
			cur_col += csi_param(0, 1);
			clamp_cursor();
			break;
		case 'D':
			cur_col -= csi_param(0, 1);
			clamp_cursor();
			break;
		case 'E':                                     // CNL
			cur_row += csi_param(0, 1);
			cur_col = 0;
			clamp_cursor();
			break;
		case 'F':                                     // CPL
			cur_row -= csi_param(0, 1);
			cur_col = 0;
			clamp_cursor();
			break;
		case 'G': case '`':                           // HPA
			cur_col = csi_param(0, 1) - 1;
			clamp_cursor();
			break;
		case 'd':                                     // VPA
			cur_row = csi_param(0, 1) - 1;
			clamp_cursor();
			break;
		case 'H': case 'f':
			cur_row = csi_param(0, 1) - 1;
			cur_col = csi_param(1, 1) - 1;
			clamp_cursor();
			break;
		case 'J':
			erase_display(csi_param(0, 0));
			break;
		case 'K':
			erase_line(csi_param(0, 0));
			break;
		case 'L':                                     // IL
			tui_scroll(cur_row, scroll_bot, -csi_param(0, 1));
			break;
		case 'M':                                     // DL
			tui_scroll(cur_row, scroll_bot, csi_param(0, 1));
			break;
		case 'r': {                                   // DECSTBM
			int top = csi_param(0, 1) - 1;
			int bot = csi_param(1, tui_rows()) - 1;
			// Clamp both ends: a host that thinks we are taller sets a bottom
			// the cursor can never reach, and line_feed stops scrolling.
			if (top < 0)
				top = 0;
			if (bot >= tui_rows())
				bot = tui_rows() - 1;
			if (top < bot) {
				scroll_top = top;
				scroll_bot = bot;
				cur_row = top;
				cur_col = 0;
			}
			break;
		}
		case 'm':
			sgr();
			break;
		case 'h':
			set_mode(1);
			break;
		case 'l':
			set_mode(0);
			break;
		case 's':                                     // ANSI save
			saved_row = cur_row;
			saved_col = cur_col;
			break;
		case 'u':                                     // ANSI restore
			cur_row = saved_row;
			cur_col = saved_col;
			clamp_cursor();
			break;
		default:
			break;    // ICH, DCH and the rest: not advertised, so ignored
	}
}

static void esc(uint8_t b) {
	switch (b) {
		case 'D':                                     // IND
			line_feed();
			break;
		case 'M':                                     // RI
			rev_line_feed();
			break;
		case 'E':                                     // NEL
			cur_col = 0;
			line_feed();
			break;
		case '7':                                     // DECSC
			saved_row = cur_row;
			saved_col = cur_col;
			saved_pen = pen;
			break;
		case '8':                                     // DECRC
			cur_row = saved_row;
			cur_col = saved_col;
			pen = saved_pen;
			clamp_cursor();
			break;
		case 'c':                                     // RIS
			ansi_reset();
			tui_fill(0, tui_cells(), TC_BLANK);
			break;
		default:
			break;    // '(' ')' and '[' are the state switch's
	}
}

void ansi_reset(void) {
	cur_row = 0;
	cur_col = 0;
	wrap_pending = 0;
	scroll_top = 0;
	scroll_bot = tui_rows() - 1;
	pen.fg = TC_FG_DEFAULT;
	pen.bold = 0;
	pen.reverse = 0;
	pen.underline = 0;
	pen.acs = 0;
	saved_row = 0;
	saved_col = 0;
	saved_pen = pen;
	alt_active = 0;
	cursor_visible = 1;
	pstate = P_GROUND;
	nparm = 0;
	csi_priv = 0;
}

void ansi_feed(const uint8_t *buf, int n) {
	for (int i = 0; i < n; i++) {
		uint8_t b = buf[i];
		switch (pstate) {
		case P_GROUND:
			if (b == 0x1b)
				pstate = P_ESC;
			else if (b == '\r') {
				cur_col = 0;
				wrap_pending = 0;
			}
			else if (b == '\n' || b == 0x0b || b == 0x0c)  // LF/VT/FF
				line_feed();
			else if (b == '\b') {
				if (cur_col > 0)
					cur_col--;
				wrap_pending = 0;
			}
			else if (b == '\t') {
				cur_col = (cur_col + TAB_STOP) & ~(TAB_STOP - 1);
				if (cur_col >= tui_cols())
					cur_col = tui_cols() - 1;
				wrap_pending = 0;
			}
			else if (b == 0x07) {
				// BEL: nothing
			}
			else if (b >= GLYPH_FIRST_ASCII)
				put_char(b);
			break;
		case P_ESC:
			if      (b == '[') {
				pstate = P_CSI;
				nparm = 0;
				parm[0] = 0;
				csi_priv = 0;
			}
			else if (b == '(' || b == ')')  // designate G0/G1
				pstate = P_CHARSET;
			else {
				esc(b);
				pstate = P_GROUND;
			}
			break;
		case P_CSI:
			if (b == '?' ) {
				csi_priv = 1;
			}
			else if (b >= '0' && b <= '9') {
				if (nparm == 0)
					nparm = 1;
				if (nparm <= CSI_PARAM_MAX)
					parm[nparm - 1] = parm[nparm - 1] * 10 + (b - '0');
			}
			else if (b == ';') {
				if (nparm < CSI_PARAM_MAX)
					parm[nparm++] = 0;
			}
			else if (b >= 0x40 && b <= 0x7e) {  // final byte
				csi(b);
				pstate = P_GROUND;
			}
			else if (b == 0x1b)  // aborted: a new ESC
				pstate = P_ESC;
			// other intermediate bytes: stay in CSI
			break;
		case P_CHARSET:
			pen.acs = (b == '0');   // '0' = DEC graphics; anything else = ASCII
			pstate = P_GROUND;
			break;
		}
	}
	set_cursor();
}

// ---- the grid --------------------------------------------------------------

int tui_font(void)  { return font_index; }
int tui_cols(void)  { return font->cols; }
int tui_rows(void)  { return font->rows; }
int tui_cells(void) { return font->cols * font->rows; }
int tui_cw(void)    { return font->cw; }
int tui_ch(void)    { return font->ch; }

static inline void mark_cell_dirty(int off)
{
	int r = off / font->cols;
	int c = off % font->cols;
	if (!row_dirty[r]) {
		row_dirty[r] = 1;
		row_first_dirty_col[r] = (uint8_t)c;
		row_last_dirty_col[r] = (uint8_t)c;
	}
	else {
		if (c < row_first_dirty_col[r])
			row_first_dirty_col[r] = (uint8_t)c;
		if (c > row_last_dirty_col[r])
			row_last_dirty_col[r] = (uint8_t)c;
	}
}

void tui_init(void)
{
	int n = font->cols * font->rows;
	for (int i = 0; i < n; i++)
		cells[i] = TC_BLANK;
	cur_off = -1;
	tui_invalidate_all();
}

void tui_reset(void) { tui_init(); }

void tui_invalidate_all(void)
{
	int n = font->cols * font->rows;
	for (int i = 0; i < n; i++)
		cells[i] |= TC_DIRTY;
	for (int r = 0; r < font->rows; r++) {
		row_dirty[r] = 1;
		row_first_dirty_col[r] = 0;
		row_last_dirty_col[r] = (uint8_t)(font->cols - 1);
	}
	scan_row = 0;
}

void tui_set_font(int profile)
{
	if (profile < 0 || profile >= TUI_FONT_COUNT || profile == font_index)
		return;
	font_index = profile;
	font = &profiles[profile];
	tui_init();
}

void tui_poke(uint16_t off, uint16_t cell)
{
	if (off >= (uint16_t)(font->cols * font->rows))
		return;
	uint16_t *p = &cells[off];
	if ((*p & TC_VAL_MASK) == (cell & TC_VAL_MASK))
		return;
	*p = (uint16_t)((cell & TC_VAL_MASK) | TC_DIRTY);
	mark_cell_dirty(off);
}

void tui_run(uint16_t off, uint16_t n, const uint8_t *chars, uint16_t attr_bits)
{
	int cap = font->cols * font->rows;
	if (off >= cap)
		return;
	if ((int)off + n > cap)
		n = (uint16_t)(cap - off);
	for (uint16_t i = 0; i < n; i++)
		tui_poke((uint16_t)(off + i), (uint16_t)(chars[i] | attr_bits));
}

void tui_fill(uint16_t off, uint16_t n, uint16_t cell)
{
	int cap = font->cols * font->rows;
	if (off >= cap)
		return;
	if ((int)off + n > cap)
		n = (uint16_t)(cap - off);
	for (uint16_t i = 0; i < n; i++)
		tui_poke((uint16_t)(off + i), cell);
}

void tui_scroll(int top, int bot, int delta)
{
	if (delta == 0)
		return;
	if (top < 0)
		top = 0;
	if (bot >= font->rows)
		bot = font->rows - 1;
	if (top > bot)
		return;
	int cols = font->cols;
	if (delta > 0) {
		for (int r = top; r <= bot; r++) {
			int src = r + delta;
			for (int c = 0; c < cols; c++) {
				uint16_t v = TC_BLANK;
				if (src <= bot)
					v = cells[src * cols + c];
				tui_poke((uint16_t)(r * cols + c), (uint16_t)(v & TC_VAL_MASK));
			}
		}
	} else {
		for (int r = bot; r >= top; r--) {
			int src = r + delta;
			for (int c = 0; c < cols; c++) {
				uint16_t v = TC_BLANK;
				if (src >= top)
					v = cells[src * cols + c];
				tui_poke((uint16_t)(r * cols + c), (uint16_t)(v & TC_VAL_MASK));
			}
		}
	}
}

// Flatten the grid into character and attribute arrays.
#define SNAP_ATTR_REVERSE   0x01
#define SNAP_ATTR_BOLD      0x02
#define SNAP_ATTR_UNDERLINE 0x04
#define SNAP_ATTR_FG_SHIFT  3
#define SNAP_ATTR_FG_MASK   0x78

void tui_snapshot(uint8_t *chars, uint8_t *attrs)
{
	int n = font->cols * font->rows;
	for (int i = 0; i < n; i++) {
		uint16_t v = cells[i];
		chars[i] = (uint8_t)(v & TC_CHAR_MASK);
		uint8_t attr = 0;
		if (v & TC_REVERSE)
			attr |= SNAP_ATTR_REVERSE;
		if (v & TC_BOLD)
			attr |= SNAP_ATTR_BOLD;
		if (v & TC_UNDERLINE)
			attr |= SNAP_ATTR_UNDERLINE;
		uint8_t fg = (uint8_t)((v & TC_FG_MASK) >> TC_FG_SHIFT);
		attr |= (uint8_t)((fg << SNAP_ATTR_FG_SHIFT) & SNAP_ATTR_FG_MASK);
		attrs[i] = attr;
	}
}

void tui_cursor(int32_t off)
{
	if (off == cur_off)
		return;
	int32_t old = cur_off;
	int cap = font->cols * font->rows;
	if (off >= 0 && off < cap)
		cur_off = off;
	else
		cur_off = -1;
	cur_blink_on = true;
	cur_blink_last = millis();
	if (old >= 0 && old < cap) {
		cells[old] |= TC_DIRTY;
		mark_cell_dirty((int)old);
	}
	if (cur_off >= 0) {
		cells[cur_off] |= TC_DIRTY;
		mark_cell_dirty((int)cur_off);
	}
}

bool tui_dirty(void)
{
	for (int r = 0; r < font->rows; r++) {
		if (row_dirty[r])
			return true;
	}
	return false;
}

// Compose row r's dirty span into scratch and push it to the panel.
static void paint_row(int r, uint16_t *scratch, unsigned scratch_px)
{
	const int cell_w = font->cw;
	const int cell_h = font->ch;
	const int cols = font->cols;
	int first_col = row_first_dirty_col[r];
	int last_col = row_last_dirty_col[r];
	int w = (last_col - first_col + 1) * cell_w;
	if (w <= 0)
		return;
	if ((unsigned)(w * cell_h) > scratch_px) {
		last_col = first_col + (int)(scratch_px / cell_h) / cell_w - 1;
		w = (last_col - first_col + 1) * cell_w;
		if (w <= 0)
			return;
	}

	for (int c = first_col; c <= last_col; c++) {
		uint16_t cell = cells[r * cols + c];
		uint8_t  ch   = (uint8_t)(cell & TC_CHAR_MASK);
		bool reversed = (cell & TC_REVERSE) != 0;
		bool cursor_shown = (cur_off >= 0 && cur_off == r * cols + c && cur_blink_on);
		if (cursor_shown)
			reversed = !reversed;

		const uint8_t *glyph;
		if      (ch >= GLYPH_FIRST_ASCII && ch <= GLYPH_LAST_ASCII)
			glyph = font->text + (ch - GLYPH_FIRST_ASCII) * cell_h;
		else if (ch >= GLYPH_BOX_BASE && ch < GLYPH_BOX_BASE + GLYPH_BOX_COUNT)
			glyph = font->box  + (ch - GLYPH_BOX_BASE) * cell_h;
		else
			glyph = font->text;   // space

		uint16_t colour = (uint16_t)((cell & TC_FG_MASK) >> TC_FG_SHIFT);
		if ((cell & TC_BOLD) && colour < TUI_PALETTE_BRIGHT_BASE)
			colour += TUI_PALETTE_BRIGHT_BASE;
		if (cursor_shown)
			colour = TC_FG_DEFAULT;
		uint16_t fg = tui_pal[colour % TUI_PALETTE_SIZE];
		uint16_t bg = 0x0000;
		if (reversed) {
			uint16_t swap = fg;
			fg = bg;
			bg = swap;
		}

		for (int y = 0; y < cell_h; y++) {
			uint8_t bits = glyph[y];
			if (cell & TC_UNDERLINE && y == cell_h - 2)
				bits = 0xFF;
			for (int x = 0; x < cell_w; x++) {
				bool on = (bits >> (GLYPH_BITS_PER_ROW - 1 - x)) & 1;
				uint16_t px = bg;
				if (on)
					px = fg;
				scratch[y * w + (c - first_col) * cell_w + x] = px;
			}
		}
		cells[r * cols + c] &= (uint16_t)~TC_DIRTY;
	}
	panel_push_band(TUI_X0 + first_col * cell_w, TUI_TOP_Y + r * cell_h,
	                w, cell_h, scratch);
	row_dirty[r] = 0;
}

void tui_full_clear(void)
{
	panel_fill(0, 0, panel_width(), panel_height(), false);
}

void tui_pump(uint32_t budget_us)
{
	if (cur_off >= 0) {
		uint32_t now = millis();
		if ((uint32_t)(now - cur_blink_last) >= tui_cursor_blink_ms) {
			cur_blink_last = now;
			cur_blink_on   = !cur_blink_on;
			cells[cur_off] |= TC_DIRTY;
			mark_cell_dirty((int)cur_off);
		}
	}

	unsigned bytes = 0;
	uint16_t *scratch = panel_scratch(&bytes);
	if (!scratch)
		return;
	unsigned scratch_px = bytes / 2;

	uint32_t started_us = micros();
	for (int i = 0; i < font->rows; i++) {
		int r = (scan_row + i) % font->rows;
		if (!row_dirty[r])
			continue;
		paint_row(r, scratch, scratch_px);
		if ((uint32_t)(micros() - started_us) > budget_us) {
			scan_row = (r + 1) % font->rows;
			return;
		}
	}
	scan_row = 0;
}

// ---- the screen ------------------------------------------------------------

static int term_load_font_profile(void) {
	if (device_record.term_font == TERM_FONT_STORED_6X12)
		return TUI_FONT_6X12;
	return TUI_FONT_8X16;
}

static void term_save_font_profile(int profile) {
	uint8_t stored = TERM_FONT_STORED_8X16;
	if (profile == TUI_FONT_6X12)
		stored = TERM_FONT_STORED_6X12;
	if (device_record.term_font == stored)
		return;
	device_record.term_font = stored;
	flag_save_block = 1;
}

// Plain ASCII, <= 58 columns so it fits the 60x18 grid.
static void term_show_help(void) {
	static const char *help =
		"\r\n"
		"         XYFR TERMINAL  -  KEY HELP\r\n"
		"\r\n"
		"  L / R arrow   move the cursor left / right\r\n"
		"  Up / Down     hold aA (or Sym), then L=Up R=Down\r\n"
		"  ESC  (vim)    Sym2 + Q   (Sym2 = hold or 2x Sym)\r\n"
		"  Ctrl + key    tap aA then Sym, then a letter\r\n"
		"  Tab = Ctrl-I     Enter = Ent     Bksp deletes\r\n"
		"  Leave term    Sym + Bksp\r\n";
	ansi_feed((const uint8_t *)help, (int)strlen(help));
	const char *mark_small = "";
	const char *mark_big   = " *";
	if (tui_font() == TUI_FONT_6X12) {
		mark_small = " *";
		mark_big   = "";
	}
	char line[96];
	int n = snprintf(line, sizeof line,
		"\r\n"
		"  Screen   [B] 60x18%s    [W] 80x25%s\r\n"
		"           any other key starts the terminal\r\n",
		mark_big, mark_small);
	if (n > 0)
		ansi_feed((const uint8_t *)line, n);
}

// The terminal owns the panel while it is up: the view engine stands down.
bool terminal_grid_active(void) { return term_peer != 0; }
bool terminal_active(void)      { return term_peer != 0; }

static void term_tx_push(const uint8_t *b, int n) {
	for (int i = 0; i < n; i++) {
		uint16_t next = (uint16_t)((term_tx_head + 1) % TERM_TX_RING);
		if (next == term_tx_tail) {
			hal_debug(LOG_WARNING, "term: tx ring full, dropping\n");
			return;
		}
		term_tx_buf[term_tx_head] = b[i];
		term_tx_head = next;
	}
}

// As much as the window will take in one write, so typing runs at the speed
// of the typist rather than one keystroke per RTT.
static void term_tx_drain(void) {
	if (term_tx_head == term_tx_tail || !term_peer)
		return;
	int room = stream_can_write(term_stream, term_peer);
	if (room <= 0)
		return;
	uint8_t out[TERM_TX_SEGMENT];
	int n = 0;
	uint16_t at = term_tx_tail;
	while (at != term_tx_head && n < (int)sizeof out && n < room) {
		out[n++] = term_tx_buf[at];
		at = (uint16_t)((at + 1) % TERM_TX_RING);
	}
	int sent = stream_write(term_stream, term_peer, out, n);
	if (sent <= 0)
		return;
	term_tx_tail = (uint16_t)((term_tx_tail + sent) % TERM_TX_RING);
}

static void put_seq(uint8_t *seq, int *n, uint8_t a, uint8_t b, uint8_t c) {
	*n = 0;
	seq[(*n)++] = a;
	if (b)
		seq[(*n)++] = b;
	if (c)
		seq[(*n)++] = c;
}

// One key to the bytes a shell expects. With symbol held, the two space keys
// are Left/Right and the nav keys are Esc/Tab.
static int key_to_bytes(int key, uint8_t *seq) {
	int n = 0;
	uint16_t mods = keyboard_get_modifiers();
	if (mods & KBD_MOD_SYMBOL) {
		if (key == ' ' && (mods & KBD_MOD_SP1))
			key = VIEW_K_LEFT;
		else if (key == ' ' && (mods & KBD_MOD_SP2))
			key = VIEW_K_RIGHT;
		else if (key == VIEW_K_UP)
			key = 0x1b;
		else if (key == VIEW_K_DOWN)
			key = '\t';
	}
	// Arrows first: their codes collide with the control range.
	if (key == VIEW_K_UP)
		put_seq(seq, &n, 0x1b, '[', 'A');
	else if (key == VIEW_K_DOWN)
		put_seq(seq, &n, 0x1b, '[', 'B');
	else if (key == VIEW_K_RIGHT)
		put_seq(seq, &n, 0x1b, '[', 'C');
	else if (key == VIEW_K_LEFT)
		put_seq(seq, &n, 0x1b, '[', 'D');
	else if (key == '\n')
		put_seq(seq, &n, '\r', 0, 0);
	else if (key == '\b')
		put_seq(seq, &n, 0x7f, 0, 0);      // backspace -> DEL
	else if (key >= 0x20 && key < 0x7f)
		put_seq(seq, &n, (uint8_t)key, 0, 0);
	else if (key < 0x20)
		put_seq(seq, &n, (uint8_t)key, 0, 0);   // Ctrl-C, Ctrl-D, Tab, ESC
	return n;
}

int app_terminal_main(int message, uint32_t param) {
	switch (message) {

	case APP_INIT:
		term_stream = kernel_listen_stream(PORT_TERM, app_terminal_main);
		if (!term_stream)
			hal_debug(LOG_ERROR, "term: PORT_TERM already bound\n");
		return 1;

	case APP_FOREGROUND:
		term_peer = param;
		view_set(NULL, NULL, NULL, NULL, NULL, NULL);
		screen_title("Terminal");
		tui_set_font(term_load_font_profile());
		ansi_reset();                  // one parser: never resume mid-sequence from another peer
		tui_reset();
		tui_full_clear();
		term_help = true;
		term_show_help();
		return 1;

	case APP_BACKGROUND:
		term_peer = 0;
		return 1;

	case APP_KEYSTROKE: {
		if ((int)param == VIEW_K_BACKSPACE)
			return 0;
		if (!term_peer)
			return 0;
		if (term_help) {
			int key = (int)param;
			if (key == 'b' || key == 'B' || key == 'w' || key == 'W') {
				int profile = TUI_FONT_8X16;
				if (key == 'w' || key == 'W')
					profile = TUI_FONT_6X12;
				tui_set_font(profile);
				term_save_font_profile(profile);
				ansi_reset();
				tui_reset();
				term_show_help();          // the '*' moves
				return 1;
			}
			term_help = false;
			ansi_reset();
			tui_reset();
			// The first write is the session: the host forks a shell or
			// reattaches to ours. Ctrl-L repaints either way.
			uint8_t form_feed = 0x0c;
			term_tx_push(&form_feed, 1);
			term_tx_drain();
			return 1;
		}
		uint8_t seq[4];
		int n = key_to_bytes((int)param, seq);
		if (n > 0) {
			term_tx_push(seq, n);
			term_tx_drain();
		}
		return 1;
	}

	case NOTIFY_STREAM_DATA:
		if (param != term_peer)        // unread, so that peer's shell stalls
			return 1;
		for (;;) {
			uint8_t buf[TERM_TX_SEGMENT];
			int n = stream_read(term_stream, param, buf, (int)sizeof buf);
			if (n <= 0)
				break;
			hal_debug(LOG_EVERYTHING, "term: rx %d from %08x\n", n, (unsigned)param);
			ansi_feed(buf, n);
		}
		return 1;

	case APP_PUMP:
		if (!term_peer)
			return 0;
		term_tx_drain();
		if (keyboard_sym2_popup())     // the picker overlays the grid; hold still
			return 1;
		{
			static bool last_ctrl = false;
			static bool named     = false;
			bool ctrl = keyboard_ctrl_armed();
			if (!named || ctrl != last_ctrl) {   // an armed Ctrl must show at once
				named     = true;
				last_ctrl = ctrl;
				if (ctrl)
					screen_title("Terminal  ^");
				else
					screen_title("Terminal");
			}
		}
		if (call_holding_audio())
			tui_pump(TUI_BUDGET_IN_CALL_US);
		else
			tui_pump(TUI_BUDGET_US);
		return 1;
	}
	return 0;
}
