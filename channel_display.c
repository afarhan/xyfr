// channel_display.c — the device side of app_channel.c's display seam.
//
// A channel prints text, so the terminal's cell grid and its parser are exactly
// the display it needs: tui.h stores and paints, ansi.h turns the host's bytes
// into cells, newlines and scrolling included.
//
// The screen is the grid split in two. The 8x16 face gives 60x18, and the
// bottom two rows are the composer with a rule above them; the text area is
// confined to what is left by setting the parser's own scroll region, so
// arriving lines can never scroll into the box.
//
// The monospace face is not a compromise here. A channel is lines of text from
// several people, and a fixed pitch is what makes the names line up.

#include <string.h>
#include <stdio.h>
#include "tui.h"
#include "ansi.h"
#include "view.h"          // VIEW_K_* — the neutral key codes
#include "display_backend.h"   // panel_fill — the same seam the grid paints through

// A whole request is composed here before it is sent, so the buffer is sized
// for one, not for the three rows that show it: the viewport scrolls over the
// text instead of the text being clipped to fit.
#define CHANNEL_EDIT_ROWS  3
#define CHANNEL_EDIT_MAX   1000

static char edit_buf[CHANNEL_EDIT_MAX + 1];
static int  edit_len;
static int  edit_cursor;              // where the caret sits, 0..edit_len
static int  edit_top;                 // first character shown, on a row boundary

static int text_rows(void) {
	return tui_rows() - CHANNEL_EDIT_ROWS;
}

// What one screenful of the log area holds. The ring keeps this much and the
// renderer walks this far forward from the top, so both come from here.
int channel_display_capacity(void) {
	return text_rows() * tui_cols();
}

// The last scanline of the last text row: the composer starts on the next one,
// so the rule sits between them and belongs to neither.
static int rule_y(void) {
	return TUI_TOP_Y + text_rows() * tui_ch() - 1;
}

static void draw_rule(void) {
	panel_fill(0, rule_y(), panel_width(), 1, true);
}

// The composer, straight into the grid: same face, same painting, and the
// cursor is a reversed cell rather than anything the panel has to know about.
// Keep the caret inside the viewport, scrolling by whole rows so the text does
// not shift sideways under the eye as it is typed.
static void edit_follow_caret(int cols, int room) {
	if (edit_cursor < edit_top)
		edit_top = (edit_cursor / cols) * cols;
	if (edit_cursor >= edit_top + room) {
		int want = edit_cursor - room + 1;
		edit_top = ((want + cols - 1) / cols) * cols;
	}
	if (edit_top > edit_len)
		edit_top = (edit_len / cols) * cols;
	if (edit_top < 0)
		edit_top = 0;
}

static void draw_edit(void) {
	int cols = tui_cols();
	uint16_t base = (uint16_t)(text_rows() * cols);
	int room = CHANNEL_EDIT_ROWS * cols - 1;
	tui_fill(base, (uint16_t)(CHANNEL_EDIT_ROWS * cols), TC_BLANK);
	edit_follow_caret(cols, room);
	int n = edit_len - edit_top;
	if (n > room)
		n = room;
	// Attribute bits carry the colour: index 0 is BLACK, so typed text needs
	// the same default foreground a blank cell already has.
	if (n > 0)
		tui_run(base, (uint16_t)n, (const uint8_t *)edit_buf + edit_top,
		        TC_FG_DEFAULT << TC_FG_SHIFT);
	int caret = edit_cursor - edit_top;
	if (caret < 0)
		caret = 0;
	if (caret > n)
		caret = n;
	uint16_t under = TC_BLANK;
	if (caret < n)
		under = (uint16_t)((TC_FG_DEFAULT << TC_FG_SHIFT) |
		                   (uint8_t)edit_buf[edit_top + caret]);
	tui_poke((uint16_t)(base + caret), (uint16_t)(under | TC_REVERSE));
	// The composer draws its own caret as a reversed cell, so the grid's cursor
	// would be a SECOND one blinking in the text above. Hidden here rather than
	// at reset because the parser turns it back on.
	tui_cursor(-1);
}

// Move the caret within the text. False means it was already at that edge, and
// the caller sends the key on -- which is how the arrows scroll the log once
// they run off the end of what you are typing.
bool channel_display_move(int dir) {
	if (dir < 0 && edit_cursor > 0) {
		edit_cursor--;
		draw_edit();
		return true;
	}
	if (dir > 0 && edit_cursor < edit_len) {
		edit_cursor++;
		draw_edit();
		return true;
	}
	return false;
}

void channel_display_reset(void) {
	tui_set_font(TUI_FONT_8X16);
	ansi_reset();
	tui_reset();
	tui_full_clear();
	edit_len = 0;
	edit_cursor = 0;
	edit_top = 0;
	edit_buf[0] = 0;
	// Confine the parser to the text area. DECSTBM is 1-based and inclusive,
	// so this is every row above the composer.
	char region[16];
	int n = snprintf(region, sizeof region, "\x1b[1;%dr", text_rows());
	ansi_feed((const uint8_t *)region, n);
	draw_edit();
	// No painting here: the engine clears the panel AFTER this returns, so
	// everything on screen is drawn from the pump, as the terminal does it.
}

// Wipe the text area and put the cursor at its top, leaving the composer and
// the rule alone. ESC[H homes within the scroll region; ESC[J clears to the end
// of it.
void channel_display_clear(void) {
	ansi_feed((const uint8_t *)"\x1b[H\x1b[J", 6);
}

void channel_display_text(const char *text, int len) {
	ansi_feed((const uint8_t *)text, len);
	draw_edit();
}

void channel_display_pump(void) {
	tui_pump(15000);
	draw_rule();
}

// True while backspace has something to delete. Below an empty composer it is
// the LEAVE gesture, which is the rule every other screen already follows.
bool channel_display_has_text(void) {
	return edit_len > 0;
}

// A key for the composer. Returns the finished line on Enter and NULL
// otherwise, so the caller decides what a line means.
const char *channel_display_key(int key) {
	if (key == VIEW_K_ENTER) {
		if (edit_len == 0)
			return NULL;
		edit_buf[edit_len] = 0;
		edit_len = 0;
		edit_cursor = 0;
		edit_top = 0;
		draw_edit();
		return edit_buf;           // the caller sends it before the next key
	}
	if (key == VIEW_K_BACKSPACE) {
		// Deletes what is BEFORE the caret, and the caret follows it back.
		if (edit_cursor > 0) {
			memmove(edit_buf + edit_cursor - 1, edit_buf + edit_cursor,
			        (size_t)(edit_len - edit_cursor));
			edit_cursor--;
			edit_len--;
		}
		draw_edit();
		return NULL;
	}
	if (key >= 0x20 && key < 0x7f && edit_len < CHANNEL_EDIT_MAX) {
		memmove(edit_buf + edit_cursor + 1, edit_buf + edit_cursor,
		        (size_t)(edit_len - edit_cursor));
		edit_buf[edit_cursor++] = (char)key;
		edit_len++;
		draw_edit();
	}
	return NULL;
}
