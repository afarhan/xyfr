// view_te.cpp — the TEXT ENGINE implementation of the view render backend
// (view_backend.h). No LVGL, no TFT_eSPI, no Adafruit_GFX: rows are composed by
// text_engine.cpp into a 4bpp coverage band and blitted one line at a time by
// ili9488.cpp. THE view backend -- there is no other. The view engine (view.cpp)
// and every screen callback are unchanged. Core 1 (UI) only.
//
// RETAINED, and not by preference. view.cpp's layout_topdown() re-runs the whole
// pass up to 128 times to converge the scroll onto the selection, so a backend
// that painted inside rb_row_set would repaint the screen 128 times per
// relayout. The rb_* calls therefore only update an in-RAM model and MEASURE
// (the engine needs the row height back immediately); te_view_present() — called
// once per ui_slice() after view_slice() — does the drawing.
//
// Where this differs from view_gfx.cpp, which is retained for the same reason:
// that backend clears the whole framebuffer and refreshes, which suits the Sharp
// and is impossible here. A full 480x320 frame is 460,800 bytes over SPI ~ 108
// ms. So present() DIFFS the model against what is already on the panel and
// repaints only the rows that changed — the same dirty-slot scheme list_box.cpp
// uses, where the drawn state IS the record and no per-row flag is needed.
//
// SCOPE (checkpoint 1): the list path — title, prompt, rows, separators, status
// dots. The editor is stubbed, as it is in view_gfx.cpp, so chat renders its
// messages but has no compose box yet.

#include "ui.h"

#include <Arduino.h>
#include <string.h>
#include <time.h>
#include "view.h"
#include "view_backend.h"
#include "view_theme.h"
#include "text_engine.h"
#include "ili9488.h"
#include "text_edit.h"
#include "kernel.h"     // screen_title_str() -- the kernel owns the screen's name
#include "netif.h"      // netif_peer  -- and its link state
#include "hal.h"        // TEMP trace
#include "terminal.h"   // terminal_grid_active() -- who owns the panel
#include "tui.h"        // tui_invalidate_all() -- ask the grid to repair itself
#include "audio.h"       // speaker_level -- the volume notch in the title bar

// ---- structs ---------------------------------------------------------------
// ROW_MAX: the shortest row is g_pad_top + mont14.height + g_pad_bottom = 26 px
// into a ~301 px viewport, so 12 fit plus a partial; 16 leaves headroom.
//
// ROW_TEXT must hold the LONGEST text any screen hands a row. That is the chat's
// 3-line preview, built into a CHAT_PREVIEW_HEAD+8 = 520 byte buffer
// (commands.cpp). Sizing this by eye cost a real bug: at 128 it silently chopped
// a 194-char preview to 127, taking the trailing " ..." with it, so a message
// rendered as two lines and a stub with no ellipsis. A retained backend OWNS the
// copy -- the item text is borrowed and gone by the time present() draws -- so
// the buffer is load-bearing, not a convenience.
#define ROW_MAX   16
#define ROW_TEXT  544
#define ROW_META  48

typedef struct {
	bool used;                 // a visible row in the committed model
	bool acq;                  // acquired during the in-progress layout pass
	char text[ROW_TEXT];
	char meta[ROW_META];
	bool has_meta;
	bool meta_inline;
	int  style;
	int  top;                  // y of the row's top edge, list-local (0 = list top)
	int  h;
	bool selected;
	bool separator;
	int  dot;
} TeRow;

// WHAT IS ON THE PANEL. The dirty scheme's whole state -- and deliberately NOT a
// TeRow. This side is only ever COMPARED against g_rows and read for erase
// geometry (top/h); its text is never drawn from, never measured, never read
// back. Keeping a second full copy of every row's text cost 16 x ~592 bytes to
// answer one yes/no question per row, so it keeps a 64-bit hash instead: the
// same diff, 9.4 KB cheaper.
//
// A hash collision would leave one row stale until the next full repaint (any
// view change sets g_full). At 64 bits that is not a risk worth costing out;
// the reason it is 64 and not 32 is that the wider hash costs 64 bytes total
// and removes the need to reason about it at all.
typedef struct {
	bool     used;
	uint64_t hash;             // over text, and meta when has_meta
	bool     has_meta;
	bool     meta_inline;
	bool     selected;
	bool     separator;
	int      style;
	int      top;              // y of the row's top edge, list-local (0 = list top)
	int      h;
	int      dot;
} TeShown;

extern "C" time_t get_current_time_seconds();     // ui.cpp (UTC epoch seconds)
extern char wifi_indicator_str[];                 // wifi_ui.cpp / ui.h
extern "C" time_t net_time(void);                 // netif.c -- 0 until NTP lands

// Title-bar telemetry. batt_adc_raw is published by audio.cpp's ADC round-robin;
// it must NOT be read with a bare analogRead(A0), which tears down the mic's
// shared-ADC DMA and kills capture.
extern volatile int batt_adc_raw;                 // audio.cpp -- latest raw A0 sample
extern int          batt_fullscale_mv;            // audio.cpp -- pack mV at raw 4095 (`bv` calibrates)

extern const tfont_t mont14;                      // body
extern const tfont_t mont10;                      // title bar + meta subtitle
extern const tfont_t fixed8x16;                   // tamzen_tfont.c: 8x16 MONOSPACE

// ---- geometry ---------------------------------------------------------------
#define MARGIN_X   6
// Fixed 20 px, and the BODY font: the bar carries icons (battery, volume, wifi,
// the signed-in eye) and the small face rendered them too faintly to read at a
// glance. 20 - mont14.height(16) = 4, so 2 px above and below.
// UI_TITLE_H (ui.h) is the one copy of the height, because an app that paints
// its own body needs the same number this bar is drawn at.
#define TITLE_H    UI_TITLE_H
#define TITLE_PAD  ((TITLE_H - mont14.height) / 2)
// The prompt is a WRAPPED BLOCK, not a one-liner: it renders in the body font and
// grows to as many lines as the text needs, honouring '\n' as a hard break (the
// engine's text_wrap_next already breaks on it — the old single-line rect just
// never gave it the chance, so every prompt was one small truncated line).
// Capped so a long prompt can't crowd out the list it is explaining; past the cap
// it ellipses as before.
#define PROMPT_PAD 6
#define PROMPT_MAX_H (ILI_H / 3)
#define DOT_W      14                             // gutter the status dot insets by

// ---- editor zone ------------------------------------------------------------
// FIXED height in both modes -- nothing grows, so rb_list_height() is a constant
// per mode and rb_edit_autosize() is always false.
//
// The margins are load-bearing, not taste. A single-line field must hold
// max_len * tfont_max_width() with NO horizontal scrolling, and the widest field
// is the 29-character contact name: 29 * 16 = 464 px. At these insets the field
// is 480 - 2*3 - 2(border) - 2*2 = 468 px, so it fits with 4 px spare. Add a Go
// button (60 + 5 gap) and it drops to 397 -- which is why single-line has no Go:
// Enter commits there, so the button was redundant anyway.
#define EDIT_M     3     // inset from the panel edge
#define EDIT_PAD   2     // inner padding between border and text
#define GO_W       60    // Go button (multiline only)
#define GO_GAP     5
#define EDIT_LINES_MULTI 3

// The theme speaks 0xRRGGBB; the panel speaks RGB565.
static inline uint16_t c565(uint32_t c) {
	return rgb((uint8_t)(c >> 16), (uint8_t)(c >> 8), (uint8_t)c);
}

// ---- the retained model -----------------------------------------------------

static TeRow g_rows[ROW_MAX];

static TeShown g_shown[ROW_MAX];
static char  g_prompt[256];   // 96 silently truncated real prompts (the delete
                              // confirmations run to ~220 chars)
static bool  g_prompt_shown = false;
static int   g_prompt_h = 0;  // measured band height incl. padding (0 = hidden)
static int   g_pad_top = 5, g_pad_bottom = 5;
static int   g_dock = 0;            // extra offset pushing the list down toward the editor
static bool  g_owns = false;        // this backend owns the panel (rb_show/rb_hide)
static bool  g_full = true;         // next present() repaints everything
static bool  g_chrome = true;       // next present() repaints title + prompt

// ---- editor state -----------------------------------------------------------
// rb_edit_* only RECORD; the single edit_open happens lazily in ensure_editor(),
// because view_set calls rb_edit_show() first and the screen then adjusts the
// mode and the cap afterwards (the "call after view_set" idiom). Opening once,
// late, avoids reopening the editor two or three times per navigation.
static bool  g_edit_shown = false;
static bool  g_edit_multi = false;
static int   g_edit_max   = 0;
static bool  g_edit_focus = false;
static bool  g_go_focus   = false;
static bool  g_edit_cfg   = false;   // config changed -> reopen, preserving text
static bool  g_edit_open  = false;   // edit_open has been called for this screen
static bool  g_edit_chrome = true;   // the BOX (border/fill/Go) needs a repaint
static char  g_edit_pre[576];        // prefill, COPIED: a caller may hand back edit_text()

static int edit_lines_n(void)  { return g_edit_multi ? EDIT_LINES_MULTI : 1; }
static int edit_box_h(void)    { return 2 + 2 * EDIT_PAD + edit_lines_n() * mont14.height; }
static int edit_zone_h(void)   { return g_edit_shown ? edit_box_h() + 2 * EDIT_M : 0; }
static bool edit_has_go(void)  { return g_edit_multi; }   // single-line commits on Enter

// The TEXT rect inside the border and padding.
static trect_t edit_rect(void) {
	int box_y = ILI_H - edit_zone_h() + EDIT_M;
	int w = ILI_W - 2 * EDIT_M - 2 - 2 * EDIT_PAD - (edit_has_go() ? (GO_W + GO_GAP) : 0);
	trect_t r = { (int16_t)(EDIT_M + 1 + EDIT_PAD), (int16_t)(box_y + 1 + EDIT_PAD),
	              (int16_t)(w > 0 ? w : 1), (int16_t)(edit_lines_n() * mont14.height) };
	return r;
}

// Open (or reopen) the editor for the current config, preserving what is typed.
static void ensure_editor(void) {
	if (!g_edit_shown)
		return;
	if (g_edit_open && !g_edit_cfg)
		return;

	static char keep[576];
	keep[0] = 0;
	if (g_edit_open) {
		const char *t = edit_text();
		strncpy(keep, t ? t : "", sizeof keep - 1);
		keep[sizeof keep - 1] = 0;
	} else {
		strncpy(keep, g_edit_pre, sizeof keep - 1);
		keep[sizeof keep - 1] = 0;
	}

	trect_t r = edit_rect();
	edit_open(&r, &mont14, g_edit_multi, NULL, g_edit_max,
	          c565(view_theme->edit_fg), c565(view_theme->edit_bg));
	for (const char *p = keep; *p; p++)
		edit_insert(*p);
	edit_set_focus(g_edit_focus);      // a fresh editor must not show a caret it has not earned

	g_edit_open   = true;
	g_edit_cfg    = false;
	g_edit_chrome = true;              // the box was re-laid-out
	g_full        = true;              // the zone moved: the list origin moved with it
}

// Two rows are the same PICTURE if every field present() draws from matches.
// FNV-1a, 64-bit. Not a security hash -- it decides whether a row needs
// repainting, and it is here because it is four lines and has no table.
static uint64_t fnv1a(uint64_t h, const char *s) {
	while (*s) {
		h ^= (unsigned char)*s++;
		h *= 1099511628211ULL;
	}
	return h;
}

static uint64_t row_hash(const TeRow *r) {
	uint64_t h = fnv1a(1469598103934665603ULL, r->text);
	if (r->has_meta)
		h = fnv1a(h ^ 0x5bf03635ULL, r->meta);   // separator: "ab"+"c" != "a"+"bc"
	return h;
}

static bool row_same(const TeRow *a, const TeShown *b) {
	if (a->used != b->used)
		return false;
	if (!a->used)  // both unused: nothing drawn either way
		return true;
	return a->top == b->top && a->h == b->h &&
	       a->selected == b->selected && a->separator == b->separator &&
	       a->dot == b->dot && a->style == b->style &&
	       a->has_meta == b->has_meta && a->meta_inline == b->meta_inline &&
	       row_hash(a) == b->hash;
}

// Record a painted row: geometry and flags verbatim, text as its hash.
static void shown_set(TeShown *d, const TeRow *r) {
	d->used        = r->used;
	d->hash        = r->used ? row_hash(r) : 0;
	d->has_meta    = r->has_meta;
	d->meta_inline = r->meta_inline;
	d->selected    = r->selected;
	d->separator   = r->separator;
	d->style       = r->style;
	d->top         = r->top;
	d->h           = r->h;
	d->dot         = r->dot;
}

// ---- lifecycle --------------------------------------------------------------
void rb_init(void) {
	memset(g_rows, 0, sizeof g_rows);
	memset(g_shown, 0, sizeof g_shown);
	g_prompt[0] = 0;
	g_prompt_shown = false;
	g_dock = 0;
	g_full = g_chrome = true;
}

// THE CLEAR HAPPENS NOW, not at the next present(). A screen is opened from
// APP_FOREGROUND and kernel_slice runs APP_PUMP in the SAME tick, so a deferred
// clear lands AFTER the app's first paint and before its second -- and an app
// that paints on change (every screen with a body of its own: the terminal, PTT)
// never redraws, so its body appears for one frame and then vanishes. Clearing
// here puts it before any app paint, where a "nothing on the panel is trusted"
// wipe belongs. g_full still marks the BOOKKEEPING as untrusted for present().
void rb_show(void) {
	g_owns = true;
	g_full = g_chrome = true;
	memset(g_shown, 0, sizeof g_shown);
	draw_rect(0, 0, ILI_W, ILI_H, c565(view_theme->screen_bg));
}

void rb_hide(void) {
	g_owns = false;
}

// ---- geometry queries -------------------------------------------------------
int rb_list_top(void)   { return TITLE_H + (g_prompt_shown ? g_prompt_h : 0); }
int rb_list_height(void){ return ILI_H - rb_list_top() - edit_zone_h(); }
int rb_list_width(void) { return ILI_W - 2 * MARGIN_X; }
int rb_row_text_width(bool has_dot) { return rb_list_width() - (has_dot ? DOT_W : 0); }

void rb_row_pad_set(int top, int bottom) {
	g_pad_top = top;
	g_pad_bottom = bottom;
}

// ---- body wrap helpers ------------------------------------------------------
// Same greedy-on-whitespace rule draw_string uses, so a measured preview and the
// rendered row agree. (rb_body_set_fixed is a no-op until a fixed-width tfont is
// converted — the terminal/full-text view is not part of checkpoint 1.)
void rb_body_set_fixed(bool on) { (void)on; }

int rb_body_cols(void) {
	int adv = text_width(&mont14, "0");             // digits are the widest common case
	int c = adv > 0 ? rb_list_width() / adv : 1;
	if (c > 0)
		return c;
	return 1;
}

uint32_t rb_body_wrap_next(const char *in, uint32_t *display_len) {
	int show = 0;
	int adv = text_wrap_next(&mont14, in, rb_list_width(), &show);
	if (display_len)
		*display_len = (uint32_t)show;
	return (uint32_t)adv;
}

void rb_body_preview(const char *in, bool in_more, int maxlines, char *out, int cap) {
	const int W = rb_list_width();

	// Pass 1: walk up to maxlines at full width and see whether anything is left.
	const char *p = in;
	int lines = 0;
	while (*p && lines < maxlines) {
		int adv = text_wrap_next(&mont14, p, W, NULL);
		if (adv <= 0)
			break;
		p += adv;
		lines++;
	}
	bool truncated = (*p != 0) || in_more;

	// Pass 2, only if it will be ellipsised: redo with the LAST line narrowed by
	// the width of " ...". Appending the suffix to a last line that already fills
	// its width can only push it onto line maxlines+1 -- the row comes out a line
	// taller than asked, with the ellipsis stranded alone on it. Reserving the
	// room while wrapping is the only way to land on exactly maxlines.
	if (truncated) {
		int ell = text_width(&mont14, " ...");
		p = in;
		lines = 0;
		while (*p && lines < maxlines) {
			int w = (lines == maxlines - 1) ? (W - ell) : W;
			if (w < 1)
				w = 1;
			int adv = text_wrap_next(&mont14, p, w, NULL);
			if (adv <= 0)
				break;
			p += adv;
			lines++;
		}
	}

	// Copy the SOURCE SPAN verbatim rather than re-joining the wrapped lines:
	// re-joining has to invent a separator, and at a hard break there was no
	// space there to restore. Re-wrapping the span reproduces the same lines,
	// because the wrap rule is deterministic.
	int n = (int)(p - in);
	if (n > cap - 5)
		n = cap - 5;
	if (n < 0)
		n = 0;
	memcpy(out, in, (size_t)n);
	while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\n'))  // swallowed by the advance
		n--;
	if (truncated && n < cap - 5) {
		const char *e = " ...";
		for (int j = 0; e[j] && n < cap - 1; j++)
			out[n++] = e[j];
	}
	out[n] = 0;
}

// ---- title / prompt / chrome ------------------------------------------------
// The NAME lives in the kernel (screen_title), not here: a screen with no list
// is named the same way as one with a list, and this backend keeps no copy to
// fall out of step. view_set() reaches the kernel through this call, so a list
// screen is still named just by being built.
void rb_title(const char *text) {
	screen_title(text);
	g_chrome = true;
}

void rb_prompt(const char *text_or_null) {
	bool was = g_prompt_shown;
	if (!text_or_null || !text_or_null[0]) {
		g_prompt_shown = false;
		g_prompt[0] = 0;
	} else {
		g_prompt_shown = true;
		strncpy(g_prompt, text_or_null, sizeof g_prompt - 1);
		g_prompt[sizeof g_prompt - 1] = 0;
	}
	int old_h = g_prompt_h;
	if (g_prompt_shown) {
		const tfont_t *pf = view_theme->font_body;
		int h = measure_text(pf, g_prompt, ILI_W - 2 * MARGIN_X, PROMPT_MAX_H);
		if (h < pf->height)
			h = pf->height;                         // never collapse to nothing
		g_prompt_h = h + PROMPT_PAD;
	} else {
		g_prompt_h = 0;
	}
	g_chrome = true;
	if (was != g_prompt_shown || old_h != g_prompt_h)
		g_full = true;                              // the list origin moved: everything shifts
}

// Defined with the rest of the chrome painting below; rb_tick gates on them.
static const char *batt_icon(void);
static const char *vol_icon(void);

void rb_tick(void) {
	// Repaint the chrome when anything IN it changed -- the old version gated
	// everything on the displayed MINUTE, which would have left the battery, the
	// keyboard layer and the volume notch stale between clock ticks.
	//
	// The layer tag and the volume notch are checked EVERY tick: you press a key
	// and expect to see it. The battery, clock and login tick move at 1 Hz at
	// most, so they are checked on a slow timer.
	static const char *last_mode = NULL;
	static const char *last_vol = NULL;
	static char     last_wifi[40] = { 0 };
	static uint32_t next_slow = 0;
	static int      last_sec = -1, last_online = -1;
	static const char *last_batt = NULL;

	const char *m = keyboard_mode_str();
	if (m != last_mode) {
		last_mode = m;
		g_chrome = true;
	}
	const char *vi = vol_icon();           // three icons, so most notch changes are free
	if (vi != last_vol) {
		last_vol = vi;
		g_chrome = true;
	}
	if (strncmp(wifi_indicator_str, last_wifi, sizeof last_wifi - 1) != 0) {
		strncpy(last_wifi, wifi_indicator_str, sizeof last_wifi - 1);
		last_wifi[sizeof last_wifi - 1] = 0;
		g_chrome = true;
	}

	uint32_t now = millis();
	if (next_slow && now < next_slow)
		return;
	next_slow = now + 250;                       // 4 Hz: enough for a seconds clock

	const char *bi = batt_icon();          // the ICON is what shows, so gate on it
	if (bi != last_batt) {
		last_batt = bi;
		g_chrome = true;
	}
	int online = ltp_is_online() ? 1 : 0;
	if (online != last_online) {
		last_online = online;
		g_chrome = true;
	}
	if (net_time()) {
		time_t t = get_current_time_seconds();
		struct tm tmv;
		gmtime_r(&t, &tmv);
		if (tmv.tm_sec != last_sec) {
			last_sec = tmv.tm_sec;
			g_chrome = true;
		}
	}
}

// ---- list layout passes -----------------------------------------------------
void rb_list_reset(void) {
	g_dock = 0;
}

void rb_list_dock(int content_h) {
	int avail = rb_list_height();
	if ((content_h < avail))
		g_dock = (avail - content_h);
	else
		g_dock = 0;
}

void rb_rows_begin(void) {
	for (int i = 0; i < ROW_MAX; i++)
		g_rows[i].acq = false;
}

rb_row rb_row_acquire(void) {
	for (int i = 0; i < ROW_MAX; i++) {
		if (!g_rows[i].acq) {
			g_rows[i].acq = true;
			return &g_rows[i];
		}
	}
	return NULL;                                    // pool full -> engine stops adding rows
}

int rb_row_set(rb_row r, const char *text, const char *meta, bool meta_inline, int style,
               bool separator, int y, bool anchor_bottom, bool selected, int dot, bool recolor) {
	(void)recolor;                                  // inline colour spans: not in checkpoint 1
	TeRow *row = (TeRow *)r;

	strncpy(row->text, text ? text : "", ROW_TEXT - 1);
	row->text[ROW_TEXT - 1] = 0;
	row->has_meta = (meta && meta[0]);
	if (row->has_meta) {
		strncpy(row->meta, meta, ROW_META - 1);
		row->meta[ROW_META - 1] = 0;
	} else {
		row->meta[0] = 0;
	}
	row->meta_inline = meta_inline;

	// MEASURE, without drawing. measure_text applies the SAME wrap walker
	// draw_string does and the same "stop before a line would overflow" cutoff,
	// so the height returned here is exactly what paint_row will fill -- they
	// cannot disagree, because there is only one rule.
	//
	// This is the function the layout loop leans on: view.cpp re-runs its pass up
	// to 128 times converging the scroll, and every pass measures every visible
	// row. Nothing here touches the panel.
	int text_w = rb_row_text_width(dot != VIEW_DOT_NONE);
	int body_h = measure_text(&mont14, row->text, text_w, rb_list_height());
	if (body_h <= 0)  // an empty row still occupies one line
		body_h = mont14.height;

	int h = g_pad_top + body_h + g_pad_bottom;
	if (row->has_meta && !meta_inline)
		h += mont10.height;

	row->h         = h;
	if (anchor_bottom)  // y is the BOTTOM edge when anchored
		row->top = (y - h);
	else
		row->top = y;
	row->style     = style;
	row->selected  = selected;
	row->separator = separator;
	row->dot       = dot;
	row->used      = true;
	return h;
}

void rb_row_hide(rb_row r) {
	((TeRow *)r)->used = false;
}

void rb_rows_commit(void) {
	for (int i = 0; i < ROW_MAX; i++) {
		if (!g_rows[i].acq)
			g_rows[i].used = false;
	}
}

// ---- text editor ------------------------------------------------------------
// Mapped onto text_edit.cpp, the engine's singleton editor. Fixed height in both
// modes: a single-line field bounded by max_len, or a 3-line box that scrolls
// VERTICALLY under the caret. Neither scrolls horizontally.

void rb_edit_show(const char *hint, const char *prefill) {
	(void)hint;                                   // no placeholder text yet
	strncpy(g_edit_pre, prefill ? prefill : "", sizeof g_edit_pre - 1);
	g_edit_pre[sizeof g_edit_pre - 1] = 0;        // COPIED: prefill may alias edit_text()
	g_edit_shown  = true;
	g_edit_open   = false;                        // reopen for this screen
	g_edit_cfg    = true;
	g_edit_chrome = true;
	g_full        = true;
}

void rb_edit_hide(void) {
	if (!g_edit_shown)
		return;
	g_edit_shown = false;
	g_edit_open  = false;
	g_full       = true;                          // the list grows back into the zone
}

const char *rb_edit_text(void) {
	if (!g_edit_shown)
		return "";
	ensure_editor();
	return edit_text();
}

void rb_edit_clear(void) {
	if (!g_edit_shown)
		return;
	g_edit_pre[0] = 0;
	g_edit_open   = false;                        // reopen empty
	g_edit_cfg    = true;
	ensure_editor();
}

void rb_edit_focus(bool on) {
	if (g_edit_focus != on) {
		g_edit_focus  = on;
		if (g_edit_open)  // the CARET follows focus: it means "type here"
			edit_set_focus(on);
		g_edit_chrome = true;                     // border colour tracks focus
	}
}

void rb_go_focus(bool on) {
	if (g_go_focus != on) {
		g_go_focus    = on;
		g_edit_chrome = true;
	}
}

void rb_edit_key(int key) {
	if (!g_edit_shown)
		return;
	ensure_editor();
	switch (key) {
		case VIEW_K_BACKSPACE: edit_backspace();  break;
		case VIEW_K_ENTER:     edit_insert('\n'); break;   // multiline only: view.cpp
		                                                   // commits single-line before us
		case VIEW_K_LEFT:      edit_move(-1);     break;
		case VIEW_K_RIGHT:     edit_move(+1);     break;
		default:
			if (key >= 32 && key < 127)
				edit_insert((char)key);
			break;
	}
}

void rb_edit_cursor_edge(bool *at_start, bool *at_end) {
	if (!g_edit_shown) {
		*at_start = true;
		*at_end = true;
		return;
	}
	ensure_editor();
	*at_start = (edit_cursor() <= 0);
	*at_end   = (edit_cursor() >= edit_len());
}

void rb_edit_set_multiline(bool on) {
	if (g_edit_multi == on)
		return;
	g_edit_multi = on;
	g_edit_cfg   = true;                          // the rect changes -> reopen
	g_full       = true;
}

void rb_edit_set_max(int max_chars) {
	if (g_edit_max == max_chars)
		return;
	g_edit_max = max_chars;
	g_edit_cfg = true;
}

// The box never grows, so the engine never needs to re-flow the list for it.
bool rb_edit_autosize(void) { return false; }

// Drawn from present(), after the rows.
//
// THE CHROME IS GATED; THE TEXT IS NOT. edit_draw() does its own per-line dirty
// tracking and returns without touching the panel when nothing changed, so it is
// free to call every frame. The BOX around it is not free: filling the field
// erases what edit_draw last put there, which then has to be invalidated and
// redrawn. Doing that unconditionally is a repaint loop -- every frame wipes the
// text and marks every line dirty so the next frame must redraw it, forever.
// That was the bug. So the border/fill/Go are painted only when something about
// them actually changed, and only then is the text invalidated to match.
static void paint_editor(void) {
	if (!g_edit_shown)
		return;
	ensure_editor();

	if (g_edit_chrome) {
		int box_y = ILI_H - edit_zone_h() + EDIT_M;
		int box_h = edit_box_h();
		int box_w = ILI_W - 2 * EDIT_M - (edit_has_go() ? (GO_W + GO_GAP) : 0);
		uint16_t border = g_edit_focus ? c565(view_theme->chrome_fg)
		                               : c565(view_theme->edit_border);

		// The zone sits below the list, so nothing else paints it.
		draw_rect(0, ILI_H - edit_zone_h(), ILI_W, edit_zone_h(), c565(view_theme->screen_bg));
		draw_rect(EDIT_M, box_y, box_w, box_h, border);
		draw_rect(EDIT_M + 1, box_y + 1, box_w - 2, box_h - 2, c565(view_theme->edit_bg));

		if (edit_has_go()) {
			int gx = ILI_W - EDIT_M - GO_W;
			uint16_t gbg = g_go_focus ? c565(view_theme->go_bg_focused) : c565(view_theme->go_bg);
			uint16_t gfg = g_go_focus ? c565(view_theme->go_fg_focused) : c565(view_theme->go_fg);
			draw_rect(gx, box_y, GO_W, box_h, gbg);
			trect_t g = { (int16_t)gx, (int16_t)(box_y + (box_h - mont14.height) / 2),
			              GO_W, (int16_t)mont14.height };
			draw_string(&g, "Go", &mont14, ALIGN_CENTER, gfg, gbg);
		}

		edit_invalidate();                 // the fill above wiped the text
		g_edit_chrome = false;
	}

	edit_draw();                           // self-gating: a no-op when nothing changed

}

// A theme swap changes every colour on the panel, so the background goes now --
// same reason as rb_show: present()'s repaint runs a tick later, by which time an
// app may have painted its own body over it.
void view_theme_set(const view_theme_t *t) {
	view_theme = t;
	g_full = g_chrome = true;
	draw_rect(0, 0, ILI_W, ILI_H, c565(view_theme->screen_bg));
}

// ---- drawing ----------------------------------------------------------------

// A row's text colour, from the same mapping view_lvgl.cpp uses.
static uint16_t row_fg_of(const TeRow *row) {
	if (row->selected)
		return c565(view_theme->row_fg_selected);
	switch (row->style) {
		case TERMINAL_GRAY:    return c565(view_theme->row_fg_dim);
		case TERMINAL_MSG_OUT: return c565(view_theme->msg_out_fg);
		case TERMINAL_MSG_IN:  return c565(view_theme->msg_in_fg);
		case TERMINAL_RED:     return rgb(255, 0, 0);
		case TERMINAL_BLUE:    return rgb(80, 140, 255);
		default:               return c565(view_theme->row_fg);
	}
}

// The status dot. The engine has no circle primitive and does not need one for
// this: at 8 px a filled square reads as a dot, and hollow-vs-filled is what
// actually carries meaning (pending vs settled).
static void draw_dot(int x, int y, int dot, uint16_t fg) {
	const int s = 8;
	if (dot == VIEW_DOT_PENDING) {
		draw_rect(x, y, s, 1, fg);
		draw_rect(x, y + s - 1, s, 1, fg);
		draw_rect(x, y, 1, s, fg);
		draw_rect(x + s - 1, y, 1, s, fg);
	} else {
		draw_rect(x, y, s, s, fg);
	}
}

static void paint_row(const TeRow *row) {
	int listTop = rb_list_top();
	int sy = listTop + g_dock + row->top;
	uint16_t bg = row->selected ? c565(view_theme->row_bg_selected) : c565(view_theme->row_bg);
	uint16_t fg = row_fg_of(row);

	// Clip to the list viewport: a row scrolled half off the top must not paint
	// over the title bar.
	int y0 = sy, y1 = sy + row->h;
	if (y1 <= listTop || y0 >= ILI_H)
		return;

	// The background rect below is clamped by hand, but the TEXT could not be:
	// draw_string lays text out from the rect it is given, and a row taller than
	// the viewport must be positioned with its top ABOVE listTop for its lower
	// half to be visible -- so the hidden lines landed on the title bar. Clamping
	// the rect would stop the row scrolling; the engine now takes a separate
	// SCISSOR for exactly this (text_engine.h). Set for the whole row paint and
	// cleared on the way out -- every exit below this point is the function end.
	{
		trect_t clip = { 0, (int16_t)listTop, (int16_t)ILI_W, (int16_t)rb_list_height() };
		text_set_clip(&clip);
	}

	// The row's own background, edge to edge, so the selection bar spans the
	// screen rather than just the text column.
	int cy0 = y0 < listTop ? listTop : y0;
	int cy1 = y1 > ILI_H ? ILI_H : y1;
	draw_rect(0, cy0, ILI_W, cy1 - cy0, bg);

	int tx = MARGIN_X;
	if (row->dot != VIEW_DOT_NONE) {
		draw_dot(MARGIN_X, sy + g_pad_top + 4, row->dot, fg);
		tx = MARGIN_X + DOT_W;
	}

	int tw = rb_row_text_width(row->dot != VIEW_DOT_NONE);
	int body_y = sy + g_pad_top;
	int body_h = row->h - g_pad_top - g_pad_bottom;

	uint16_t mfg = row->selected ? c565(view_theme->row_fg_selected)
	                             : c565(view_theme->meta_fg);

	// The meta line is a SUBHEADING -- sender and timestamp go ABOVE the message,
	// as view_lvgl.cpp has always placed them ("meta (sender + timestamp) on TOP",
	// body below it). The comments in view.h / view_backend.h calling it a
	// subtitle "under" the text are stale; the renderer is the authority.
	if (row->has_meta && !row->meta_inline) {
		trect_t m = { (int16_t)tx, (int16_t)body_y, (int16_t)tw, (int16_t)mont10.height };
		draw_string(&m, row->meta, &mont10, ALIGN_LEFT | TEXT_ELLIPSES, mfg, bg);
		body_y += mont10.height;                    // VW_META_GAP is 0 in the LVGL backend
		body_h -= mont10.height;
	}

	trect_t r = { (int16_t)tx, (int16_t)body_y, (int16_t)tw, (int16_t)body_h };
	if (r.h > 0)
		draw_string(&r, row->text, &mont14, TEXT_MULTILINE, fg, bg);

	// Inline meta shares the body's line, to its right, bottom-aligned with the
	// body's baseline and ellipsised -- it must never wrap, or home stops being
	// one row per contact.
	if (row->has_meta && row->meta_inline) {
		int used = text_width(&mont14, row->text);
		int mx = tx + used + 8;
		int mw = ILI_W - mx - MARGIN_X;
		if (mw > 0) {
			trect_t m = { (int16_t)mx,
			              (int16_t)(body_y + (mont14.height - mont10.height)),
			              (int16_t)mw, (int16_t)mont10.height };
			draw_string(&m, row->meta, &mont10, ALIGN_LEFT | TEXT_ELLIPSES, mfg, bg);
		}
	}

	// The separator is drawn SEPARATELY with the generic primitive: it is the
	// list's chrome, not part of the text render.
	if (row->separator && y1 <= ILI_H)
		draw_rect(0, y1 - 1, ILI_W, 1, c565(view_theme->separator));

	text_set_clip(NULL);   // the row is done; chrome outside the list draws freely
}

// Battery percentage from the pack voltage: 4.2 V full, 3.0 V empty. The raw
// ADC -> mV scale folds in the /2 sense divider and VREF via batt_fullscale_mv
// (calibrate with `bv`), so only the end points live here.
static int batt_pct(void) {
	int mv = batt_adc_raw * batt_fullscale_mv / 4095;
	int pct = (mv - 3000) * 100 / (4200 - 3000);
	if (pct < 0)
		pct = 0;
	if (pct > 100)
		pct = 100;
	return pct;
}

static const char *batt_icon(void) {
	int p = batt_pct();
	if (p >= 80)
		return LV_SYMBOL_BATTERY_FULL;
	if (p >= 55)
		return LV_SYMBOL_BATTERY_3;
	if (p >= 30)
		return LV_SYMBOL_BATTERY_2;
	if (p >= 10)
		return LV_SYMBOL_BATTERY_1;
	return LV_SYMBOL_BATTERY_EMPTY;
}

// Ten volume notches onto three icons: silent, some, loud. A number told you
// nothing an icon does not, and cost twice the width.
static const char *vol_icon(void) {
	if (speaker_level <= 0)
		return LV_SYMBOL_MUTE;
	if (speaker_level <= 5)
		return LV_SYMBOL_VOLUME_MID;
	return LV_SYMBOL_VOLUME_MAX;
}

static void paint_chrome(bool full) {
	uint16_t bar = c565(view_theme->chrome_bg);
	uint16_t fg  = c565(view_theme->chrome_fg);
	const int16_t ty = TITLE_PAD;
	const int16_t th = (int16_t)mont14.height;

	// PER-CELL, not whole-bar. draw_string already fills its own band as a side
	// effect, so repainting every cell on every tick was redundant AND visible:
	// the full-bar clear below, followed by eight separate transfers, left the bar
	// momentarily empty -- a blink once a second as soon as the clock showed
	// seconds. The clear now happens only on a full repaint (which also paints the
	// static gaps between cells); after that each cell is drawn only when its own
	// text changes, so a ticking clock repaints 62 px and nothing else.
	static char s_vol[8], s_wifi[24], s_title[96], s_batt[8], s_mode[8], s_clk[16];
	static bool s_mode_alt = false;
	if (full) {
		draw_rect(0, 0, ILI_W, TITLE_H, bar);
		s_vol[0] = s_wifi[0] = s_title[0] = s_batt[0] = s_mode[0] = s_clk[0] = 1;
		s_vol[1] = s_wifi[1] = s_title[1] = s_batt[1] = s_mode[1] = s_clk[1] = 0;
	}
	// Redraw `cell` only if `now` differs from what is on the panel.
	#define CHROME_CELL(cache, now) \
		(strcmp((cache), (now)) != 0 && (snprintf((cache), sizeof(cache), "%s", (now)), 1))

	// Right-anchored from the clock inward: clock, battery, layer tag. The clock
	// is back at the standard MARGIN_X inset -- the earlier clipping was the band
	// being too narrow for a wide "17:51:38" at the body font, not the inset, and
	// clk_w now measures for the widest digits. The battery sits tight against
	// it (2 px) so the two read as one cluster.
	// Bands sized to MEASURED content, not guessed: "00:00:00" is 60 px, a battery
	// icon exactly 18, "ABC"/"&#$" 33 and 29. The old 76/24/40 left 16 px of dead
	// slack to the left of the right-aligned clock, and that slack -- not the
	// inset -- was the visible gap holding the battery away from the time.
	// The clock is drawn MONOSPACE (fixed8x16), which is the actual fix for the
	// jitter rather than a relocation of it. In the proportional body font
	// "11:11:11" is 36 px and "04:44:44" is 65 -- a 29 px swing, so whichever edge
	// you pin, the other one walks. Right-aligned it nudged against the battery;
	// left-aligned it merely moved the walk into the margin. At 8 px per cell
	// every time is exactly 64 px and NEITHER edge can move. 62 also clipped the
	// widest time (ALIGN_RIGHT clips from the left, so it lost a leading digit).
	const int clk_w = 66, mode_w = 34, batt_w = 18;
	const int clk_x  = ILI_W - MARGIN_X - 62;
	const int batt_x = clk_x  - 2 - batt_w;
	const int mode_x = batt_x - 6 - mode_w;

	// Left: volume icon, then the wifi icon + signal strength (no SSID).
	const int vol_w = 22, wifi_w = 56;
	trect_t v = { MARGIN_X, ty, (int16_t)vol_w, th };
	if (CHROME_CELL(s_vol, vol_icon()))
		draw_string(&v, vol_icon(), &mont14, ALIGN_LEFT, fg, bar);

	trect_t w = { (int16_t)(MARGIN_X + vol_w + 2), ty, (int16_t)wifi_w, th };
	if (CHROME_CELL(s_wifi, wifi_indicator_str))
		draw_string(&w, wifi_indicator_str, &mont14, ALIGN_LEFT | TEXT_ELLIPSES, fg, bar);

	// Middle: the signed-in eye, then the screen title.
	const int title_x = MARGIN_X + vol_w + 2 + wifi_w + 8;
	const int title_w = batt_x - 6 - title_x;
	if (title_w > 0) {
		char buf[96];
		// The eye reports OUR reachability, unless the screen named a peer --
		// then it reports that peer's link, so a thread says whether the person
		// it is about can be reached. LOOP for trying is the same glyph the
		// Wi-Fi indicator uses while it is still working on it.
		const char *eye = LV_SYMBOL_EYE_CLOSE;
		const uint8_t *peer = screen_peer_key();
		if (!peer) {
			if (ltp_is_online())
				eye = LV_SYMBOL_EYE_OPEN;
		} else {
			netif_peer_state ps = netif_peer(peer);
			if (ps == NETIF_PEER_UP)
				eye = LV_SYMBOL_EYE_OPEN;
			else if (ps == NETIF_PEER_TRYING)
				eye = LV_SYMBOL_LOOP;
		}
		snprintf(buf, sizeof buf, "%s %s", eye, screen_title_str());
		// CENTRED, and genuinely on the panel rather than just within its band:
		// the band runs 94..386, whose midpoint is 240 = ILI_W/2. That is luck
		// rather than design (the left cluster is 88 px, the right one 94), so if
		// any neighbouring band is resized this stops being true and the title
		// will drift off centre without anything looking obviously wrong.
		trect_t t = { (int16_t)title_x, ty, (int16_t)title_w, th };
		if (CHROME_CELL(s_title, buf))
			draw_string(&t, buf, &mont14, ALIGN_CENTER | TEXT_ELLIPSES, fg, bar);
	}

	trect_t b = { (int16_t)batt_x, ty, (int16_t)batt_w, th };
	if (CHROME_CELL(s_batt, batt_icon()))
		draw_string(&b, batt_icon(), &mont14, ALIGN_RIGHT, fg, bar);

	// The layer tag is REVERSED whenever the keyboard is not in plain lower case.
	// Shifted/symbol layers are transient states you need to notice without
	// reading, and inverting the cell is visible at a glance where a changed
	// three-character string is not.
	const char *mode = keyboard_mode_str();
	bool mode_alt = (strcmp(mode, "abc") != 0);
	trect_t m = { (int16_t)mode_x, ty, (int16_t)mode_w, th };
	if (CHROME_CELL(s_mode, mode) || mode_alt != s_mode_alt) {
		s_mode_alt = mode_alt;                   // the INVERSION is state too
		draw_string(&m, mode, &mont14, ALIGN_RIGHT,
		            mode_alt ? bar : fg, mode_alt ? fg : bar);
	}

	char clk[16] = "";
	if (net_time()) {
		time_t now = get_current_time_seconds();
		struct tm tmv;
		gmtime_r(&now, &tmv);
		snprintf(clk, sizeof clk, "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
	}
	trect_t c = { (int16_t)clk_x, ty, (int16_t)clk_w, th };
	if (CHROME_CELL(s_clk, clk))
		draw_string(&c, clk, &fixed8x16, ALIGN_LEFT, fg, bar);
	#undef CHROME_CELL

	if (g_prompt_shown) {
		trect_t p = { MARGIN_X, (int16_t)(TITLE_H + 3),
		              (int16_t)(ILI_W - 2 * MARGIN_X),
		              (int16_t)(g_prompt_h - PROMPT_PAD) };
		draw_string(&p, g_prompt, view_theme->font_body,
		            ALIGN_LEFT | TEXT_MULTILINE | TEXT_ELLIPSES,
		            c565(view_theme->chrome_fg), c565(view_theme->screen_bg));
	}
}

// ---- Sym2 popup overlay -----------------------------------------------------
// A bare 3x10 grid of the Sym2 characters pinned to the bottom 48 px, shown ONLY
// while keyboard_sym2_popup() is armed: hold '&' past sym2_hold_ms (or
// double-tap it) and press the key under the character you want.
//
// It OVERLAYS -- no layout reservation, nothing reflows. That is what makes it
// cheap to show and dismiss, and it is why dismissing has to repair what it
// covered (see legend_erase).
//
// Cells are drawn in the MONOSPACE face: this is a keyboard map, so the columns
// must line up with each other, which a proportional font cannot do. The
// dividers are drawn AFTER the cells, because draw_string fills its own band and
// would otherwise erase the line along each row's top edge.
#define LEGEND_ROWS 3
#define LEGEND_COLS 12      // the keycap grid is 3 rows of 12 (keyboard.cpp)
#define LEGEND_CH   16                       // fixed8x16.height
#define LEGEND_H    (LEGEND_ROWS * LEGEND_CH)
#define LEGEND_CW   (ILI_W / LEGEND_COLS)    // 40

static bool g_legend_shown = false;          // what is ON the panel

static void paint_legend(void) {
	uint16_t fg = c565(view_theme->chrome_fg);
	uint16_t bg = c565(view_theme->screen_bg);
	const int y0 = ILI_H - LEGEND_H;

	draw_rect(0, y0, ILI_W, LEGEND_H, bg);   // SOLID: it hides the content, never blends

	for (int r = 0; r < LEGEND_ROWS; r++) {
		for (int c = 0; c < LEGEND_COLS; c++) {
			const char *t = keyboard_legend_cell(r, c);
			if (!t || !t[0])
				continue;
			trect_t cell = { (int16_t)(c * LEGEND_CW), (int16_t)(y0 + r * LEGEND_CH),
			                 (int16_t)LEGEND_CW, (int16_t)LEGEND_CH };
			draw_string(&cell, t, &fixed8x16, ALIGN_CENTER, fg, bg);
		}
	}

	draw_rect(0, y0, ILI_W, 1, fg);          // top border, separating it from the content
	for (int r = 1; r < LEGEND_ROWS; r++)
		draw_rect(0, y0 + r * LEGEND_CH, ILI_W, 1, fg);
}

// Repair what the overlay covered. g_full would also work but costs a ~108 ms
// full-frame repaint and reads as a screen change -- dismissing a transient
// popup should not flash. So invalidate only what sat under the band: any row it
// overlapped, plus the editor, which lives at the bottom by definition.
static void legend_erase(void) {
	// The repair depends on WHO owns the panel. The terminal renders its own grid
	// (tui.cpp) and knows nothing about g_shown, so it has to be told to redraw;
	// the view backend invalidates the rows the band covered.
	if (terminal_grid_active()) {
		tui_invalidate_all();
		return;
	}
	const int y0 = ILI_H - LEGEND_H;
	const int listTop = rb_list_top();
	for (int i = 0; i < ROW_MAX; i++) {
		if (!g_shown[i].used)
			continue;
		int ry = listTop + g_dock + g_shown[i].top;
		if (ry + g_shown[i].h > y0)
			g_shown[i].used = false;         // != g_rows[i] -> present() repaints it
	}
	draw_rect(0, y0, ILI_W, LEGEND_H, c565(view_theme->row_bg));
	g_edit_chrome = true;
}

// THE SYM2 OVERLAY IS NOT A VIEW. It is a keyboard affordance and must appear
// over whatever owns the panel, and on a screen with no list that is the APP:
// present() paints the title bar and stops, so an overlay drawn from there would
// never reach the terminal's grid or the PTT screen. Painting it from present()
// is what once left the title bar reading "&#$" on the terminal with no picker
// beneath it. So it is pumped from the loop instead, after everyone has painted.
//
// It repaints on EVERY pump while armed rather than tracking whether something
// overdrew it: tui_pump repaints dirty cells progressively and would eat into
// the band with no signal we could observe. 480x48 is ~5.4 ms, and the popup is
// armed only until the next keypress, so the cost is bounded by the gesture.
// PAINTED ONCE, on arming. Repainting every tick is what made the band flicker:
// at the UI rate that is ~33 redraws a second of a picture that never changes.
// Whoever owns the panel underneath must leave it alone while it is up -- the
// terminal freezes its grid for exactly this -- and legend_erase() repairs what
// the band covered when the next key dismisses it.
void te_legend_pump(void) {
	bool want = keyboard_sym2_popup();
	if (want == g_legend_shown)
		return;
	g_legend_shown = want;
	if (want)
		paint_legend();
	else
		legend_erase();
}

// Called once per ui_slice(), after view_slice(). The ONLY place pixels move.
void te_view_present(void) {
	if (!g_owns)
		return;

	bool was_full = g_full;
	if (g_full) {
		// No clear here: rb_show() already wiped the panel, synchronously, so it
		// cannot land on top of an app that has painted its own body since.
		memset(g_shown, 0, sizeof g_shown);
		g_chrome      = true;
		g_edit_chrome = true;
	}
	if (g_chrome) {
		paint_chrome(was_full);
		g_chrome = false;
	}

	// Repaint only rows whose picture changed, then blank the strip left behind
	// by a row that went away.
	int painted = 0;
	for (int i = 0; i < ROW_MAX; i++) {
		if (row_same(&g_rows[i], &g_shown[i]))
			continue;
		if (g_rows[i].used) {
			paint_row(&g_rows[i]);
			painted++;
		} else if (g_shown[i].used) {
			int listTop = rb_list_top();
			int sy = listTop + g_dock + g_shown[i].top;
			int y0 = sy < listTop ? listTop : sy;
			int y1 = sy + g_shown[i].h;
			if (y1 > ILI_H)
				y1 = ILI_H;
			if (y1 > y0)
				draw_rect(0, y0, ILI_W, y1 - y0, c565(view_theme->row_bg));
		}
		shown_set(&g_shown[i], &g_rows[i]);
	}
	(void)painted;
	paint_editor();

	g_full = false;
}

