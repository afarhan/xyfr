#pragma once
//
// view.h — THE VIEW MODEL: one screen shape, one callback.
//
// A screen is a vertical stack of three OPTIONAL zones — Prompt / List / Text-
// entry — driven by a single WndProc-style callback per screen. The callback
// answers "what is item N", "N was activated", "this text was entered"; it never
// touches LVGL. The engine (view.c) owns virtualization, scroll, selection and
// focus, and is itself LVGL-free — it drives a thin render backend (view_backend.h,
// implemented today by view_lvgl.cpp) which is the ONLY code that calls LVGL, so
// LVGL can later be swapped for a minimal in-house list+editor lib.
//
// Device-only (the host
// CLI has no UI); compiled as C++ in the sketch. Core 1 (UI) only.
//
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- the screen callback -------------------------------------------------
//
// Op codes are named for the ZONE that raises them: LIST_* from the list view,
// EDIT_* from the text editor (the Prompt zone is static, no events). One cb per
// screen receives them all. `item_index` is a SIGNED coordinate the screen
// defines, 0 = the item the view anchors on at open (negative = up, positive =
// down). Enter is symmetric: LIST_SELECTED on the list, EDIT_ENTER in the editor.
typedef enum {
	// ---- list view ----
	LIST_GET_ITEM,   // data = view_item_t* to fill (text ptr + style + opaque user).
	                 //   return 0  -> an item exists at item_index (engine renders it);
	                 //   return -1 -> NO item there (past the top OR bottom edge).
	                 //   This is the SOLE bounds mechanism AND the lazy-load hook.
	LIST_SELECTED,   // item_index activated (Enter on the list). data = that row's opaque `user`.
	LIST_BACK,       // Backspace on the list (no editor consumed it). data = NULL. A "go back"
	                 //   gesture: the cb may navigate away (view_set) or ignore it (default).
	LIST_COUNT,      // OPTIONAL. return count or -1 = unknown. Engine never depends on it.
	LIST_KEY,        // A printable/unhandled key while the LIST has focus (nav + Enter already
	                 //   consumed theirs). item_index = the key char; data = NULL. The cb may act
	                 //   on it (return 0) or ignore it. Used by the call view for +/- volume with
	                 //   no dedicated menu row. Other screens ignore it (default fall-through).
	// ---- text editor ----
	EDIT_ENTER,      // Enter pressed in the editor. data = const char* (the entry text). item_index = 0.
} view_op_t;

// Optional per-row status dot, drawn at the row's left (replaces a leading glyph).
// Priority is the cb's call (e.g. home: unread > reachable > pending). On a colour
// panel: red/green filled, pending hollow; on the mono panel red/green both render
// filled (no colour) and pending stays hollow.
typedef enum {
	VIEW_DOT_NONE = 0,   // no indicator (default)
	VIEW_DOT_UNREAD,     // red filled — a message is waiting
	VIEW_DOT_REACHABLE,  // green filled — endpoint resolved & user-VERIFIED key
	VIEW_DOT_PENDING,    // hollow — lookup not yet succeeded
	VIEW_DOT_UNVERIFIED, // orange filled — VALID/usable but key not yet user-verified
} view_dot_t;

// One list item, filled by the cb on LIST_GET_ITEM.
// Row-level markup for a STATIC items array: a row whose text begins "###" is a
// HEADING/value row (rendered TERMINAL_HIGHLIGHT, the "###" stripped). This is
// what lets a plain const char*[] express emphasis, so a screen only needs the
// callback form for genuinely dynamic content. Inline spans (*bold*) are a
// follow-up and belong in the render backend, which owns fonts and metrics.
#define VIEW_MARK_HEADING "###"

typedef struct {
	const char *text;   // BORROWED: point at your OWN memory (string literal / reused scratch). Consumed
	                    //   (copied into the row) before the next cb call. May embed LV_SYMBOL_* inline.
	uint16_t    style;  // a TERMINAL_* token (ui.h): conveys colour AND alignment (in left / out right).
	void       *user;   // opaque per-row handle (e.g. a logbook record offset). Returned as `data` on
	                    //   LIST_SELECTED. NOTE void* is 32-bit here — a 64-bit record_id won't fit.
	const char *meta;   // OPTIONAL small-grey line ABOVE `text` (e.g. a message's sender + timestamp).
	                    //   NULL = none. Borrowed, like text.
	bool        separator;  // draw a bottom dividing line under this row (cb-controlled; default off).
	uint8_t     dot;    // OPTIONAL view_dot_t status circle at the row's left. 0 = none.
	bool        meta_inline;  // draw `meta` on the SAME line, right of `text`, in the small
	                      //   title font (font_meta) instead of stacked above it in the body
	                      //   font. Home uses it: name in the body font, partkey + message
	                      //   preamble small. Ellipsised if it doesn't fit; never wraps.
	bool        recolor;  // parse LVGL "#RRGGBB text#" spans in `text` (inline colour). OFF by default —
	                      //   keep it off for user text (a literal '#' would be eaten). Home uses it to
	                      //   grey the partkey on the same line as the name.
} view_item_t;

typedef int (*view_cb_t)(view_op_t op, int item_index, void *data);

// ---- public API ----------------------------------------------------------

// Build + show a view, replacing the current screen and ACTIVATING the view
// system (input routes here until an old list_view screen calls list_open()).
//   prompt==NULL       -> no Prompt zone.   items!=NULL -> static list (engine
//   serves LIST_GET_ITEM/COUNT from the NULL-terminated array; cb only handles
//   LIST_SELECTED/EDIT_ENTER).   input_hint==NULL -> no Text-entry zone.
//   input_prefill -> seed the entry (NULL = empty).
void view_set(view_cb_t cb, const char *title, const char *prompt,
              const char **items, const char *input_hint, const char *input_prefill);

// The current view's list data changed -> re-query visible items + repaint,
// preserving the anchor. Coalesced; SAFE TO CALL FROM CORE 0 (raises a flag the
// UI loop drains). The event-driven repaint (inbound msg / ack / inbound call).
void view_invalidate(void);

// Re-arm bottom-follow on a bottom-anchored view (chat): the next dirty-drain
// scrolls to the newest item. Pair with view_invalidate() to "refill + scroll
// to latest" on an inbound message. Never touches focus or the editor text.
void view_follow_newest(void);

// Bumped by every view_invalidate(). A dynamic screen compares it against a
// cached copy to know its underlying data may have changed (e.g. the chat reloads
// its logbook window on a mismatch — one scan per change, not per row).
extern volatile uint32_t view_epoch;

// Live entry text of the current view (or "" if none / no entry zone).
const char *view_input_text(void);

// Programmatic selection: set the selected index + scroll it into view.
void view_select(int item_index);

// The current list selection index. A screen that repaints itself (view_set) and
// wants to keep the highlight where it was reads this first, then view_select()s it
// back afterwards — e.g. the call view after a +/- volume key.
int view_selected(void);

// Restrict the editor to a set of printable characters (e.g. "0123456789.:" for
// a numeric/IP screen): a typed printable char not in `allowed` is dropped;
// control/cursor keys always pass. Opt-in per screen — call AFTER view_set (which
// clears it), so it never leaks to the next screen. NULL = no restriction.
void view_set_input_filter(const char *allowed_or_null);

// Editor height mode. Default (and reset by every view_set) is SINGLE-LINE: a
// one-text-line box that scrolls horizontally. Call with true AFTER view_set to
// make it an AUTO-GROWING composer — starts one line, grows with the wrapped
// text (pushing the list up) until it fills the screen, then scrolls internally.
// Use for chat, a 24-word phrase, etc. Navigation is identical either way
// (right-at-end / down -> Go). Opt-in per screen; never inherited across a nav.
void view_set_input_multiline(bool on);

// Cap the editor at `n` CHARACTERS (0 = the backend's own limit). Call AFTER
// view_set, which resets it — same idiom as view_set_input_filter. A character
// count, not a pixel width: on a proportional font a pixel cap holds 28 of '1'
// and 18 of 'W', so a field could not be specified as "takes an IP address" and
// be true. Size the field so n * (widest glyph) fits it — nothing scrolls
// horizontally; a field needing more than a line wants view_set_input_multiline.
void view_set_input_max(int n);

// Vertical padding above/below each list row (the leading between rows). Default
// (reset by every view_set) is the theme's standard. The chat uses a tight top +
// looser bottom (the subheading's font leading already pads the top); the full-text
// view uses a small symmetric pad (tight line leading). Opt-in per screen.
void view_set_row_pad(int top, int bottom);

// List body font mode. Default (reset by every view_set) is the theme's
// proportional body font. Call with true AFTER view_set to render list rows in a
// FIXED-WIDTH font (8 px/char) — so a screen can wrap text by exact byte math
// with no per-glyph measuring. The chat uses this for its line-windowed render.
// Opt-in per screen; never inherited across a navigation.
void view_set_body_fixed(bool on);

// Columns (whole characters) that fit one list row in the fixed-width font —
// the wrap width for a view_set_body_fixed(true) screen. Meaningful only in that
// mode. Depends on the list width, so query it after the view is shown.
int view_body_cols(void);

// Wrap `in` in the PROPORTIONAL body font to the list width, at most `maxlines`
// lines (joined by '\n') into out[cap]; appends " ..." when the text runs longer
// (or `in_more` marks the source pre-truncated). The chat's 3-line preview — LVGL
// wraps, so the preview matches a full render.
void view_body_preview(const char *in, bool in_more, int maxlines, char *out, int cap);

// Advance one proportional line of `in` at the list width (same rule/metrics as
// the preview). Returns bytes consumed; *display_len = bytes to show (trailing
// break char excluded). The full-text view builds its line table with this.
uint32_t view_body_wrap_next(const char *in, uint32_t *display_len);

// ---- engine <-> platform glue (called by ui.cpp / keyboard.cpp) ----------

// True while a view owns the screen (vs. an old list_view screen).
bool view_is_active(void);

// Deliver a "back" gesture (ESC/backspace) to the active view. Returns true if the
// view navigated to a parent (consumed it), so the caller skips global go-home.
bool view_back(void);

// The active view's callback (NULL when no view is active). Lets a poller ask
// "is screen X showing?" (e.g. chat_poll repaints home when a message arrives).
view_cb_t view_current(void);

// Deactivate the view system (hide its screen). Called by list_open() so the
// legacy screens take input back during incremental migration.
void view_deactivate(void);

// Route one keyboard byte (keyboard_read()'s output) into the active view.
// Uses the neutral VIEW_K_* codes below (which match the keyboard layer's bytes).
void view_handle_key(int key);

// Editor-focus queries for keyboard.cpp's l/r cursor-vs-nav decision, mirroring
// list_input_is_focused()/list_input_cursor_edge() but for the view's editor.
bool view_input_focused(void);
void view_input_cursor_edge(bool *at_start, bool *at_end);

// Per-tick from ui_slice (core 1): repaint if view_dirty, refresh chrome.
void view_slice(void);

// Keyboard byte codes the engine routes. These equal the values keyboard.cpp
// emits today (LVGL's LV_KEY_*), declared here so the engine needs no lvgl.h —
// the keyboard layer owns this contract, not LVGL.
enum {
	VIEW_K_BACKSPACE = 8,   // '\b'  ('<' key)
	VIEW_K_NEXT      = 9,   // group-next  (plain right at a text edge / nav)
	VIEW_K_ENTER     = 10,  // '\n'  ('e' key)
	VIEW_K_PREV      = 11,  // group-prev  (plain left at a text edge / nav)
	VIEW_K_UP        = 17,
	VIEW_K_DOWN      = 18,
	VIEW_K_RIGHT     = 19,
	VIEW_K_LEFT      = 20,
	VIEW_K_ESC       = 27,  // a working key: delivered like any other
};

#ifdef __cplusplus
}
#endif
