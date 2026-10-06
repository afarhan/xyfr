#pragma once
//
// view_backend.h — the RENDER BACKEND seam (the LVGL HAL for the view model).
//
// THE ONLY code below the view engine that calls LVGL is the implementation of
// this header (view_lvgl.cpp). The engine (view.c) drives the screen entirely
// through these primitives, so replacing LVGL with a minimal in-house list+editor
// library is a matter of reimplementing exactly this file — no engine/screen
// change. Core 1 (UI) only.
//
// The model: a persistent screen with a title-bar/chrome, an optional Prompt
// label, a scrollable list area rendered as a RECYCLED POOL of text rows (only
// the on-screen rows exist), and an optional text editor at the bottom. The
// engine measures-on-render: rb_row_set returns the row's pixel height.
//
#include <stdint.h>
#include <stdbool.h>

// ---- lifecycle / show-hide ----
void rb_init(void);        // create the persistent objects (once). Hidden until rb_show.
void rb_show(void);        // reveal the view screen + point the keyboard indev at it.
void rb_hide(void);        // hide the view screen (legacy list_view takes over).

// ---- geometry ----
int  rb_list_top(void);    // y of the list viewport's top (below title + prompt, if shown)
int  rb_list_height(void); // px height available to the list (shrinks when prompt/editor shown)
int  rb_list_width(void);
// Usable width for a row's TEXT, i.e. rb_list_width() minus the row padding and
// (when has_dot) the status-dot gutter. Lets a screen measure whether its composed
// line fits on ONE row without duplicating the backend's private padding constants.
int  rb_row_text_width(bool has_dot);

// ---- per-view row styling ----
void rb_row_pad_set(int top, int bottom);   // vertical padding above/below each row

// ---- fixed-width body font (opt-in per view; default off = theme body font) ----
void rb_body_set_fixed(bool on);  // true => list rows render in the fixed font (full-text view)
int  rb_body_cols(void);          // whole chars that fit one row in the fixed font (MEASURED advance)

// Wrap `in` in the proportional body font to the list width, at most `maxlines`
// lines into out[cap], appending " ..." when longer (or in_more). The chat's
// 3-line message preview.
void rb_body_preview(const char *in, bool in_more, int maxlines, char *out, int cap);

// Advance one proportional line of `in` (same width/rule as the preview). Returns
// bytes consumed; *display_len = bytes to show. The full-text view's line table.
uint32_t rb_body_wrap_next(const char *in, uint32_t *display_len);

// ---- title + prompt zones (plain text) ----
void rb_title(const char *text);          // title-bar body (icon/clock/wifi are chrome, see rb_tick)
void rb_prompt(const char *text_or_null); // NULL/"" hides the prompt zone (grows the list)
void rb_tick(void);                       // 1 Hz-ish chrome refresh (wifi indicator, clock, OK/WARN icon)

// List/prompt vertical placement. The engine calls rb_list_reset() before laying
// out rows (full-area container + prompt at top, so a render is never clipped),
// then rb_list_dock(content_h) after — which, when an editor is present and the
// laid-out content is shorter than the available area, slides the list (and the
// prompt right on top of it) down to sit just above the editor.
void rb_list_reset(void);
void rb_list_dock(int content_h);

// ---- list: a recycled pool of text rows ----
// A layout pass is rb_rows_begin() ... a run of rb_row_acquire()/rb_row_set() ...
// rb_rows_commit(). The engine renders each visible row IMMEDIATELY after its cb
// fills it (the item text is borrowed and may be reused next call), top-down or
// bottom-up. rb_row_set both measures (wrap to list width) and places, returning
// the pixel height so the engine can advance.
typedef void *rb_row;
void   rb_rows_begin(void);                  // mark all pool rows free at the start of a pass
rb_row rb_row_acquire(void);                 // reuse a free row (returns NULL if the pool is full)
int    rb_row_set(rb_row r, const char *text, const char *meta, bool meta_inline, int style, bool separator,
                  int y, bool anchor_bottom, bool selected, int dot, bool recolor);
                                             // place + paint at y (top edge, or BOTTOM edge if anchor_bottom):
                                             // `text` in the body font; `meta` (if non-NULL) a small grey
                                             // line ABOVE it + a bottom separator; `dot` (view_dot_t)
                                             // draws a status circle at the left, insetting the text. RETURNS height.
void   rb_row_hide(rb_row r);                // hide one acquired row (engine drops a partly-visible edge row)
void   rb_rows_commit(void);                 // hide any rows not acquired this pass

// ---- text editor (the entry zone) + the "Go" send button ----
// The entry zone is a multi-line text box plus a focusable "Go" button to its
// right: Enter in the box inserts a newline; the engine sends only when Go has
// focus and Enter is pressed (the BlackBerry model — a real Send vs a plain Enter).
void        rb_edit_show(const char *hint, const char *prefill); // create/reveal + place the box + Go
void        rb_edit_hide(void);
const char *rb_edit_text(void);
void        rb_edit_clear(void);
void        rb_edit_focus(bool on);          // show/hide the editor's cursor (engine focus on the box)
void        rb_go_focus(bool on);            // highlight the Go button (engine focus on Go)
void        rb_edit_key(int key);            // forward a key (printable/newline/backspace/cursor) to the box
void        rb_edit_cursor_edge(bool *at_start, bool *at_end);   // for keyboard.cpp's l/r decision
void        rb_edit_set_multiline(bool on);  // false = 1-line box (default); true = a FIXED multi-line box
void        rb_edit_set_max(int max_chars);  // cap the field by CHARACTER count (0 = backend default)
bool        rb_edit_autosize(void);          // LEGACY: the box is fixed-height in both modes, so this is
                                             //   always false for a fixed backend. Kept for the LVGL one,
                                             //   whose composer still grows.
