#pragma once
//
// text_edit.h — the singleton text editor.
//
// Per the spec: ONE editor exists. It owns a flat buffer, a table of per-line
// character counts, and a cursor/mark pair. The ONLY way text changes is
// "replace the span between mark and cursor" — typing replaces a zero-length
// span (an insert), backspace replaces a one-character span with nothing. That
// single primitive is what keeps reflow honest: every edit has a known start
// point, so reflow restarts at the line containing MARK rather than at line 0.
//
// STEP 5 SCOPE: append and delete at the end only. Cursor movement, top_line
// scrolling and full editing are steps 6 and 7; the fields they need already
// exist here so those steps add behaviour rather than re-shaping the state.
//
#include <stdint.h>
#include <stdbool.h>
#include "tfont.h"
#include "text_engine.h"

#ifndef EDIT_BUF_MAX
#define EDIT_BUF_MAX   10240        // compile-time tunable, per the spec
#endif
#define EDIT_MAX_LINES 512

// Bind the editor to a rectangle. `multiline` false makes Enter signal "done"
// instead of inserting a break. `filter`, if non-NULL, is the ONLY set of
// characters accepted (e.g. "0123456789." for an IP address); anything else is
// ignored at the keystroke.
//
// `max_len` caps the text at that many CHARACTERS (0 = the buffer cap alone).
// A character count, not a pixel width: on a proportional face a pixel cap
// holds 28 of '1' and 18 of 'W', so a field could not be specified as "takes an
// IP address" and be true.
//
// SCROLLING: vertical only, and only when multiline. The box is a FIXED height
// either way; a multiline box scrolls its lines under the caret (top_line +
// scroll_into_view), which is what makes a 3-line chat composer work. There is
// NO horizontal scrolling in either mode -- a render-time x offset is painful to
// debug and buys nothing here. So a single-line field must be sized to hold its
// whole content: max_len * tfont_max_width(f) <= r->w, checked where the field
// is declared. A field needing more than one line's worth gets a multiline box,
// not a scroller.
void edit_open(const trect_t *r, const tfont_t *f, bool multiline,
               const char *filter, int max_len, uint16_t fg, uint16_t bg);

// Replace the mark..cursor span with `c`. With mark == cursor this inserts.
// Returns false if the buffer is full or the filter rejected the character.
bool edit_insert(char c);

// Replace the one character before the cursor with nothing.
bool edit_backspace(void);

// Move the cursor by `delta` characters (negative = left). Clamped to the
// buffer. Mark follows the cursor, so the next edit is an insert at the new
// position rather than a replace of the traversed span.
void edit_move(int delta);

// Move the cursor one display line up/down, keeping the column where possible.
// Display lines, not paragraphs — this is what the arrow keys drive.
void edit_move_line(int delta);

void edit_home(void);        // start of the current display line
void edit_end(void);         // end of the current display line

// Move a whole word. Forward: to the start of the next word; back: to the start
// of this one. Word boundaries are the spec's non-printing characters (space and
// newline), the same rule reflow uses to choose break points.
void edit_move_word(int delta);

// Replace the character AT the cursor with nothing (the Del key, as opposed to
// backspace which takes the one before).
bool edit_delete_forward(void);

// Delete the word before the cursor.
bool edit_delete_word(void);

// Repaint only the lines whose content changed. Returns lines actually blitted.
int  edit_draw(void);

int  edit_cursor(void);
int  edit_cursor_line(void);
int  edit_top_line(void);

// Force a full repaint next time.
void edit_invalidate(void);

// Show or hide the caret. A caret means "type here", so it must NOT be drawn
// while the screen's focus is elsewhere -- a chat's composer sits under the
// message list and is only focused after arrowing down into it. Defaults to
// shown, so a bare harness needs no extra call. Toggling repaints just the
// caret's line, which is what erases it.
void edit_set_focus(bool on);

const char *edit_text(void);
int  edit_len(void);
int  edit_lines(void);
bool edit_done(void);        // single-line mode: Enter was pressed
