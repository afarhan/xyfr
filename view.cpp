// view.cpp — THE VIEW ENGINE. Pure UI logic: virtualization, scroll, selection,
// focus, key routing, the static-list default, and the repaint flag. LVGL-FREE —
// it drives the screen only through the render backend (view_backend.h), so the
// future minimal in-house lib swaps in by reimplementing that backend, not this.
// Device-only, core 1 (UI).

#include <stdint.h>
#include <string.h>
#include "view.h"
#include "view_backend.h"
#include "ui.h"           // TERMINAL_* style tokens
#include "hal.h"          // TEMP trace

// ---- active view state ---------------------------------------------------

static view_cb_t    v_cb        = NULL;
static const char **v_items     = NULL;   // non-NULL -> static list (engine serves GET_ITEM/COUNT)
static bool         v_active    = false;  // view owns the screen (vs. a legacy list_view screen)
static bool         v_has_input = false;
// Focus target: the list, the text box, or the Go (send) button.
enum {
	F_LIST = 0,
	F_EDIT,
	F_GO
};
static int          v_focus     = F_LIST;
static bool         v_bottom    = false;  // bottom-anchored (chat: newest pinned to bottom)
static bool         v_follow    = false;  // bottom-anchored + tracking the newest item
static int          v_sel       = 0;      // SIGNED selected list index
static int          v_anchor    = 0;      // top_index (top-anchored) or bottom_index (bottom-anchored)
static uint32_t     v_gen       = 0;      // bumped on every view_set — lets a key handler detect that a
                                          //   cb navigated to a new view (and stop mutating the old state)
static bool         v_multiline = false;  // editor mode; single-line makes Enter COMMIT
static const char  *v_input_filter = NULL;// if non-NULL, only these printable chars reach the editor
                                          //   (e.g. "0123456789.:" for the relay-IP screen). Opt-in;
                                          //   cleared by view_set so it never leaks to the next screen.

volatile bool     view_dirty = false;
volatile uint32_t view_epoch = 0;

// ---- callback dispatch (with the static-list default handler) ------------

static int v_item_count(void){
	int n = 0;
	if (v_items)
		while (v_items[n])
			n++;
	return n;
}

// Route an op to the screen cb, except that a static `items` list answers
// LIST_GET_ITEM / LIST_COUNT from the array (the cb still gets SELECTED/ENTER).
static int vcb(view_op_t op, int idx, void *data){
	if (v_items){
		if (op == LIST_GET_ITEM){
			int n = v_item_count();
			if (idx < 0 || idx >= n)
				return -1;
			view_item_t *it = (view_item_t *)data;
			const char *t = v_items[idx];
			// Row-level markup: a leading "###" marks a HEADING/value row (the thing
			// the screen is actually showing — a generated id, a seed phrase). Lets a
			// static const char*[] express emphasis, so a screen needs the callback
			// form only for genuinely dynamic content. Inline spans (*bold*) come
			// later and belong in the backend, which owns fonts and metrics.
			it->style = TERMINAL_NORMAL;
			if (t && t[0] == '#' && t[1] == '#' && t[2] == '#') {
				t += 3;
				it->style = TERMINAL_HIGHLIGHT;
			}
			it->text  = t;
			it->user  = (void *)(intptr_t)idx;
			return 0;
		}
		if (op == LIST_COUNT)
			return v_item_count();
	}
	if (v_cb)
		return v_cb(op, idx, data);
	return -1;
}

static bool item_exists(int idx){
	view_item_t it = { "", TERMINAL_NORMAL, NULL };
	return vcb(LIST_GET_ITEM, idx, &it) == 0;
}

// The largest index that has an item (the newest, for a bottom-anchored view).
static int find_newest(void){
	int n = (v_sel > v_anchor) ? v_sel : v_anchor;
	if (n < 0)
		n = 0;
	while (n > 0 && !item_exists(n))  // settle onto a real item
		n--;
	while (item_exists(n + 1))
		n++;
	return n;
}

// ---- layout (anchor-outward virtualization) ------------------------------

static void layout_topdown(void){
	// Rows are children of the list container, whose origin is already the list
	// top — so lay out in CONTAINER-LOCAL coords [0, rb_list_height()], not screen.
	rb_list_reset();                       // full-area base (so a render is never clipped)
	int top = 0, h = rb_list_height();
	int content_h = 0;
	for (int tries = 0; tries < 128; tries++){
		rb_rows_begin();
		int y = top, idx = v_anchor, first = v_anchor, last = v_anchor - 1;
		bool any = false;
		while (y < top + h){
			view_item_t it = { "", TERMINAL_NORMAL, NULL };
			if (vcb(LIST_GET_ITEM, idx, &it) != 0)
				break;
			rb_row r = rb_row_acquire();
			if (!r)
				break;
			int rh = rb_row_set(r, it.text, it.meta, it.meta_inline, it.style, it.separator, y, false, v_focus == F_LIST && idx == v_sel, it.dot, it.recolor);
			if (any && y + rh > top + h) {  // don't show a partly-visible bottom row
				rb_row_hide(r);
				break;
			}
			last = idx; any = true; y += rh; idx++;
		}
		rb_rows_commit();
		content_h = y - top;
		if (v_focus != F_LIST || !any)
			break;
		if (v_sel < first) {  // scroll up to reveal sel
			v_anchor = v_sel;
			continue;
		}
		if (v_sel > last) {  // scroll down one
			v_anchor++;
			continue;
		}
		break;
	}
	// With an editor present, dock the (short) prompt+list just above it.
	if (v_has_input)
		rb_list_dock(content_h);
}

// One top-down pass from `start` (no scroll convergence) — used to top-align a
// thread that doesn't fill the viewport, so it starts just below the title rather
// than floating against the compose box.
static void render_topdown_from(int start){
	int top = 0, h = rb_list_height();
	rb_rows_begin();
	int y = top, idx = start, last = start;
	bool any = false;
	while (y < top + h){
		view_item_t it = { "", TERMINAL_NORMAL, NULL };
		if (vcb(LIST_GET_ITEM, idx, &it) != 0)
			break;
		rb_row r = rb_row_acquire();
		if (!r)
			break;
		int rh = rb_row_set(r, it.text, it.meta, it.meta_inline, it.style, it.separator, y, false, v_focus == F_LIST && idx == v_sel, it.dot, it.recolor);
		// A bottom row that spills past the viewport stays RENDERED (the list clips it),
		// so its visible head shows instead of the whole message vanishing when there
		// was almost-but-not-quite room. It isn't counted in `last` (still the bottom-
		// most FULLY-visible row), so selecting it scrolls it fully in.
		if (any && y + rh > top + h)
			break;
		last = idx; any = true; y += rh; idx++;
	}
	rb_rows_commit();
	// Keep the bottom-anchored state consistent: v_anchor is the bottom-most fully
	// shown row, so a later bottom-up pass (e.g. scrolling back down) starts right.
	v_anchor = last;
}

static void layout_bottomup(void){
	// Clear any dock left by a previous top-down pass: a bottom-anchored layout
	// never docks, and a STALE dock offsets every painted row downward — the
	// empty-thread chat bug, where the first reply rendered below the clip.
	rb_list_reset();
	int top = 0, h = rb_list_height();   // container-local coords (see layout_topdown)
	for (int tries = 0; tries < 128; tries++){
		rb_rows_begin();
		int y = top + h, idx = v_anchor, first = v_anchor;
		bool any = false, hit_oldest = false;
		while (y > top){
			view_item_t it = { "", TERMINAL_NORMAL, NULL };
			if (vcb(LIST_GET_ITEM, idx, &it) != 0) {  // no older item (top edge)
				hit_oldest = true;
				break;
			}
			rb_row r = rb_row_acquire();
			if (!r)
				break;
			int rh = rb_row_set(r, it.text, it.meta, it.meta_inline, it.style, it.separator, y, true, v_focus == F_LIST && idx == v_sel, it.dot, it.recolor);
			// A top row that spills above the viewport stays RENDERED (the list clips
			// it), so its visible tail shows instead of the whole message vanishing.
			// It isn't counted in `first` (still the topmost FULLY-visible row), so
			// selecting it scrolls it fully in.
			if (any && y - rh < top)
				break;
			first = idx; any = true; y -= rh; idx--;
		}
		rb_rows_commit();
		// Converge the selection into view FIRST — before the underfull top-align.
		// Otherwise, scrolled near the oldest, the render hits the top edge with room
		// (hit_oldest) and top-aligns to the oldest, bypassing the down-scroll: a DOWN
		// press moved v_sel to a newer message below the viewport but the view never
		// followed (selection "disappeared"). Scrolling up was unaffected.
		if (v_focus == F_LIST && any){
			if (v_sel > v_anchor) {  // sel below bottom -> scroll down
				v_anchor = v_sel;
				continue;
			}
			if (v_sel < first){
				// sel above the top FULLY-visible row. If it's the OLDEST (nothing older),
				// top-align from it so the first message sits fully at the top instead of
				// staying clipped (which pinned the highlight to "second from top" and
				// pushed the newest off the bottom). Otherwise scroll up one and retry.
				if (!item_exists(v_sel - 1)) {
					render_topdown_from(v_sel);
					return;
				}
				v_anchor--; continue;
			}
		}
		// Underfull (ran out of older messages with room to spare, and v_sel is now in
		// view): top-align from the oldest so the thread starts just below the title.
		if (any && hit_oldest && y > top) {
			render_topdown_from(first);
			return;
		}
		return;
	}
}

static void relayout(void){
	if (v_bottom)
		layout_bottomup();
	else
		layout_topdown();
	rb_edit_focus(v_focus == F_EDIT);
	rb_go_focus(v_focus == F_GO);
}

// ---- public API ----------------------------------------------------------

void view_set(view_cb_t cb, const char *title, const char *prompt,
              const char **items, const char *input_hint, const char *input_prefill){
	v_cb        = cb;
	v_items     = items;
	v_has_input = (input_hint != NULL);
	v_focus     = F_LIST;
	v_follow    = false;
	view_dirty     = false;
	v_input_filter = NULL;                    // opt-in per screen; never inherited across a navigation
	v_multiline = false;                      // single-line default; a screen opts in after view_set
	rb_edit_set_multiline(false);             // the BACKEND must be told too -- without this the
	                                          //   mode leaks from the previous screen (a chat's
	                                          //   3-line box turned up on the relay-IP field)
	rb_edit_set_max(0);                       // and re-caps after view_set, like the filter
	rb_body_set_fixed(false);                 // default proportional body; a screen opts into fixed after view_set
	rb_row_pad_set(5, 5);                     // default row leading; a screen overrides after view_set
	v_gen++;                                  // a navigation: any in-flight key handler must not touch us

	rb_show();
	rb_title(title ? title : "");
	rb_prompt(prompt);                       // NULL/"" hides the zone
	if (v_has_input)
		rb_edit_show(input_hint, input_prefill);
	else
		rb_edit_hide();

	// Infer anchoring + initial selection. An item above index 0 => a history
	// list (chat) => bottom-anchored, newest pinned to the bottom.
	v_bottom = item_exists(-1);
	bool have0 = item_exists(0);
	if (v_bottom){
		v_anchor = v_sel = find_newest();
		v_follow = true;
	} else {
		v_anchor = v_sel = 0;
	}
	if (!have0 && v_has_input)  // empty list -> start in the text box
		v_focus = F_EDIT;

	v_active = true;
	relayout();
}

void view_set_input_filter(const char *allowed_or_null){
	v_input_filter = allowed_or_null;   // pointer borrowed (pass a string literal); cleared by view_set
}

void view_set_input_max(int n){
	rb_edit_set_max(n);
}

void view_set_input_multiline(bool on){
	v_multiline = on;            // remembered: it decides what Enter MEANS (see view_handle_key)
	rb_edit_set_multiline(on);   // backend resizes the editor box + list container
	if (v_active)  // re-render rows into the resized list viewport
		relayout();
}

void view_set_body_fixed(bool on){
	rb_body_set_fixed(on);       // backend renders rows in the fixed-width font
	if (v_active)  // re-render rows in the new font
		relayout();
}

void view_set_row_pad(int top, int bottom){
	rb_row_pad_set(top, bottom);
	if (v_active)
		relayout();
}

int view_body_cols(void){
	return rb_body_cols();
}

void view_body_preview(const char *in, bool in_more, int maxlines, char *out, int cap){
	rb_body_preview(in, in_more, maxlines, out, cap);
}

uint32_t view_body_wrap_next(const char *in, uint32_t *display_len){
	return rb_body_wrap_next(in, display_len);
}

void view_invalidate(void){
	view_dirty = true;        // core-0-safe: drained by view_slice on core 1
	view_epoch++;             // signals dynamic screens their data may have changed
}

void view_follow_newest(void){
	// Re-arm bottom-follow: the next dirty-drain (view_slice) jumps the anchor to
	// the newest item. Focus and the editor's text are untouched — this only
	// affects which rows are shown. No-op for a top-anchored view (v_follow unused).
	v_follow = true;
}

const char *view_input_text(void){
	if (v_has_input)
		return rb_edit_text();
	return "";
}

void view_select(int item_index){
	if (!v_active)
		return;
	v_focus = F_LIST;
	v_sel = item_index;
	if (v_bottom)
		v_follow = !item_exists(v_sel + 1);
	relayout();
}

int view_selected(void){ return v_sel; }

// ---- glue (ui.cpp / keyboard.cpp) ----------------------------------------

bool view_is_active(void){ return v_active; }

view_cb_t view_current(void){ return v_active ? v_cb : NULL; }

void view_deactivate(void){
	if (!v_active)
		return;
	v_active = false;
	rb_hide();
}

bool view_input_focused(void){ return v_active && v_focus == F_EDIT; }

// A "back" gesture (ESC / backspace) delivered to the active view. Returns true if
// the view CONSUMED it — i.e. its cb navigated to a parent screen (view_set bumped
// v_gen / swapped the cb, or deactivated). The caller (ui_slice) then skips the
// global go-home. A view that doesn't handle LIST_BACK leaves everything unchanged
// -> not consumed -> home as before.
bool view_back(void){
	if (!v_active)
		return false;
	uint32_t   gen = v_gen;
	view_cb_t  cb  = v_cb;
	vcb(LIST_BACK, v_sel, NULL);
	return !v_active || v_gen != gen || v_cb != cb;
}

void view_input_cursor_edge(bool *at_start, bool *at_end){
	rb_edit_cursor_edge(at_start, at_end);
}

void view_slice(void){
	if (!v_active)
		return;
	rb_tick();
	if (view_dirty){
		view_dirty = false;
		// A FOLLOWED view that has GAINED CONTENT since view_set must switch to
		// bottom-anchored — history (an item at -1) or even a single first message
		// (item 0): the bottom-up pass's underfull top-align is what gives a short
		// thread its consistent under-the-title look, where the top-down pass would
		// dock it against the editor like a form. Only promotes (never demotes);
		// v_follow is the guard — only a thread-shaped screen ever sets it.
		if (v_follow && !v_bottom && (item_exists(-1) || item_exists(0)))
			v_bottom = true;
		if (v_bottom && v_follow)
			v_anchor = v_sel = find_newest();
		relayout();
	}
}

void view_handle_key(int key){
	if (!v_active)
		return;

	// --- focus on the Go (send) button ---
	if (v_focus == F_GO){
		switch (key){
			case VIEW_K_ENTER: {                              // Go = SEND
				uint32_t gen = v_gen;
				vcb(EDIT_ENTER, 0, (void *)rb_edit_text());   // cb sends; may view_invalidate OR navigate (view_set)
				if (v_gen != gen || !v_active)  // cb switched views — leave the new one untouched
					return;
				rb_edit_clear();
				v_focus = F_EDIT;                             // back to the box for the next message
				relayout();
				return;
			}
			case VIEW_K_LEFT:
			case VIEW_K_PREV:
			case VIEW_K_UP:                                   // back to the text box
				v_focus = F_EDIT;
				relayout();
				return;
			default:
				return;                                       // right/down on Go: nothing
		}
	}

	// --- focus in the text box: Enter inserts a newline; arrow off an edge moves ---
	if (v_focus == F_EDIT){
		// A SINGLE-LINE field COMMITS on Enter. The field is the whole purpose of
		// such a screen (an IP, a name, a code), so making the user arrow down to
		// Go first is a keystroke for nothing -- and single-line screens draw no
		// Go button at all. A MULTILINE composer keeps the BlackBerry split:
		// Enter is a newline, Go sends.
		if (key == VIEW_K_ENTER && !v_multiline){
			uint32_t gen = v_gen;
			vcb(EDIT_ENTER, 0, (void *)rb_edit_text());
			if (v_gen != gen || !v_active)  // cb navigated away
				return;
			rb_edit_clear();
			relayout();
			return;
		}
		switch (key){
			case VIEW_K_DOWN:
			case VIEW_K_NEXT:                                 // off the end -> Go (send) button
				if (!v_multiline)  // no Go button on a single-line screen
					return;
				v_focus = F_GO;
				relayout();
				return;
			case VIEW_K_UP:
			case VIEW_K_PREV:                                 // off the top -> back to the list
				v_focus = F_LIST;
				v_sel = find_newest();                        // the row just above the box (newest item)
				if (v_bottom)
					v_follow = true;
				relayout();
				return;
			default:
				// Per-screen input mask: drop a printable char not in the allowed
				// set (control/cursor keys always pass). Opt-in via view_set_input_filter.
				if (v_input_filter && key >= 32 && key < 127 && !strchr(v_input_filter, key))
					return;
				rb_edit_key(key);                             // Enter(newline) / printable / backspace / cursor
				// Only a text change can alter the box height — skip the (O(n)) re-measure
				// on pure cursor moves (left/right), which is what dragged as text grew.
				if (key == VIEW_K_ENTER || key == VIEW_K_BACKSPACE || (key >= 32 && key < 127))
					if (rb_edit_autosize())  // growable box changed height -> re-flow the list
						relayout();
				return;
		}
	}

	// --- focus on the list ---
	switch (key){
		case VIEW_K_UP:
		case VIEW_K_PREV:
			if (item_exists(v_sel - 1)){
				v_sel--;
				if (v_bottom)
					v_follow = false;
				relayout();
			}
			return;
		case VIEW_K_DOWN:
		case VIEW_K_NEXT:
			if (item_exists(v_sel + 1)){
				v_sel++;
				if (v_bottom)
					v_follow = !item_exists(v_sel + 1);
				relayout();
			} else if (v_has_input){                          // past the newest -> into the text box
				v_focus = F_EDIT;
				relayout();
			}
			return;
		case VIEW_K_ENTER: {
			view_item_t it = { "", TERMINAL_NORMAL, NULL };
			if (vcb(LIST_GET_ITEM, v_sel, &it) == 0)
				vcb(LIST_SELECTED, v_sel, it.user);
			return;
		}
		default:
			vcb(LIST_KEY, key, NULL);   // offer the raw key to the screen (call view: +/- volume)
			return;
	}
}
