#pragma once
//
// view_theme.h — the swappable LOOK of the view UI: every colour and font in
// one place. Swap the active theme to restyle the whole view layer at once
// (dark / light / monochrome / …). Colours are 0xRRGGBB.
//
// The font fields point at Xyfr's own tfont tables (tfont.h). They used to be
// lv_font_t*, which made this a backend-level header tied to LVGL; it is now
// renderer-independent, and the tables live in view_theme.cpp. Row colours/fonts take effect on the next render; chrome (screen /
// editor) on the next screen open or via view_theme_set().
//
#include <stdint.h>
#include "tfont.h"

typedef struct {
	const tfont_t *font_body;     // message / menu item text
	const tfont_t *font_meta;     // small subtitle line (e.g. message timestamps)
	const tfont_t *font_title;    // title-bar text

	uint32_t screen_bg;             // whole-screen background
	uint32_t chrome_fg;             // title bar (title / wifi / clock) + prompt text
	uint32_t chrome_bg;             // title-bar FILL. Its own colour so the bar reads as
	                                //   chrome rather than as part of the list; it replaces
	                                //   the hairline that used to separate them.

	uint32_t row_bg;                // received message / default list item
	uint32_t row_bg_sent;           // sent message (the "highlight" style)
	uint32_t row_bg_selected;       // the focused row
	uint32_t row_fg;                // body text
	uint32_t row_fg_selected;       // body text on the focused row (contrast vs row_bg_selected)
	uint32_t row_fg_dim;            // dimmed text (TERMINAL_GRAY)
	uint32_t msg_out_fg;            // sent message accent — the "You · time" subheading (red)
	uint32_t msg_in_fg;             // received message accent — the sender subheading (green)
	uint32_t meta_fg;               // subtitle text (non-message rows)
	uint32_t separator;             // the hard line between message rows

	uint32_t edit_bg;               // compose box fill
	uint32_t edit_fg;               // compose box typed text
	uint32_t edit_border;           // compose box border
	uint32_t go_bg;                 // Go button fill, unfocused
	uint32_t go_bg_focused;         // Go button fill, focused
	uint32_t go_fg;                 // Go label, unfocused
	uint32_t go_fg_focused;         // Go label, focused
} view_theme_t;

extern const view_theme_t THEME_DARK;    // default
extern const view_theme_t THEME_LIGHT;
extern const view_theme_t THEME_MONO;    // black/white, white separators

extern const view_theme_t *view_theme;          // the active theme (defaults to &THEME_DARK)
void view_theme_set(const view_theme_t *t);      // swap it (re-applies chrome; rows re-theme on next render)
