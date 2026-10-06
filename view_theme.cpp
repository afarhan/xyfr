// view_theme.cpp -- the theme TABLES: pure data, no renderer.
//
// These lived at the top of view_lvgl.cpp, outside its backend #if, because they
// were "pure data that always compiles". They were not: they named
// lv_font_montserrat_* and so kept <lvgl.h> -- and the whole library -- in the
// build. LVGL is being removed because it is the largest body of unaudited
// third-party code inside the trust boundary, so the tables move here and the
// font fields now point at Xyfr's own tfont tables.
//
// THEME_MONO's fonts were the Adafruit GFX FreeSans + a 1bpp Montserrat, which
// came with the Sharp GFX experiment (view_gfx.cpp). That backend is gone too;
// the mono theme keeps its own COLOURS (black on white, which is what the
// reflective panel needs) and shares the engine's fonts.

#include "display_select.h"   // DISPLAY_ILI9488 -- MUST be included: an undefined
                              // macro in #if is silently 0, so without this the
                              // panel test below picks THEME_MONO on the colour
                              // TFT and the whole UI comes up black-on-white.
                              // view_lvgl.cpp used to get it via ui.h.
#include "view_theme.h"

extern const tfont_t mont14;   // body
extern const tfont_t mont10;   // chrome + meta

const view_theme_t THEME_DARK = {
	&mont14, &mont10, &mont10,
	/*screen_bg*/0x000000, /*chrome_fg*/0xFFFFFF, /*chrome_bg*/0x002050,
	/*row_bg*/0x000000, /*row_bg_sent*/0x3F3F3F, /*row_bg_selected*/0x1565C0,
	/*row_fg*/0xFFFFFF, /*row_fg_selected*/0xFFFFFF, /*row_fg_dim*/0x808080,
	/*msg_out_fg*/0x00E5FF, /*msg_in_fg*/0x34C759, /*meta_fg*/0x9E9E9E,   // sent cyan / recv green subheading
	/*separator*/0xFFFFFF,
	/*edit_bg*/0x101010, /*edit_fg*/0xFFFFFF, /*edit_border*/0x888888,
	/*go_bg*/0x404040, /*go_bg_focused*/0x1565C0, /*go_fg*/0xFFFFFF, /*go_fg_focused*/0xFFFFFF,
};
const view_theme_t THEME_LIGHT = {
	&mont14, &mont10, &mont10,
	/*screen_bg*/0xFFFFFF, /*chrome_fg*/0xFFFFFF, /*chrome_bg*/0x002050,
	/*row_bg*/0xFFFFFF, /*row_bg_sent*/0xE0E0E0, /*row_bg_selected*/0x90CAF9,
	/*row_fg*/0x000000, /*row_fg_selected*/0x000000, /*row_fg_dim*/0x707070,
	/*msg_out_fg*/0xD32F2F, /*msg_in_fg*/0x2E7D32, /*meta_fg*/0x808080,   // sent red / recv green subheading
	/*separator*/0x000000,
	/*edit_bg*/0xF5F5F5, /*edit_fg*/0x000000, /*edit_border*/0x888888,
	/*go_bg*/0xE0E0E0, /*go_bg_focused*/0x90CAF9, /*go_fg*/0x000000, /*go_fg_focused*/0x000000,
};
// Monochrome: white background, black text everywhere; the focused row inverts to
// white-on-black. (Timestamps are black too — no grey — per "black text everywhere".)
const view_theme_t THEME_MONO = {
	// FreeSans (Adafruit GFX, FreeType-MONO-hinted) for the body; the Montserrat
	// 1bpp for the meta subtitle AND the whole top bar (wifi · title · clock all use
	// font_title). Icons fall back to font_mono_14. Sized up ~1.5x from the original
	// 9/10 for readability on the reflective panel (body is the largest crisp gfx
	// FreeSans available; chrome uses the 14 Montserrat). Chrome geometry (title bar,
	// rows, editor) is font-relative, so it follows these sizes automatically.
	&mont14, &mont10, &mont10,
	/*screen_bg*/0xFFFFFF, /*chrome_fg*/0x000000, /*chrome_bg*/0xFFFFFF,
	/*row_bg*/0xFFFFFF, /*row_bg_sent*/0xFFFFFF, /*row_bg_selected*/0x000000,
	/*row_fg*/0x000000, /*row_fg_selected*/0xFFFFFF, /*row_fg_dim*/0x000000,
	/*msg_out_fg*/0x000000, /*msg_in_fg*/0x000000, /*meta_fg*/0x000000,   // 1-bit panel: no colour (spacing differentiates)
	/*separator*/0x000000,
	/*edit_bg*/0xFFFFFF, /*edit_fg*/0x000000, /*edit_border*/0x000000,
	/*go_bg*/0xFFFFFF, /*go_bg_focused*/0x000000, /*go_fg*/0x000000, /*go_fg_focused*/0xFFFFFF,
};
// Theme per panel: the colour TFT (ILI9488) uses the dark theme; the Sharp
// reflective monochrome panel wants black-on-white (a dark theme is unreadable
// on it) — exactly THEME_MONO. The theme definitions themselves are untouched.
#if DISPLAY_ILI9488
const view_theme_t *view_theme = &THEME_DARK;
#else
const view_theme_t *view_theme = &THEME_MONO;
#endif
