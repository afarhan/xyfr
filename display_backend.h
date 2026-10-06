#pragma once
#include <stdint.h>

#include "display_select.h"

#ifdef __cplusplus
extern "C" {
#endif

// ─── The narrow display contract ─────────────────────────────────────────────
// ui.cpp talks to these three functions and never knows which panel is compiled.
// ALL per-panel divergence — driver include, the display object, the flush, the
// geometry-specific LVGL bring-up, COM inversion — lives in display_backend.cpp,
// gated by DISPLAY_ILI9488 (display_select.h). (Geometry #defines stay in ui.h,
// since the resolution is part of the UI's public contract used everywhere.)

// Panel hardware bring-up. Call BEFORE lv_init(): it touches the SPI/TFT
// peripheral and, on the Sharp panel, paints a cleared (white) framebuffer so
// the boot splash isn't an inverted flash.
void display_begin(void);

// Create + fully configure the LVGL display — geometry, draw buffer, colour

// Periodic COM inversion for the Sharp panel (EXTMODE tied low → software VCOM).
// No-op on the ILI9488 path. Call ~1 Hz.
void display_vcom_tick(void);

// Bench diagnostic (serial `dt <mode>`): draw straight through the DRIVER,
// bypassing LVGL, to isolate where an edge offset comes from. mode 'b' = fill
// black; 'w' = fill white; 'f' = white fill + 1px black frame at the extreme
// panel edges + centre cross. LVGL repaints over it on its next invalidation.
void display_test_pattern(char mode);

// ─── panel_*: draw straight to the panel, below the view engine ──────────────
// A tiny both-panel text/rect layer for screens that run BEFORE the view engine
// exists — restore mode and the firmware updater, which paint during boot and
// poll the keyboard themselves. (Was `dt_*`, for "direct text": direct meaning
// "not through LVGL", a distinction that stopped existing when LVGL was removed.) Colours are the panel's own theme (ILI9488
// white-on-black, Sharp black-on-white); the caller thinks only fg/bg. Text uses
// the engine's own tfont tables: size 1 = mont10 (chrome), size >= 2 = mont14.
// On the Sharp panel drawing is buffered — call panel_present() to push a frame; on
// ILI9488 drawing is immediate and panel_present() is a no-op.
void panel_begin(void);                                     // init the panel + clear
void panel_clear(void);                                     // clear to background
void panel_text(int x, int y, uint8_t size, const char *s); // foreground text at (x,y)
void panel_fill(int x, int y, int w, int h, bool fg);       // filled rect (true=fg, false=bg)
void panel_frame(int x, int y, int w, int h);               // foreground outline rect
void panel_present(void);                                   // push a frame (Sharp refresh; ILI9488 no-op)
int  panel_width(void);
int  panel_height(void);
int  panel_text_width(uint8_t size, const char *s);         // pixel width of `s` at `size` (for right/centre align)
void panel_glyph_blit(int x, int y, int w, int h, const uint8_t *a8);

// --- band blit, for the terminal grid renderer -----------------------------
// panel_scratch() hands out the shared compositing band buffer. SAFE ONLY while
// lv_timer_handler() is suspended (the terminal owns the panel for its whole
// lifetime); anything else must not use it.
uint16_t *panel_scratch(unsigned *bytes);
// Push a prepared RGB565 band straight to the panel in one transfer. On the
// 1-bit Sharp there is no RGB565, so it thresholds per pixel into the
// framebuffer instead -- correct, just slower (see the note in tui_paint.cpp).
void panel_push_band(int x, int y, int w, int h, const uint16_t *px); // blit a w*h A8-coverage glyph box (bulk transfer on ILI9488)

// Off-screen band compositing — kills the clear-then-repaint BLINK on the direct
// ILI9488 path. Bracket a repaint: every panel_fill/panel_frame/panel_text between these
// composes into an off-screen buffer covering (x,y,w,h), and panel_canvas_end() blits
// the finished band in ONE transfer, so the panel never shows the intermediate
// clear. The band must fit the shared draw buffer (~1/10 screen); a larger area
// falls back to live drawing. On Sharp, drawing already composes in the framebuffer
// so these just bracket the refresh.
void panel_canvas_begin(int x, int y, int w, int h);
void panel_canvas_end(void);

// Text ink level for subsequent panel_text() (0..255 grey; 255 = full white, the
// default). ILI9488 renders the grey; the 1-bit Sharp panel ignores it (text
// stays black). Set it before dimmer text, reset to 255 after.
void panel_text_color(uint8_t grey);
void panel_text_center(int y, uint8_t size, const char *s); // horizontally-centred text

#ifdef __cplusplus
}
#endif
