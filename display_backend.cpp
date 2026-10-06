// display_backend.cpp — the ONE place that knows which physical display is
// compiled (DISPLAY_ILI9488, display_select.h). Implements the three-function
// contract in display_backend.h; ui.cpp is display-agnostic.

#include "display_backend.h"
#include <Arduino.h>
#if DISPLAY_ILI9488
#else
#include <Adafruit_GFX.h>
#include <Fonts/FreeSans9pt7b.h>
#include <Fonts/FreeSans12pt7b.h>
#include <SPI.h>
#include "sharp_ls032.h"
#endif
#include "ui.h"   // TFT_HOR_RES / TFT_VER_RES geometry
#include "text_engine.h"   // tfont + text_width (panel_text renders from our own tables)
#include "ili9488.h"       // ONE panel driver: panel_* pushes through the engine too

// Off-screen band buffer for the panel_* compositor (~1/10 screen, RGB565).
// It was LVGL's partial-render buffer; LVGL is gone, but panel_canvas_begin/end
// still composes bands here so the boot/restore chrome does not blink.
#define DRAW_BUF_SIZE (TFT_HOR_RES * TFT_VER_RES / 10 * 2)
static uint32_t draw_buf[DRAW_BUF_SIZE / 4];

// Max glyph box for the panel_* text renderer's scratch buffers (montserrat_14 fits).
#define PANEL_GLYPH_MAX 48

#if DISPLAY_ILI9488
// ─── ILI9488 (RGB565), driven by ili9488.cpp over SPI1 ──────────────────────

void display_begin(void){
	ili_init();
}

void display_test_pattern(char mode){
	const uint16_t BK = rgb(0,0,0), WH = rgb(255,255,255);
	if (mode == 'b') {
		ili_fill_rect(0, 0, ILI_W, ILI_H, BK);
		return;
	}
	if (mode == 'w') {
		ili_fill_rect(0, 0, ILI_W, ILI_H, WH);
		return;
	}
	ili_fill_rect(0, 0, ILI_W, ILI_H, WH);                       // 'f': frame + centre cross
	ili_fill_rect(0, 0, ILI_W, 1, BK);
	ili_fill_rect(0, ILI_H - 1, ILI_W, 1, BK);
	ili_fill_rect(0, 0, 1, ILI_H, BK);
	ili_fill_rect(ILI_W - 1, 0, 1, ILI_H, BK);
	ili_fill_rect(0, ILI_H / 2, ILI_W, 1, BK);
	ili_fill_rect(ILI_W / 2, 0, 1, ILI_H, BK);
}



void display_vcom_tick(void){ /* COM driven by hardware EXTCOMIN path; nothing to do */ }

// Direct text-UI (display_backend.h) — ILI9488: white-on-black, drawn immediately.
void panel_begin(void){
	ili_init();
	pinMode(6, OUTPUT); digitalWrite(6, HIGH);   // backlight on (GPIO6) — ui_init isn't run in dt mode
	ili_fill_rect(0, 0, ILI_W, ILI_H, rgb(0,0,0));
}
void panel_clear(void){ ili_fill_rect(0, 0, ILI_W, ILI_H, rgb(0,0,0)); }

// ── off-screen band compositing (draw_buf as the back buffer) ────────────────
// While panel_canvas != NULL, panel_fill/panel_frame/panel_glyph_blit compose into draw_buf
// (an RGB565 band covering panel_c*), and panel_canvas_end() blits it in one transfer.
static uint16_t *panel_canvas = NULL;
static int panel_cx, panel_cy, panel_cw, panel_ch;
static uint8_t panel_ink = 255;                                    // text ink level (255=white)
void panel_text_color(uint8_t grey){ panel_ink = grey; }
static inline uint16_t panel_blend(uint16_t bg, uint8_t cov, uint8_t shade){   // blend bg toward grey(shade) by cov
	int tr = shade >> 3, tg = shade >> 2, tb = shade >> 3;
	int r = (bg >> 11) & 0x1F, g = (bg >> 5) & 0x3F, b = bg & 0x1F;
	r += ((tr - r) * cov) / 255; g += ((tg - g) * cov) / 255; b += ((tb - b) * cov) / 255;
	return (uint16_t)((r << 11) | (g << 5) | b);
}
void panel_canvas_begin(int x, int y, int w, int h){
	if((long)w * h * 2 > (long)sizeof(draw_buf)) {  // too big -> live (may blink)
		panel_canvas = NULL;
		return;
	}
	panel_canvas = (uint16_t *)draw_buf; panel_cx = x; panel_cy = y; panel_cw = w; panel_ch = h;
	for(int i = 0; i < w * h; i++)  // clear the band to black
		panel_canvas[i] = 0x0000;
}
void panel_canvas_end(void){
	if(!panel_canvas)
		return;
	ili_set_window(panel_cx, panel_cy, panel_cw, panel_ch);
	ili_push_pixels(panel_canvas, (uint32_t)panel_cw * panel_ch);                         // one bulk transfer
	panel_canvas = NULL;
}

void panel_fill(int x, int y, int w, int h, bool fg){
	if(panel_canvas){
		uint16_t c = fg ? 0xFFFF : 0x0000;
		for(int yy = 0; yy < h; yy++){ int cy = y + yy - panel_cy; if(cy < 0 || cy >= panel_ch) continue;
			for(int xx = 0; xx < w; xx++){ int cx = x + xx - panel_cx; if(cx < 0 || cx >= panel_cw) continue;
				panel_canvas[cy * panel_cw + cx] = c; } }
		return;
	}
	ili_fill_rect(x, y, w, h, fg ? rgb(255,255,255) : rgb(0,0,0));
}
void panel_frame(int x, int y, int w, int h){
	if(panel_canvas){ panel_fill(x, y, w, 1, true); panel_fill(x, y + h - 1, w, 1, true);
	               panel_fill(x, y, 1, h, true); panel_fill(x + w - 1, y, 1, h, true); return; }
	const uint16_t WH = rgb(255,255,255);
	ili_fill_rect(x, y, w, 1, WH);
	ili_fill_rect(x, y + h - 1, w, 1, WH);
	ili_fill_rect(x, y, 1, h, WH);
	ili_fill_rect(x + w - 1, y, 1, h, WH);
}
void panel_present(void){ /* immediate; bands are pushed by panel_canvas_end() */ }
int  panel_width(void){ return ILI_W; }
int  panel_height(void){ return ILI_H; }
// White-on-black: an A8 coverage box is a grey-level image (white ink over black).
// In a canvas, alpha-composite onto the band (correct over overlaps/non-black bg);
// live, build the box in RAM and push it in one transfer.
void panel_glyph_blit(int x, int y, int w, int h, const uint8_t *a8){
	if(panel_canvas){
		for(int py = 0; py < h; py++){ int cy = y + py - panel_cy; if(cy < 0 || cy >= panel_ch) continue;
			for(int px = 0; px < w; px++){ uint8_t cov = a8[py * w + px]; if(!cov) continue;
				int cx = x + px - panel_cx; if(cx < 0 || cx >= panel_cw) continue;
				uint16_t *d = &panel_canvas[cy * panel_cw + cx];
				*d = panel_blend(*d, cov, panel_ink); } }
		return;
	}
	static uint16_t buf[PANEL_GLYPH_MAX * PANEL_GLYPH_MAX];
	int n = w * h;
	if(n > PANEL_GLYPH_MAX * PANEL_GLYPH_MAX)
		return;
	for(int i = 0; i < n; i++) {
		uint8_t v = (uint16_t)a8[i] * panel_ink / 255;
		buf[i] = rgb(v, v, v);
	}
	ili_set_window(x, y, w, h);
	ili_push_pixels(buf, (uint32_t)n);
}

uint16_t *panel_scratch(unsigned *bytes){
	if(bytes)
		*bytes = (unsigned)sizeof(draw_buf);
	return (uint16_t *)draw_buf;
}
void panel_push_band(int x, int y, int w, int h, const uint16_t *px){
	ili_set_window(x, y, w, h);
	ili_push_pixels(px, (uint32_t)w * h);           // one bulk SPI transfer
}
// panel_text / panel_text_width live in the shared section below (panel-agnostic).

#else
// ─── Sharp LS032B7DD02 (1-bit memory LCD) ────────────────────────────────────
// Native 336x536 portrait; the driver rotates to 536x336 landscape
// (setRotation(3)). LVGL renders 1-bit (I1); my_disp_flush packs each tile into
// the driver's framebuffer and refresh() pushes only the dirty native-line band.
// See sharp_ls032.* for the SPI protocol + wiring. SCK/MOSI/CS = 10/11/13 (SPI1).
#define SHARP_SCK   10
#define SHARP_MOSI  11
#define SHARP_SS    13
#define MONO_BLACK  0
#define MONO_WHITE  1

// Non-static: view_gfx.cpp externs `display` when the experimental GFX view
// backend is selected.
Sharp_LS032 display(&SPI1, SHARP_SCK, SHARP_MOSI, SHARP_SS);

/* The bitblt for the Sharp panel, native 1-bit (LV_COLOR_FORMAT_I1): LVGL has
 * already rendered the tile as packed monochrome — fonts thresholded at draw
 * time on glyph COVERAGE, so strokes are crisp instead of anti-aliased-then-
 * luminance-thresholded (the old RGB565 path dropped pixels on thin strokes).
 *
 * I1 buffer layout (verified against lv_refr.c get_max_row / draw_buf_flush):
 *   - px_map starts with an 8-byte palette (2 colours x lv_color32_t); the
 *     pixel rows begin at px_map + 8.
 *   - 1 bit per pixel, MSB-first (bit 7 = leftmost pixel of the byte).
 *   - LVGL rounds I1 flush areas so x1/x2 land on byte boundaries, so each row
 *     is a whole number of bytes: stride = width/8.
 *   - bit == 1 is the high-luminance colour (white), bit == 0 is black —
 *     lines up with MONO_WHITE/MONO_BLACK with no inversion.
 * drawPixel accumulates the dirty native-line band; refresh() (on the final
 * tile) pushes only that band over SPI. */
// Optional top inset: the whole UI can be shifted DOWN by SHARP_TOP_INSET (the
// flush offsets every pixel by +SHARP_TOP_INSET and the LVGL drawable height is
// reduced by the same amount when the Sharp backend is written, so nothing runs off the bottom).
// Set to 0 = no shift (UI sits at the top edge, reverted from the earlier 15 px
// down-shift). Raise it only for a unit whose bezel truly clips the title bar.
#define SHARP_TOP_INSET 0
static void my_disp_flush(lv_display_t *disp, const lv_area_t *area, uint8_t *px_map){
	px_map += 8;                                  // skip the I1 palette
	int32_t w = area->x2 - area->x1 + 1;          // byte-aligned by LVGL
	int32_t stride = (w + 7) >> 3;                // bytes per row (align 1)
	for (int32_t y = area->y1; y <= area->y2; y++) {
		const uint8_t *row = px_map + (y - area->y1) * stride;
		for (int32_t x = 0; x < w; x++) {
			uint8_t bit = (row[x >> 3] >> (7 - (x & 7))) & 1;
			display.drawPixel(area->x1 + x, y + SHARP_TOP_INSET, bit ? MONO_WHITE : MONO_BLACK);
		}
	}
	if (lv_display_flush_is_last(disp))
		display.refresh();   // push only the dirty native-line band over SPI
	lv_display_flush_ready(disp);
}

void display_begin(void){
	display.begin();
	display.clearDisplay();
	display.setRotation(1);   // 336x536 portrait -> 536x336 landscape (rotated 180 from setRotation(3))
	display.refresh();        // paint the cleared (white) framebuffer before the splash
}

// display_create() was the LVGL display registration and is GONE -- nothing
// called it once ui_init() switched to ili_init(). The Sharp port needs its own
// bring-up over sharp_ls032.*, not this.

void display_test_pattern(char mode){
	if (mode == 'b') {
		display.fillScreen(MONO_BLACK);
	}
	else if (mode == 'w') {
		display.fillScreen(MONO_WHITE);
	}
	else { // 'f': frame at the extreme edges + centre cross, on white
		display.fillScreen(MONO_WHITE);
		int w = display.width(), h = display.height();          // 536 x 336 (rotated)
		display.drawRect(0, 0, w, h, MONO_BLACK);               // 1px frame at the true edges
		display.drawFastHLine(0, h / 2, w, MONO_BLACK);         // centre cross
		display.drawFastVLine(w / 2, 0, h, MONO_BLACK);
	}
	display.refresh();
}

void display_vcom_tick(void){
	// EXTMODE is tied low → COM polarity is inverted by the M1 bit we send (no
	// external EXTCOMIN clock). The LC needs a roughly constant inversion period
	// (datasheet fCOM 0.5-5 Hz), so toggle ~1 Hz regardless of redraw activity
	// (refresh() adopts the current polarity without flipping it, so this owns
	// the cadence).
	static uint32_t last = 0;
	uint32_t now = millis();
	if (now - last >= 1000) {
		last = now;
		display.toggleVCOM();
	}
}

// Direct text-UI (display_backend.h) — Sharp: black-on-white, buffered (present = refresh).
void panel_begin(void){ display.begin(); display.setRotation(1); display.fillScreen(MONO_WHITE); display.refresh(); }
void panel_clear(void){ display.fillScreen(MONO_WHITE); }
void panel_fill(int x, int y, int w, int h, bool fg){ display.fillRect(x, y, w, h, fg ? MONO_BLACK : MONO_WHITE); }
void panel_frame(int x, int y, int w, int h){ display.drawRect(x, y, w, h, MONO_BLACK); }
void panel_present(void){ display.refresh(); }
int  panel_width(void){ return display.width(); }
int  panel_height(void){ return display.height(); }
// Black-on-white 1-bit: threshold each coverage pixel. drawPixel writes the
// in-RAM framebuffer (panel_present -> refresh does the bitblt), so no per-pixel SPI.
void panel_glyph_blit(int x, int y, int w, int h, const uint8_t *a8){
	for(int py = 0; py < h; py++)
		for(int px = 0; px < w; px++){
			uint8_t c = a8[py * w + px];
			if(c)
				display.drawPixel(x + px, y + py, c >= 128 ? MONO_BLACK : MONO_WHITE);
		}
}

uint16_t *panel_scratch(unsigned *bytes){
	if(bytes)
		*bytes = (unsigned)sizeof(draw_buf);
	return (uint16_t *)draw_buf;
}
// The Sharp panel is 1-bit and its gate lines run along logical X, so there is
// no cheap "band" here -- a text row touches every gate line. Threshold per
// pixel into the framebuffer and let refresh() coalesce; correct, but the
// column-major traversal that makes this fast is deliberately still TODO.
void panel_push_band(int x, int y, int w, int h, const uint16_t *px){
	for(int py = 0; py < h; py++)
		for(int pxi = 0; pxi < w; pxi++)
			display.drawPixel(x + pxi, y + py, px[py * w + pxi] ? MONO_BLACK : MONO_WHITE);
}
// Sharp already composes clear+text in the framebuffer, so a canvas is just a
// refresh bracket (no separate off-screen buffer needed to avoid the blink).
void panel_canvas_begin(int x, int y, int w, int h){ (void)x; (void)y; (void)w; (void)h; }
void panel_canvas_end(void){ display.refresh(); }
void panel_text_color(uint8_t grey){ (void)grey; }   // 1-bit panel: no grey, text stays black
// panel_text / panel_text_width live in the shared section below (panel-agnostic).
#endif // DISPLAY_ILI9488

// ─── panel_text / panel_text_width: render from Xyfr's OWN font tables ─────────────
// Was: decode lvgl's packed A1/A2/A4 glyph formats through lv_font_get_glyph_dsc.
// Now: tfont (tfont.h), which is uniform-height, byte-aligned-row 4bpp coverage
// -- so the unpack is a nibble read with no per-glyph offset arithmetic, and the
// cell top IS the draw y. Still no runtime and no allocation: safe on the restore
// boot path, which brings nothing up.

extern const tfont_t mont14;
extern const tfont_t mont10;

// size 1 -> the small chrome font (== the theme's font_title/font_meta);
// size >= 2 -> the body font (== font_body).
static const tfont_t *panel_font_for(uint8_t size){
	if ((size <= 1))
		return &mont10;
	return &mont14;
}

void panel_text(int x, int y, uint8_t size, const char *s){
	const tfont_t *f = panel_font_for(size);
	static uint8_t a8[PANEL_GLYPH_MAX * PANEL_GLYPH_MAX];             // glyph coverage scratch
	const unsigned char *p = (const unsigned char *)s;
	while(*p){
		uint32_t cp = tfont_utf8(&p, p + 4);
		int gi = tfont_index(f, cp);
		if(gi < 0)
			continue;
		int w = f->width[gi], h = f->height;
		if(w > 0 && h > 0 && w * h <= PANEL_GLYPH_MAX * PANEL_GLYPH_MAX){
			const uint8_t *bm = f->bitmap + f->offset[gi];
			int rb = tfont_row_bytes(f, w);
			for(int py = 0; py < h; py++){
				const uint8_t *row = bm + (size_t)py * rb;
				for(int px = 0; px < w; px++){
					uint8_t nib = (px & 1) ? (row[px >> 1] & 0x0F) : (uint8_t)(row[px >> 1] >> 4);
					a8[py * w + px] = (uint8_t)(nib * 255 / 15);
				}
			}
			panel_glyph_blit(x, y, w, h, a8);                       // one bulk transfer per glyph
		}
		x += w;
	}
}

int panel_text_width(uint8_t size, const char *s){
	return text_width(panel_font_for(size), s);
}

void panel_text_center(int y, uint8_t size, const char *s){
	panel_text((panel_width() - panel_text_width(size, s)) / 2, y, size, s);
}
