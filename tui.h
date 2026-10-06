// tui.h — the device's 80x25 terminal cell buffer and its renderer.
//
// The device does NO terminal emulation. The host runs libvterm, diffs the
// screen and sends changed cell runs (see secserver/termg.h); this side just
// stores them and paints. That is why there is no escape-sequence parser here.
//
// Layout: 80 cols x 6 px = 480 = the ILI9488 width exactly; 25 rows x 12 px =
// 300, leaving 20 px at the top for the SAME title bar every other screen has.

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "ui.h"        // UI_TITLE_H (the grid origin) + TFT_HOR_RES

#ifdef __cplusplus
extern "C" {
#endif

// Worst-case buffer sizing (the densest profile, 6x12 -> 80x25). The ACTIVE grid
// may be smaller with a larger font -- always use tui_cols()/tui_rows()/tui_cells()
// for the live dimensions, never these.
#define TUI_COLS_MAX   80
#define TUI_ROWS_MAX   25
#define TUI_CELLS_MAX  (TUI_COLS_MAX * TUI_ROWS_MAX)   // 2000
#define TUI_TOP_Y      UI_TITLE_H                      // grid origin: below the title bar

// The densest grid must fill the panel EXACTLY -- 20 + 25*12 = 320. A taller
// bar would clip the bottom row with nothing looking obviously wrong, which is
// why this is asserted rather than left to whoever next edits UI_TITLE_H.
_Static_assert(TUI_TOP_Y + TUI_ROWS_MAX * 12 == TFT_HOR_RES,
               "UI_TITLE_H + the 6x12 grid must fill the panel exactly");

// Font profiles: the choice sets the grid size (cols x rows) and glyph metrics.
enum {
	TUI_FONT_6X12 = 0,
	TUI_FONT_8X16 = 1,
	TUI_FONT_COUNT = 2
};
void tui_set_font(int profile);   // select + re-init the grid (clears it)
int  tui_font(void);              // current profile
int  tui_cols(void);              // active columns
int  tui_rows(void);              // active rows
int  tui_cells(void);             // cols * rows
int  tui_cw(void);                // glyph cell width  (px)
int  tui_ch(void);                // glyph cell height (px)

// One cell, 16 bits. Attributes live in the upper bits so the low byte is just
// the character -- a run of plain text memcmp's as bytes.
#define TC_CHAR_MASK 0x00FFu
#define TC_REVERSE   0x0100u                  // fg/bg swap (vi/less status lines)
#define TC_BOLD      0x0200u
#define TC_UNDERLINE 0x0400u
#define TC_FG_SHIFT  11                       // 4-bit ANSI colour index
#define TC_FG_MASK   0x7800u
#define TC_DIRTY     0x8000u                  // device-owned: needs repainting
#define TC_VAL_MASK  0x7FFFu                  // everything except DIRTY

#define TC_FG_DEFAULT 7u                      // ANSI white
#define TC_BLANK     ((TC_FG_DEFAULT << TC_FG_SHIFT) | 0x0020u)   // space, default fg

void tui_init(void);
void tui_reset(void);                          // all blank + full repaint
void tui_invalidate_all(void);                 // repaint everything as-is
void tui_full_clear(void);                     // wipe the raw panel (kills LVGL chrome ghosts)

// Write one cell / a run / a fill. All compare-before-write: an unchanged cell
// costs nothing and is NOT marked dirty, so the buffer is its own shadow and no
// second copy is needed.
void tui_poke(uint16_t off, uint16_t cell);
void tui_run (uint16_t off, uint16_t n, const uint8_t *chars, uint16_t attr_bits);
void tui_fill(uint16_t off, uint16_t n, uint16_t cell);

// Scroll rows [top,bot] by delta (>0 = content moves UP), blanking what comes
// in. Mirrors the host's own scroll so a scrolled screen costs ~50 bytes on the
// network instead of a full repaint.
void tui_scroll(int top, int bot, int delta);

// Copy the grid out as char/attr bytes (the shape termg_apply works on).
void tui_snapshot(uint8_t *chars, uint8_t *attrs);

void tui_cursor(int32_t off);                  // <0 hides it
bool tui_dirty(void);

// Draw pending cells, spending at most `budget_us`. Resumable: whatever it does
// not finish stays dirty for the next tick. The firmware is SINGLE-CORE and the
// voice pump shares this loop, so a whole-screen blit must never happen in one
// go.
void tui_pump(uint32_t budget_us);

#ifdef __cplusplus
}
#endif
