#pragma once
// The terminal's public face. Everything else lives in app_terminal.c: the
// ANSI parser, the cell grid, the screen and its handler.
//
// A SCREEN, opened with screen_push(APP_TERM, contact). These two exist
// because the panel is shared: the Sym2 legend band paints over the grid and
// has to ask the grid to repair itself afterwards, and the view engine has to
// know to stand down.

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// True while the terminal owns the panel.
bool terminal_grid_active(void);
bool terminal_active(void);

int app_terminal_main(int message, uint32_t param);

#ifdef __cplusplus
}
#endif
