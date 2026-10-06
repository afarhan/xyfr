// ansi.h — the VT100/ANSI-subset parser in app_terminal.c: raw shell bytes in,
// cells in the terminal grid out. Covers exactly the `xyfr` terminfo entry
// (secserver/xyfr.ti): cursor addressing, scroll regions, erase, SGR
// colour/bold/reverse/underline, DEC line drawing, a light alt-screen, cursor
// show/hide. No UTF-8, no background colour.
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Reset cursor, pen, scroll region and parser state. Does not clear the grid.
void ansi_reset(void);

// Feed n bytes of shell output into the grid.
void ansi_feed(const uint8_t *b, int n);

#ifdef __cplusplus
}
#endif
