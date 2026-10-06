#pragma once

// ─── Display selection (compile-time) ────────────────────────────────────────
// This single switch picks which physical panel the firmware drives. Only the
// selected backend compiles; the unselected one costs nothing. Everything above
// the display HAL (the view model, themes, fonts, layout) is shared — both
// panels render the same monochrome black-on-white UI (THEME_MONO), the ILI9488
// just in RGB565 at 480x320 instead of 1-bit at 536x336.
//
//   0 = Sharp LS032B7DD02   536x336, 1-bit reflective memory LCD (sharp_ls032.*, needs Adafruit_GFX)
//   1 = ILI9488 TFT         480x320, RGB565 (ili9488.*, no library)
//
// The panel can also be chosen at compile time WITHOUT editing this file, by
// defining DISPLAY_ILI9488 on the compiler command line — e.g.
//   arduino-cli compile --build-property build.extra_flags=-DDISPLAY_ILI9488=1
// or, via the build wrapper,  PANEL=ili9488 tools/build.sh build.
// The #ifndef guard below lets that external -D win; the value here is only the
// fallback when nothing defines it (so an unadorned Arduino IDE build = ILI9488,
// the shipping panel). Build for the Sharp with PANEL=sharp tools/build.sh build.
#ifndef DISPLAY_ILI9488
#define DISPLAY_ILI9488  1
#endif
