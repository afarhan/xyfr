#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "ui_symbols.h"
#include "display_select.h"
#include "phone_state.h"   // enum phone_state + WIFI_* + the two C-callable hooks

#ifdef __cplusplus
extern "C" {
#endif

// Display geometry. The whole UI uses TFT_VER_RES as the WIDTH and TFT_HOR_RES
// as the HEIGHT (landscape, a convention inherited from the rotated ILI9488
// build). Which panel is active is set by DISPLAY_ILI9488 (display_select.h).
#if DISPLAY_ILI9488
// ILI9488 TFT, 320x480 native, rotated 90 deg by LVGL/TFT_eSPI to 480x320.
#define TFT_HOR_RES   320   // display height (landscape)
#define TFT_VER_RES   480   // display width  (landscape)
#else
// Sharp LS032B7DD02 — 336x536 native (PORTRAIT), driven by the custom
// large-panel protocol in sharp_ls032.cpp. The UI runs landscape 536x336,
// achieved by rotating the panel in the driver (display.setRotation(3) —
// 90 deg + 180 flip), not via LVGL rotation.
#define TFT_HOR_RES   336   // display height (landscape)
#define TFT_VER_RES   536   // display width  (landscape)
#endif

// Left inset for ALL screens. Historically 10
// on the ILI9488 to clear a supposed bezel overlap — but on the actual units the
// glass is fully visible there, so the inset just exposed a strip of the (white)
// boot-splash screen at the left of the dark UI ("the white bar"). 0 = true
// edge-to-edge on both panels. Raise it only for a unit whose bezel really does
// encroach on the active area.
#define UI_BEZEL_X 0

// THE TITLE BAR HEIGHT, for every screen. The bar itself is painted in ONE
// place (the view engine's chrome, see view_te.cpp) and named by screen_title()
// (kernel.h), so an app never draws it -- but an app that paints its own body
// needs to know where that body may start. This is that number, and it is the
// only copy: the terminal's grid origin and the PTT screen's first row are both
// this. At 20 the terminal's densest grid fills the panel exactly
// (20 + 25*12 = 320 = TFT_HOR_RES), which is asserted where the grid is sized.
#define UI_TITLE_H 20

// The view layer renders through the in-house text engine (text_engine.cpp +
// ili9488.cpp + the mont14/mont10 tfont tables): no LVGL, no TFT_eSPI, no
// Adafruit_GFX. view_te.cpp is THE backend -- it OWNS the panel, because
// ili9488.cpp and TFT_eSPI cannot both drive SPI1. See
// ~/Documents/radiocloud/text_engine (its own sketch + repo) for the engine.
//
// There were once two selector macros here, UI_VIEW_BACKEND_GFX and
// UI_VIEW_BACKEND_TE, plus g_gfx_owns_display to referee which renderer owned
// the Sharp framebuffer. The GFX experiment's file (view_gfx.cpp) was deleted
// with LVGL and the flag was never set true, so all three were removed: a
// choice between one thing is not a choice.

void ui_init();
void ui_slice();
extern uint32_t ui_slice_ticks;   // TEMP hang trace (2026-08-11)
void ui_tick(void);              // draw the no-LVGL chrome bar (wifi|title|battery|clock) via panel_*
void ui_set_title(const char *t);// name RESTORE MODE's bar. An app uses screen_title()

// The +/- volume keys, for any screen that offers them (home, contact menu, call,
// PTT). Returns 1 if the key was a volume key and has been applied.
int  ui_volume_key(int key);

// Display backlight auto-off (impl in ui.cpp). display_kick() records the last
// activity time (call on activity); display_pump() applies the on/off (LED stays
// on for display_timeout ms after the last kick) and runs from keyboard_scan().
// Stored as the last-kick timestamp + unsigned-elapsed compare, so it's wrap-safe
// for months of uptime.
extern uint32_t display_timeout;
extern uint32_t display_kicked_ms;
void display_kick(void);
void display_pump(void);
bool display_is_on(void);   // is the backlight currently lit? (keyboard wake-swallow)
void ui_vcom_tick();   // periodic COM inversion for the Sharp panel (call ~1 Hz from ui_slice)
void ui_force_refresh();   // immediate full repaint (boot: finish the home paint)
void ui_splash_clear();    // remove the boot splash once the home screen is ready

void keyboard_scan();   // fast matrix poll — call from loop()
char keyboard_read();   // consumes the latched character
// Terminal gestures. Exit is out-of-band because with the Ctrl layer every
// 0x00-0x1F value is real input, so no sentinel key code is safe.
bool keyboard_ctrl_armed(void);       // one-shot Ctrl armed (title-bar '^')
const char *keyboard_mode_str(void);  // current layer for the title bar
bool keyboard_sym2_popup(void);       // true while the Sym2 popup picker is armed (overlay shows only then)
const char *keyboard_legend_cell(int row, int col);  // Sym2 popup cell text (row 0..2, col 0..11)
bool keyboard_space_held();  // either space key held right now (PTT space-to-talk poll)

// Which hardware revision's keyboard is fitted. The two boards carry the same
// keycaps in the same places but connect them to different matrix positions, and
// v3 adds a dedicated Up and Down. Stored in device_record.keyboard_layout, where
// 0 means the probe has not run and v2 is assumed so the device stays usable.
#define KBD_LAYOUT_UNKNOWN 0
#define KBD_LAYOUT_V2      1
#define KBD_LAYOUT_V3      2
void keyboard_set_layout(uint8_t layout);

// One matrix position that is down, or -1 — raw, mapping nothing. This is what
// the layout probe reads: it asks for a key by where it sits on the keyboard, so
// no table has to be correct for the answer to be usable.
int keyboard_raw_down(void);

// A space key held right now, straight off the matrix — for the boot gesture,
// before any scan has run.
bool keyboard_boot_space_held(void);

// Ask which keyboard is fitted and store the answer (keyboard_probe.cpp).
// Blocks until four corner presses agree on one board. Returns that layout.
uint8_t keyboard_probe_run(void);

// Live physical (raw matrix) state of the nav/modifier keys as OR'd bits, taken
// as one atomic snapshot. Apps (e.g. the terminal) read this to interpret keys
// without knowing the matrix layout — the bits are semantic; the indices stay
// private to keyboard.cpp.
enum {
	KBD_MOD_L         = 1 << 0,   // left / backward nav key ('l')
	KBD_MOD_R         = 1 << 1,   // right / forward nav key ('r')
	KBD_MOD_SYMBOL    = 1 << 2,   // symbol-shift '&'
	KBD_MOD_SHIFT     = 1 << 3,   // case-shift 'aA'
	KBD_MOD_SP1       = 1 << 4,   // left space
	KBD_MOD_SP2       = 1 << 5,   // right space
	KBD_MOD_ENTER     = 1 << 6,   // enter
	KBD_MOD_BACKSPACE = 1 << 7,   // backspace
};
uint16_t keyboard_get_modifiers(void);

#define TERMINAL_NORMAL 0
#define TERMINAL_REVERSE 1
#define TERMINAL_BLUE 2
#define TERMINAL_RED 3
#define TERMINAL_HIGHLIGHT 4
#define TERMINAL_GRAY 5
#define TERMINAL_MSG_OUT 6   // sent message body (coloured text, default bg)
#define TERMINAL_MSG_IN  7   // received message body (coloured text, default bg)

void phone_dump_key(const uint8_t *key, int length);

// enum phone_state, the WIFI_* states, wifi_get_status() and phone_state_set()
// live in phone_state.h -- they are the only part of this header plain-C code
// needs, and kernel.c cannot include a C++ header. These two are C++-only
// (no C caller) so they stay here.
enum phone_state phone_state_get();
const char* phone_state_name(enum phone_state s);

extern volatile bool exit_screen_request;  // set by the exit gesture; ui_slice pops the screen
extern volatile bool vox_telem;          // bench: serial `vh` → 2/s VOX telemetry line to serial (spk_env/mic_vox_gain)

// WiFi managment (WIFI_* states + wifi_get_status: phone_state.h)
extern char wifi_indicator_str[];
void wifi_init();
void wifi_poll();
void ui_wifi_state(int state); //returns the signal strength
void wifi_open();
void wifi_forget(char *ssid);

void registration_start();
void key_import_start();          // "Sign In..." — import an existing key from a 24-word phrase
void key_import_ui_pump();        // resolves the pending post-import sign-in (server-confirmed)
void disk_key_start();            // Settings > Disk Key — set the at-rest disk key (typed or generated)
void disk_unlock_start();         // cold-boot unlock screen (store LOCKED) — from ui_setup
void pin_set_start();             // Settings > Set PIN — configure the UI screen-lock PIN
void burner_set_start();          // Settings > Admin > Set Burner Code — the duress code
void pin_lock();                  // Settings > Lock — lock the screen now (manual)
void pin_show_lock_screen();      // show the PIN lock screen (used on wake while ui_locked)
bool ui_pin_is_set();             // true if a UI screen-lock PIN is configured
extern volatile bool ui_locked;   // UI screen lock engaged (see ui.cpp / registeration.cpp)
void registration_pump_send();   // call from core 0 loop()
void registration_ui_pump();     // call from ui_slice() on core 1
void unblock_ui_pump();          // call from ui_slice() on core 1 (Unblock DoH outcome)

void go_home(void);
void go_admin();                  // Settings > Admin submenu
void go_security();               // Settings > Security submenu (the disk-key flow's "back" target)

// Polled from ui_slice() on core 1: while a chat thread (a view) is open, repaint
// on a logbook-head change (inbound message / our own send). No-op otherwise.

// Flush a deferred home +/- volume change to flash once the speaker is idle (a
// flash write pauses audio, so it must never land mid-playback). Call each ui_slice.
void home_volume_save_pump(void);

// True when the device has heard a fresh msg2 from the central server
// within the last two login_repeat_period cycles. Drives the OK/WARNING
// icon in the title bar.
bool ltp_is_online();

#ifdef __cplusplus
}
#endif
