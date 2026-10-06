#include "debug.h"
#include <Arduino.h>
#include "display_backend.h"
#include <time.h>
#include <pico/rand.h>
#include "ui.h"
#include "ili9488.h"
#include "text_engine.h"
extern const tfont_t mont14;
#include "view.h"
#include "kernel.h"        // screen_key — the app sees a key before the view
#include "view_backend.h"
#include "terminal.h"
#include "device_record.h"

// Declared in wg.h inside extern "C". Returns wall-clock UTC seconds:
// boot-relative millis() plus a correction that NTP refreshes (and which
// defaults to 2026-05-01 UTC so wg.c's cookie-age comparisons behave
// before NTP succeeds — see ntp.h).
#include "netif.h"   // net_time — the network clock

extern "C" time_t get_current_time_seconds(){
  // netif owns the NTP client and every socket, so its answer is THE answer.
  // net_time() is 0 until the first sync, and only then does the fallback below
  // apply — a fixed date that exists so wg's cookie-age arithmetic behaves
  // before we know the time, not as a clock anyone should record against.
  time_t net = net_time();
  if (net)
    return net;
  // Before the first sync we do not know the time. This is not a clock: it is a
  // plausible date so wg's cookie-age arithmetic behaves, and nothing should be
  // recorded against it. 2026-05-01 00:00:00 UTC.
  return (time_t)1777593600L + (time_t)(millis() / 1000);
}

// ---- RESTORE MODE'S chrome bar: wifi | title | battery | clock -------------
// Every KERNEL screen — list or not — is named by screen_title() and its bar is
// painted once by the view engine (view_te.cpp). This one exists for the mode
// that has no kernel and no screen stack: restore_net.cpp drives its own loop,
// so it draws its own bar and names it with ui_set_title(). Do not reach for
// this from an app. All text via panel_* (display_backend).
extern volatile int batt_adc_raw;      // audio.cpp — latest raw A0 sample
extern int          batt_fullscale_mv; // audio.cpp — pack mV at raw 4095
// net_time comes from netif.h, included above

#define UI_CHROME_H 24
static char s_ui_title[24] = "";
void ui_set_title(const char *t){ snprintf(s_ui_title, sizeof s_ui_title, "%s", t ? t : ""); }

void ui_tick(void){
  // Self-throttled: callers call this as often as they like (tight or sparse) —
  // ui_tick decides its own repaint cadence (~1 Hz, enough for the clock/battery).
  static uint32_t last = 0;
  uint32_t now = millis();
  if (last != 0 && (uint32_t)(now - last) < 1000)
    return;
  last = now;

  int W = panel_width();
  panel_canvas_begin(0, 0, W, UI_CHROME_H);                // compose the bar off-screen -> no blink
  panel_fill(0, 0, W, UI_CHROME_H, false);                 // clear the bar to background
  char wbuf[80];                                         // the REAL wifi glyph + the SSID (montserrat)
  snprintf(wbuf, sizeof wbuf, LV_SYMBOL_WIFI " %s", wifi_indicator_str);
  panel_text(2, 4, 1, wbuf);                                // wifi (left) — like vw_wifi
  int tw = panel_text_width(1, s_ui_title);                // title (centred) — like vw_title
  panel_text((W - tw) / 2, 4, 1, s_ui_title);
  // clock flush right, battery voltage just to its left (both right-aligned) — like vw_clock/vw_batt.
  // Time stays 00:00:00 in restore mode (no NTP there); shows real time when synced.
  char clk[12]; int hh = 0, mm = 0, ss = 0;
  if (net_time()) {
    time_t t = get_current_time_seconds();
    struct tm tm;
    gmtime_r(&t, &tm);
    hh = tm.tm_hour;
    mm = tm.tm_min;
    ss = tm.tm_sec;
  }
  snprintf(clk, sizeof clk, "%02d:%02d:%02d", hh, mm, ss);
  int cw = panel_text_width(1, clk);
  panel_text(W - cw - 4, 4, 1, clk);
  char bv[12]; int mv = batt_adc_raw * batt_fullscale_mv / 4095;
  snprintf(bv, sizeof bv, "%d.%02dV", mv / 1000, (mv % 1000) / 10);
  int bw = panel_text_width(1, bv);
  panel_text(W - cw - 4 - bw - 8, 4, 1, bv);
  panel_fill(0, UI_CHROME_H - 1, W, 1, true);              // separator hairline under the bar
  panel_canvas_end();                                       // blit the finished bar in one transfer
}

// Replacement for libc's rand()/srand() backed by the RP2350 hardware
// random source. wg.c's fill_random() calls rand() byte-by-byte; without
// this override the handshake would draw from the stdlib LCG. The linker
// resolves the `rand`/`srand` symbols here before scanning libc.a, so no
// wg.c edits are needed. srand() is a no-op (the hardware RNG needs no
// seeding) but is provided so the linker doesn't drag libc's rand.o in
// alongside to satisfy a stray srand() reference.
extern "C" int rand(void){
  // Mask the sign bit: rand() must return a non-negative int and
  // RAND_MAX is 0x7FFFFFFF on newlib. wg.c only consumes the low 8
  // bits, but any uniform 31-bit value works for general callers.
  return (int)(get_rand_32() & 0x7FFFFFFF);
}

extern "C" void srand(unsigned int seed){
  (void)seed;
}

//Some hardware definitions/pins
#define BACKLIGHT 6

bool mouse_down = false;

static bool display_led_on = true;   // mirrors the backlight (display_pump owns it)


// Legacy no-op: LVGL focus groups are gone; the view engine routes keys itself.

// The display backend (display_backend.cpp) owns the panel object, the LVGL
// flush, and the draw buffer — selected by DISPLAY_ILI9488. ui.cpp is
// display-agnostic: it calls display_begin() / display_vcom_tick().

// (on_touch removed — no touch screen on this device; input is keyboard-only.)

// Global "back to home" request. The ESC chord (both spaces, keyboard.cpp) is
// caught here at the indev — NOT per control — and the UI loop (ui_slice) acts
// on it by cleaning up the current screen via go_home(). One flag, one place.
// Raised by the exit gesture; ui_slice acts on it so the screen teardown runs
// outside the key path.
volatile bool exit_screen_request = false;
// Bench: serial `vh` toggles a low-rate (2/s) VOX telemetry line to serial
// (spk_env / mic_vox_gain). No screen HUD — the direct-panel HUD was dropped
// (it took the whole panel over and hid the call view). See the .ino.
volatile bool vox_telem = false;
// UI screen lock: set on the backlight-off timeout / manual Lock (when a UI PIN
// is set). The lock screen (registeration.cpp) clears it on the correct PIN. The
// volume_key is NOT evicted — the phone keeps receiving while locked.
volatile bool ui_locked = false;

// Keys come straight from the matrix. The terminal polls keyboard_read() itself,
// and the first key after a display timeout only wakes the screen.
//
// ESC IS NOT TOUCHED HERE. It is a working key in a terminal, so the UI claims
// no global gesture on it and it travels like any other key.
static void te_keyboard_pump(void){
  char pressed = keyboard_read();
  if (!pressed)
    return;
  bool was_off = !display_led_on;
  display_kick();
  if (was_off)                            // first key only wakes the screen
    return;

  // THE EXIT GESTURE, and it never reaches an app:
  //
  //   backspace && ((in an edit field && symbol-shifted) || not in one)
  //
  // Plain backspace is too useful in an editor to also mean "leave", so inside a
  // field it takes the symbol shift; anywhere else it leaves on its own. A
  // screen that draws its OWN editor -- the channel's composer -- says so by
  // taking the key above, which is why this runs after the app and not before.
  // THE APP SEES EVERY KEY FIRST, backspace included. Non-zero means it took
  // the key; 0 passes it on. Non-zero means it took the key; 0 passes
  // it to the view, which is what lets one screen treat Enter as Go and another
  // as a newline, and what lets a screen with no list take the keyboard whole.
  if (screen_key((int)(unsigned char)pressed))
    return;

  if (pressed == (char)VIEW_K_BACKSPACE) {
    bool in_edit_field = !view_is_active() || view_input_focused();
    bool symbol_shifted = (keyboard_get_modifiers() & KBD_MOD_SYMBOL) != 0;
    // A backspace with nothing to its left deletes nothing, so it means LEAVE:
    // an empty field or a cursor at position 0 exits like shift+backspace. The
    // terminal is unaffected (no view active there, cursor_edge stays false).
    bool at_field_start = false;
    if (view_is_active() && view_input_focused()) {
      bool at_end = false;
      view_input_cursor_edge(&at_field_start, &at_end);
    }
    if (symbol_shifted || !in_edit_field || at_field_start) {
      exit_screen_request = true;         // drained by ui_slice, off the key path
      return;
    }
  }

  if (view_is_active())
    view_handle_key((int)(unsigned char)pressed);
}

void set_backlight(bool on){
  pinMode(BACKLIGHT, OUTPUT);
  if (on)
    digitalWrite(BACKLIGHT, HIGH);
  else
    digitalWrite(BACKLIGHT, LOW);
}

// ---- display backlight auto-off ------------------------------------------
// The display LED stays on for display_timeout ms after the last activity, then
// turns off (power save). Any activity "kicks" -- records now as the last-active
// time: a keystroke (on_read_keyboard / the keyboard scan), and a live call,
// which kicks from the call app's own tick (so the screen stays lit through the
// call and for one display_timeout after it ends). display_pump() (the on/off check) runs from
// keyboard_scan(). Stored as the last-kick TIMESTAMP (not a deadline) and tested
// with the unsigned-elapsed idiom `(uint32_t)(now - kick) < timeout`, which stays
// wrap-safe across the ~49.7-day millis() rollover — correct for a device left
// running for months (a deadline compared with (int32_t)(now-deadline) would flip
// spuriously once the deadline aged past ~24.8 days). Non-static globals so
// they're runtime-editable.
uint32_t display_timeout   = 30000;   // ms of inactivity before the LED turns off
uint32_t display_kicked_ms = 0;       // millis() of the last activity; seeded in ui_init()

// NOTE: a CPU-clock throttle (drop clk_sys when the screen sleeps) was tried here
// for battery but REMOVED — on the Pico 2W the CYW43 WiFi runs off a PIO/SPI clock
// derived from clk_sys, so changing it destabilised WiFi/calls. The core runs at a
// fixed 150 MHz; backlight auto-off below is the only display power saving.

void display_kick(void){ display_kicked_ms = millis(); }

bool display_is_on(void){ return display_led_on; }

void display_pump(void){
  bool want_on = (uint32_t)(millis() - display_kicked_ms) < display_timeout;   // unsigned elapsed: wrap-safe for months
  if (want_on != display_led_on){
    set_backlight(want_on);
    display_led_on = want_on;
    // UI screen lock: arm it when the screen goes dark (if a PIN is set), and
    // demand the PIN when the screen next wakes while locked. The volume_key is
    // never touched, so the phone keeps receiving through all of this.
    if (!want_on){
      if (ui_pin_is_set())
        ui_locked = true;
    } else if (ui_locked){
      pin_show_lock_screen();
    }
    if (want_on)
      screen_wake();
  }
}



// Force an immediate, complete repaint (flush all pending invalid areas now).
// Used at boot so the home screen finishes painting before loop() starts.
void ui_force_refresh(){ /* the engine draws synchronously -- nothing is pending */ }

// Periodic display housekeeping (Sharp panel: COM inversion; no-op on ILI9488).
// Called once per ui_slice() on core 1. See display_backend.cpp.
void ui_vcom_tick(){ display_vcom_tick(); }

void ui_init(){
  Debug.println("Starting core1");
  //if (device_record.magic == 0x00C0FFEE)
  //  return;

  set_backlight(true);
  display_kick();   // arm the auto-off deadline (display on for display_timeout from boot)

  // The text engine owns the panel: ili9488.cpp drives SPI1 directly. This
  // replaces the entire LVGL bring-up that used to live here -- display_begin,
  // lv_init, lv_tick_set_cb, display_create, the keypad indev and an LVGL label
  // for the splash. ui_init() still runs EARLY in setup(), before the volume
  // mount, so the panel is alive and showing something during the ~1-2s wait; it
  // touches no flash and reads no `block`.
  ili_init();
  draw_rect(0, 0, ILI_W, ILI_H, rgb(0, 0, 0));
  {
    trect_t s = { 0, (int16_t)(ILI_H / 2 - mont14.height / 2), ILI_W, (int16_t)mont14.height };
    draw_string(&s, "Xyfr is booting", &mont14, ALIGN_CENTER, rgb(255, 255, 255), rgb(0, 0, 0));
  }
  rb_init();
}

// Remove the boot splash (called from ui_setup once the home screen is ready).
void ui_splash_clear(){ /* the engine's splash is painted over by the first view */ }

void phone_dump_key(const uint8_t *key, int length){
	while(length--)
		Debug.printf("%02x", *key++);
	Debug.print('\n');
}

static volatile uint8_t g_phone_state = PS_OFFLINE;
void phone_state_set(enum phone_state s){ g_phone_state = (uint8_t)s; }
enum phone_state phone_state_get(){ return (enum phone_state)g_phone_state; }
const char* phone_state_name(enum phone_state s){
	switch (s) {
	case PS_OFFLINE:         return "offline";
	case PS_WIFI_CONNECTING: return "wifi connecting";
	case PS_WIFI_CONNECTED:  return "wifi connected";
	case PS_UNBLOCKING:      return "unblocking";
	case PS_SIGNING_IN:      return "signing in";
	case PS_SIGNED_IN:       return "signed in";
	case PS_CALLING:         return "calling";
	case PS_INCOMING:        return "incoming";
	case PS_CONNECTED:       return "connected";
	case PS_HANGING_UP:      return "hanging up";
	case PS_WIFI_FAILED:     return "wifi failed";
	}
	return "unknown";
}

// ---- wifi state + the UI slice (moved here when list_view.cpp was retired; they
// ---- were parked in that file but belong to the UI layer, not the legacy list) --
// The view's chrome reads wifi_indicator_str (the SSID/RSSI text) and
// wifi_get_status(); this int was only ever consumed by list_view's refresh_title,
// which went with that file. Kept as a no-op so wifi_ui's three call sites stay
// meaningful if a backend wants the numeric state back.
void ui_wifi_state(int state){
	(void)state;
}

// The view layer owns ALL screen chrome now (wifi - title - clock live in
// view_lvgl's vw_* labels, refreshed by rb_tick from view_slice). The old
// update_title_bar() painted list_view's title objects, which the view has
// occluded since the migration, and went with that file.
uint32_t ui_slice_ticks = 0;   // TEMP hang trace (2026-08-11)

void ui_slice(){
  ui_slice_ticks++;
  te_keyboard_pump();  /* keys go straight from the matrix into the view engine */
  // The view subsystem (when a view is active): refresh chrome + repaint on the
  // event-driven view_dirty flag. Cheap no-op when no view is active.
  view_slice();
  // Repaint the rows whose picture changed (see view_te.cpp).
  extern void te_view_present(void);
  te_view_present();
  // (chat_poll is gone: home is a kernel screen now and consumes the
  // home_needs_refresh flag in its own APP_PUMP.)
  // Flush a deferred home-volume change to flash once the speaker goes idle (never
  // mid-playback — a flash write pauses the audio DMA).
  home_volume_save_pump();
  // The exit gesture, acted on HERE so the go_home / view_set it performs runs
  // outside the engine's own dispatch. A screen on the stack pops -- leaving via
  // the gesture has to unwind it, or the frame stays behind and the next open
  // pushes a second one on top.
  if (exit_screen_request) {
    exit_screen_request = false;
    if (screen_active())
      screen_pop();
    else if (!view_back())
      go_home();
  }
  // registration_ui_pump renders the activation outcome after core 0
  // replies — same deferred, out-of-event-dispatch placement.
  registration_ui_pump();
  // key_import_ui_pump turns the post-import "signing in..." screen into a
  // server-CONFIRMED success or a truthful failure.
  key_import_ui_pump();
  // unblock_ui_pump renders the DoH "Unblock" outcome once core 0 sets
  // doh_result — same deferred placement (replaces the old wait_on_flag spin).
  unblock_ui_pump();
  // welcome_wifi_pump flips the onboarding welcome between the WiFi gate and the
  // three-path chooser as the async WiFi connect completes or drops.
  extern void welcome_wifi_pump(void);
  welcome_wifi_pump();
  // Backlight on/off moved to keyboard_scan() (the per-loop poll that runs in
  // EVERY mode), so it works in the terminal's grid mode too, where ui_slice()
  // is skipped. Don't re-add display_pump() here.
}
