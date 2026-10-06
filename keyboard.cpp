#include "ui_symbols.h"
#include <Arduino.h>
#include "ui.h"
#include "view.h"
#include "debug.h"   // Debug.printf — non-blocking serial telemetry for rollover events
#include "terminal.h" // terminal_active() — backspace deletes in the terminal, not exits

// A SCANCODE is a PHYSICAL KEY POSITION, numbered row-major over the 3x12
// keycap grid. The matrix scan produces a matrix position -- row*KBD_COLS+col --
// and one per-board table turns that into a scancode. Everything else in this
// file works in scancodes, so the character tables, the special-key constants
// and the neighbour map are the same on every board.
//
//   sc  0..11   l  Q  W  E  R  T  Y  U  I  O  P  b
//   sc 12..23   r  A  S  D  F  G  H  J  K  L  c  e
//   sc 24..35   u  Z  X  C  V  S1 S2 B  N  M  &  d
//
// v2 has no key at SC_UP or SC_DOWN; v3 adds those two.
#define KBD_ROWS   6      // matrix rows
#define KBD_COLS   6      // matrix columns
#define MATRIX_KEYS  (KBD_ROWS * KBD_COLS)
#define KBD_KEYS   36     // keycaps: 3 rows of 12
#define KEY_COLS   12     // keycaps per row

#define SC_LEFT    0
#define SC_BKSP   11
#define SC_RIGHT  12
#define SC_CASE   22
#define SC_ENTER  23
#define SC_UP     24
#define SC_SPACE1 29
#define SC_SPACE2 30
#define SC_SYMBOL 34
#define SC_DOWN   35

static const uint8_t kbd_row[KBD_ROWS] = {0,1,2,3,7,8};
static const uint8_t kbd_col[KBD_COLS] = {14,15,18,20,21,22};

// The base layer. Letters are their own keycap; the rest are markers the switch
// below dispatches on: '<' backspace, 'e' enter, 'l'/'r' the arrows, 'u'/'d' the
// v3 vertical keys, 'c' case-shift, '&' symbol-shift, 's'/'p' the two spaces.
static const char base_map[KBD_KEYS] = {
  'l', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '<',
  'r', 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'c', 'e',
  'u', 'Z', 'X', 'C', 'V', 's', 'p', 'B', 'N', 'M', '&', 'd'
};

// Symbol layer (keyboard_mode == SYMBOL_CASE). The top row carries the digits in
// order, Q..P = 1234567890, so there is no dedicated digit key and '.' is
// symbol-shift+M. The special keys are matched on base_map before this table is
// consulted, so their entries here just mirror it.
static const char symbol_map[KBD_KEYS] = {
  'l', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '<',
  'r', '*', '#', '(', ')', '/', ':', ';', '\'','"', 'c', 'e',
  'u', '_', '-', '+', '?', '@', '$', '!', ',', '.', '&', 'd'
};

// Sym2 layer: the extended/programming symbols, armed by HOLDING symbol-shift
// past sym2_hold_ms. One-shot -- one key, then back to letters. Identical to
// symbol_map except the top row Q..P -> ESC [ ] { } ^ & ~ \ = (Q's ESC is a real
// 0x1b, a dedicated Escape in the terminal), plus A -> Tab, D -> '<', F -> '>'.
static const char symbol2_map[KBD_KEYS] = {
  'l', 0x1b,'[', ']', '{', '}', '^', '&', '~', '\\','=', '<',
  'r', '\t','#', '<', '>', '/', ':', ';', '\'','"', 'c', 'e',
  'u', '_', '-', '+', '?', '@', '$', '!', ',', '.', '&', 'd'
};

// ---- the matrix: one table per board ---------------------------------------
// Matrix position (row*KBD_COLS + col) -> scancode, -1 where no key is fitted.
// KBD_LAYOUT_* are what device_record.keyboard_layout stores; 0 means the probe
// has not run yet and v2 is assumed so the device stays usable.

static const int8_t matrix_v2[MATRIX_KEYS] = {
   1, 13, 11,  7, 19, 32,      /* matrix row 0 */
   2, 14, 25,  8, 20, 33,      /* row 1 */
   3, 15, 26,  9, 21, -1,      /* row 2 -- col 5 unfitted */
   4, 10,  5, 29,  6, 30,      /* row 3 */
  16, 22, 17, 12, 18,  0,      /* row 4 */
  27, 34, 28, -1, 31, 23,      /* row 5 -- col 3 unfitted */
};

static const int8_t matrix_v3[MATRIX_KEYS] = {
  25, 24, 26, 27, 28, 29,      /* matrix row 0 */
   1,  0,  2,  3,  4,  5,      /* row 1 */
  13, 12, 14, 15, 16, 17,      /* row 2 */
  34, 35, 33, 32, 31, 30,      /* row 3 */
  22, 23, 21, 20, 19, 18,      /* row 4 */
  10, 11,  9,  8,  7,  6,      /* row 5 */
};

static const int8_t *matrix_map = matrix_v2;
static bool key_fitted[KBD_KEYS];     // rebuilt by keyboard_set_layout()


static uint8_t  kbd_state[KBD_KEYS];
static uint32_t kbd_repeat_at[KBD_KEYS];
// Char each key emitted on its fresh press, so auto-repeat reproduces THAT char --
// e.g. releasing '&' while still holding M keeps repeating '.', not 'M'. 0 = the key
// emitted nothing char-specific (special keys), so a repeat re-evaluates it instead.
static char     kbd_emit[KBD_KEYS];

// Raw "is this matrix position held right now?" snapshot, refreshed every scan.
// keyboard_space_held() reads it so a poller (the PTT Talk screen's space-to-talk
// gate) can query a key's live state without re-scanning the matrix.
static bool     s_key_now[KBD_KEYS];

// The latch between the fast matrix poll and LVGL. keyboard_scan() (run from
// loop() at ~5 ms, outside LVGL) writes the most recent emitted character here;
// keyboard_read() (the LVGL keypad indev, ~30 ms) reads it and clears it back to
// 0. Single slot: a held/auto-repeating key just rewrites the same value, so the
// LVGL read rate naturally caps repeats; two DISTINCT keys pressed between two
// LVGL reads coalesce to the later one (the fast-double / brush case — future
// rollover work refines this). volatile so a later core0/core1 split is safe.
static volatile char kbd_pending = 0;

#define REPEAT_INITIAL_MS 250
#define REPEAT_PERIOD_MS  80

// One-shot Ctrl, armed by pressing the two shift keys in IMMEDIATE succession
// (case then symbol, or symbol then case). Holding them together was rejected
// as painful -- they sit side by side. "Immediate" means no other key in
// between, so typing 'A' then '#' (case,A,symbol,3) cannot arm it by accident.
// One Ctrl gives everything else for free: Tab is Ctrl-I, ESC is Ctrl-[.
static bool ctrl_armed = false;
static char last_mod = 0;             // 'c' / '&' if the PREVIOUS key was a shift
bool keyboard_ctrl_armed(void) { return ctrl_armed; }

// Terminal ESC chord grace: how long a plain lone arrow stays SILENT after a
// fresh press, giving a slow hand time to press the OTHER arrow and form the ESC
// chord (both arrows down = ESC, no tight window). Released within the grace ->
// one cursor move (a tap); still held when it lapses -> begins scrolling. Was a
// 30 ms fixed window that leaked cursor moves before the chord could form.
// Runtime-tunable (house convention for timer knobs).
uint32_t arrow_chord_ms = 350;

// Sticky vertical arrows (terminal only). Two keys have to serve four
// directions, and shell history / menu navigation is SUSTAINED vertical work --
// pressing shift before every step is the tedious part. After one shifted
// arrow, bare arrows keep moving vertically for this long, each press
// refreshing the window. It lapses on its own and any other key cancels it, so
// unlike a hard mode there is nothing to get stuck in.
#define VERT_STICKY_MS 1500
static uint32_t vert_sticky_until = 0;

// Keys that auto-repeat when held: everything except the shift modifiers ('&' sym,
// 'c' case) -- they don't emit a character, so repeating them is meaningless.
static inline bool is_repeat_key(char key){
  return key != '&' && key != 'c';
}

// Chording modifiers — overlap with these is intentional (a shift/sym chord), never
// a brush, so the rollover logic exempts them.
static inline bool is_modifier(int sc){ return sc == SC_CASE || sc == SC_SYMBOL; }

// Neighbours that brush, per scancode (-1 = none). The home row A S D F G H J K L
// is flanked VERTICALLY by Q W E R T Y U I O above and Z X C V sp sp B N M below,
// plus two HORIZONTAL pairs at the left edge: the left arrow sits beside Q and the
// right arrow beside A, and both graze while typing. Listed rather than derived
// from the grid, because scancodes exactly 12 apart are not always neighbours in
// the sense that matters -- deriving would make the two arrows brush each other
// and break the both-arrows chord. Other horizontal pairs are omitted (not a
// failure mode). The eager rollover swallows a fresh press whose neighbour here is
// already held; modifiers are exempt.
#define KBD_NEIGH_MAX 3
static const int8_t kbd_vneigh[KBD_KEYS][KBD_NEIGH_MAX] = {
  /* 0  l */ {  1, -1, -1 },  /* 1  Q */ { 13,  0, -1 },  /* 2  W */ { 14, -1, -1 },
  /* 3  E */ { 15, -1, -1 },  /* 4  R */ { 16, -1, -1 },  /* 5  T */ { 17, -1, -1 },
  /* 6  Y */ { 18, -1, -1 },  /* 7  U */ { 19, -1, -1 },  /* 8  I */ { 20, -1, -1 },
  /* 9  O */ { 21, -1, -1 },  /* 10 P */ { -1, -1, -1 },  /* 11 < */ { -1, -1, -1 },
  /* 12 r */ { 13, -1, -1 },  /* 13 A */ {  1, 25, 12 },  /* 14 S */ {  2, 26, -1 },
  /* 15 D */ {  3, 27, -1 },  /* 16 F */ {  4, 28, -1 },  /* 17 G */ {  5, 29, -1 },
  /* 18 H */ {  6, 30, -1 },  /* 19 J */ {  7, 31, -1 },  /* 20 K */ {  8, 32, -1 },
  /* 21 L */ {  9, 33, -1 },  /* 22 c */ { -1, -1, -1 },  /* 23 e */ { -1, -1, -1 },
  /* 24 u */ { 12, -1, -1 },  /* 25 Z */ { 13, -1, -1 },  /* 26 X */ { 14, -1, -1 },
  /* 27 C */ { 15, -1, -1 },  /* 28 V */ { 16, -1, -1 },  /* 29 sp*/ { 17, -1, -1 },
  /* 30 sp*/ { 18, -1, -1 },  /* 31 B */ { 19, -1, -1 },  /* 32 N */ { 20, -1, -1 },
  /* 33 M */ { 21, -1, -1 },  /* 34 & */ { -1, -1, -1 },  /* 35 d */ { 23, -1, -1 },
};

#define LOWER_CASE 0
#define UPPER_CASE 1
#define SYMBOL_CASE 2
#define SYMBOL2_CASE 3

// The live keyboard layer (was a static local in keyboard_scan_char). File-scope
// now so the title bar can show it via keyboard_mode_str().
static uint8_t keyboard_mode = LOWER_CASE;

// '&' is a QUASIMODE (Raskin): held = active, released = gone, so it can't strand
// you. Hold '&' + key => Sym1 (symbol_map). Hold '&' with nothing typed for
// sym2_hold_ms => this arms: a bottom popup appears, '&' can be released, and the
// next key picks its Sym2 char (a non-printing key dismisses). File-scope so the
// popup overlay + keyboard_mode_str() + keyboard_sym2_popup() can read it.
static bool sym2_popup = false;

// Sym2 entry timing (runtime-tunable, house convention). Hold '&' at least
// sym2_hold_ms, or tap it twice within sym2_double_tap_ms, to enter sticky Sym2.
uint32_t sym2_hold_ms       = 1000;
uint32_t sym2_double_tap_ms = 400;

// The current layer as a short label for the chrome.
const char *keyboard_mode_str(void) {
  // The label SHOWS the layer by example rather than naming it: "aaa" vs "AAA"
  // reads as noise at a glance, where the character shapes are unmistakable.
  if (sym2_popup)  // popup armed: next key picks a Sym2 char
    return "&#$";
  switch (keyboard_mode) {
    case UPPER_CASE:   return "ABC";
    case SYMBOL_CASE:  return "123";
    default:           return "abc";
  }
}

// True while the Sym2 popup is armed -- the overlay (bottom keymap) shows only then.
bool keyboard_sym2_popup(void) { return sym2_popup; }

// The Sym2 popup overlay's cell (row 0..2, col 0..KEY_COLS-1): the Sym2 char the
// physical key at that position produces, so you press the key under the char you
// want. A scancode IS that position, so the grid needs no table. The dismiss keys
// (case/sym) and any position this board does not fit render blank. Returns a
// short static string; "" = blank.
const char *keyboard_legend_cell(int row, int col) {
  static char buf[4];
  if (row < 0 || row > 2 || col < 0 || col >= KEY_COLS)
    return "";
  int sc = row * KEY_COLS + col;
  if (!key_fitted[sc])
    return "";
  if (sc == SC_CASE || sc == SC_SYMBOL)  // dismiss keys
    return "";
  char c = symbol2_map[sc];
  if ((unsigned char)c < 0x20) {        // control chars (Esc/Tab) are terminal-only
    if (!terminal_active())  // off the terminal they'd just be LVGL nav keys -> blank
      return "";
    if (c == 0x1b)
      return "Esc";
    if (c == '\t')
      return "Tab";
    return "";
  }
  if (c == ' ' || c == 0)
    return "";
  buf[0] = c;
  buf[1] = 0;
  return buf;
}

// The full matrix scan + emit logic. Returns the emitted character (0 = none).
// Formerly keyboard_read(); now driven by keyboard_scan() at the fast loop rate
// instead of by LVGL, so fresh presses are caught within ~5 ms and every key gets
// a real millis() edge (the basis for the rollover overlap logic to come).
static char keyboard_scan_char(){
  // keyboard_mode is now file-scope (see above) so the title bar can read it.
  // '&' quasimode tracking: when it was pressed (for the hold-to-popup timer), its
  // physical held state, whether a Sym1 key was used during the hold, and the letter
  // layer to restore on release. (Sym2 popup state is the file-scope sym2_popup.)
  static uint32_t symbol_press_ms   = 0;
  static bool     symbol_held       = false;
  static bool     symbol_consumed   = false;
  static bool     sym1_oneshot      = false;   // a quick '&' tap armed: next key is one Sym1 symbol
  static uint8_t  mode_at_symbol_press = LOWER_CASE;

  for (int i = 0; i < KBD_ROWS; i++)
    pinMode(kbd_row[i], INPUT);
  for (int j = 0; j < KBD_COLS; j++)
    pinMode(kbd_col[j], INPUT_PULLUP);

  bool key_now[KBD_KEYS];
  for (int k = 0; k < KBD_KEYS; k++)
    key_now[k] = false;

  // Strobe the matrix and record what is down BY SCANCODE. This is the only place
  // a matrix_map position exists; every line below works in scancodes.
  for (int i = 0; i < KBD_ROWS; i++){
    pinMode(kbd_row[i], OUTPUT);
    digitalWrite(kbd_row[i], LOW);
    for (int j = 0; j < KBD_COLS; j++){
      if (digitalRead(kbd_col[j]) != LOW)
        continue;
      int sc = matrix_map[i * KBD_COLS + j];
      if (sc >= 0)
        key_now[sc] = true;
    }
    digitalWrite(kbd_row[i], HIGH);
    pinMode(kbd_row[i], INPUT);
  }

  // Publish the raw snapshot for keyboard_space_held() — captured here, before the
  // emit loop below (which can early-return on the first produced character).
  for (int k = 0; k < KBD_KEYS; k++)
    s_key_now[k] = key_now[k];

  uint32_t now = millis();

  // Wake the display on ANY physical key activity, at the input source -- the one
  // point that keeps the backlight alive for every screen (terminal included).
  // If the screen was ASLEEP, the waking key is a WAKE gesture, not input:
  // swallow every key that's down (mark it silent for the whole hold) so a stray
  // press on wake can't fire a menu item or fire off a message. display_pump()
  // (keyboard_scan) lights the panel this same scan; only a fresh press AFTER
  // wake reaches the app. Catches modifiers too (raw key_now[]).
  bool any_key = false;
  for (int k = 0; k < KBD_KEYS; k++) if (key_now[k]) { any_key = true; break; }
  if (any_key)
    display_kick();
  if (any_key && !display_is_on()) {
    for (int k = 0; k < KBD_KEYS; k++)
      if (key_now[k])
        kbd_state[k] = 2;
    return 0;
  }

  // Track '&' hold state up front so the per-key loop below sees a
  // consistent symbol_held even when other keys are processed in the
  // same scan (the loop returns on the first emitted character, so
  // we can't rely on the case '&' branch running first).
  bool symbol_was_held = symbol_held;
  symbol_held = key_now[SC_SYMBOL];

  if (symbol_held && !symbol_was_held) {
    symbol_press_ms = now;                       // fresh press: start the hold-to-popup timer
    if (sym1_oneshot) {                          // cancel a pending one-shot from a prior tap
      sym1_oneshot = false;
      keyboard_mode = mode_at_symbol_press;
    }
    mode_at_symbol_press = keyboard_mode;        // the letter layer to restore on release
  }

  // Hold '&' with nothing typed for sym2_hold_ms -> arm the one-shot Sym2 popup.
  // Once armed, '&' may be released; the popup owns the next key (emit loop below).
  if (symbol_held && !symbol_consumed && !sym2_popup &&
      (uint32_t)(now - symbol_press_ms) >= sym2_hold_ms)
    sym2_popup = true;

  // Momentary Sym1 (a quasimode): while '&' is held and the popup hasn't armed, the
  // letter keys emit their symbol_map char. Released = gone, so you can't get stranded.
  if (symbol_held && !sym2_popup)
    keyboard_mode = SYMBOL_CASE;

  // Release: decide what the '&' interaction was.
  if (symbol_was_held && !symbol_held) {
    if (sym2_popup) {
      // popup armed -> it owns the next key; leave keyboard_mode alone
    } else if (symbol_consumed) {
      keyboard_mode = mode_at_symbol_press;      // momentary Sym1 was used -> back to letters
    } else {
      // quick tap, nothing typed (held < popup delay) -> arm one-shot Sym1: the next
      // key emits one symbol_map char, then reverts (handled in the emit loop).
      keyboard_mode = SYMBOL_CASE;
      sym1_oneshot  = true;
    }
    symbol_consumed = false;
  }

  // ---- Arrow ESC chord (terminal) / focus-eject (elsewhere) ----------------
  // ESC in the terminal is BOTH arrows down, with NO timing window -- hold one,
  // then press the other whenever you like. So a plain lone arrow is held SILENT
  // while pressed (no cursor move leaks while a slow hand reaches for the chord);
  // it emits ONE move on RELEASE (a tap), or begins scrolling if still held when
  // the grace (arrow_chord_ms) lapses. Shift-layer arrows (vertical nav) and the
  // non-terminal case keep their old immediate behaviour. Elsewhere both-arrows
  // ejects textarea focus back into the list (VIEW_K_PREV).
  static int8_t   lone_arrow   = -1;    // plain lone arrow held, decision pending
  static uint32_t lone_since   = 0;
  static bool     lone_scrolled = false;
  {
    bool L = key_now[SC_LEFT], R = key_now[SC_RIGHT];

    if (L && R) {                                   // chord -> ESC, once on formation
      bool fresh_chord = !kbd_state[SC_LEFT] || !kbd_state[SC_RIGHT];
      kbd_state[SC_LEFT]      = 1;
      kbd_state[SC_RIGHT]     = 1;
      kbd_repeat_at[SC_LEFT]  = now + REPEAT_INITIAL_MS;
      kbd_repeat_at[SC_RIGHT] = now + REPEAT_INITIAL_MS;
      lone_arrow = -1;
      lone_scrolled = false;
      if (!fresh_chord)  // held: don't repeat the ESC
        return 0;
      if (terminal_active())
        return (char)0x1b;
      return VIEW_K_PREV;
    }

    if (terminal_active()) {
      bool shifted = (keyboard_mode == SYMBOL_CASE || keyboard_mode == UPPER_CASE) ||
                     (vert_sticky_until && (int32_t)(now - vert_sticky_until) < 0);
      if ((L || R) && !shifted) {                   // plain lone arrow: silent until release
        int ai = SC_RIGHT;
        if (L)
          ai = SC_LEFT;
        char mv = VIEW_K_RIGHT;
        if (ai == SC_LEFT)
          mv = VIEW_K_LEFT;
        if (lone_arrow != ai) {
          lone_arrow = ai;
          lone_since = now;
          lone_scrolled = false;
        }
        kbd_state[ai] = 1;                          // own it; the per-key loop won't emit
        if (lone_scrolled) {                        // already scrolling: repeat on the deadline
          if ((int32_t)(now - kbd_repeat_at[ai]) < 0)
            return 0;
          kbd_repeat_at[ai] = now + REPEAT_PERIOD_MS;
          return mv;
        }
        if ((uint32_t)(now - lone_since) >= arrow_chord_ms) {   // grace lapsed while held -> scroll
          lone_scrolled = true;
          kbd_repeat_at[ai] = now + REPEAT_PERIOD_MS;
          return mv;
        }
        return 0;                                   // grace: silent, awaiting chord or release
      }
      if (lone_arrow >= 0 && !(L || R)) {           // released before a chord -> tap emits now
        int  ai  = lone_arrow;
        bool tap = !lone_scrolled;
        lone_arrow = -1;
        lone_scrolled = false;
        kbd_state[ai] = 0;
        if (tap) {
          if ((ai == SC_LEFT))
            return VIEW_K_LEFT;
          return VIEW_K_RIGHT;
        }
      } else if (shifted) {
        lone_arrow = -1;                            // shift takes over -> fall through to per-key
        lone_scrolled = false;
      }
    }
  }

  // (The both-SPACES chord was REMOVED: the two space keys sit side by side, so
  // ordinary typing brushed them and aborted the session. Detaching is now a
  // long-press of the two ARROW keys -- the most distant pair on the board.)

  // (The two-space "back / exit" chord was removed — it brushed too easily. The
  // back gesture is now the Backspace key, handled per-key in the switch below:
  // ESC unless the text editor is focused and non-empty, where it deletes a char.)

  for (int index = 0; index < KBD_KEYS; index++){
    if (!key_now[index]){
      kbd_state[index] = 0;
      kbd_emit[index]  = 0;   // forget the remembered char when the key lifts
      continue;
    }

    char key = base_map[index];

    // State 2 = a brush that was swallowed on its fresh press: stay silent for the
    // whole hold, so a swallowed repeat key (e.g. an arrow) can't start auto-repeating.
    if (kbd_state[index] == 2)
      continue;

    bool fresh_press = (kbd_state[index] == 0);

    if (!fresh_press) {
      // Held: only emit again if this is a repeat-eligible key whose
      // next-repeat deadline has elapsed.
      if (!is_repeat_key(key))
        continue;
      if ((int32_t)(now - kbd_repeat_at[index]) < 0)
        continue;
      kbd_repeat_at[index] = now + REPEAT_PERIOD_MS;
      // Repeat the char this key FIRST emitted, not a re-evaluation through the
      // current mode (so releasing '&' mid-hold doesn't flip '.' back to 'M'). Keys
      // that set no char (backspace/enter/arrows) fall through and re-evaluate.
      if (kbd_emit[index])
        return kbd_emit[index];
    } else {
      kbd_state[index] = 1;
      if (is_repeat_key(key))
        kbd_repeat_at[index] = now + REPEAT_INITIAL_MS;
      // Eager rollover-rejection: a fresh press whose neighbour is already held is a
      // brush (thumb rolled across rows, or grazed the arrow left of Q/A) — swallow
      // it (mark state 2). The first-pressed key already emitted and holds the slot.
      // Modifiers are exempt. Checking kbd_state (committed) rather than the raw read
      // makes the first-processed key win a same-scan tie, so one of the pair survives.
      if (!is_modifier(index)) {
        int held_n = -1;
        for (int k = 0; k < KBD_NEIGH_MAX; k++) {
          int n = kbd_vneigh[index][k];
          if (n >= 0 && kbd_state[n] && !is_modifier(n)) {
            held_n = n;
            break;
          }
        }
        if (held_n >= 0) {
          kbd_state[index] = 2;   // held-swallowed brush
          // Telemetry: which key got swallowed and which held neighbour triggered it,
          // so a Serial-monitor session can count brushes over time (are you or the
          // keyboard improving?). Non-blocking Debug — drops if the CDC TX is full.
          Debug.printf("kbd: rollover swallowed '%c'[%d] (brush with held '%c'[%d])\n",
                       key, index, base_map[held_n], held_n);
          continue;
        }
      }
    }

    // Ctrl arming: a shift key pressed straight after the OTHER shift key.
    if (key == 'c' || key == '&') {
      if (last_mod && last_mod != key) {
        ctrl_armed = true;
        last_mod = 0;
        keyboard_mode = LOWER_CASE;      // don't leave the symbol layer armed too
        return 0;                        // the modifier itself emits nothing
      }
      last_mod = key;
    } else {
      last_mod = 0;                      // any other key breaks the sequence
    }

    // Typing anything that is not an arrow means you are back to editing a
    // line, so the arrows should mean horizontal again immediately.
    if (key != 'l' && key != 'r')
      vert_sticky_until = 0;

    // Sym2 popup one-shot: once armed (hold '&' with nothing typed), the next fresh
    // key press picks its Sym2 char and closes the popup. Non-printing keys
    // (up/down arrows l/r, backspace, enter, case-shift) DISMISS -- type nothing.
    // '&' is skipped so re-holding it doesn't self-consume the popup.
    if (sym2_popup && fresh_press && key != '&') {
      kbd_state[index] = 1;
      sym2_popup = false;
      symbol_consumed = true;                 // don't re-arm the popup while '&' stays held
      keyboard_mode = mode_at_symbol_press;   // back to the pre-'&' letter layer
      if (key == '<' || key == 'e' || key == 'l' || key == 'r' || key == 'c' || key == 'u' || key == 'd')
        return 0;                             // dismiss: no character
      char sc = symbol2_map[index];
      if (!sc || sc == ' ')
        return 0;
      if ((unsigned char)sc < 0x20 && !terminal_active())
        return 0;                             // Esc/Tab are terminal-only; off it they'd be LVGL nav
      return kbd_emit[index] = sc;            // the picked Sym2 char (held -> auto-repeats it)
    }

    // One-shot Sym1 (armed by a quick '&' tap): the next key is a single symbol,
    // then back to letters. Non-symbol keys (backspace/enter/arrows/case) just
    // pass through normally, also consuming the one-shot.
    if (sym1_oneshot && fresh_press && key != '&') {
      sym1_oneshot = false;
      keyboard_mode = mode_at_symbol_press;   // revert after this key
      if (key != '<' && key != 'e' && key != 'l' && key != 'r' && key != 'c' && key != 'u' && key != 'd') {
        kbd_state[index] = 1;
        char s1 = symbol_map[index];
        if (s1 && s1 != ' ')
          return kbd_emit[index] = s1;
        return 0;
      }
      // special key: fall through to normal handling (mode already reverted)
    }

    // With Ctrl armed, a letter becomes its control code and disarms.
    if (ctrl_armed && key >= 'A' && key <= 'Z') {
      ctrl_armed = false;
      return (char)(key - 'A' + 1);      // Ctrl-A = 0x01 ... Ctrl-Z = 0x1A
    }
    if (ctrl_armed && key >= 'a' && key <= 'z') {
      ctrl_armed = false;
      return (char)(key - 'a' + 1);
    }

    switch(key){
      case 'c':
        // In SYMBOL_CASE the 'c' key is the digit '4' (see symbol_map[2]).
        // The case-toggle branch below would silently swallow the press
        // and just exit symbol mode, which is why '4' looks dead while
        // every other digit works. Mirror the 'u' -> '0' special case
        // at the bottom of this function: emit the digit and revert
        // to LOWER_CASE so the next press is a regular letter.
        if (keyboard_mode == SYMBOL_CASE) {
          if (symbol_held)
            symbol_consumed = true;
          else
            keyboard_mode = LOWER_CASE;
          return symbol_map[index];
        }
        // From lower OR Sym2, case-shift goes to caps (leaving Sym2); from caps
        // back to lower.
        if (keyboard_mode == LOWER_CASE || keyboard_mode == SYMBOL2_CASE)
          keyboard_mode = UPPER_CASE;
        else
          keyboard_mode = LOWER_CASE;
        break;
      case '&':
        // Entry (hold/double-tap) and exit (tap in Sym2) are handled at the top
        // of the scan; here just arm Sym from the letter layers, and leave Sym2
        // alone so a tap-to-exit isn't pre-empted by flipping to Sym on the press.
        if (keyboard_mode != SYMBOL2_CASE)
          keyboard_mode = SYMBOL_CASE;
        break;
      case 'e':
        return '\n';
      case '<':
        // ALWAYS a plain backspace. Whether it means "delete a character" or
        // "leave this screen" depends on where the focus is and whether symbol
        // is held, and the driver is the wrong place to know either: ui.cpp
        // applies that rule in one place, for every screen including the
        // terminal.
        return '\b';
      case 'u':
        return VIEW_K_UP;
      case 'd':
        return VIEW_K_DOWN;
      case 'l':
      case 'r': {
        // Symbol-shift or case-shift turns the left/right keys into up/down
        // (e.g. shell history in the terminal, vertical nav elsewhere).
        if (keyboard_mode == SYMBOL_CASE || keyboard_mode == UPPER_CASE) {
          if (keyboard_mode == SYMBOL_CASE) {
            if (symbol_held)  // sustained while '&' held
              symbol_consumed = true;
            else
              keyboard_mode = LOWER_CASE;
          } else {
            keyboard_mode = LOWER_CASE;                 // case-shift is a one-shot
          }
          if (terminal_active())
            vert_sticky_until = now + VERT_STICKY_MS;
          if ((key == 'l'))
            return VIEW_K_UP;
          return VIEW_K_DOWN;
        }
        // In the terminal, plain left/right ARE the cursor arrows — sent to the
        // shell as ESC[D / ESC[C. There's no LVGL editor to gate them on, so the
        // normal focus/PREV-NEXT list-nav logic below doesn't apply.
        if (terminal_active()) {
          if (vert_sticky_until && (int32_t)(now - vert_sticky_until) < 0) {
            vert_sticky_until = now + VERT_STICKY_MS;   // keep the run going
            if ((key == 'l'))
              return VIEW_K_UP;
            return VIEW_K_DOWN;
          }
          vert_sticky_until = 0;
          if ((key == 'l'))
            return VIEW_K_LEFT;
          return VIEW_K_RIGHT;
        }
        bool at_start = false, at_end = false;
        // The view engine owns the "is the text editor focused, and where's the
        // cursor?" decision — every screen is a view now.
        bool focused = view_is_active() && view_input_focused();
        if (focused)
          view_input_cursor_edge(&at_start, &at_end);
        if (key == 'l') {
          if ((focused && !at_start))
            return VIEW_K_LEFT;
          return VIEW_K_PREV;
        }
        else {
          if ((focused && !at_end))
            return VIEW_K_RIGHT;
          return VIEW_K_NEXT;
        }
      }
      case 's':
      case 'p':
        // Held '&' + space is a PLAIN SPACE: the driver stays dumb and lets an
        // app (the terminal) read the physical symbol + which space via
        // keyboard_get_modifiers() and decide Left/Right. '@' / '$' still reach
        // the user via a quick '&' tap (one-shot Sym1, handled above) or the Sym2
        // popup — both fire with '&' released, so they bypass this.
        if (symbol_held) {
          symbol_consumed = true;   // don't arm a one-shot Sym1 on '&' release
          return ' ';
        }
        // SP1/SP2 are space in the letter layers, but carry symbols (@ / $) in
        // the symbol layer — mirror the default-case symbol handling.
        if (keyboard_mode == SYMBOL_CASE) {
          if (symbol_held)
            symbol_consumed = true;
          else
            keyboard_mode = LOWER_CASE;
          return kbd_emit[index] = symbol_map[index];
        }
        if (keyboard_mode == SYMBOL2_CASE) {
          if (symbol_held)
            symbol_consumed = true;
          else  // one-shot
            keyboard_mode = LOWER_CASE;
          return kbd_emit[index] = symbol2_map[index];
        }
        return ' ';
      default:
        if (!islower(key)){
          switch(keyboard_mode){
            case UPPER_CASE:
              keyboard_mode = LOWER_CASE;
              return kbd_emit[index] = toupper(key);
            case SYMBOL_CASE:
              if (symbol_held)
                symbol_consumed = true;
              else
                keyboard_mode = LOWER_CASE;
              return kbd_emit[index] = symbol_map[index];
            case SYMBOL2_CASE:
              if (symbol_held)  // held: sustained
                symbol_consumed = true;
              else  // one-shot: revert to aaa after one key
                keyboard_mode = LOWER_CASE;
              return kbd_emit[index] = symbol2_map[index];
            default:
              return kbd_emit[index] = tolower(key);
          }
        }
        keyboard_mode = LOWER_CASE;
    }
  }
  return 0;
}

// Is either space key held right now? Used by the PTT Talk screen to poll the
// space-to-talk gate. Polled by SCANCODE rather than by character, because
// base_map carries the markers 's'/'p' there, not ' '. Freshness = the
// keyboard_scan() rate.
bool keyboard_space_held(void){
  return s_key_now[SC_SPACE1] || s_key_now[SC_SPACE2];
}

// One atomic snapshot of the nav/modifier keys' physical state as OR'd KBD_MOD_*
// bits (ui.h). Same s_key_now[] source as keyboard_space_held(); apps read this
// to interpret keys without knowing the matrix layout.
uint16_t keyboard_get_modifiers(void){
  uint16_t m = 0;
  if (s_key_now[SC_LEFT])
    m |= KBD_MOD_L;
  if (s_key_now[SC_RIGHT])
    m |= KBD_MOD_R;
  if (s_key_now[SC_SYMBOL])
    m |= KBD_MOD_SYMBOL;
  if (s_key_now[SC_CASE])
    m |= KBD_MOD_SHIFT;
  if (s_key_now[SC_SPACE1])
    m |= KBD_MOD_SP1;
  if (s_key_now[SC_SPACE2])
    m |= KBD_MOD_SP2;
  if (s_key_now[SC_ENTER])
    m |= KBD_MOD_ENTER;
  if (s_key_now[SC_BKSP])
    m |= KBD_MOD_BACKSPACE;
  return m;
}

// Fast matrix poll — call from loop() (NOT LVGL), every iteration (~5 ms). Runs the
// scan + emit logic and latches any produced character. A no-key scan (0) leaves an
// unconsumed latch intact so a keystroke isn't lost before LVGL's next read.
void keyboard_scan(void){
  char c = keyboard_scan_char();
  if (c)
    kbd_pending = c;
  // The backlight on/off belongs to the keyboard poll, not to any one screen:
  // keyboard_scan_char() above kicks the display timer on ANY key, and actuating the
  // LED right here -- the one poll that runs every loop in EVERY mode -- is what
  // makes the panel wake/sleep correctly even in the terminal's grid mode, where
  // ui_slice() (display_pump()'s old home) is skipped entirely. Pure GPIO unless
  // a UI PIN is set; the PIN lock-screen path inside display_pump() is LVGL and
  // is a known follow-up if the two-core split is ever restored (it would then
  // want to run on the UI core, not here).
  display_pump();
}

// Hand over the latched character and clear it. No matrix work here — that
// happens in keyboard_scan().
char keyboard_read(void){
  char c = kbd_pending;
  kbd_pending = 0;
  return c;
}

// Which board's matrix_map to read the matrix through. Anything but KBD_LAYOUT_V3
// gets v2, so an unset record (a blank or newly wiped device, and any unit
// flashed before the field existed) still has a usable keyboard while the probe
// has not run. Called at boot from setup(), and again when the probe answers.
void keyboard_set_layout(uint8_t layout) {
  if (layout == KBD_LAYOUT_V3)
    matrix_map = matrix_v3;
  else
    matrix_map = matrix_v2;
  for (int sc = 0; sc < KBD_KEYS; sc++)
    key_fitted[sc] = false;
  for (int w = 0; w < MATRIX_KEYS; w++) {
    int sc = matrix_map[w];
    if (sc >= 0)
      key_fitted[sc] = true;
  }
}

// Is a space key held right now, read straight off the matrix? For the boot
// gesture, which runs before any scan has filled s_key_now[]. Mapped through the
// loaded layout, so it means the key under the user's thumb rather than a
// position -- the two boards put space in different places.
bool keyboard_boot_space_held(void) {
  int pos = keyboard_raw_down();
  if (pos < 0)
    return false;
  int sc = matrix_map[pos];
  return sc == SC_SPACE1 || sc == SC_SPACE2;
}

// The raw matrix position of a key that is down, or -1. For the layout probe,
// which has to read a key BEFORE it knows the matrix_map: it reports where the key
// sits in the matrix and maps nothing, so no table has to be right for it to
// work. Deliberately outside the emit path — no character, no auto-repeat, and
// no brush rejection, since the neighbour map is expressed in scancodes and
// there are none yet.
int keyboard_raw_down(void) {
  for (int i = 0; i < KBD_ROWS; i++)
    pinMode(kbd_row[i], INPUT);
  for (int j = 0; j < KBD_COLS; j++)
    pinMode(kbd_col[j], INPUT_PULLUP);

  int found = -1;
  for (int i = 0; i < KBD_ROWS; i++) {
    pinMode(kbd_row[i], OUTPUT);
    digitalWrite(kbd_row[i], LOW);
    for (int j = 0; j < KBD_COLS; j++) {
      if (digitalRead(kbd_col[j]) == LOW && found < 0)
        found = i * KBD_COLS + j;
    }
    digitalWrite(kbd_row[i], HIGH);
    pinMode(kbd_row[i], INPUT);
  }
  return found;
}
