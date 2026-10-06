#pragma once
//
// ui_symbols.h -- the icon and key-code constants the UI uses, defined HERE
// rather than pulled from lvgl.h.
//
// LVGL is being removed from Xyfr because it is the largest body of unaudited
// third-party code inside the trust boundary of a secure comms device -- not to
// save RAM. These constants were its widest remaining foothold: ~140 uses across
// files that otherwise call no LVGL at all, each one pulling in <lvgl.h> and
// with it the whole library.
//
// The NAMES are kept identical on purpose. Renaming would have meant editing
// every call site, and a mechanical 140-site sweep is exactly where a typo
// hides; keeping them makes this header the entire change, with every use
// unchanged and reviewable. The VALUES are copied verbatim from lvgl.
//
// The icons are UTF-8 codepoints in the FontAwesome block. Xyfr renders them
// from the sparse tier of its own font tables (tfont.h); every codepoint below
// was checked present in mont14 when this header was generated.

// ---- icons (UTF-8, FontAwesome block) ----
#define LV_SYMBOL_BELL           "\xEF\x83\xB3"   /* U+F0F3 */
#define LV_SYMBOL_CALL           "\xEF\x82\x95"   /* U+F095 */
#define LV_SYMBOL_CLOSE          "\xEF\x80\x8D"   /* U+F00D */
#define LV_SYMBOL_DOWNLOAD       "\xEF\x80\x99"   /* U+F019 */
#define LV_SYMBOL_EDIT           "\xEF\x8C\x84"   /* U+F304 */
#define LV_SYMBOL_ENVELOPE       "\xEF\x83\xA0"   /* U+F0E0 */
#define LV_SYMBOL_EYE_CLOSE      "\xEF\x81\xB0"   /* U+F070 */
#define LV_SYMBOL_EYE_OPEN       "\xEF\x81\xAE"   /* U+F06E */
#define LV_SYMBOL_FILE           "\xEF\x85\x9B"   /* U+F15B */
#define LV_SYMBOL_GPS            "\xEF\x84\xA4"   /* U+F124 */
#define LV_SYMBOL_HOME           "\xEF\x80\x95"   /* U+F015 */
#define LV_SYMBOL_KEYBOARD       "\xEF\x84\x9C"   /* U+F11C */
#define LV_SYMBOL_LEFT           "\xEF\x81\x93"   /* U+F053 */
#define LV_SYMBOL_LIST           "\xEF\x80\x8B"   /* U+F00B */
#define LV_SYMBOL_LOOP           "\xEF\x81\xB9"   /* U+F079 */
#define LV_SYMBOL_MUTE           "\xEF\x80\xA6"   /* U+F026 */
#define LV_SYMBOL_OK             "\xEF\x80\x8C"   /* U+F00C */
#define LV_SYMBOL_PLUS           "\xEF\x81\xA7"   /* U+F067 */
#define LV_SYMBOL_REFRESH        "\xEF\x80\xA1"   /* U+F021 */
#define LV_SYMBOL_RIGHT          "\xEF\x81\x94"   /* U+F054 */
#define LV_SYMBOL_SAVE           "\xEF\x83\x87"   /* U+F0C7 */
#define LV_SYMBOL_SD_CARD        "\xEF\x9F\x82"   /* U+F7C2 */
#define LV_SYMBOL_SETTINGS       "\xEF\x80\x93"   /* U+F013 */
#define LV_SYMBOL_TRASH          "\xEF\x8B\xAD"   /* U+F2ED */
#define LV_SYMBOL_UPLOAD         "\xEF\x82\x93"   /* U+F093 */
#define LV_SYMBOL_VOLUME_MAX     "\xEF\x80\xA8"   /* U+F028 */
#define LV_SYMBOL_WARNING        "\xEF\x81\xB1"   /* U+F071 */
#define LV_SYMBOL_WIFI           "\xEF\x87\xAB"   /* U+F1EB */

// Added for the icon title bar: the 5-step battery scale and the mid volume
// level. All verified present in mont14's sparse tier when added.
#define LV_SYMBOL_BATTERY_EMPTY  "\xEF\x89\x84"   /* U+F244 */
#define LV_SYMBOL_BATTERY_1      "\xEF\x89\x83"   /* U+F243 */
#define LV_SYMBOL_BATTERY_2      "\xEF\x89\x82"   /* U+F242 */
#define LV_SYMBOL_BATTERY_3      "\xEF\x89\x81"   /* U+F241 */
#define LV_SYMBOL_BATTERY_FULL   "\xEF\x89\x80"   /* U+F240 */
#define LV_SYMBOL_VOLUME_MID     "\xEF\x80\xA7"   /* U+F027 */

// Key codes deliberately live in view.h as VIEW_K_*, not here: they are the
// engine's own neutral codes and defining a second set as macros here collided
// with lvgl's enum of the same names while both were still in the build.
