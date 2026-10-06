#pragma once
//
// kernel.h — the notification loop.
//
// ONE KIND OF THING: a handler with its own state, in its own source file.
// Network, media and the user all arrive at that one function. A handler is
// created at APP_INIT and lives to power-off; it is never allocated, never
// destroyed, and its buffers are file statics.
//
// TWO WAYS TO BE REACHED, and they are independent:
//   - A SOCKET remembers its handler. Its messages arrive whether or not that
//     handler is on the screen stack, or ever has been.
//   - THE SCREEN STACK decides who is DISPLAYED. Only the top frame gets
//     APP_FOREGROUND / APP_BACKGROUND / APP_SELECTION / APP_KEYSTROKE.
// So a messaging app is both — it owns a port and it has a screen — while
// call.c owns a port and no screen, and an alert has a screen and no port.
//
// Core 0. Portable C.

#include <stdint.h>
#include <stdbool.h>
#include "stream.h"      // stream_handle

#ifdef __cplusplus
extern "C" {
#endif

// Non-zero = handled. Only APP_KEYSTROKE reads it: 1 swallows the key, 0 passes
// it to the view engine, which is what lets Enter be Go on one screen and a
// newline on another.
typedef int (*msg_handler_fn)(int notification, uint32_t param);

// ONE NAMESPACE. Two enums both starting at 0 feeding one dispatch loop is a
// collision nobody would catch, so every layer emits from this.
enum {
	APP_INIT = 0,            // once at boot, before anything else. param 0
	APP_PUMP,                // every core-0 tick. param now_ms()
	APP_FOREGROUND,          // now on top of the stack. param = launch argument
	APP_BACKGROUND,          // no longer on top. param = the same argument
	APP_SELECTION,           // a row was activated. param = that row's string
	APP_KEYSTROKE,           // any key, before the GUI. param = key code

	NOTIFY_DATAGRAM,         // a datagram on my port. param = remote_userid
	NOTIFY_STREAM_DATA,      // param = remote_userid
	NOTIFY_STREAM_DELIVERED,
	NOTIFY_PEER_UP,          // a link to them came up

	NOTIFY_CALL_INCOMING,    // param = partkey, for all four
	NOTIFY_CALL_RINGING,
	NOTIFY_CALL_ACTIVE,
	NOTIFY_CALL_ENDED,       // a MISSED call is ENDED for a peer never seen ACTIVE

	NOTIFY_MSG_UPDATE,       // a contact's stored thread changed (new record, a
	                         // delivery flip, a delete). param = that contact's
	                         // partkey. THE LOGBOOK IS THE MODEL: a receiver
	                         // re-reads it; the notification carries no data.
};

// APP_FOREGROUND builds the display and is the ONLY place that happens — on
// first push and on every return from a screen above, so there is no second
// "resume" notification to keep in step with it.

// ---- sockets ---------------------------------------------------------------
// One handler per (transport, port). kernel_listen_stream takes stream.c's port
// on the caller's behalf and returns the handle its writes will name.
stream_handle kernel_listen_stream  (uint16_t port, msg_handler_fn handler);
bool          kernel_listen_datagram(uint16_t port, msg_handler_fn handler);

// The datagram body, borrowed for the duration of NOTIFY_DATAGRAM and no longer
// — netif's buffer, so voice costs no copy.
const uint8_t *kernel_datagram_body(int *len);

// ---- the screen stack ------------------------------------------------------
// A screen_id indexes app_table in kernel.c: one app per id.
enum {
	APP_CALL = 0,
	APP_TERM,
	APP_CHAT,       // a contact's conversation thread. arg = partkey
	APP_MSG_MENU,   // one message's actions (view/retry/delete). arg = record_id
	APP_MSG_VIEW,   // one message, full text. arg = record_id
	APP_HOME,       // app_home.c: the conversations list. arg unused
	APP_SETTINGS,   // app_home.c. arg unused
	APP_ADMIN,      // app_home.c. arg unused
	APP_SECURITY,   // app_home.c: keys, PIN, burner, dev mode. arg unused
	APP_PTT,        // app_ptt.c: push-to-talk to one contact. arg = partkey
	APP_CHANNEL,    // app_channel.c: a channel session. arg = host partkey
	APP_PICK,       // the generic chooser — pushed via screen_pick(), never directly
	APP_ASK,        // the generic text prompt — pushed via screen_ask(), never directly
	APP_COUNT
};

// Addressee for a notification every app should see. Not a member of the enum
// above: that one is a dense index into app_table, and this is deliberately
// outside it.
#define APP_ALL 0xFFFFu

// Queue a notification for delivery by the next kernel_slice(). Coalesced — one
// already pending with the same (app_id, notification, param) is not queued
// twice, which is what makes dropping one on a full queue harmless. Returns
// whether it was accepted, never what the handler thought: it has not run yet.
bool post_notification(uint16_t app_id, uint16_t notification, uint32_t param);


// A TRANSITION IS A REQUEST. A handler calls one from inside its own
// APP_SELECTION or APP_KEYSTROKE — the frame it asks to destroy is the one
// running — so the kernel records it and kernel_slice() applies it. One per
// tick; a second is refused and logged.
bool screen_push   (int screen_id, uint32_t arg);  // on top; the one below stays
bool screen_replace(int screen_id, uint32_t arg);  // pop self, push this in place
void screen_pop    (void);                         // reveal the one below
void screen_clear  (void);                         // empty the stack WITHOUT go_home:
                                                   // the handoff to a legacy view flow,
                                                   // which takes the display itself

// ---- the title bar ---------------------------------------------------------
// EVERY screen is named the same way, and no screen paints the bar: the view
// engine's chrome is the one painter, and it reads this string. Set it from
// APP_FOREGROUND, which arrives on first push AND on every return from a screen
// above -- so backing out of a screen restores the name below it with no stack
// of titles to keep. Call it again whenever the name changes mid-screen (the
// terminal marks an armed Ctrl this way); the chrome repaints a cell only when
// its text actually differs, so re-setting the same string costs nothing.
// view_set() forwards its own title argument here, so a list screen is already
// named by being built.
void        screen_title    (const char *title);
const char *screen_title_str(void);                // what the chrome paints

// Whose reachability the title-bar eye reports. NULL (the default, and what
// every transition resets to) means OUR OWN online state; a key means that
// peer's link, so a per-peer screen can say offline/trying/online about the
// peer it is actually about.
//
// The FULL key, not a partkey: netif addresses by full key, and a screen always
// has the contact in hand at the moment it names one. Passing the partkey would
// force the chrome to re-read the contact from flash on every repaint to
// recover the key it had already loaded.
void screen_peer(const uint8_t key[32]);
const uint8_t *screen_peer_key(void);   // NULL = report our own state

// ---- the generic screens (handlers in app_home.c) --------------------------
// One request at a time — a pick cannot stack over a pick. Backing out delivers
// nothing: the caller's own FOREGROUND-on-return is the cancel path.
//
// screen_pick: a chooser. `items` NULL-terminated, BORROWED until the screen
// closes (point at statics). on_pick(index, text) runs on selection, then the
// screen pops itself — so on_pick must NOT request a transition; it mutates
// state and the caller's re-render shows the result. NULL on_pick = info screen.
void screen_pick(const char *title, const char *prompt, const char **items,
                 void (*on_pick)(int index, const char *text));

// screen_ask: a text prompt. `mask` = allowed characters (NULL = any); `prefill`
// seeds the field; is_secret asks the backend to obscure the echo (accepted now,
// rendered plain until the engine grows masking). on_answer returns NULL to
// accept (the screen pops) or an error prompt to re-show WITH the input kept.
// Same rule as on_pick: no transitions from inside the callback.
void screen_ask(const char *title, const char *question, const char *mask,
                const char *prefill, bool is_secret,
                const char *(*on_answer)(const char *text));

// The platform's side of APP_KEYSTROKE and APP_SELECTION.
//
// screen_key is SYNCHRONOUS: the engine needs the swallow answer before it moves
// on, so it cannot be queued. screen_selection is QUEUED and delivered by
// kernel_slice, because acting on a row usually rebuilds the screen and that
// must not happen inside the engine's own dispatch; its text is copied, the row
// string being the view's to reuse.
//
// screen_active() is false when the stack is empty and the platform owns the
// display.
int  screen_key      (int key);
void screen_selection(const char *text);
bool screen_active   (void);

// What is on screen is out of date; repaint it. A DISPLAY operation, so it names
// no peer: deciding whether a change is worth showing belongs to the app that
// knows both the change and what its screen is displaying.
void screen_invalidate(void);

// The backlight came back on. Sends APP_FOREGROUND to the top screen on the
// next slice, so no screen needs wake handling of its own.
void screen_wake(void);

// Post a notification to EVERY handler, delivered by the next kernel_slice() — the
// asynchronous twin of the NOTIFY_* the kernel raises itself. How an engine
// tells the screens the model changed without naming one: each receiver decides
// from param whether it cares. False = the queue is full and the post was
// dropped (a receiver that re-reads the model on every post loses nothing).
bool kernel_post(int notification, uint32_t param);

// ---- the network -----------------------------------------------------------
// KEYS STOP HERE. Above this line netif addresses by the full 32 bytes, a
// 4-byte collision being a stated threat; below it a peer is a remote_userid.
bool kernel_send_frame(uint32_t remote_userid, uint8_t port,
                       const void *body, int len);
void kernel_frame_in  (const uint8_t peer_key[32], const uint8_t *frame, int len);
void kernel_peer_up   (const uint8_t peer_key[32]);

// stream.c's upcalls. It reports a transport event and names no notification, so the
// transport needs no part of the enum above. FALSE = nothing is bound to that
// port, and the caller then frees the slot — an unowned stream is not kept.
bool kernel_stream_data     (uint16_t port, uint32_t remote_userid);
bool kernel_stream_delivered(uint16_t port, uint32_t remote_userid);

// ---- the stamp clock -------------------------------------------------------
// ONE notion of "now" for everything that goes on flash, so a stamp and a cutoff
// compared against it cannot come from different clocks.
//
// THE WALL CLOCK IS NOT ENOUGH ON ITS OWN. get_current_time_seconds() counts
// from a fixed date plus millis() until NTP lands, so early in a boot it reads
// months below real time. The floor is the newest stamp anyone has shown us —
// the log's own entries, seen by the mount crawl, and every stamp minted since.
// So this is the real clock once NTP has synced and the log's newest stamp
// before that, which is what lets a device whose NTP is blocked still say how
// old its records are.
uint32_t kernel_time_now(void);

// The same, claimed: strictly greater than every stamp seen or issued, so no two
// records share a value and the number orders them. It raises the floor itself,
// which makes that true of the function rather than of one careful caller.
uint32_t kernel_time_mint(void);

// Raise the floor to a stamp read off flash. Without this call the clock has no
// floor at all, and the mount crawl is the only place one can come from.
void kernel_time_seen(uint32_t stamp);

void kernel_init(void);

// The stack tick: netif, streams, calls, storage. Core 0, every ~5 ms.
void kernel_pump(void);

// The app tick: drain queued selections, apply a pending screen transition, then
// APP_PUMP every handler. SEPARATE FROM kernel_pump BECAUSE OF ORDER — a
// transition ends in a repaint, so it runs where the UI runs, and pumping after
// it means a screen that popped never gets one more APP_PUMP.
//
// Called once per UI tick by the device, and from the stack loop by the host,
// which has no UI. Miss it and every app stops, messaging included.
void kernel_slice(void);

#ifdef __cplusplus
}
#endif
