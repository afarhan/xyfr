// kernel.c — the portable core-0 loop, shared by the device and the host CLI.
//
// An app is one handler, int (*)(int notification, uint32_t param), with its
// own state in its own file, created at APP_INIT and alive to power-off. It is
// reached two independent ways: a port binding, so a socket's traffic arrives
// whether or not the app is on screen; and the screen stack, which decides
// what is displayed. app_table lists every app; bindings[] maps
// (transport, port) to a handler.
//
// Inbound: netif hands every authenticated frame to netif_frame_in.
// kernel_frame_in reads the 4-byte common header and gives a datagram to the
// port's owner as NOTIFY_DATAGRAM, the body parked in datagram_body for that
// one call. Stream frames go to stream.c, which reports back through
// kernel_stream_data / kernel_stream_delivered. Outbound datagrams go through
// kernel_send_frame, which resolves the contact and prepends the header.
//
// The screen stack holds (screen_id, arg). A handler asks for a push, pop,
// replace or clear from inside its own callback, so the request is recorded
// and applied afterwards by kernel_slice. A pop that empties the stack calls
// go_home(); only the kernel can tell that from being covered. Keys are
// delivered at once, because the view engine needs the answer (1 = swallowed).
// Selections are queued, because acting on one rebuilds the screen. Posted
// notifications (kernel_post) are queued, coalesced on (app, notification,
// param), and broadcast to every handler once.
//
// kernel_slice, from the UI loop at ~10 Hz: drain selections, drain posted
// notifications, apply the pending transition, then APP_PUMP to every handler
// once. kernel_pump, from the main loop at ~200 Hz: netif, the contact query,
// calls, streams, cmdq, the settings block.
//
// Below netif a peer is its 32-byte key; above this file a peer is a
// remote_userid.

#include "hal.h"
#include "device_record.h"
#include "contacts.h"
#include "secure_store.h"
#include "cmdq.h"
#include "wg.h"
#include "call.h"
#include "msg.h"
#include "terminal.h"
#include "peer_data.h"
#include "netif.h"
#include "stream.h"
#include "config.h"
#include "kernel.h"
#include "phone_state.h"    // the C-safe half of ui.h

#include <string.h>
#include <stdio.h>

extern time_t get_current_time_seconds();

// ---- the stamp clock -------------------------------------------------------
// See kernel.h. The floor is what the log has shown us; before NTP it is the
// only thing standing between a new record and a stamp months in the past.
static uint32_t stamp_floor;

void kernel_time_seen(uint32_t stamp) {
	if (stamp > stamp_floor)
		stamp_floor = stamp;
}

uint32_t kernel_time_now(void) {
	uint32_t stamp = (uint32_t)get_current_time_seconds();
	if (stamp <= stamp_floor)
		return stamp_floor;
	return stamp;
}

uint32_t kernel_time_mint(void) {
	uint32_t stamp = kernel_time_now();
	if (stamp <= stamp_floor)
		stamp = stamp_floor + 1;
	stamp_floor = stamp;
	return stamp;
}

#define BINDING_MAX         5    // (transport, port) rows: voice, MSG, terminal, channel
#define SELECTION_SLOTS     4    // row selections awaiting delivery
#define SELECTION_TEXT      64
#define NOTIFICATION_SLOTS  32   // 8 bytes each

// ---- structs ---------------------------------------------------------------

struct binding {
	uint8_t        transport;    // 0 = free
	uint16_t       port;
	msg_handler_fn handler;
};

struct app {
	const char    *log_name;
	msg_handler_fn main;
};

struct screen_frame {
	uint8_t  screen_id;          // index into app_table
	uint32_t arg;                // handed to the app with every FOREGROUND and BACKGROUND
};

enum transition_kind {
	TRANSITION_NONE = 0,
	TRANSITION_PUSH,
	TRANSITION_REPLACE,
	TRANSITION_POP,
	TRANSITION_CLEAR,
};

// A queued row selection. Copied, because the row string belongs to the view
// and is rebuilt on the next repaint.
struct pending_selection {
	char text[SELECTION_TEXT];
};

int app_call_main(int notification, uint32_t param);
int app_terminal_main(int notification, uint32_t param);
int app_chat_main(int notification, uint32_t param);
int app_channel_main(int notification, uint32_t param);
int app_msg_menu_main(int notification, uint32_t param);
int app_msg_view_main(int notification, uint32_t param);
int app_home_main(int notification, uint32_t param);
int app_settings_main(int notification, uint32_t param);
int app_admin_main(int notification, uint32_t param);
int app_security_main(int notification, uint32_t param);
int app_ptt_main(int notification, uint32_t param);
int app_pick_main(int notification, uint32_t param);
int app_ask_main(int notification, uint32_t param);
void go_home(void);   // the platform's no-screen display

static const struct app app_table[APP_COUNT] = {
	[APP_CALL]     = { "call",     app_call_main },
	[APP_TERM]     = { "term",     app_terminal_main },
	[APP_CHAT]     = { "chat",     app_chat_main },
	[APP_CHANNEL]  = { "channel",  app_channel_main },
	[APP_MSG_MENU] = { "msgmenu",  app_msg_menu_main },
	[APP_MSG_VIEW] = { "msgview",  app_msg_view_main },
	[APP_HOME]     = { "home",     app_home_main },
	[APP_SETTINGS] = { "settings", app_settings_main },
	[APP_ADMIN]    = { "admin",    app_admin_main },
	[APP_SECURITY] = { "security", app_security_main },
	[APP_PTT]      = { "ptt",      app_ptt_main },
	[APP_PICK]     = { "pick",     app_pick_main },
	[APP_ASK]      = { "ask",      app_ask_main },
};

static struct binding      bindings[BINDING_MAX];
static struct screen_frame *screen_stack;   // screen_depth frames, from kernel_init
static int screen_depth;
static int                 screen_stack_top;    // count; 0 = nothing showing

static enum transition_kind pending_kind;
static int                  pending_screen;
static uint32_t             pending_arg;

static struct pending_selection selections[SELECTION_SLOTS];
static int                      selection_head;
static int                      selection_count;

static uint64_t notification_queue[NOTIFICATION_SLOTS];   // app<<48 | notification<<32 | param
static int      notification_queue_head;
static int      notification_queue_count;

static char    screen_title_text[64];
static uint8_t screen_peer_pub[32];
static bool    screen_peer_set;             // false = the title bar reports our own state

static const uint8_t *datagram_body;        // netif's buffer, borrowed for one dispatch
static int            datagram_len;

static netif_state s_last_netif_state = NETIF_DOWN;   // kernel_pump is the only writer
static int         s_identity_ok     = -1;            // 1 accepted, 0 refused, -1 none this boot
static int         s_identity_reason = 0;

// ---- identity --------------------------------------------------------------

int kernel_online(void) {
	return s_last_netif_state == NETIF_ONLINE;
}

// Polled by the registration screen; nothing is notified.
int kernel_identity_result(int *reason) {
	if (reason)
		*reason = s_identity_reason;
	return s_identity_ok;
}

void kernel_identity_reset(void) {
	s_identity_ok     = -1;
	s_identity_reason = 0;
}

void on_identity_result(bool ok, const uint8_t key[32], int reason) {
	s_identity_ok     = ok;
	s_identity_reason = reason;
	if (!ok) {
		hal_debug(LOG_ERROR, "identity: refused (reason=%d); netif rolled back\n", reason);
		return;
	}
	memcpy(device_record.my_private_key, key, KEY_LEN);   // netif holds it in RAM only
	flag_save_block = 1;
	hal_debug(LOG_WARNING, "identity: now %08x, persisting\n",
	          (unsigned)get_part_key((uint8_t *)key));
}

static void netif_frame_in(const uint8_t peer_key[32],
                           frame_event ev, const uint8_t *data, int len) {
	unsigned pk = get_part_key((uint8_t *)peer_key);
	if (ev == FRAME_PEER_UP) {
		hal_debug(LOG_EVERYTHING, "netif: link up peer=%08x\n", pk);
		kernel_peer_up(peer_key);
		return;
	}
	kernel_frame_in(peer_key, data, len);
}

// ---- port bindings ---------------------------------------------------------

static msg_handler_fn handler_for(uint8_t transport, uint16_t port) {
	for (int i = 0; i < BINDING_MAX; i++) {
		if (bindings[i].transport == transport && bindings[i].port == port)
			return bindings[i].handler;
	}
	return NULL;
}

// The slot index, or -1.
static int bind_port(uint8_t transport, uint16_t port, msg_handler_fn handler) {
	if (!handler || port == 0)
		return -1;
	if (handler_for(transport, port)) {
		hal_debug(LOG_ERROR, "kernel: transport %u port %u already bound\n",
		          (unsigned)transport, (unsigned)port);
		return -1;
	}
	for (int i = 0; i < BINDING_MAX; i++) {
		if (bindings[i].transport != 0)
			continue;
		bindings[i].transport = transport;
		bindings[i].port      = port;
		bindings[i].handler   = handler;
		return i;
	}
	hal_debug(LOG_ERROR, "kernel: no free binding for port %u\n", (unsigned)port);
	return -1;
}

stream_handle kernel_listen_stream(uint16_t port, msg_handler_fn handler) {
	int slot = bind_port(DATA_STREAM, port, handler);
	if (slot < 0)
		return 0;
	stream_handle h = stream_listen(port);
	if (!h)
		bindings[slot].transport = 0;    // both or neither
	return h;
}

bool kernel_listen_datagram(uint16_t port, msg_handler_fn handler) {
	return bind_port(DATA_DATAGRAM, port, handler) >= 0;
}

// One handler may hold two ports and be a screen as well, so any list of
// handlers must reject a repeat or an event reaches it twice.
static int add_once(msg_handler_fn *out, int n, int max, msg_handler_fn handler) {
	if (!handler || n >= max)
		return n;
	for (int i = 0; i < n; i++) {
		if (out[i] == handler)
			return n;
	}
	out[n++] = handler;
	return n;
}

static int add_port_owners(msg_handler_fn *out, int n, int max) {
	for (int i = 0; i < BINDING_MAX; i++) {
		if (bindings[i].transport == 0)
			continue;
		n = add_once(out, n, max, bindings[i].handler);
	}
	return n;
}

// ---- the screen stack ------------------------------------------------------

static bool request_transition(enum transition_kind kind, int screen_id, uint32_t arg) {
	if (pending_kind != TRANSITION_NONE) {
		hal_debug(LOG_ERROR, "kernel: a transition is already pending\n");
		return false;
	}
	if (kind != TRANSITION_POP && (screen_id < 0 || screen_id >= APP_COUNT))
		return false;
	pending_kind   = kind;
	pending_screen = screen_id;
	pending_arg    = arg;
	return true;
}

bool screen_push(int screen_id, uint32_t arg) {
	return request_transition(TRANSITION_PUSH, screen_id, arg);
}

bool screen_replace(int screen_id, uint32_t arg) {
	return request_transition(TRANSITION_REPLACE, screen_id, arg);
}

void screen_pop(void) {
	request_transition(TRANSITION_POP, 0, 0);
}

// Empty the stack without go_home: a legacy view_set flow takes the display
// and ends in go_home itself.
void screen_clear(void) {
	request_transition(TRANSITION_CLEAR, 0, 0);
}

bool screen_active(void) {
	return screen_stack_top > 0;
}

// ---- the title bar ---------------------------------------------------------
// The kernel holds the name and the view engine paints it, so a screen with
// no list is named like any other.

void screen_title(const char *title) {
	if (!title)
		title = "";
	snprintf(screen_title_text, sizeof screen_title_text, "%s", title);
}

void screen_peer(const uint8_t key[32]) {
	if (!key) {
		screen_peer_set = false;
		return;
	}
	memcpy(screen_peer_pub, key, 32);
	screen_peer_set = true;
}

const uint8_t *screen_peer_key(void) {
	if (!screen_peer_set)
		return NULL;
	return screen_peer_pub;
}

const char *screen_title_str(void) {
	return screen_title_text;
}

// ---- dispatch --------------------------------------------------------------

static const char *notification_name(int code) {
	switch (code) {
	case APP_INIT:                return "INIT";
	case APP_FOREGROUND:          return "FOREGROUND";
	case APP_BACKGROUND:          return "BACKGROUND";
	case APP_SELECTION:           return "SELECTION";
	case APP_KEYSTROKE:           return "KEY";
	case NOTIFY_DATAGRAM:         return "DATAGRAM";
	case NOTIFY_STREAM_DATA:      return "STREAM_DATA";
	case NOTIFY_STREAM_DELIVERED: return "STREAM_DELIVERED";
	case NOTIFY_PEER_UP:          return "PEER_UP";
	case NOTIFY_CALL_INCOMING:    return "CALL_INCOMING";
	case NOTIFY_CALL_RINGING:     return "CALL_RINGING";
	case NOTIFY_CALL_ACTIVE:      return "CALL_ACTIVE";
	case NOTIFY_CALL_ENDED:       return "CALL_ENDED";
	case NOTIFY_MSG_UPDATE:       return "MSG_UPDATE";
	case APP_PUMP:                return NULL;   // every tick; never logged
	default:                      return NULL;
	}
}

static int deliver(msg_handler_fn handler, const char *who,
                   int notification, uint32_t param) {
	if (!handler)
		return 0;
	const char *name = notification_name(notification);
	if (name)
		hal_debug(LOG_EVERYTHING, "app: %s <- %s(%u)\n", who, name, (unsigned)param);
	return handler(notification, param);
}

// To the top screen. 0 when the stack is empty.
static int deliver_top(int notification, uint32_t param) {
	if (screen_stack_top <= 0)
		return 0;
	const struct app *app = &app_table[screen_stack[screen_stack_top - 1].screen_id];
	return deliver(app->main, app->log_name, notification, param);
}

// A wake reuses APP_FOREGROUND instead of a notification of its own, so no
// screen needs a case for it. Deferred because the backlight is actuated from
// the keyboard poll, which is not where app handlers run -- and under the
// two-core split would not be the same core.
static bool screen_wake_pending;

void screen_wake(void) {
	screen_wake_pending = true;
}

// APP_FOREGROUND or APP_BACKGROUND to the top frame, with its own arg.
static void notify_top(int notification) {
	if (notification == APP_FOREGROUND)
		screen_peer_set = false;     // a screen that wants the peer eye sets it in its FOREGROUND
	if (screen_stack_top <= 0)
		return;
	deliver_top(notification, screen_stack[screen_stack_top - 1].arg);
}

static void apply_transition(void) {
	enum transition_kind kind = pending_kind;
	if (kind == TRANSITION_NONE)
		return;
	pending_kind = TRANSITION_NONE;

	if (kind == TRANSITION_CLEAR) {
		if (screen_stack_top > 0)
			notify_top(APP_BACKGROUND);
		screen_stack_top = 0;
		return;
	}
	if (kind == TRANSITION_POP) {
		if (screen_stack_top <= 0)
			return;
		notify_top(APP_BACKGROUND);
		screen_stack_top--;
		if (screen_stack_top == 0)
			go_home();
		else
			notify_top(APP_FOREGROUND);
		return;
	}
	notify_top(APP_BACKGROUND);
	if (kind == TRANSITION_REPLACE && screen_stack_top > 0)
		screen_stack_top--;
	if (screen_stack_top >= screen_depth) {
		hal_debug(LOG_ERROR, "kernel: screen stack full, refusing %d\n", pending_screen);
		notify_top(APP_FOREGROUND);
		return;
	}
	screen_stack[screen_stack_top].screen_id = (uint8_t)pending_screen;
	screen_stack[screen_stack_top].arg       = pending_arg;
	screen_stack_top++;
	notify_top(APP_FOREGROUND);
}

// ---- UI events -------------------------------------------------------------

int screen_key(int key) {
	return deliver_top(APP_KEYSTROKE, (uint32_t)key);
}

void screen_selection(const char *text) {
	if (!text)
		return;
	if (selection_count >= SELECTION_SLOTS) {
		hal_debug(LOG_WARNING, "kernel: selection queue full, dropped [%s]\n", text);
		return;
	}
	int slot = (selection_head + selection_count) % SELECTION_SLOTS;
	size_t n = strlen(text);
	if (n >= SELECTION_TEXT) {           // matched by strcmp, so truncated would match nothing
		hal_debug(LOG_ERROR, "kernel: selection text over %d bytes: [%s]\n",
		          SELECTION_TEXT - 1, text);
		return;
	}
	memcpy(selections[slot].text, text, n + 1);
	selection_count++;
}

static void drain_selections(void) {
	while (selection_count > 0) {
		const char *text = selections[selection_head].text;
		selection_head = (selection_head + 1) % SELECTION_SLOTS;
		selection_count--;
		deliver_top(APP_SELECTION, (uint32_t)(uintptr_t)text);
	}
}

// Something the home list shows has changed. Names no peer: the caller knows
// what changed, not what is on screen.
void screen_invalidate(void) {
	home_needs_refresh = 1;
}

// ---- the notification queue ------------------------------------------------

static uint64_t pack_notification(uint16_t app_id, uint16_t notification, uint32_t param) {
	return ((uint64_t)app_id << 48) | ((uint64_t)notification << 32) | param;
}

static uint16_t notification_app(uint64_t m) {
	return (uint16_t)(m >> 48);
}

static uint16_t notification_id(uint64_t m) {
	return (uint16_t)(m >> 32);
}

static uint32_t notification_param(uint64_t m) {
	return (uint32_t)m;
}

bool post_notification(uint16_t app_id, uint16_t notification, uint32_t param) {
	uint64_t m = pack_notification(app_id, notification, param);
	for (int i = 0; i < notification_queue_count; i++) {
		if (notification_queue[(notification_queue_head + i) % NOTIFICATION_SLOTS] == m)
			return true;                 // already pending
	}
	if (notification_queue_count >= NOTIFICATION_SLOTS) {
		hal_debug(LOG_WARNING, "kernel: notification queue full, dropped %u to app %u\n",
		          (unsigned)notification, (unsigned)app_id);
		return false;
	}
	notification_queue[(notification_queue_head + notification_queue_count) % NOTIFICATION_SLOTS] = m;
	notification_queue_count++;
	return true;
}

static bool pop_notification(uint64_t *out) {
	if (notification_queue_count <= 0)
		return false;
	*out = notification_queue[notification_queue_head];
	notification_queue_head = (notification_queue_head + 1) % NOTIFICATION_SLOTS;
	notification_queue_count--;
	return true;
}

bool kernel_post(int notification, uint32_t param) {
	return post_notification(APP_ALL, (uint16_t)notification, param);
}

// ---- the network, both ways ------------------------------------------------

const uint8_t *kernel_datagram_body(int *len) {
	if (len)
		*len = datagram_len;
	return datagram_body;
}

void kernel_frame_in(const uint8_t peer_key[32], const uint8_t *frame, int len) {
	if (len < DATA_HEADER_LEN)
		return;
	const struct data_hdr *h = (const struct data_hdr *)frame;
	uint16_t body_len = be16(h->len);
	if (body_len > len - DATA_HEADER_LEN)
		return;
	if (h->transport != DATA_DATAGRAM) {     // netif gives stream frames to stream.c
		hal_debug(LOG_WARNING, "kernel: transport %u is not a datagram\n",
		          (unsigned)h->transport);
		return;
	}
	msg_handler_fn handler = handler_for(DATA_DATAGRAM, h->port);
	if (!handler) {
		hal_debug(LOG_WARNING, "kernel: datagram port %u has no owner\n",
		          (unsigned)h->port);
		return;
	}
	datagram_body = frame + DATA_HEADER_LEN;
	datagram_len  = body_len;
	handler(NOTIFY_DATAGRAM, get_part_key((uint8_t *)peer_key));
	datagram_body = NULL;
	datagram_len  = 0;
}

// Datagrams only; a stream app writes through stream.c.
bool kernel_send_frame(uint32_t remote_userid, uint8_t port,
                       const void *body, int len) {
	struct contact_record contact;
	if (!contact_get(&contact, remote_userid))
		return false;
	if (len < 0 || len > MAX_PACKET_SIZE - DATA_HEADER_LEN)
		return false;
	uint8_t frame[MAX_PACKET_SIZE];
	struct data_hdr *h = (struct data_hdr *)frame;
	h->transport = DATA_DATAGRAM;
	h->port      = port;
	h->len       = be16((uint16_t)len);
	if (len > 0)
		memcpy(frame + DATA_HEADER_LEN, body, (size_t)len);
	return frame_write(contact.key, frame, DATA_HEADER_LEN + len) != FRAME_FAILED;
}

// Every port owner hears it; screens do not.
void kernel_peer_up(const uint8_t peer_key[32]) {
	msg_handler_fn heard[BINDING_MAX];
	int n = add_port_owners(heard, 0, BINDING_MAX);
	uint32_t userid = get_part_key((uint8_t *)peer_key);
	for (int i = 0; i < n; i++)
		deliver(heard[i], "port", NOTIFY_PEER_UP, userid);
}

// False = nothing bound to that port; stream.c frees the slot.
static bool stream_notify(uint16_t port, uint32_t remote_userid, int notification) {
	msg_handler_fn handler = handler_for(DATA_STREAM, port);
	if (!handler)
		return false;
	deliver(handler, "stream", notification, remote_userid);
	return true;
}

bool kernel_stream_data(uint16_t port, uint32_t remote_userid) {
	return stream_notify(port, remote_userid, NOTIFY_STREAM_DATA);
}

bool kernel_stream_delivered(uint16_t port, uint32_t remote_userid) {
	return stream_notify(port, remote_userid, NOTIFY_STREAM_DELIVERED);
}

// Every handler once: every screen, plus every port owner not already a screen.
static void broadcast(int notification, uint32_t param) {
	msg_handler_fn heard[APP_COUNT + BINDING_MAX];
	const int max = (int)(sizeof heard / sizeof heard[0]);
	int n = 0;
	for (int i = 0; i < APP_COUNT; i++)
		n = add_once(heard, n, max, app_table[i].main);
	n = add_port_owners(heard, n, max);
	for (int i = 0; i < n; i++)
		heard[i](notification, param);
}

// ---- the two ticks ---------------------------------------------------------

void kernel_slice(void) {
	drain_selections();
	uint64_t m;
	while (pop_notification(&m)) {
		uint16_t app_id = notification_app(m);
		if (app_id == APP_ALL) {
			broadcast(notification_id(m), notification_param(m));
			continue;
		}
		if (app_id >= APP_COUNT)
			continue;
		const struct app *app = &app_table[app_id];
		deliver(app->main, app->log_name, notification_id(m), notification_param(m));
	}
	apply_transition();    // after the drains, so a transition they request lands this slice
	// After the transition: the screen told it is visible has to be the one that
	// ended up on top.
	if (screen_wake_pending) {
		screen_wake_pending = false;
		notify_top(APP_FOREGROUND);
	}
	broadcast(APP_PUMP, now_ms());
}

void kernel_init(void) {
	// Before anything can be pushed, and before any module's APP_INIT.
	if (!screen_stack) {
		screen_stack = kernel_alloc((size_t)kernel_cfg->screen_stack * sizeof *screen_stack);
		if (!screen_stack) {
			hal_debug(LOG_CRITICAL, "kernel: no screen stack\n");
			return;
		}
		screen_depth = kernel_cfg->screen_stack;
	}
	if (!store_init())
		hal_debug(LOG_ERROR, "kernel_init: store_init failed\n");
	store_boot_unlock();   // the default passphrase, or upgrade a NOENC device in place
	block_read();
	store_begin_session(); // after block_read, or it persists an empty image; before any mount
	contacts_init();
	block_ready = 1;
	contact_lookup_init();
	call_init();
	cmdq_init(&cmdq_ui_to_fs);
	stream_init(kernel_cfg->stream_slots);
	msg_register();        // after stream_init: sizes its pool from stream_slot_count()
	broadcast(APP_INIT, 0);   // every handler has bound its port by now
	// After the store is unlocked: no private key, no handshake. netif keeps
	// the pointer, so a relay edit takes effect through netif_relogin().
	frame_init(&device_record, netif_frame_in, contact_resolve_addr,
	           contact_resolve_psk);
	// The relay's peer-to-peer forwarder never adds a cookie, so inbound msg1
	// must be accepted with mac2 = 0.
	wireguard_ask_mac2(false);
}

void kernel_pump(void) {
	// Pumps that originate traffic are gated on the radio: a packet pushed into
	// cyw43/lwIP during association wedged the device. frame_pump is not gated;
	// it advances timers, and a send that never left costs no retry.
	const int online = (wifi_get_status() == WIFI_ONLINE);
	netif_state st = frame_pump();
	if (st != s_last_netif_state) {
		if (st == NETIF_ONLINE) {        // a fresh login, never a rekey
			phone_state_set(PS_SIGNED_IN);
			msg_login_prod();
		}
		const char *state_name = "down";
		if (st == NETIF_ONLINE)
			state_name = "ONLINE";
		else if (st == NETIF_JOINING)
			state_name = "joining";
		hal_debug(LOG_WARNING, "netif: %s\n", state_name);
		s_last_netif_state = st;
	}
	if (online)
		contact_query_pump();
	call_pump();                         // not gated: a call must time out offline too
	if (online)
		stream_pump();

	cmdq_dispatch();
	block_pump();
}
