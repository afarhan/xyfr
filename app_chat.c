// app_chat.c - the chat app: a contact's conversation on screen. Three screens,
// each its own handler in the kernel's screen table: the thread (APP_CHAT,
// the message list and composer), the message menu (APP_MSG_MENU, one
// message's actions), and the full-text view (APP_MSG_VIEW).
//
// The message log is the model and the only source of truth. Every row rendered
// here is read from it on demand; nothing is duplicated into app state beyond a
// bounded window of record metadata. msg.c is the controller and appears in
// exactly three places: msg_post() and msg_attempt_delivery() going down,
// and NOTIFY_MSG_UPDATE coming back up - a posted partkey that says "re-read
// the model", carrying no data. This file holds no engine state and the engine
// holds no screen state.
//
// Screen flow: the thread pushes the menu over itself; "View full text"
// replaces the menu, so backing out of the full text lands on the thread.
// Popping the thread empties the stack and the kernel shows home.
//
// Core 0. Portable C (the host links stubs; there is no UI there).

#include <string.h>
#include <stdio.h>
#include <time.h>
#include "hal.h"
#include "kernel.h"        // APP_*, NOTIFY_MSG_UPDATE, screen_* transitions
#include "msg.h"           // msg_post / msg_attempt_delivery / msg_ensure_log
#include "contacts.h"
#include "device_record.h"       // MAX_NAME
#include "ui.h"            // TERMINAL_MSG_* row styles
#include "ui_symbols.h"
#include "config.h"
#include "view.h"

// ---- structs ---------------------------------------------------------------

// One wrapped line of the full-text view: where it starts in the payload and
// how many bytes of it are shown.
struct msgview_line {
	uint16_t start;    // payload byte offset
	uint16_t len;      // display bytes (the trailing break excluded)
	uint8_t  style;
};

#define CHAT_COMPOSE_MAX  1024  // what a user may TYPE; msg_post takes any size
#define CHAT_PREVIEW_LINES   3  // message-list preview: at most this many lines, then "..."
#define CHAT_PREVIEW_HEAD  512  // body bytes read for a preview (covers 3 lines of narrow glyphs)
#define MSGVIEW_MAX_LINES  500  // full-text view: resident line-table entries
#define MSGVIEW_LINE_BYTES 256  // max bytes read/shown for one proportional line

// ---- the open thread --------------------------------------------------------
// One thread on screen at a time, so its state is file-static. The window holds
// record metadata only (newest first, index 0 = newest); bodies are read from
// the log per row.
static uint32_t chat_partkey;
static char     chat_name[MAX_NAME];
static bool     chat_on_top;                 // the thread screen is displayed

static struct msg_record *chat_recs;      // chat_cap records, allocated on the first load
static int         chat_cap;
static int         chat_recs_n;
static uint32_t    chat_seen_epoch = 0xFFFFFFFF;   // != view_epoch -> reload the window

// The message the menu / full view is about, and where to put the selection
// back when the thread returns to the top.
static uint32_t sel_record;
static int      sel_index;          // signed thread index (0 = newest, negative = older)
static bool     reselect_pending;

// The peer's display label: the contact's name, or the bare partkey when the
// contact is nameless or gone.
static const char *peer_label(void) {
	static char uid_hex[9];
	if (chat_name[0])
		return chat_name;
	snprintf(uid_hex, sizeof uid_hex, "%08x", (unsigned)chat_partkey);
	return uid_hex;
}

// Rebuild the newest window when a view_invalidate has bumped the epoch: a
// cheap guard so a relayout's many LIST_GET_ITEM calls scan the log only once.
static void chat_reload_if_needed(void) {
	if (chat_seen_epoch == view_epoch)
		return;
	chat_seen_epoch = view_epoch;
	msg_ensure_log();      // mounts on volume_key alone, so history works offline
	if (!chat_recs) {
		chat_recs = kernel_alloc((size_t)kernel_cfg->chat_records * sizeof *chat_recs);
		if (!chat_recs) {
			chat_recs_n = 0;
			return;
		}
		chat_cap = kernel_cfg->chat_records;
	}
	chat_recs_n = msg_recent(chat_partkey, chat_recs, chat_cap);
	if (chat_recs_n < 0)
		chat_recs_n = 0;
}

// Map a signed index (0 = newest, negative = older) to a loaded record, paging
// older from the log on demand. NULL = no record there: the engine's edge.
static const struct msg_record *chat_at(int i) {
	if (i > 0)
		return NULL;
	chat_reload_if_needed();
	int k = -i;
	while (k >= chat_recs_n && chat_recs_n > 0 && chat_recs_n < chat_cap) {
		uint32_t before = chat_recs[chat_recs_n - 1].record_id;
		int got = msg_recent_before(chat_partkey, before,
		                            &chat_recs[chat_recs_n], chat_cap - chat_recs_n);
		if (got <= 0)
			break;
		chat_recs_n += got;
	}
	if (k >= 0 && k < chat_recs_n)
		return &chat_recs[k];
	return NULL;
}

// The first CHAT_PREVIEW_LINES lines of the body, wrapped in the proportional
// font (matches a full render), " ..." when longer. Reads a head, never the
// whole message.
static void chat_preview(const struct msg_record *m, char *out, int cap) {
	char body[CHAT_PREVIEW_HEAD + 1];
	// Ask for ONE more byte than can be shown: getting it is what "there is
	// more" means. Asking msg_read how long the message is would cost a second
	// read of the same flash, once per row, to learn what this read already says.
	int want = CHAT_PREVIEW_HEAD;
	int got  = msg_read(m->contact_id, m->record_id, 0, body, want + 1);
	if (got < 0)
		got = 0;
	bool more = (got > want);
	if (more)
		got = want;
	body[got] = 0;
	view_body_preview(body, more, CHAT_PREVIEW_LINES, out, cap);
}

// "dd Mon HH:MM" into out; "" if the timestamp does not convert.
static void format_timestamp(uint32_t timestamp, char *out, int cap) {
	out[0] = 0;
	time_t t = (time_t)timestamp;
	struct tm *tm = gmtime(&t);
	if (tm)
		strftime(out, cap, "%d %b %H:%M", tm);
}

// ---- the thread screen (APP_CHAT) ---------------------------------------

static int chat_view_cb(view_op_t op, int i, void *data) {
	switch (op) {
	case LIST_GET_ITEM: {
		const struct msg_record *r = chat_at(i);
		if (!r)
			return -1;
		view_item_t *it = (view_item_t *)data;
		static char preview[CHAT_PREVIEW_HEAD + 8];
		static char metabuf[80];              // borrowed by the engine until the next call
		chat_preview(r, preview, sizeof preview);
		it->text = preview;
		// Small grey meta line: sender + date + time, "sending" while undelivered.
		char ts[24];
		format_timestamp(r->timestamp, ts, sizeof ts);
		const char *who = peer_label();
		if (r->kind == ENTRY_MSG_OUT)
			who = "You";
		if (r->kind == ENTRY_MSG_OUT && !msg_is_delivered(*r))
			snprintf(metabuf, sizeof metabuf, "%s   %s   sending", who, ts);
		else
			snprintf(metabuf, sizeof metabuf, "%s   %s", who, ts);
		it->meta = metabuf;
		it->separator = false;          // colour + meta already separate messages
		if (r->kind == ENTRY_MSG_OUT)
			it->style = TERMINAL_MSG_OUT;
		else
			it->style = TERMINAL_MSG_IN;
		it->user = (void *)(uintptr_t)r->record_id;
		return 0;
	}
	case LIST_SELECTED:
		// Enter on a message: its action menu goes on top of us. The transition
		// is a queued request, so asking from inside the engine's dispatch is
		// safe: nothing repaints until kernel_slice applies it.
		sel_index  = i;
		sel_record = (uint32_t)(uintptr_t)data;
		reselect_pending = true;
		screen_push(APP_MSG_MENU, sel_record);
		return 0;
	case EDIT_ENTER: {
		// Go on the composer. The controller stores + sends; the repaint comes
		// back as NOTIFY_MSG_UPDATE like any other change to the model.
		const char *text = (const char *)data;
		bool has_content = false;
		for (const char *p = text; p && *p; p++) {
			if (*p != ' ' && *p != '\n' && *p != '\r') {
				has_content = true;
				break;
			}
		}
		if (!has_content)
			return 0;
		if (msg_post(chat_partkey, text) != 0)
			hal_debug(LOG_ERROR, "chat: send to %08x failed\n", (unsigned)chat_partkey);
		return 0;
	}
	default:
		return 0;
	}
}

// Build + show the thread view fresh from the log.
static void chat_render(void) {
	chat_seen_epoch = view_epoch - 1;   // force a window rebuild on first access
	chat_recs_n = 0;
	char title[MAX_NAME + 8];
	snprintf(title, sizeof title, LV_SYMBOL_LEFT " %s", peer_label());
	view_set(chat_view_cb, title, NULL, NULL, "Type a message", NULL);
	view_set_input_multiline(true);     // composer grows; Enter = newline, Go sends
	view_set_input_max(CHAT_COMPOSE_MAX);
	view_set_row_pad(2, 8);             // tight top (the meta line pads it), looser bottom
	// This view follows the newest message from birth. view_set cannot infer that
	// from an empty thread (no item at -1), and without it the engine lays the
	// first message out as a docked form until an event promotes the anchoring.
	view_follow_newest();
	view_invalidate();
}

int app_chat_main(int message, uint32_t param) {
	switch (message) {

	case APP_FOREGROUND: {
		if (param != chat_partkey) {
			chat_partkey = param;
			reselect_pending = false;
			sel_index = 0;
		}
		chat_name[0] = 0;
		{
			struct contact_record ct;
			bool have_contact = contact_get(&ct, chat_partkey);
			if (have_contact) {
				strncpy(chat_name, ct.name, sizeof chat_name - 1);
				chat_name[sizeof chat_name - 1] = 0;
			}
			// Retry what is pending, and do not open a link and sit on it.
			// Sending is what opens a link, so the session stays short-lived,
			// which is the contract for the anon socket: an anon session left
			// idle while the user types loses its NAT mapping, and the relay
			// then drops every frame on that session's endpoint pin. Nothing
			// pending means nothing opened.
			msg_attempt_delivery(chat_partkey);
			// The title eye reports this peer, not us.
			if (have_contact)
				screen_peer(ct.key);
		}
		// Looking at the thread is what clears its unread dot.
		if (msg_ensure_log())
			msg_mark_read(chat_partkey);
		chat_render();
		if (reselect_pending) {
			// Returning from the menu: land on the message it was about. If a
			// delete removed it, its old index now holds the next-older message;
			// if the oldest went, fall to the next-newer.
			reselect_pending = false;
			int landing = sel_index;
			if (!chat_at(landing))
				landing++;
			if (landing > 0)
				landing = 0;
			if (chat_at(landing))
				view_select(landing);
		}
		chat_on_top = true;
		return 1;
	}

	case APP_BACKGROUND:
		// Covered or destroyed, and the kernel knows which so we need not: state
		// stays for a return, and a destroy is followed by a fresh FOREGROUND.
		chat_on_top = false;
		return 1;

	case NOTIFY_MSG_UPDATE:
		if (!chat_on_top || param != chat_partkey)
			return 0;
		view_follow_newest();
		view_invalidate();
		return 1;

	default:
		return 0;
	}
}

// ---- the message menu (APP_MSG_MENU) ------------------------------------
// A static list over one record: view full text, retry (only where it means
// anything, on an undelivered outbound), delete. Matched by row text via the
// kernel's selection queue, like the call screen's buttons.

static const char *menu_items[5];
static int         menu_n;

// The static-list adapter: the engine hands back the row index for a static
// list (view.cpp:68), so resolve it against our own array and queue the text.
static int menu_bridge_cb(view_op_t op, int i, void *data) {
	(void)data;
	if (op != LIST_SELECTED)
		return 0;
	if (i < 0 || i >= menu_n)
		return 0;
	screen_selection(menu_items[i]);
	return 0;
}

int app_msg_menu_main(int message, uint32_t param) {
	switch (message) {

	case APP_FOREGROUND: {
		sel_record = param;
		menu_n = 0;
		menu_items[menu_n++] = LV_SYMBOL_FILE "  View full text";
		struct msg_record m;
		if (msg_ensure_log() && msg_get(chat_partkey, sel_record, &m) &&
		    m.kind == ENTRY_MSG_OUT && !msg_is_delivered(m))
			menu_items[menu_n++] = LV_SYMBOL_REFRESH "  Retry";
		menu_items[menu_n++] = LV_SYMBOL_TRASH "  Delete";
		menu_items[menu_n] = NULL;
		view_set(menu_bridge_cb, peer_label(), "Message", menu_items, NULL, NULL);
		return 1;
	}

	case APP_SELECTION: {
		const char *text = (const char *)(uintptr_t)param;
		if (strstr(text, "View full text")) {
			// Replace, not push: backing out of the full text lands on the thread.
			screen_replace(APP_MSG_VIEW, sel_record);
			return 1;
		}
		if (strstr(text, "Retry")) {
			// Re-query the endpoint and re-arm delivery. The user's call: a failed
			// delivery cannot tell "peer offline" from "peer moved relay".
			msg_attempt_delivery(chat_partkey);
			screen_pop();
			return 1;
		}
		if (strstr(text, "Delete")) {
			if (msg_ensure_log() && msg_delete_one(chat_partkey, sel_record)) {
				screen_invalidate();
				kernel_post(NOTIFY_MSG_UPDATE, chat_partkey);
			}
			screen_pop();
			return 1;
		}
		return 1;
	}

	default:
		return 0;
	}
}

// ---- the full-text view (APP_MSG_VIEW) ----------------------------------
// One message wrapped top-to-bottom. Scanned once into a line table (payload
// offset + display length per line); rendering walks the table and reads each
// line's bytes from the log, so the whole message is never resident. A message
// wrapping past MSGVIEW_MAX_LINES gets a sliding window instead.

static struct msgview_line msgview_lines[MSGVIEW_MAX_LINES];
static int      msgview_n;           // lines resident in the table
static int      msgview_base;        // global line index of msgview_lines[0]
static int      msgview_total;       // wrapped lines in all, table size aside
static uint16_t msgview_body_len;
static uint16_t msgview_body_at;     // where the body starts: past the fields
static bool     msgview_is_outbound; // direction, for the text colour

// Fill the table with up to MSGVIEW_MAX_LINES lines starting at global line
// `from`, wrapping proportionally over storage windows. A scan from 0 also
// counts msgview_total.
static void msgview_fill(int from) {
	if (from < 0)
		from = 0;
	msgview_base = from;
	msgview_n = 0;
	bool full = (from == 0);
	if (full)
		msgview_total = 0;

	if (msgview_body_len == 0) {              // empty body: one blank line
		msgview_lines[0].start = 0;
		msgview_lines[0].len   = 0;
		msgview_lines[0].style = 0;
		msgview_n = 1;
		if (full)
			msgview_total = 1;
		return;
	}

	uint32_t pos = 0;
	int line = 0;
	while (pos < msgview_body_len) {
		char win[MSGVIEW_LINE_BYTES];    // a proportional line is shorter than this
		uint32_t left = msgview_body_len - pos;
		uint16_t want = MSGVIEW_LINE_BYTES - 1;
		if (left < want)
			want = (uint16_t)left;
		int got = msg_read(chat_partkey, sel_record,
		                   msgview_body_at + pos, win, want);
		if (got < 0)
			got = 0;
		win[got] = 0;
		uint32_t display_len = 0;
		uint32_t advance = view_body_wrap_next(win, &display_len);
		if (advance == 0)
			break;
		if (line >= from && msgview_n < MSGVIEW_MAX_LINES) {
			msgview_lines[msgview_n].start = (uint16_t)pos;
			msgview_lines[msgview_n].len   = (uint16_t)display_len;
			msgview_lines[msgview_n].style = 0;
			msgview_n++;
		}
		pos += advance;
		line++;
		if (full)
			msgview_total = line;
		else if (msgview_n >= MSGVIEW_MAX_LINES)    // window filled (total already known)
			break;
	}
}

static int msg_view_cb(view_op_t op, int i, void *data) {
	switch (op) {
	case LIST_GET_ITEM: {
		if (i < 0 || i >= msgview_total)      // top-anchored: 0 = first line
			return -1;
		if (i < msgview_base || i >= msgview_base + msgview_n) {   // outside the window: slide it
			int from = 0;
			if (i > MSGVIEW_MAX_LINES / 2)
				from = i - MSGVIEW_MAX_LINES / 2;
			msgview_fill(from);
		}
		int k = i - msgview_base;
		view_item_t *it = (view_item_t *)data;
		static char linebuf[MSGVIEW_LINE_BYTES];
		int got = 0;
		if (k >= 0 && k < msgview_n && msgview_lines[k].len)
			got = msg_read(chat_partkey, sel_record,
			               msgview_body_at + msgview_lines[k].start, linebuf, msgview_lines[k].len);
		if (got < 0)
			got = 0;
		linebuf[got] = 0;
		it->text = linebuf;
		it->meta = NULL;
		it->separator = false;
		if (msgview_is_outbound)                      // match the thread colours
			it->style = TERMINAL_MSG_OUT;
		else
			it->style = TERMINAL_MSG_IN;
		it->user = NULL;
		return 0;
	}
	case LIST_SELECTED:                  // Enter on a line: done reading
		screen_pop();
		return 0;
	default:
		return 0;
	}
}

int app_msg_view_main(int message, uint32_t param) {
	switch (message) {

	case APP_FOREGROUND: {
		sel_record = param;
		struct msg_record m;
		if (!msg_ensure_log() || !msg_get(chat_partkey, sel_record, &m)) {
			screen_pop();
			return 1;
		}
		msgview_is_outbound = (m.kind == ENTRY_MSG_OUT);
		// The one screen that needs a total up front: it wraps the whole message
		// into a line table before painting any of it, so it cannot discover the
		// end by reading until short.
		msgview_body_at  = 0;
		msgview_body_len = 0;
		int total = msg_body_len(chat_partkey, sel_record);
		if (total > 0)
			msgview_body_len = (uint16_t)total;
		msgview_fill(0);                      // scan the whole message into the line table
		char ts[24];
		format_timestamp(m.timestamp, ts, sizeof ts);
		const char *who = peer_label();
		if (msgview_is_outbound)
			who = "You";
		char title[40];
		snprintf(title, sizeof title, LV_SYMBOL_LEFT " %s  %s", who, ts);
		view_set(msg_view_cb, title, NULL, NULL, NULL, NULL);
		view_set_row_pad(2, 2);          // tight line leading: each line is a row
		return 1;
	}

	default:
		return 0;
	}
}
