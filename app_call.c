// app_call.c - the call app: the voice-call state machine and its screen, in
// one file, behind one handler.
//
// Nothing is signalled. The first voice frame with a new call_id is the call:
// the callee rings on receiving it, answers locally, and a hangup sends
// nothing. The peer learns a call is over because its next voice frame draws
// VOICE_SUB_CALL_ENDED. So every voice frame carries a 16-bit call_id, and
// per peer we keep the highest id seen each way: an id within
// CALL_ID_STALE_WINDOW below the high-water is a straggler from a finished
// call and is answered CALL_ENDED; anything else is a new call. The ids start
// random per peer, so ours are unguessable.
//
// Phases: OUTGOING (we called, media flows so the callee rings) -> ACTIVE on
// the first frame back. INCOMING (they called; we ring locally and send
// ringback) -> ACTIVE on answer. Either -> ENDED, which lingers on screen for
// call_ended_linger_ms and then frees the slot. OUTGOING and INCOMING time out
// after call_ring_timeout_ms; ACTIVE ends after call_voice_timeout_ms with no
// inbound frame, which works because a sender never suppresses voice - a muted
// mic transmits silence.
//
// The hardware has one owner: the first call whose media flows. Voice is
// contacts-only (admit_media), refused before a slot is taken, and the refusal
// is a CALL_ENDED so it looks like busy.
//
// The screen shows one call, matches its rows by text, and is told of phase
// changes by NOTIFY_CALL_*; it polls nothing. Pushing the screen for a peer
// with no call originates one. Backing out leaves the call live.
//
// Peers are remote_userids: the kernel carries frames both ways and netif
// decides how they travel. Core 0.

#include <string.h>
#include <stdio.h>
#include "hal.h"
#include "audio.h"
#include "config.h"
#include "kernel.h"
#include "policy.h"
#include "peer_data.h"
#include "call.h"
#include "ui.h"
#include "ui_symbols.h"
#include "view.h"
#include "device_record.h"
#include "contacts.h"

#define PEER_ID_SLOTS       8
#define VOICE_FRAME_SAMPLES 320   // 40 ms of 8 kHz mono
#define VOICE_FRAME_MS      40
#define IGNORED_HISTORY     4

// ---- structs ---------------------------------------------------------------

// In use iff phase != CALL_FREE. The handle is index + 1.
struct call {
	enum call_phase phase;
	uint32_t remote_userid;
	uint16_t call_id;
	uint32_t phase_started_ms;   // ring timeout, ENDED linger, ringback cadence
	uint32_t last_rx_ms;         // last inbound media
};

// The call_id high-waters per peer. They outlive any one call because their
// job is to judge the next one.
struct peer_call_ids {
	uint32_t remote_userid;      // 0 = free
	uint16_t last_originated;
	uint16_t last_received;
	uint32_t touched_ms;
};

uint32_t call_voice_timeout_ms = 5000;
uint32_t call_ring_timeout_ms  = 30000;
uint32_t call_ended_linger_ms  = 3000;

static struct call         *calls;           // call_slots entries, from call_init
static int                  call_slots;
static struct peer_call_ids peer_ids[PEER_ID_SLOTS];
static bool                 s_audio_open;

// The screen.
static call_handle     screen_call;          // 0 = not on screen
static enum call_phase screen_phase;
static uint32_t        ended_at_ms;
static int             redraw_row = -1;      // repaint requested from a key handler; done in APP_PUMP
static const char     *call_items[6];        // borrowed by the view engine for the life of the view
static char            call_status[96];
static char            mute_item[24];
static call_handle     ignored_calls[IGNORED_HISTORY];   // by handle: dismissing one ring must not silence the next
static uint8_t         ignored_pos;

int  app_call_main(int message, uint32_t param);
void app_ptt_inbound(uint32_t remote_userid, const uint8_t *pcm, int len);   // app_ptt.c

void call_init(void) {
	if (!calls) {
		calls = kernel_alloc((size_t)kernel_cfg->call_slots * sizeof *calls);
		if (!calls) {
			hal_debug(LOG_CRITICAL, "call: no call slots — no call can be placed\n");
			return;
		}
		call_slots = kernel_cfg->call_slots;
	}
	memset(calls, 0, (size_t)call_slots * sizeof *calls);
	memset(peer_ids, 0, sizeof peer_ids);
	if (!kernel_listen_datagram(PORT_VOICE, app_call_main))
		hal_debug(LOG_ERROR, "call: PORT_VOICE already bound - no inbound voice\n");
}

// ---- slots and handles -----------------------------------------------------

static struct call *call_at(call_handle handle) {
	if (handle == 0 || handle > call_slots)
		return NULL;
	struct call *c = &calls[handle - 1];
	if (c->phase == CALL_FREE)
		return NULL;
	return c;
}

static call_handle handle_of(const struct call *c) {
	return (call_handle)((c - calls) + 1);
}

static struct call *call_for_peer(uint32_t remote_userid) {
	for (int i = 0; i < call_slots; i++) {
		if (calls[i].phase != CALL_FREE && calls[i].remote_userid == remote_userid)
			return &calls[i];
	}
	return NULL;
}

static struct call *call_alloc(uint32_t remote_userid) {
	for (int i = 0; i < call_slots; i++) {
		if (calls[i].phase != CALL_FREE)
			continue;
		struct call *c = &calls[i];
		memset(c, 0, sizeof *c);
		c->remote_userid = remote_userid;
		return c;
	}
	return NULL;
}

// ---- the peer's call_id high-waters ----------------------------------------

static struct peer_call_ids *peer_ids_for(uint32_t remote_userid) {
	struct peer_call_ids *oldest = &peer_ids[0];
	for (int i = 0; i < PEER_ID_SLOTS; i++) {
		if (peer_ids[i].remote_userid == remote_userid) {
			peer_ids[i].touched_ms = now_ms();
			return &peer_ids[i];
		}
		if (peer_ids[i].remote_userid == 0)
			oldest = &peer_ids[i];
		else if (oldest->remote_userid != 0
		         && (int32_t)(peer_ids[i].touched_ms - oldest->touched_ms) < 0)
			oldest = &peer_ids[i];
	}
	oldest->remote_userid    = remote_userid;
	oldest->last_originated  = (uint16_t)hal_rand();
	oldest->last_received    = (uint16_t)hal_rand();
	oldest->touched_ms       = now_ms();
	return oldest;
}

static bool call_id_is_stale(uint16_t id, uint16_t high_water, int16_t *out_diff) {
	int16_t diff = (int16_t)(id - high_water);
	if (out_diff)
		*out_diff = diff;
	return diff <= 0 && diff >= -CALL_ID_STALE_WINDOW;
}

// ---- audio -----------------------------------------------------------------

static bool call_media_flows(const struct call *c) {
	return c->phase == CALL_PHASE_OUTGOING || c->phase == CALL_PHASE_ACTIVE;
}

static struct call *audio_owner(void) {
	for (int i = 0; i < call_slots; i++) {
		if (calls[i].phase != CALL_FREE && call_media_flows(&calls[i]))
			return &calls[i];
	}
	return NULL;
}

static void audio_follow_owner(void) {
	bool want = audio_owner() != NULL;
	if (want == s_audio_open)
		return;
	s_audio_open = want;
	if (want)
		audio_open();
	else
		audio_close();    // flush, so the hangup tail does not click
}

static void call_to_ended(struct call *c, const char *why) {
	if (c->phase == CALL_PHASE_ENDED)
		return;
	hal_debug(LOG_EVERYTHING, "call: %08x ended in phase %d - %s\n",
	          (unsigned)c->remote_userid, (int)c->phase, why);
	uint32_t peer = c->remote_userid;
	c->phase            = CALL_PHASE_ENDED;
	c->phase_started_ms = now_ms();
	audio_follow_owner();
	if (peer) {
		app_call_main(NOTIFY_CALL_ENDED, peer);
		screen_invalidate();      // home clears "Return to call" or shows a missed call
	}
}

// ---- what the user does ----------------------------------------------------

call_handle call_originate(uint32_t remote_userid) {
	if (call_for_peer(remote_userid))
		return 0;
	struct call *c = call_alloc(remote_userid);
	if (!c)
		return 0;

	struct peer_call_ids *ids = peer_ids_for(remote_userid);
	ids->last_originated = (uint16_t)(ids->last_originated + 1);

	c->phase            = CALL_PHASE_OUTGOING;
	c->call_id          = ids->last_originated;
	c->phase_started_ms = now_ms();
	c->last_rx_ms       = now_ms();
	audio_follow_owner();
	hal_debug(LOG_EVERYTHING, "call: originating to %08x call_id=%04x\n",
	          (unsigned)remote_userid, (unsigned)c->call_id);
	return handle_of(c);
}

bool call_answer(call_handle handle) {
	struct call *c = call_at(handle);
	if (!c || c->phase != CALL_PHASE_INCOMING)
		return false;
	c->phase            = CALL_PHASE_ACTIVE;
	c->phase_started_ms = now_ms();
	c->last_rx_ms       = now_ms();
	audio_follow_owner();
	hal_debug(LOG_EVERYTHING, "call: answered %08x call_id=%04x\n",
	          (unsigned)c->remote_userid, (unsigned)c->call_id);
	app_call_main(NOTIFY_CALL_ACTIVE, c->remote_userid);
	return true;
}

bool call_hangup(call_handle handle) {
	struct call *c = call_at(handle);
	if (!c)
		return false;
	hal_debug(LOG_EVERYTHING, "call: hangup %08x call_id=%04x\n",
	          (unsigned)c->remote_userid, (unsigned)c->call_id);
	call_to_ended(c, "the user hung up");
	return true;
}

// ---- what the UI asks ------------------------------------------------------

enum call_phase call_phase_of(call_handle handle) {
	struct call *c = call_at(handle);
	if (!c)
		return CALL_FREE;
	return c->phase;
}

call_handle call_of_peer(uint32_t remote_userid) {
	struct call *c = call_for_peer(remote_userid);
	if (!c)
		return 0;
	return handle_of(c);
}

call_handle call_holding_audio(void) {
	struct call *c = audio_owner();
	if (!c)
		return 0;
	return handle_of(c);
}

call_handle call_ringing(void) {
	for (int i = 0; i < call_slots; i++) {
		if (calls[i].phase == CALL_PHASE_INCOMING)
			return handle_of(&calls[i]);
	}
	return 0;
}

uint32_t call_peer_of(call_handle handle) {
	struct call *c = call_at(handle);
	if (!c)
		return 0;
	return c->remote_userid;
}

// ---- transmit and receive --------------------------------------------------

// [call_id:2][subtype:2][media]; kernel.c prepends the common header.
static void send_voice(uint32_t remote_userid, uint16_t call_id, uint16_t subtype,
                       const int16_t *media, int media_bytes) {
	uint8_t frame[VOICE_HEADER_LEN + VOICE_FRAME_SAMPLES * sizeof(int16_t)];
	uint16_t id_be  = be16(call_id);
	uint16_t sub_be = be16(subtype);
	memcpy(frame,     &id_be,  2);
	memcpy(frame + 2, &sub_be, 2);
	if (media_bytes > 0)
		memcpy(frame + VOICE_HEADER_LEN, media, (size_t)media_bytes);
	kernel_send_frame(remote_userid, PORT_VOICE, frame, VOICE_HEADER_LEN + media_bytes);
}

static void send_call_ended(uint32_t remote_userid, uint16_t call_id) {
	send_voice(remote_userid, call_id, VOICE_SUB_CALL_ENDED, NULL, 0);
}

static void send_media(struct call *c, const int16_t *frame) {
	send_voice(c->remote_userid, c->call_id, VOICE_SUB_MEDIA,
	           frame, VOICE_FRAME_SAMPLES * (int)sizeof(int16_t));
}

static void voice_media_in(uint32_t remote_userid, uint16_t call_id,
                           const uint8_t *payload, int len) {
	struct peer_call_ids *ids = peer_ids_for(remote_userid);
	struct call *c = call_for_peer(remote_userid);

	if (c && c->phase != CALL_PHASE_ENDED && call_id == c->call_id) {
		c->last_rx_ms = now_ms();
		if (c->phase == CALL_PHASE_OUTGOING) {      // the first frame back is the answer
			c->phase = CALL_PHASE_ACTIVE;
			if ((int16_t)(call_id - ids->last_received) > 0)
				ids->last_received = call_id;
			audio_follow_owner();
			hal_debug(LOG_EVERYTHING, "call: %08x answered (OUTGOING -> ACTIVE)\n",
			          (unsigned)remote_userid);
			app_call_main(NOTIFY_CALL_ACTIVE, remote_userid);
		}
		if (call_media_flows(c))
			audio_play_voice(payload, len);
		return;
	}

	int16_t diff;
	if (call_id_is_stale(call_id, ids->last_received, &diff)) {
		send_call_ended(remote_userid, call_id);
		return;
	}

	// A new call_id.
	if (admit_media(remote_userid) == ADMIT_REJECT) {
		hal_debug(LOG_WARNING, "call: %08x not admitted - voice refused\n",
		          (unsigned)remote_userid);
		if (diff > 0)
			ids->last_received = call_id;   // its retries are then stragglers, not new calls
		send_call_ended(remote_userid, call_id);
		return;
	}
	if (c) {                                // one call per peer, ENDED included
		send_call_ended(remote_userid, call_id);
		return;
	}
	struct call *nc = call_alloc(remote_userid);
	if (!nc) {
		hal_debug(LOG_ERROR, "call: pool full - refusing %08x\n", (unsigned)remote_userid);
		send_call_ended(remote_userid, call_id);
		return;
	}

	nc->phase            = CALL_PHASE_INCOMING;
	nc->call_id          = call_id;
	nc->phase_started_ms = now_ms();
	nc->last_rx_ms       = now_ms();
	if (diff > 0)
		ids->last_received = call_id;
	hal_debug(LOG_EVERYTHING, "call: incoming from %08x call_id=%04x\n",
	          (unsigned)remote_userid, (unsigned)call_id);
	app_call_main(NOTIFY_CALL_INCOMING, remote_userid);
	screen_invalidate();
}

void call_frame_in(uint32_t remote_userid, const uint8_t *body, int len) {
	if (len < VOICE_HEADER_LEN)
		return;
	uint16_t call_id, subtype;
	memcpy(&call_id, body,     2);
	memcpy(&subtype, body + 2, 2);
	call_id = be16(call_id);
	subtype = be16(subtype);

	switch (subtype & VOICE_SUB_KIND_MASK) {
	case VOICE_SUB_MEDIA:
		voice_media_in(remote_userid, call_id, body + VOICE_HEADER_LEN,
		               len - VOICE_HEADER_LEN);
		break;
	case VOICE_SUB_CALL_ENDED: {
		struct call *c = call_for_peer(remote_userid);
		if (c && c->call_id == call_id)
			call_to_ended(c, "the peer sent CALL_ENDED");
		break;
	}
	case VOICE_SUB_PTT:
		app_ptt_inbound(remote_userid, body + VOICE_HEADER_LEN,
		                len - VOICE_HEADER_LEN);
		break;
	default:
		break;                        // a kind we do not know is not media
	}
}

// ---- the pump --------------------------------------------------------------

static bool ring_is_audible(const struct call *c) {
	return admit_media(c->remote_userid) == ADMIT_RING;   // re-asked every tick, so presence applies at once
}

void call_pump(void) {
	uint32_t now = now_ms();

	for (int i = 0; i < call_slots; i++) {
		struct call *c = &calls[i];
		switch (c->phase) {
		case CALL_FREE:
			break;
		case CALL_PHASE_ENDED:
			if ((now - c->phase_started_ms) > call_ended_linger_ms) {
				c->phase = CALL_FREE;
				audio_follow_owner();
			}
			break;
		case CALL_PHASE_OUTGOING:
		case CALL_PHASE_INCOMING:
			if ((now - c->phase_started_ms) > call_ring_timeout_ms)
				call_to_ended(c, "ring timeout, never answered");
			break;
		case CALL_PHASE_ACTIVE:
			if ((now - c->last_rx_ms) > call_voice_timeout_ms)
				call_to_ended(c, "no inbound voice, the peer is gone");
			break;
		}
	}

	// Ringback to every caller on one frame boundary; each call's tone position
	// comes from its own phase_started_ms.
	static uint32_t ringback_due_ms;
	bool send_ringback = (int32_t)(now - ringback_due_ms) >= 0;
	if (send_ringback)
		ringback_due_ms = now + VOICE_FRAME_MS;
	bool ring_locally = false;
	for (int i = 0; i < call_slots; i++) {
		struct call *c = &calls[i];
		if (c->phase != CALL_PHASE_INCOMING)
			continue;
		if (ring_is_audible(c))
			ring_locally = true;
		if (!send_ringback)
			continue;
		int16_t frame[VOICE_FRAME_SAMPLES];
		uint16_t cadence = (uint16_t)((now - c->phase_started_ms) / VOICE_FRAME_MS);
		audio_ringback_frame(frame, VOICE_FRAME_SAMPLES, &cadence);
		send_media(c, frame);
	}
	if (ring_locally)
		audio_ring_start();
	else
		audio_ring_stop();

	struct call *owner = audio_owner();
	if (owner) {
		while (audio_capture_ready() >= VOICE_FRAME_SAMPLES) {
			int16_t frame[VOICE_FRAME_SAMPLES];
			audio_capture_voice(frame, VOICE_FRAME_SAMPLES);
			send_media(owner, frame);
		}
	}
}

// ---- the screen ------------------------------------------------------------

static bool was_ignored(call_handle call) {
	for (int i = 0; i < IGNORED_HISTORY; i++) {
		if (ignored_calls[i] == call)
			return true;
	}
	return false;
}

static const char *peer_name(uint32_t partkey) {
	static char name[MAX_NAME];
	struct contact_record c;
	name[0] = 0;
	if (contact_get(&c, partkey))
		snprintf(name, sizeof name, "%s", c.name);
	return name;
}

static const char *phase_label(enum call_phase p) {
	switch (p) {
	case CALL_PHASE_OUTGOING: return "Ringing";
	case CALL_PHASE_INCOMING: return "Incoming";
	case CALL_PHASE_ACTIVE:   return "Connected";
	case CALL_PHASE_ENDED:    return "Call Ended";
	default:                  return "";
	}
}

// A static list: the engine serves the rows itself and hands back the index.
static int call_view_cb(view_op_t op, int item_index, void *data) {
	(void)item_index;
	if (op == LIST_BACK) {
		screen_pop();                     // leaving does not end the call
		return 0;
	}
	if (op != LIST_SELECTED)
		return 0;
	int idx = (int)(intptr_t)data;
	if (idx < 0 || idx >= (int)(sizeof call_items / sizeof call_items[0]))
		return 0;
	if (call_items[idx])
		screen_selection(call_items[idx]);
	return 0;
}

static void render_call_screen(enum call_phase p, uint32_t partkey) {
	const char *name = peer_name(partkey);
	if (p == CALL_PHASE_ACTIVE) {
		const char *muted = "";
		if (mic_muted)
			muted = "   MUTED";
		if (name[0])
			snprintf(call_status, sizeof call_status,
			         "Talking to %s\nVolume: %d (use + and - keys)%s",
			         name, speaker_level, muted);
		else
			snprintf(call_status, sizeof call_status,
			         "Talking to %08X\nVolume: %d (use + and - keys)%s",
			         (unsigned)partkey, speaker_level, muted);
	}
	else if (name[0])
		snprintf(call_status, sizeof call_status, " %s  %08X\n%s",
		         name, (unsigned)partkey, phase_label(p));
	else
		snprintf(call_status, sizeof call_status, "%08X\n%s",
		         (unsigned)partkey, phase_label(p));

	int n = 0;
	switch (p) {
	case CALL_PHASE_INCOMING:
		call_items[n++] = LV_SYMBOL_OK    "  Answer";
		call_items[n++] = LV_SYMBOL_CLOSE "  Refuse";
		call_items[n++] = LV_SYMBOL_LEFT  "  Ignore";
		break;
	case CALL_PHASE_OUTGOING:
		call_items[n++] = LV_SYMBOL_CLOSE "  Hangup";
		break;
	case CALL_PHASE_ACTIVE: {
		call_items[n++] = LV_SYMBOL_CLOSE "  Hangup";
		const char *mute_state = "Off";
		if (mic_muted)
			mute_state = "On";
		snprintf(mute_item, sizeof mute_item, LV_SYMBOL_MUTE "  Mute: %s", mute_state);
		call_items[n++] = mute_item;
		break;
	}
	default:
		break;                       // ENDED: the status line only
	}
	call_items[n] = NULL;            // never NULL items: the engine would treat the view as dynamic
	screen_phase = p;
	view_set(call_view_cb, "Call", call_status, call_items, NULL, NULL);
}

static void screen_leaving(void) {
	// The volume is saved here, not per keypress, so no flash write lands mid-call.
	if (device_record.volume_notch != (uint8_t)(speaker_level + 1)) {
		device_record.volume_notch = (uint8_t)(speaker_level + 1);
		flag_save_block = 1;
	}
	screen_call  = 0;
	screen_phase = CALL_FREE;
	ended_at_ms  = 0;
	redraw_row   = -1;
}

static void on_call_row_selected(const char *text) {
	if (strstr(text, "Answer")) {
		call_answer(screen_call);
		return;
	}
	if (strstr(text, "Hangup") || strstr(text, "Refuse")) {
		call_hangup(screen_call);
		return;
	}
	if (strstr(text, "Ignore")) {        // nothing is sent; the ring ages out
		ignored_calls[ignored_pos] = screen_call;
		ignored_pos = (uint8_t)((ignored_pos + 1) % IGNORED_HISTORY);
		screen_pop();
		return;
	}
	if (strstr(text, "Mute")) {
		mic_muted = !mic_muted;
		redraw_row = view_selected();
	}
}

int app_call_main(int message, uint32_t param) {
	switch (message) {

	case NOTIFY_DATAGRAM: {
		int len = 0;
		const uint8_t *body = kernel_datagram_body(&len);
		if (!body)
			return 0;
		call_frame_in(param, body, len);
		return 1;
	}

	case NOTIFY_CALL_INCOMING: {
		if (screen_call)                  // one screen: a second caller waits
			return 1;
		call_handle c = call_of_peer(param);
		if (!c || was_ignored(c))
			return 1;
		if (ui_locked)                    // still rings, answerable once unlocked
			return 1;
		display_kick();
		screen_push(APP_CALL, param);
		return 1;
	}

	case NOTIFY_CALL_ACTIVE:
	case NOTIFY_CALL_ENDED:
		if (!screen_call || call_peer_of(screen_call) != param)
			return 1;
		if (message == NOTIFY_CALL_ENDED)
			ended_at_ms = now_ms();
		render_call_screen(call_phase_of(screen_call), param);
		return 1;

	case APP_FOREGROUND:
		screen_call = call_of_peer(param);
		if (!screen_call) {
			screen_call = call_originate(param);
			if (!screen_call) {
				screen_pop();
				return 1;
			}
		}
		ended_at_ms = 0;
		redraw_row  = -1;
		render_call_screen(call_phase_of(screen_call), param);
		return 1;

	case APP_BACKGROUND:
		screen_leaving();
		return 1;

	case APP_SELECTION:
		if (screen_call)
			on_call_row_selected((const char *)(uintptr_t)param);
		return 1;

	case APP_KEYSTROKE:
		if (!screen_call)
			return 0;
		if (ui_volume_key((int)param)) {
			redraw_row = view_selected();
			return 1;
		}
		return 0;

	case APP_PUMP:
		if (!screen_call)
			return 0;
		if (call_phase_of(screen_call) != CALL_FREE)
			display_kick();
		if (redraw_row >= 0) {
			int row = redraw_row;
			redraw_row = -1;
			render_call_screen(call_phase_of(screen_call), call_peer_of(screen_call));
			view_select(row);
		}
		if (ended_at_ms && (uint32_t)(now_ms() - ended_at_ms) >= call_ended_linger_ms)
			screen_pop();
		return 1;
	}
	return 0;
}
