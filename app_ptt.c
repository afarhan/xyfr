// app_ptt.c - the push-to-talk app. Half-duplex voice with no call: a frame
// that arrives plays at once, and transmitting is holding the space key on
// this screen.
//
// PTT rides PORT_VOICE as subtype VOICE_SUB_PTT with call_id 0. app_call.c
// owns the port and hands the subtype here (app_ptt_inbound); that is the
// only coupling. Frames are the same 320-sample PCM as a call.
//
// Receive: admit_media, then the contact's CONTACT_ALLOW_PTT bit. Opening this
// screen for a contact sets that bit, since choosing to talk to someone is
// choosing to hear them back. A refused frame is dropped with no reply. A
// frame is not played while we transmit or while a call owns the speaker.
// With no screen open, the amp is opened on the first admitted frame and
// closed PTT_RX_HOLD_MS after the last; with the screen open it is on for the
// whole visit.
//
// Every admitted voice frame is answered with a zero-payload PTT frame. That
// return is how a talker knows it is heard: any PTT frame from the screen's
// peer stamps ptt_last_returned_ms. Transmitting into silence for
// ptt_ack_timeout_ms puts "Peer not answering" on screen, stops the mic, and
// drops and reopens the netif link, since a peer that lost our session drops
// our frames without a reply. The stamp is reset on the key press, not held
// over from opening the screen.
//
// The last contact transmitted to is the tuned peer; its route is refreshed
// every pump, whether or not the screen is up, so the next press is quick.
//
// The screen is direct-draw below the title bar: a view with no list. It
// paints from APP_PUMP, never from FOREGROUND, because the engine clears the
// panel on the tick after view_set and would wipe it.
//
// Core 0. Portable C.

#include <string.h>
#include <stdio.h>
#include "hal.h"
#include "kernel.h"
#include "peer_data.h"
#include "device_record.h"
#include "contacts.h"
#include "policy.h"
#include "audio.h"
#include "call.h"
#include "ui.h"
#include "ui_symbols.h"
#include "view.h"
#include "display_backend.h"
#include "netif.h"

#define VOICE_FRAME_SAMPLES 320    // 40 ms of 8 kHz mono, as app_call.c
#define PTT_RX_HOLD_MS      1500   // headless: amp stays open this long past the last frame
#define PTT_DROP_LOG_MS     1000   // a refused sender arrives at 25 fps; log at most this often
#define PTT_COUNTS_PAINT_MS 500

#define PTT_TOP_Y     UI_TITLE_H
#define PTT_BAND_H    20
#define PTT_COUNTS_Y  (panel_height() - 44)
#define PTT_DIM_GREY  180
#define PTT_WHITE     255

enum ptt_ui_state {
	PTT_UI_UNPAINTED = -1,
	PTT_UI_CONNECTING = 0,
	PTT_UI_READY,
	PTT_UI_TALKING,
};

uint32_t ptt_max_tx_ms      = 60000;  // stuck-key backstop
uint32_t ptt_ack_timeout_ms = 5000;

static uint32_t ptt_screen_peer;      // the screen's contact; 0 = screen not open
static uint32_t ptt_tuned_peer;       // the last contact transmitted to
static uint8_t  ptt_tuned_key[KEY_LEN];
static bool     ptt_talking;
static uint32_t ptt_tx_since_ms;
static uint32_t ptt_rx_log_ms;
static uint32_t ptt_tx_frames;        // counters on screen; reset when it opens
static uint32_t ptt_rx_frames;
static bool     ptt_rx_active;        // headless: the amp is open for receive
static uint32_t ptt_rx_last_ms;
static uint32_t ptt_last_returned_ms; // last PTT frame of any kind from the screen's peer
static bool     ptt_peer_silent;      // the warning is due
static bool     ptt_silent_painted;   // the warning is on the panel
static int      ptt_ui_painted = PTT_UI_UNPAINTED;

// ---- transmit ---------------------------------------------------------------

static void ptt_send_frame_to(uint32_t userid, const int16_t *media, int media_bytes) {
	uint8_t frame[VOICE_HEADER_LEN + VOICE_FRAME_SAMPLES * sizeof(int16_t)];
	uint16_t id_be  = be16(0);
	uint16_t sub_be = be16(VOICE_SUB_PTT);
	memcpy(frame,     &id_be,  2);
	memcpy(frame + 2, &sub_be, 2);
	if (media_bytes > 0)
		memcpy(frame + VOICE_HEADER_LEN, media, (size_t)media_bytes);
	bool sent = kernel_send_frame(userid, PORT_VOICE, frame,
	                              VOICE_HEADER_LEN + media_bytes);
	if (sent && media_bytes > 0)      // the counter is voice only, not the returns
		ptt_tx_frames++;
}

static void ptt_send_frame(const int16_t *media, int media_bytes) {
	ptt_send_frame_to(ptt_screen_peer, media, media_bytes);
}

static void ptt_tx_stop(void) {
	ptt_talking = false;
}

static void ptt_tx_start(void) {
	if (ptt_talking)
		return;
	if (call_holding_audio()) {
		hal_debug(LOG_WARNING, "ptt: refused to talk, a call holds the audio\n");
		return;
	}
	ptt_talking = true;
	ptt_tx_since_ms = now_ms();
	struct contact_record c;
	if (contact_get(&c, ptt_screen_peer)) {
		ptt_tuned_peer = ptt_screen_peer;
		memcpy(ptt_tuned_key, c.key, sizeof ptt_tuned_key);
	}
}

// ---- the screen -------------------------------------------------------------

static void ptt_paint_counts(void) {
	int w = panel_width();
	panel_canvas_begin(0, PTT_COUNTS_Y, w, PTT_BAND_H);
	panel_fill(0, PTT_COUNTS_Y, w, PTT_BAND_H, false);
	static char counts[40];
	snprintf(counts, sizeof counts, "out %u   in %u",
	         (unsigned)ptt_tx_frames, (unsigned)ptt_rx_frames);
	panel_text_color(PTT_DIM_GREY);
	panel_text_center(PTT_COUNTS_Y + 2, 2, counts);
	panel_text_color(PTT_WHITE);
	panel_canvas_end();
}

static void ptt_paint_warning(bool on) {
	int w = panel_width();
	int y = panel_height() / 2 + 44;
	panel_canvas_begin(0, y, w, PTT_BAND_H);
	panel_fill(0, y, w, PTT_BAND_H, false);
	if (on)
		panel_text_center(y + 2, 2, "Peer not answering");
	panel_canvas_end();
	ptt_silent_painted = on;
}

static void ptt_paint(int state) {
	panel_fill(0, PTT_TOP_Y, panel_width(), panel_height() - PTT_TOP_Y, false);
	ptt_silent_painted = false;
	struct contact_record c;
	static char name[MAX_NAME];
	if (contact_get(&c, ptt_screen_peer) && c.name[0])
		snprintf(name, sizeof name, "%s", c.name);
	else
		snprintf(name, sizeof name, "%08X", (unsigned)ptt_screen_peer);
	const char *status = "Connecting...";
	const char *hint   = "";
	if (state == PTT_UI_READY) {
		status = "Connected";
		hint   = "Hold SPACE to talk";
	} else if (state == PTT_UI_TALKING) {
		status = "TRANSMITTING";
		hint   = "Release SPACE to stop";
	}
	int mid = panel_height() / 2;
	panel_text_center(30, 3, name);
	panel_text_center(mid - 16, 3, status);
	panel_text_color(PTT_DIM_GREY);
	panel_text_center(mid + 20, 2, hint);
	panel_text_center(panel_height() - 22, 2, "Backspace to exit");
	panel_text_color(PTT_WHITE);
	panel_present();
	ptt_ui_painted = state;
	ptt_paint_counts();
}

int app_ptt_main(int message, uint32_t param) {
	switch (message) {

	case APP_FOREGROUND:
		ptt_screen_peer = param;
		ptt_ui_painted = PTT_UI_UNPAINTED;
		ptt_tx_frames = 0;
		ptt_rx_frames = 0;
		view_set(NULL, NULL, NULL, NULL, NULL, NULL);
		screen_title("PTT");
		{
			struct contact_record c;
			if (contact_get(&c, ptt_screen_peer)) {
				if (!(c.settings & CONTACT_ALLOW_PTT)) {   // before audio_open: no flash write with the amp live
					c.settings |= CONTACT_ALLOW_PTT;
					contact_save(&c);
				}
				netif_open_route(c.key);
				screen_peer(c.key);
			}
		}
		audio_open();
		ptt_last_returned_ms = now_ms();
		ptt_peer_silent      = false;
		return 1;

	case APP_BACKGROUND:
		ptt_tx_stop();
		audio_close();
		ptt_screen_peer = 0;
		return 1;

	case APP_KEYSTROKE:
		if ((int)param == ' ')
			return 1;
		if ((int)param == VIEW_K_BACKSPACE) {
			screen_pop();
			return 1;
		}
		if (ui_volume_key((int)param)) {
			ptt_ui_painted = PTT_UI_UNPAINTED;
			return 1;
		}
		return 0;

	case APP_PUMP: {
		if (ptt_tuned_peer)
			netif_refresh_route(ptt_tuned_key);
		if (!ptt_screen_peer && ptt_rx_active &&
		    (uint32_t)(now_ms() - ptt_rx_last_ms) >= PTT_RX_HOLD_MS) {
			ptt_rx_active = false;
			audio_close();
		}
		if (!ptt_screen_peer)
			return 0;
		bool link_up = netif_route_alive(ptt_screen_peer);
		bool space_down = keyboard_space_held();
		bool want_tx = link_up && space_down;
		static bool space_was_down;
		if (space_down && !space_was_down)
			ptt_last_returned_ms = now_ms();
		space_was_down = space_down;
		if (space_down) {
			uint32_t silence_now = now_ms();
			if ((uint32_t)(silence_now - ptt_last_returned_ms) >= ptt_ack_timeout_ms) {
				ptt_peer_silent = true;
				want_tx = false;
				ptt_tx_stop();
				struct contact_record c;
				if (contact_get(&c, ptt_screen_peer)) {
					netif_drop_route(c.key);
					netif_open_route(c.key);
				}
				ptt_last_returned_ms = silence_now;   // paces the retries
			}
		}
		if (want_tx && !ptt_talking)
			ptt_tx_start();
		if (!want_tx && ptt_talking)
			ptt_tx_stop();
		if (ptt_talking &&
		    (uint32_t)(now_ms() - ptt_tx_since_ms) >= ptt_max_tx_ms) {
			hal_debug(LOG_WARNING, "ptt: max transmit time reached, stopping\n");
			ptt_tx_stop();
		}
		if (ptt_talking) {
			while (audio_capture_ready() >= VOICE_FRAME_SAMPLES) {
				int16_t pcm[VOICE_FRAME_SAMPLES];
				int got = audio_capture_voice(pcm, VOICE_FRAME_SAMPLES);
				if (got < VOICE_FRAME_SAMPLES)
					break;
				ptt_send_frame(pcm, VOICE_FRAME_SAMPLES * (int)sizeof(int16_t));
			}
		}
		int state = PTT_UI_CONNECTING;
		if (ptt_talking)
			state = PTT_UI_TALKING;
		else if (link_up)
			state = PTT_UI_READY;
		if (state != ptt_ui_painted) {
			ptt_paint(state);
			return 1;
		}
		if (ptt_peer_silent != ptt_silent_painted)
			ptt_paint_warning(ptt_peer_silent);
		static uint32_t shown_tx, shown_rx, counts_painted_ms;
		uint32_t now = now_ms();
		if ((shown_tx != ptt_tx_frames || shown_rx != ptt_rx_frames) &&
		    (uint32_t)(now - counts_painted_ms) >= PTT_COUNTS_PAINT_MS) {
			shown_tx = ptt_tx_frames;
			shown_rx = ptt_rx_frames;
			counts_painted_ms = now;
			ptt_paint_counts();
		}
		return 1;
	}

	default:
		return 0;
	}
}

// ---- receive ----------------------------------------------------------------

// From app_call.c, for VOICE_SUB_PTT. `pcm` is borrowed for this call.
void app_ptt_inbound(uint32_t remote_userid, const uint8_t *pcm, int len) {
	if (ptt_screen_peer && remote_userid == ptt_screen_peer) {
		ptt_last_returned_ms = now_ms();
		ptt_peer_silent = false;
	}
	if (len <= 0)
		return;                      // a return: never played, never answered
	bool allowed = false;
	if (admit_media(remote_userid) != ADMIT_REJECT) {
		struct contact_record c;
		if (contact_get(&c, remote_userid) && (c.settings & CONTACT_ALLOW_PTT))
			allowed = true;
	}
	if (!allowed) {
		uint32_t now = now_ms();
		if ((uint32_t)(now - ptt_rx_log_ms) >= PTT_DROP_LOG_MS) {
			ptt_rx_log_ms = now;
			hal_debug(LOG_WARNING, "ptt: dropped from %08x (not allowed)\n",
			          (unsigned)remote_userid);
		}
		return;
	}
	ptt_rx_frames++;
	ptt_send_frame_to(remote_userid, NULL, 0);   // the return, sent even while we transmit
	if (ptt_talking)
		return;
	if (call_holding_audio())
		return;
	if (!ptt_screen_peer && !ptt_rx_active) {
		ptt_rx_active = true;
		audio_open();
	}
	ptt_rx_last_ms = now_ms();
	audio_play_ptt(pcm, len);
}
