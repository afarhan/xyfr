// stream.c — a reliable byte stream between two contacts, over netif.
//
// A stream is (peer, port). A port belongs to one app: the app binds it with
// stream_listen and gets a handle, and every later call names that handle, so
// an app cannot reach a port it does not hold.
//
// The algorithm is stop-and-wait. Each direction holds one segment. `inflight`
// is the segment we sent and have not had acked. `unread` is the segment we
// received and the app has not taken. Nothing else is buffered. A write is
// refused while a segment is in flight. A received segment is dropped while the
// previous one is unread, and no ack is sent, so the peer stops. That is the
// backpressure: an app that does not read stalls its peer.
//
// Every packet carries seq, ack and window. seq is the byte offset of the
// segment. ack is the offset we have taken so far, minus the bytes still in
// `unread`, because the sender treats an ack as delivery and the bytes must be
// with the app first. window is advisory: we advertise ours and ignore the
// peer's, since one segment fits any window.
//
// The first write to a (peer, port) creates the stream and goes out at seq 0
// with payload. Seq 0 with payload is the reset: the receiver clears its
// receive state and takes a slot if it has none. Its send direction is left
// alone, because a first packet, a retransmit of it, and a peer that restarted
// look the same here. A packet for an unknown stream is dropped without reply.
// A pure ack (no payload) never resets.
//
// The app hears about a stream only from stream_pump: data arrived, or a write
// was delivered. stream_process_incoming records what happened and returns.
// After each call up, the pump finds the slot again by (peer, port), because
// the app may have dropped or replaced it. The ack for a received segment goes
// out from the pump, after the app has read it.
//
// Retransmit every stream_retransmit_ms, stream_retries times. Then the segment
// has gone a whole budget unanswered and netif is asked about the peer. Its one
// bool settles nothing, so neither answer is taken as final. "Alive" is also a
// session the relay has stopped routing, so that case drops the link and opens a
// fresh one. "No route" is also a first handshake still running -- the common
// case, and dropping it would destroy the link about to carry us -- so that case
// only opens a link if none exists, and waits another budget. Either way the
// peer is called gone after stream_relinks attempts. A stream idle for
// stream_idle_ms is reaped. There is no keepalive; an app that must stay up
// sends something.
//
// Core 0. Portable C.

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "hal.h"
#include "netif.h"
#include "peer_data.h"
#include "stream.h"
#include "contacts.h"
#include "kernel.h"
#include "wg.h"

uint32_t stream_retransmit_ms = 1000;
uint32_t stream_idle_ms       = 30000;   // matches netif_idle_ms
uint8_t  stream_retries       = 5;
uint8_t  stream_relinks       = 2;       // fresh sessions tried before a peer is gone

#define STREAM_KEY_LEN 32
#define STREAM_HDR     14
#define STREAM_OWN_HDR (STREAM_HDR - DATA_HEADER_LEN)   // `len` counts from after the common header
#define STREAM_SEG_MAX 1024                             // one segment; a near-full terminal repaint
#define STREAM_PORTS   4

// ---- structs -----------------------------------------------------------------

#pragma pack(push, 1)
// transport, port, len are the common header (peer_data.h). window is last so
// seq and ack stay four-byte aligned.
struct stream_hdr {
	uint8_t  transport;   // DATA_STREAM
	uint8_t  port;        // PORT_MSG, PORT_TERM, ...
	uint16_t len;         // be; bytes after the common header
	uint32_t seq;         // be
	uint32_t ack;         // be
	uint16_t window;      // be
};
#pragma pack(pop)

struct stream {
	bool     used;
	uint8_t  peer[STREAM_KEY_LEN];
	uint32_t remote_userid;
	uint16_t port;
	uint32_t idle_at_ms;

	uint8_t  inflight[STREAM_SEG_MAX];
	uint16_t inflight_len;           // 0 = nothing in flight
	uint32_t inflight_seq;
	uint32_t send_next;              // offset the next write will carry
	uint8_t  retries_left;
	uint8_t  relinks;                // reopen attempts spent on this segment
	uint32_t retransmit_at_ms;

	uint8_t  unread[STREAM_SEG_MAX];
	uint16_t unread_len;
	uint32_t recv_next;              // offset we expect next

	bool     delivered;              // pump: tell the app our segment landed
	bool     reap;                   // pump: free this slot
};

// kernel_stream_data or kernel_stream_delivered.
typedef bool (*stream_notify_fn)(uint16_t port, uint32_t remote_userid);

static struct stream *pool;
static int            pool_slots;
static uint16_t       bound_port[STREAM_PORTS];   // handle-1 -> port; 0 = free

// Static: this runs inside netif's receive path, and a kilobyte of stack there
// wedges the device.
static uint8_t packet_buf[STREAM_HDR + STREAM_SEG_MAX];

// ---- ports -------------------------------------------------------------------

stream_handle stream_listen(uint16_t app_port) {
	if (app_port == 0)
		return 0;
	for (int i = 0; i < STREAM_PORTS; i++) {
		if (bound_port[i] == app_port) {
			hal_debug(LOG_ERROR, "stream: port %u already bound\n", (unsigned)app_port);
			return 0;
		}
	}
	for (int i = 0; i < STREAM_PORTS; i++) {
		if (bound_port[i] == 0) {
			bound_port[i] = app_port;
			return (stream_handle)(i + 1);
		}
	}
	return 0;
}

void stream_stop(stream_handle handle) {
	if (handle > 0 && handle <= STREAM_PORTS)
		bound_port[handle - 1] = 0;
}

static uint16_t port_of(stream_handle handle) {
	if (handle == 0 || handle > STREAM_PORTS)
		return 0;
	return bound_port[handle - 1];
}

// ---- slots -------------------------------------------------------------------

static struct stream *slot_find(uint32_t remote_userid, uint16_t port) {
	if (!pool)
		return NULL;
	for (int i = 0; i < pool_slots; i++) {
		if (pool[i].used && pool[i].port == port &&
		    pool[i].remote_userid == remote_userid)
			return &pool[i];
	}
	return NULL;
}

static struct stream *slot_of_handle(stream_handle handle, uint32_t remote_userid) {
	uint16_t app_port = port_of(handle);
	if (!app_port)
		return NULL;
	return slot_find(remote_userid, app_port);
}

static struct stream *slot_take(const uint8_t peer[STREAM_KEY_LEN], uint16_t port) {
	if (!pool)
		return NULL;
	for (int i = 0; i < pool_slots; i++) {
		if (pool[i].used)
			continue;
		struct stream *s = &pool[i];
		memset(s, 0, sizeof *s);
		s->used          = true;
		s->port          = port;
		s->remote_userid = get_part_key((uint8_t *)peer);
		s->retries_left  = stream_retries;
		s->idle_at_ms    = now_ms() + stream_idle_ms;
		memcpy(s->peer, peer, STREAM_KEY_LEN);
		return s;
	}
	hal_debug(LOG_WARNING, "stream: pool full (%d slots)\n", pool_slots);
	return NULL;
}

static void slot_free(struct stream *s) {
	memset(s, 0, sizeof *s);
}

// ---- transmit ----------------------------------------------------------------

static void tx_packet(struct stream *s, uint32_t seq,
                      const uint8_t *data, int len) {
	struct stream_hdr *h = (struct stream_hdr *)packet_buf;
	uint16_t room = STREAM_SEG_MAX;
	if (s->unread_len)
		room = 0;
	h->transport = DATA_STREAM;
	h->port      = (uint8_t)s->port;
	h->len       = be16((uint16_t)(STREAM_OWN_HDR + len));
	h->seq       = be32(seq);
	h->ack       = be32(s->recv_next - s->unread_len);
	h->window    = be16(room);
	if (len > 0)
		memcpy(packet_buf + STREAM_HDR, data, (size_t)len);
	if (frame_write(s->peer, packet_buf, STREAM_HDR + len) == FRAME_FAILED)
		hal_debug(LOG_WARNING, "stream: send to port %u failed\n", (unsigned)s->port);
}

static void tx_ack(struct stream *s) {
	tx_packet(s, s->send_next, NULL, 0);
}

static void tx_inflight(struct stream *s) {
	hal_debug(LOG_EVERYTHING, "stream: tx seq=%u port=%u len=%d\n",
	          (unsigned)s->inflight_seq, (unsigned)s->port, s->inflight_len);
	tx_packet(s, s->inflight_seq, s->inflight, s->inflight_len);
	s->retransmit_at_ms = now_ms() + stream_retransmit_ms;
}

// ---- receive -----------------------------------------------------------------

void stream_process_incoming(const uint8_t peer[STREAM_KEY_LEN],
                             const uint8_t *seg, int len) {
	const struct stream_hdr *h = (const struct stream_hdr *)seg;
	if (len < STREAM_HDR || h->transport != DATA_STREAM)
		return;
	uint16_t port    = h->port;
	int      payload = (int)be16(h->len) - STREAM_OWN_HDR;
	uint32_t seq     = be32(h->seq);
	uint32_t ack     = be32(h->ack);
	if (payload < 0 || payload > len - STREAM_HDR || payload > STREAM_SEG_MAX)
		return;

	hal_debug(LOG_EVERYTHING, "stream: rx from %08x port=%u seq=%u ack=%u len=%d\n",
	          (unsigned)get_part_key((uint8_t *)peer), (unsigned)port,
	          (unsigned)seq, (unsigned)ack, payload);

	struct stream *s = slot_find(get_part_key((uint8_t *)peer), port);

	if (seq == 0 && payload > 0) {           // the reset
		if (!s)
			s = slot_take(peer, port);
		if (!s)
			return;
		s->recv_next  = 0;
		s->unread_len = 0;
	}
	if (!s) {
		hal_debug(LOG_EVERYTHING, "stream: drop port %u seq %u — no such stream\n",
		          (unsigned)port, (unsigned)seq);
		return;
	}

	s->idle_at_ms = now_ms() + stream_idle_ms;

	if (s->inflight_len && ack >= s->inflight_seq + s->inflight_len) {
		s->inflight_len     = 0;
		s->retransmit_at_ms = 0;
		s->retries_left     = stream_retries;
		s->relinks          = 0;
		s->delivered        = true;
	}

	if (payload <= 0)
		return;
	if (s->unread_len) {
		hal_debug(LOG_EVERYTHING, "stream: port %u unread %u — withholding ack\n",
		          (unsigned)port, (unsigned)s->unread_len);
		return;
	}
	if (seq != s->recv_next) {
		hal_debug(LOG_EVERYTHING, "stream: port %u seq %u want %u\n",
		          (unsigned)port, (unsigned)seq, (unsigned)s->recv_next);
		tx_ack(s);
		return;
	}
	memcpy(s->unread, seg + STREAM_HDR, (size_t)payload);
	s->unread_len = (uint16_t)payload;
	s->recv_next += (uint32_t)payload;
}

// ---- the app-facing calls (via kernel.c) -------------------------------------

int stream_write(stream_handle handle, uint32_t remote_userid,
                 const uint8_t *data, int len) {
	uint16_t app_port = port_of(handle);
	if (!app_port)
		return 0;
	if (len <= 0)
		return 0;
	struct stream *s = slot_find(remote_userid, app_port);
	if (!s) {
		struct contact_record contact;
		if (!contact_get(&contact, remote_userid))
			return 0;
		s = slot_take(contact.key, app_port);
		if (!s)
			return 0;
	}
	if (s->inflight_len)
		return 0;
	if (len > STREAM_SEG_MAX)
		len = STREAM_SEG_MAX;
	memcpy(s->inflight, data, (size_t)len);
	s->inflight_len  = (uint16_t)len;
	s->inflight_seq  = s->send_next;
	s->send_next    += (uint32_t)len;
	s->retries_left  = stream_retries;
	s->relinks       = 0;
	s->idle_at_ms    = now_ms() + stream_idle_ms;
	tx_inflight(s);
	return len;
}

int stream_read(stream_handle handle, uint32_t remote_userid,
                uint8_t *out, int max) {
	struct stream *s = slot_of_handle(handle, remote_userid);
	if (!s || max <= 0)
		return 0;
	int n = max;
	if ((int)s->unread_len < max)
		n = (int)s->unread_len;
	if (n <= 0)
		return 0;
	memcpy(out, s->unread, (size_t)n);
	if (n < (int)s->unread_len)
		memmove(s->unread, s->unread + n, (size_t)(s->unread_len - n));
	s->unread_len -= (uint16_t)n;
	return n;
}

int stream_can_read(stream_handle handle, uint32_t remote_userid) {
	struct stream *s = slot_of_handle(handle, remote_userid);
	if (!s)
		return 0;
	return (int)s->unread_len;
}

int stream_can_write(stream_handle handle, uint32_t remote_userid) {
	uint16_t app_port = port_of(handle);
	if (!app_port)
		return 0;
	struct stream *s = slot_find(remote_userid, app_port);
	if (s && s->inflight_len)
		return 0;
	return STREAM_SEG_MAX;               // no slot yet: the write creates one
}

bool stream_exists(stream_handle handle, uint32_t remote_userid) {
	return slot_of_handle(handle, remote_userid) != NULL;
}

int stream_slot_count(void) {
	return pool_slots;
}

// ---- pump --------------------------------------------------------------------

void stream_init(int slots) {
	if (slots <= 0)
		slots = STREAM_SLOTS_DEFAULT;
	pool = calloc((size_t)slots, sizeof *pool);
	if (!pool) {
		hal_debug(LOG_CRITICAL, "stream: cannot allocate %d x %u bytes\n",
		          slots, (unsigned)sizeof *pool);
		pool_slots = 0;
		return;
	}
	pool_slots = slots;
	hal_debug(LOG_WARNING, "stream: pool %d x %u = %u bytes\n",
	          slots, (unsigned)sizeof *pool,
	          (unsigned)((size_t)slots * sizeof *pool));
}

// Tell the kernel, then find the slot again: the app may have dropped it or
// replaced it. NULL if no app is bound to the port.
static struct stream *notify_kernel_and_refind(uint32_t remote_userid, uint16_t port,
                                               stream_notify_fn notify) {
	if (!notify(port, remote_userid)) {
		struct stream *gone = slot_find(remote_userid, port);
		if (gone)
			slot_free(gone);
		return NULL;
	}
	return slot_find(remote_userid, port);
}

void stream_pump(void) {
	uint32_t now = now_ms();
	for (int i = 0; i < pool_slots; i++) {
		struct stream *s = &pool[i];
		if (!s->used)
			continue;
		uint32_t remote_userid = s->remote_userid;
		uint16_t port          = s->port;

		if (s->reap) {
			slot_free(s);
			continue;
		}
		if (s->delivered) {
			s->delivered = false;
			s = notify_kernel_and_refind(remote_userid, port, kernel_stream_delivered);
			if (!s)
				continue;
		}
		if (s->unread_len) {
			s = notify_kernel_and_refind(remote_userid, port, kernel_stream_data);
			if (!s)
				continue;
			if (!s->unread_len)
				tx_ack(s);
		}

		if (s->inflight_len && (int32_t)(now - s->retransmit_at_ms) >= 0) {
			if (s->retries_left == 0) {
				if (s->relinks >= stream_relinks) {
					hal_debug(LOG_WARNING, "stream: port %u peer gone\n",
					          (unsigned)port);
					s->reap = true;
					continue;
				}
				s->relinks++;
				if (netif_route_alive(get_part_key(s->peer))) {
					// A whole budget into a link netif calls alive. The
					// session is the thing that died, so mint another.
					hal_debug(LOG_WARNING,
					          "stream: port %u link stale, reopening (%u)\n",
					          (unsigned)port, (unsigned)s->relinks);
					netif_drop_route(s->peer);
				} else {
					// No route yet. A handshake may still be running, and
					// netif_open_route does nothing when a link exists, so
					// this cannot disturb one.
					hal_debug(LOG_WARNING,
					          "stream: port %u no route, waiting (%u)\n",
					          (unsigned)port, (unsigned)s->relinks);
				}
				netif_open_route(s->peer);
				s->retries_left = stream_retries;
			}
			s->retries_left--;
			tx_inflight(s);
			continue;
		}

		if ((int32_t)(now - s->idle_at_ms) >= 0)
			s->reap = true;
	}
}
