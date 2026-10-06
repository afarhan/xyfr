// stream_test.c — two endpoints in one process over a frame_write stub that
// routes by peer key, on a virtual clock. Exercises the real stream.c:
// sequence 0 as the reset, dedup, discard of an unknown stream, backpressure
// by silence, and both sides writing at once.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>
#include "contacts.h"
#include "stream.h"
#include "kernel.h"
#include "netif.h"
#include "hal.h"

extern uint32_t stream_idle_ms;
extern uint32_t stream_retransmit_ms;
extern uint8_t  stream_retries;
extern uint8_t  stream_relinks;

static uint32_t clock_ms = 1000;
uint32_t now_ms(void) { return clock_ms; }
time_t   now_seconds(void) { return 0; }
void     hal_delay_ms(uint32_t ms) { (void)ms; }
int      hal_log_level = LOG_CRITICAL;
void hal_debug(int level, const char *fmt, ...) {
	if (level < hal_log_level) return;
	va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
}

// get_part_key lives in wg.c, which would drag the whole crypto core into a
// transport test. Same big-endian rule; real builds link the real one.
uint32_t get_part_key(const uint8_t *key) {
	return ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
	       ((uint32_t)key[2] <<  8) |  (uint32_t)key[3];
}

static stream_handle H_MSG, H_TERM;   // this test is the app that owns them

static int passed, failed;
#define CHECK(cond, what) do {                                            \
	if (cond) { passed++; }                                               \
	else { failed++; printf("  FAIL %s (line %d)\n", (what), __LINE__); } \
} while (0)

static uint8_t KEY_A[32] = { 0xAA, 1, 2, 3 };
static uint8_t KEY_B[32] = { 0xBB, 4, 5, 6 };
#define UID_A 0xAA010203u
#define UID_B 0xBB040506u

// stream.c resolves a userid to an address exactly once, when it opens a slot.
bool contact_get(struct contact_record *pc, uint32_t userid) {
	memset(pc, 0, sizeof *pc);
	if (userid == UID_A) { memcpy(pc->key, KEY_A, 32); return true; }
	if (userid == UID_B) { memcpy(pc->key, KEY_B, 32); return true; }
	return false;
}

// ---- the network ------------------------------------------------------------
struct frame {
	uint8_t to[32];
	uint8_t buf[2048];
	int len;
};
static struct frame net[64];
static int net_n, drop_next, dropped, sent_total;

// The route is up unless a test says otherwise: stream.c asks netif whether
// silence means loss or a peer that is gone.
static bool link_up = true;
bool netif_route_alive(uint32_t dest_partkey) { (void)dest_partkey; return link_up; }

// What the pump reaches for when a budget runs out. Counted, so a test can tell
// "it waited for the handshake" from "it minted a fresh session" -- the two
// cases behave identically from outside, and only one of them is safe while a
// first handshake is still running. Dropping a route takes it down, as netif's
// link_release does.
static int route_drops, route_opens;
void netif_drop_route(const uint8_t peer_key[32]) {
	(void)peer_key;
	route_drops++;
	link_up = false;
}
void netif_open_route(const uint8_t peer_key[32]) {
	(void)peer_key;
	route_opens++;
}

frame_status frame_write(const uint8_t peer_key[32], const uint8_t *data, int len) {
	sent_total++;
	if (drop_next > 0) { drop_next--; dropped++; return FRAME_SENT; }
	if (net_n >= 64 || len > (int)sizeof net[0].buf) return FRAME_FAILED;
	memcpy(net[net_n].to, peer_key, 32);
	memcpy(net[net_n].buf, data, (size_t)len);
	net[net_n].len = len;
	net_n++;
	return FRAME_SENT;
}

// ---- the app -------------------------------------------------------------
static int ev_data, ev_delivered;
static bool port_owned = true;
static bool read_on_data = true;
static uint8_t got[4096];
static int got_len;

// stream.c reports transport events; the kernel is what would turn them into
// app messages, so a test standing in for the kernel implements these two.
bool kernel_stream_data(uint16_t port, uint32_t remote_userid) {
	if (!port_owned)
		return false;
	ev_data++;
	if (!read_on_data)
		return true;
	stream_handle h = H_TERM;
	if (port == PORT_MSG)
		h = H_MSG;
	int n = stream_read(h, remote_userid, got + got_len, (int)sizeof got - got_len);
	if (n > 0)
		got_len += n;
	return true;
}

bool kernel_stream_delivered(uint16_t port, uint32_t remote_userid) {
	(void)port;
	(void)remote_userid;
	if (!port_owned)
		return false;
	ev_delivered++;
	return true;
}

// Deliver everything queued, pumping between generations so events fire. Which
// endpoint a frame came FROM is the opposite of who it is addressed to.
static void run(void) {
	for (int round = 0; round < 40; round++) {
		if (net_n) {
			struct frame batch[64];
			int n = net_n;
			memcpy(batch, net, sizeof(struct frame) * (size_t)n);
			net_n = 0;
			for (int i = 0; i < n; i++) {
				const uint8_t *from = KEY_B;
				if (batch[i].to[0] == 0xBB)
					from = KEY_A;
				stream_process_incoming(from, batch[i].buf, batch[i].len);
			}
		}
		stream_pump();
		if (!net_n) break;
	}
}

// No teardown exists in the protocol, so a test resets the way a device does:
// let both slots go idle and be reaped.
static void clear_both(void) {
	clock_ms += stream_idle_ms + 100;
	stream_pump();
	stream_pump();
	clock_ms += 10;
	got_len = 0;
}

int main(void) {
	stream_init(6);
	H_MSG  = stream_listen(PORT_MSG);
	H_TERM = stream_listen(PORT_TERM);
	CHECK(H_MSG && H_TERM && H_MSG != H_TERM, "two ports bind to distinct handles");
	CHECK(stream_listen(PORT_MSG) == 0, "a port already held cannot be bound twice");

	printf("a write creates the stream, at sequence 0\n");
	int w = stream_write(H_MSG, UID_B, (const uint8_t *)"hello", 5);
	CHECK(w == 5, "the write took every byte");
	CHECK(stream_exists(H_MSG, UID_B), "and there is now a stream");
	CHECK(stream_can_write(H_MSG, UID_B) == 0, "one packet in flight");
	run();
	CHECK(ev_data >= 1, "the far side was told data arrived");
	CHECK(got_len == 5 && memcmp(got, "hello", 5) == 0, "bytes intact");
	CHECK(ev_delivered >= 1, "the sender was told it landed");
	CHECK(stream_can_write(H_MSG, UID_B) > 0, "and may write again");

	printf("a replayed packet delivers nothing\n");
	got_len = 0;
	stream_write(H_MSG, UID_B, (const uint8_t *)"world", 5);
	struct frame dup = net[0];
	run();
	CHECK(got_len == 5, "it arrived once");
	got_len = 0;
	stream_process_incoming(KEY_A, dup.buf, dup.len);
	stream_pump();
	CHECK(got_len == 0, "and the replay is dropped, not re-delivered");

	printf("loss and retransmit\n");
	got_len = 0;
	drop_next = 1;
	stream_write(H_MSG, UID_B, (const uint8_t *)"survives", 8);
	run();
	CHECK(dropped == 1, "a packet was dropped");
	CHECK(got_len == 0, "and did not arrive");
	clock_ms += stream_retransmit_ms + 50;
	run();
	CHECK(got_len == 8, "the retransmit got through");

	printf("an unknown stream is discarded, never answered\n");
	clear_both();
	uint8_t stray[16 + 4] = {0};
	stray[0] = 9;                            // DATA_STREAM
	stray[3] = PORT_MSG;              // port, big-endian
	stray[5] = 4;                            // len = 4
	stray[11] = 200;                         // seq = 200, not 0
	int quiet = sent_total;
	stream_process_incoming(KEY_A, stray, (int)sizeof stray);
	stream_pump();
	CHECK(sent_total == quiet, "nothing was sent in reply");
	CHECK(!stream_exists(H_MSG, UID_A), "and no stream was created");

	printf("sequence 0 resets a live receiver — no silent loss\n");
	// The receiver holds live state; the sender forgets and restarts at 0. Were
	// the reset conditional, the receiver would re-ack its old high offset and
	// the sender would believe bytes landed that were never taken.
	clear_both();
	stream_write(H_MSG, UID_B, (const uint8_t *)"first half", 10);
	run();
	CHECK(got_len == 10, "the first bytes were taken");
	clock_ms += stream_idle_ms + 100;        // the sender forgets: reap, reboot
	stream_pump(); stream_pump();
	got_len = 0;
	stream_write(H_MSG, UID_B, (const uint8_t *)"again", 5);
	run();
	CHECK(got_len == 5 && memcmp(got, "again", 5) == 0,
	      "the reset was honoured and the new bytes taken");

	printf("backpressure is silence\n");
	clear_both();
	read_on_data = false;                    // the app stops reading
	stream_write(H_MSG, UID_B, (const uint8_t *)"unread", 6);
	run();
	CHECK(stream_can_read(H_MSG, UID_A) == 6, "it sits unread");
	CHECK(stream_can_read(H_MSG, UID_A) == 6,
	      "and a second write cannot displace it");
	read_on_data = true;
	run();

	printf("both sides writing at once\n");
	clear_both();
	stream_write(H_MSG, UID_B, (const uint8_t *)"from A", 6);
	stream_write(H_MSG, UID_A, (const uint8_t *)"from B", 6);
	run();
	CHECK(got_len == 12, "both directions delivered, neither reset the other");

	// Withholding tx_ack is not enough on its own: EVERY packet carries an ack
	// field, so a data packet going one way can acknowledge bytes the other
	// way that the app has not taken. Invisible while one side is silent — a
	// silent side has no data packet to carry it — and silent message loss the
	// moment both directions are busy, because the sender records delivered for
	// something the receiver may still drop.
	printf("a data packet must not ack what the app has not taken\n");
	clear_both();
	read_on_data = false;                    // neither app takes its bytes
	int delivered_before = ev_delivered;     // the counter is cumulative
	stream_write(H_MSG, UID_B, (const uint8_t *)"unread A", 8);
	stream_write(H_MSG, UID_A, (const uint8_t *)"unread B", 8);
	run();
	// The premature ack rides a DATA packet, so one has to go out AFTER the
	// peer's bytes arrived — which on a stop-and-wait link means a retransmit.
	clock_ms += stream_retransmit_ms + 50;
	run();
	CHECK(ev_delivered == delivered_before, "neither sender was told it landed");
	CHECK(stream_can_read(H_MSG, UID_A) == 8, "the bytes are still unread");
	read_on_data = true;
	run();
	CHECK(ev_delivered > delivered_before,
	      "and delivery follows once the app takes them");

	printf("a port nobody owns\n");
	clear_both();
	port_owned = false;
	stream_write(H_TERM, UID_B, (const uint8_t *)"anyone?", 7);
	run();
	CHECK(!stream_exists(H_TERM, UID_A), "the slot was forgotten");
	port_owned = true;

	// No notification for this: an app reconciles against stream_exists on its
	// own tick, because a quiet reap and a vanished peer look identical here.
	printf("an idle stream is reaped, silently\n");
	clear_both();
	stream_write(H_MSG, UID_B, (const uint8_t *)"quiet", 5);
	run();
	clock_ms += stream_idle_ms + 100;
	stream_pump();
	stream_pump();
	CHECK(!stream_exists(H_MSG, UID_B), "the slot is gone");
	CHECK(!stream_exists(H_MSG, UID_A), "at both ends");

	// The retry budget alone cannot tell lost packets from a peer that is gone.
	// While netif says the link holds, the bytes are still deliverable.
	printf("a first handshake outlasting the budget is waited for, not dropped\n");
	clear_both();
	link_up = false;                         // no route yet: the handshake is running
	drop_next = 99;                          // and nothing gets through meanwhile
	route_drops = 0;
	route_opens = 0;
	stream_write(H_MSG, UID_B, (const uint8_t *)"before the link", 15);
	for (int i = 0; i < (int)stream_retries + 2; i++) {
		clock_ms += stream_retransmit_ms + 10;
		stream_pump();
	}
	CHECK(stream_exists(H_MSG, UID_B),
	      "a budget of silence with no route does not reap");
	CHECK(route_drops == 0,
	      "a handshake in progress is never dropped");
	CHECK(route_opens > 0,
	      "a link is asked for when none exists");

	link_up = true;                          // the handshake completes
	drop_next = 0;
	ev_delivered = 0;
	clock_ms += stream_retransmit_ms + 10;
	stream_pump();                           // the next retransmit gets through
	run();
	CHECK(ev_delivered > 0,
	      "the segment held across the handshake is delivered");

	printf("a link that carries nothing gets a fresh session, then is given up on\n");
	clear_both();
	link_up = true;                          // netif says alive...
	drop_next = 99;                          // ...but nothing comes back
	route_drops = 0;
	route_opens = 0;
	stream_write(H_MSG, UID_B, (const uint8_t *)"into the void", 13);
	for (int i = 0; i < (int)stream_retries + 2; i++) {
		clock_ms += stream_retransmit_ms + 10;
		stream_pump();
	}
	CHECK(route_drops > 0,
	      "a stale session is dropped rather than retransmitted into");
	CHECK(stream_exists(H_MSG, UID_B),
	      "one dead budget is not the peer being gone");

	for (int i = 0; i < ((int)stream_retries + 2) * ((int)stream_relinks + 1); i++) {
		clock_ms += stream_retransmit_ms + 10;
		stream_pump();
	}
	CHECK(!stream_exists(H_MSG, UID_B),
	      "the peer is given up on after stream_relinks attempts");
	link_up = true;
	drop_next = 0;

	printf("\n==== %d passed, %d failed ====\n", passed, failed);
	return failed ? 1 : 0;
}
