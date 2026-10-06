// net_arduino.cpp — device (RP2350) backend for the net HAL declared in hal.h.
// Wraps Arduino WiFiUDP. The portable core (session.cpp/requests.cpp/.ino) holds
// only opaque `net_sock*` handles; this file is the one place WiFiUDP appears.
// Host counterpart: secserver/net_posix.c (BSD UDP).

#include <WiFi.h>
#include <WiFiUdp.h>
#include "hal.h"

struct net_sock {
	WiFiUDP udp;
};

int net_loss_pct = 0;   // hal.h: simulated inbound loss, percent

net_sock *net_open(uint16_t port) {
	net_sock *s = new net_sock();
	if (!s)
		return nullptr;
	if (!s->udp.begin(port)) {  // port 0 = ephemeral
		delete s;
		return nullptr;
	}
	return s;
}

void net_close(net_sock *s) {
	if (!s)
		return;
	s->udp.stop();
	delete s;
}

uint16_t net_local_port(net_sock *s) {
	return s ? s->udp.localPort() : 0;
}

// HARD GATE: the radio link state is checked at the I/O primitives themselves,
// so NO caller (any pump, retry, or future sloppy code path) can move a packet
// in or out unless WiFi is actually associated. Gated on WiFi.status() — the
// cyw43 driver's own truth, not the app's WIFI_* bookkeeping — so it holds even
// if that bookkeeping is wrong. (net_open/socket creation is deliberately NOT
// gated: those were never the problem; only touching the lwIP tx/rx path is.)
static inline bool radio_up(void) { return WiFi.status() == WL_CONNECTED; }

int net_send(net_sock *s, uint32_t ip4, uint16_t port, const uint8_t *buf, int len) {
	if (!s)
		return -3;
	if (!radio_up())  // radio down — never enter the lwIP tx path
		return -9;
	IPAddress ip(ip4);
	if (!s->udp.beginPacket(ip, port))
		return -1;
	int ret = s->udp.write(buf, (size_t)len);
	if (!s->udp.endPacket())
		return -2;
	return ret;
}

int net_recv(net_sock *s, uint32_t *src_ip4, uint16_t *src_port, uint8_t *buf, int max) {
	if (!s)
		return -1;
	if (!radio_up())  // radio down — nothing to receive
		return 0;
	// Loops so a simulated drop moves on to the next datagram. Returning 0 for a
	// dropped one would end the caller's drain loop with packets still queued,
	// which is a stall, not a loss — and at 25 fps voice that overruns the
	// receive buffer instead of testing retransmission.
	for (;;) {
		int n = s->udp.parsePacket();
		if (n <= 0)  // nothing waiting
			return 0;
		if (n > max) {  // oversize — drop (matches old drain)
			s->udp.flush();
			return 0;
		}
		IPAddress src = s->udp.remoteIP();
		if (src_ip4)  // raw v4, octet0 in low byte
			*src_ip4  = (uint32_t)src;
		if (src_port)
			*src_port = s->udp.remotePort();
		int r = s->udp.read(buf, (size_t)n);
		if (r <= 0)
			return 0;
		// Read it off the socket BEFORE discarding it. Dropping earlier would
		// leave the datagram queued and deliver it on the next call.
		if (net_loss_pct > 0 && (int)(hal_rand() % 100u) < net_loss_pct)
			continue;
		return r;
	}
}
