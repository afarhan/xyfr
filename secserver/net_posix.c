// net_posix.c — host (Linux) backend for the net HAL declared in ../hal.h.
// BSD UDP sockets; counterpart of the device's net_arduino.cpp. Used by the
// unified CLI (client.c) so the same session/requests/stream core runs on host.
//
// IP convention matches the rest of the stack: uint32 ipv4 with octet 0 in the
// LOW byte (the device's IPAddress raw layout). On a little-endian host this is
// exactly the in-memory byte order of sockaddr_in.sin_addr.s_addr (network
// order), so the raw uint32 maps across with no conversion.

#include "hal.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct net_sock {
	int fd;
};

net_sock *net_open(uint16_t port) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return NULL;

	// Non-blocking so net_recv() returns 0 (not blocks) when the socket is empty
	// — the drain loop relies on that.
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);

	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family      = AF_INET;
	a.sin_addr.s_addr = INADDR_ANY;
	a.sin_port        = htons(port);   // 0 = ephemeral (kernel picks)
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return NULL; }

	net_sock *s = (net_sock *)malloc(sizeof(*s));
	if (!s) { close(fd); return NULL; }
	s->fd = fd;
	return s;
}

void net_close(net_sock *s) {
	if (!s) return;
	if (s->fd >= 0) close(s->fd);
	free(s);
}

uint16_t net_local_port(net_sock *s) {
	if (!s) return 0;
	struct sockaddr_in a;
	socklen_t len = sizeof(a);
	if (getsockname(s->fd, (struct sockaddr *)&a, &len) < 0) return 0;
	return ntohs(a.sin_port);
}

int net_send(net_sock *s, uint32_t ip4, uint16_t port, const uint8_t *buf, int len) {
	if (!s) return -3;
	struct sockaddr_in a;
	memset(&a, 0, sizeof(a));
	a.sin_family      = AF_INET;
	a.sin_addr.s_addr = ip4;           // octet0-low == network bytes on LE host
	a.sin_port        = htons(port);
	ssize_t r = sendto(s->fd, buf, (size_t)len, 0, (struct sockaddr *)&a, sizeof(a));
	return (r < 0) ? -1 : (int)r;
}

int net_loss_pct = 0;   // hal.h: simulated inbound loss, percent

int net_recv(net_sock *s, uint32_t *src_ip4, uint16_t *src_port, uint8_t *buf, int max) {
	if (!s) return -1;
	// Loops so a simulated drop moves on to the next datagram rather than
	// reporting an empty socket, which would end the caller's drain early.
	for (;;) {
		struct sockaddr_in a;
		socklen_t len = sizeof(a);
		ssize_t r = recvfrom(s->fd, buf, (size_t)max, 0, (struct sockaddr *)&a, &len);
		if (r < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		if (r == 0)
			return 0;
		if (net_loss_pct > 0 && (int)(hal_rand() % 100u) < net_loss_pct)
			continue;
		if (src_ip4)  *src_ip4  = a.sin_addr.s_addr;   // octet0-low on LE host
		if (src_port) *src_port = ntohs(a.sin_port);
		return (int)r;
	}
}
