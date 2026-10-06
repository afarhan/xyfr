// netif.c — the network interface. See netif.h for the contract.
//
// The link pool, its state machine and its retry logic are statics with no
// public surface at all, which is the point: a tenant addresses a peer by its
// static key and can reach nothing else in here.
//
// Three properties worth not breaking, each of which fixed a measured bug:
//   1. A frame goes to the destination's ingress relay, resolved once at
//      bring-up and held on the link — never to our own relay.
//   2. A link's session id never changes once up. Nothing binds by it anyway:
//      tenants address by peer key, which is not recycled like a slot index.
//   3. No tenant can mistake "a link exists" for "my call exists". Failure
//      arrives as FRAME_FAILED or as the tenant's own timeout.
//      netif_route_alive() reports the route and is for retry policy only — a
//      peer that went offline fails its rekey, so its route falls away while a
//      lossy one keeps its. It says nothing about whether the caller's own work
//      still exists.
//
// Core 0 only. Portable C (device + host CLI).

#include <string.h>
#include "hal.h"          // now_ms, hal_debug, LOG_*
#include "netif.h"
#include "device_record.h"      // struct device_record — injected at frame_init, not reached for
#include "peer_data.h"   // DATA_HEADER_LEN, DATA_STREAM, MAX_PACKET_SIZE
#include "stream.h"      // the reliable transport this layer demuxes to
#include "wg.h"

// ---- structs ---------------------------------------------------------------

// An address as this backend encodes it: four bytes of IPv4 then a big-endian
// UDP port. Only addr_encode/addr_decode below may assume that.
#define NETIF_ADDR_IP4_LEN 6

struct link {
	struct peer peer;               // wg: keys, session_id, cookie, remote_static_public
	uint8_t     state;
	uint8_t     retries_left;       // handshake attempts remaining
	// Where the peer is, as opaque bytes: ip4 plus port today, a frequency and a
	// slot tomorrow. Only addr_encode/addr_decode below know the layout, so
	// swapping the medium touches those two and nothing else in this file.
	uint8_t     addr[NETIF_ADDR_MAX];
	uint8_t     addr_len;
	uint32_t    next_retry_ms;
	uint32_t    last_activity_ms;   // authenticated INBOUND only: a link is alive if
	                                // the peer is answering, and by nothing else
	uint32_t    handshake_at_ms;    // current keys established    -> rekey
	uint32_t    refresh_at_ms;      // next route-refresh frame may go out
};

// RFC 5905 header. We send it almost entirely zeroed and read one field back:
// txTm_s, the server's transmit timestamp in NTP seconds.
struct ntp_packet {
	uint8_t  li_vn_mode;      // leap indicator | version | mode
	uint8_t  stratum;
	uint8_t  poll;
	uint8_t  precision;
	uint32_t rootDelay;
	uint32_t rootDispersion;
	uint32_t refId;
	uint32_t refTm_s;         // reference timestamp
	uint32_t refTm_f;
	uint32_t origTm_s;        // originate timestamp
	uint32_t origTm_f;
	uint32_t rxTm_s;          // receive timestamp
	uint32_t rxTm_f;
	uint32_t txTm_s;          // transmit timestamp — the one field we use
	uint32_t txTm_f;
};

// The contact query (msg7/msg8) in flight. Structurally a handshake: one at a
// time, the same retry counter and deadline, advanced by the same pump. Only the
// payload differs.
struct remote_lookup {
	bool         busy;
	struct query peer_query;        // process-lifetime: wg keeps a pointer into it
	uint8_t      key[KEY_LEN];      // partkey in [0..3]; completed by the answer
	uint8_t      retries_left;
	uint32_t     next_retry_ms;
};

// ---- link pool --------------------------------------------------------------
// A link is a peer's static key plus the bookkeeping for a wg session to it.
// Nothing that is not link state belongs here.
#define NETIF_LINKS       8
#define LINK_SERVER       0   // pinned: the login link. The server is just another
                              // link — a known key at a known address, both of
                              // which arrived with the config — so it needs no
                              // special machinery, only a slot that is never
                              // evicted and an address taken from the config
                              // rather than from the resolver.
#define LINK_FREE         0
#define LINK_HANDSHAKING  1
#define LINK_ALIVE        2

static struct link       links[NETIF_LINKS];
static struct device_record *device;

// ---- our identity -------------------------------------------------------------
// wg holds one static keypair, so netif is its sole owner: nothing else may call
// wireguard_init.
#define NETIF_ACTIVATION_CODE_LEN 16
static uint8_t private_key[KEY_LEN];                        // the identity in force
static uint8_t public_key[KEY_LEN];                        // ... and its public half
static uint8_t activation_code[NETIF_ACTIVATION_CODE_LEN];

static bool is_zero_key(const uint8_t *k) {
	for (int i = 0; i < KEY_LEN; i++)
		if (k[i])
			return false;
	return true;
}

// Install private_key as the device's wg identity and cache its public half. The
// public key is needed on the receive path (the crossing-handshake tie-break
// below), so it is derived once here rather than per inbound msg1.
static void identity_apply(void) {
	static const uint8_t basepoint[KEY_LEN] = { 9 };
	wireguard_init(private_key);
	curve25519(public_key, private_key, basepoint);
}

static bool    activation_in_flight;
static netif_on_frame          on_frame;
static netif_resolve_cb  resolve_addr;
static netif_psk_cb      resolve_psk;
static net_sock         *identity_socket;    // shared listener: inbound msg1 lands here
static net_sock         *anon_socket;        // opened lazily

// Which socket a packet arrived on, for the receive log only. The socket a
// link sends on is derived from its role in link_socket().
#define INTERFACE_IDENTITY 0
#define INTERFACE_ANON     1
static bool              interface_ready;

// ---- tunables (non-static globals, house style) ----
uint32_t netif_handshake_retry_ms = 3000;        // between msg1 attempts
uint8_t  netif_handshake_retries  = 3;
uint32_t netif_rekey_ms           = 120UL*1000;  // < wg REJECT_AFTER_TIME (180 s)
uint32_t netif_offline_recheck_ms = 5UL*1000;   // medium down: recheck, don't back off
uint32_t netif_keepalive_ms       = 20UL*1000;  // hold the upstream NAT mapping open
uint32_t netif_idle_ms            = 30UL*1000;   // min silence before a full pool may harvest a slot

// ---- time from the network (NTP) ---------------------------------------------
#define NTP_PORT        123
#define NTP_EPOCH_DELTA 2208988800UL   // 1900-01-01 .. 1970-01-01

uint32_t netif_ntp_retry_ms   = 30UL*1000;          // until we have it
uint32_t netif_ntp_refresh_ms = 6UL*60UL*60UL*1000; // and again, occasionally
// Hardcoded until it earns its own field in struct device_record. Deliberately
// not folded into endpoints[] — those slots mean "server" and "relay", and one
// field with two meanings is how a data model rots.
static const char *time_source = "162.159.200.1";

static time_t  net_epoch;      // UTC at the moment we synced (0 = never)
static uint32_t net_epoch_at_ms;  // now_ms() then, so net_time() can advance it
static uint32_t ntp_at_ms;

// Parse dotted quad into the low-byte-first uint32 the send path uses.
static bool ip_parse(const char *t, uint32_t *out) {
	uint32_t octet[4] = { 0, 0, 0, 0 };
	int n = 0;
	int v = 0;
	int digits = 0;
	for (const char *p = t; ; p++) {
		if (*p >= '0' && *p <= '9') {
			v = v * 10 + (*p - '0');
			digits++;
			continue;
		}
		if (digits == 0 || v > 255 || n > 3)
			return false;
		octet[n++] = (uint32_t)v;
		v = 0;
		digits = 0;
		if (*p == 0)
			break;
		if (*p != '.')
			return false;
	}
	if (n != 4)
		return false;
	*out = octet[0] | (octet[1] << 8) | (octet[2] << 16) | (octet[3] << 24);
	return true;
}

time_t net_time(void) {
	if (net_epoch == 0)
		return 0;                                   // we do not know; say so
	return net_epoch + (time_t)((now_ms() - net_epoch_at_ms) / 1000u);
}

static void ntp_send(void) {
	uint32_t ip4;
	if (!time_source || !time_source[0])
		return;                                     // no source configured: never ask
	if (!identity_socket || !ip_parse(time_source, &ip4)) {
		ntp_at_ms = now_ms() + netif_offline_recheck_ms;   // no socket yet: recheck soon
		return;
	}
	struct ntp_packet pkt;
	memset(&pkt, 0, sizeof pkt);
	pkt.li_vn_mode = 0x1B;                          // LI=0, VN=3, Mode=3 (client)
	int sent = net_send(identity_socket, ip4, NTP_PORT, (const uint8_t *)&pkt, sizeof pkt);
	if (sent != (int)sizeof pkt) {
		// A request that never left does not cost a retry, the same rule the
		// handshake follows. The radio is usually still associating for the first
		// seconds of a boot, and burning the full retry there leaves the device
		// online with no clock for the best part of a minute.
		ntp_at_ms = now_ms() + netif_offline_recheck_ms;
		return;
	}
	ntp_at_ms = now_ms() + netif_ntp_retry_ms;
}

static bool ntp_receive(uint16_t src_port, const uint8_t *pkt, int len) {
	if (src_port != NTP_PORT || len < (int)sizeof(struct ntp_packet))
		return false;
	struct ntp_packet p;
	memcpy(&p, pkt, sizeof p);
	uint32_t tx = be32(p.txTm_s);
	if (tx < NTP_EPOCH_DELTA)
		return false;
	net_epoch    = (time_t)(tx - NTP_EPOCH_DELTA);
	net_epoch_at_ms = now_ms();
	ntp_at_ms  = now_ms() + netif_ntp_refresh_ms;
	hal_debug(LOG_EVERYTHING, "netif: time synced (%lu)\n", (unsigned long)net_epoch);
	return true;
}


// ---- the remote query -------------------------------------------------------
static struct remote_lookup lookup;

// msg8 decode, local to this file: netif must not include contacts.h, and the
// transmission format is the backend's own business anyway.
static bool query_decode(const uint8_t *data, uint16_t length, uint8_t *out_status,
                         uint8_t out_key[KEY_LEN], uint32_t *out_ip4, uint16_t *out_port) {
	if (length < sizeof(struct msg_contact_response) || data[0] != MSG_CONTACT_RESPONSE)
		return false;
	uint8_t payload[QUERY_RESPONSE_PAYLOAD_LEN];
	size_t  plen = 0;
	if (peer_query_process(&lookup.peer_query, (uint8_t *)data, length, NULL, 0, payload, &plen)
	    != REQUEST_SUCCESS)
		return false;
	if (plen < QUERY_RESPONSE_PAYLOAD_LEN)
		return false;
	*out_status = payload[0];
	memcpy(out_key, payload + 1, KEY_LEN);
	memcpy(out_ip4, payload + 1 + KEY_LEN, sizeof(uint32_t));
	const uint8_t *port_be = payload + 1 + KEY_LEN + sizeof(uint32_t);
	*out_port = (uint16_t)((port_be[0] << 8) | port_be[1]);
	return true;
}

// Opened on first use. Sending a query on identity_socket instead would hand the
// relay exactly the correlation this socket exists to break.
static net_sock *open_anon_socket(void) {
	if (!anon_socket) {
		anon_socket = net_open(0);
		if (!anon_socket)
			hal_debug(LOG_ERROR, "netif: anon socket open failed\n");
		else
			hal_debug(LOG_EVERYTHING, "netif: anon socket up\n");
	}
	return anon_socket;
}

// The socket follows the role, and is derived rather than stored so the two
// cannot drift: wg already records which end we are (peer_handshake_request_
// generate sets is_initiator, peer_handshake_request_process clears it) and it
// does so at exactly the moment the answer changes. A link we originated goes
// out anonymously; a link the peer originated must answer on the identity
// socket, that being the endpoint the relay resolved us at and pinned the
// session to. The login is the one exception, since it is our identity.
static net_sock *link_socket(const struct link *l) {
	if (l == &links[LINK_SERVER])
		return identity_socket;
	if (l->peer.is_initiator)
		return open_anon_socket();
	return identity_socket;
}

static void query_send(void) {
	struct msg_contact_request m7;
	uint8_t pk_be[QUERY_REQUEST_PAYLOAD_LEN];
	memcpy(pk_be, lookup.key, 4);              // the partkey, transmitted big-endian
	lookup.peer_query.partkey = get_part_key(lookup.key);
	peer_query_generate(&lookup.peer_query, MSG_CONTACT_REQUEST, get_fresh_sessionid(),
	                    get_part_key(lookup.peer_query.peer.remote_static_public),
	                    pk_be, sizeof pk_be, &m7);
	// A query goes to OUR ingress — the one address netif legitimately owns — but
	// leaves on the ANONYMOUS socket, never the identity one.
	net_sock *sk = open_anon_socket();
	if (!sk) {
		lookup.next_retry_ms = now_ms() + netif_offline_recheck_ms;
		return;                      // no socket: we never transmitted, so no retry
	}
	int sent = net_send(sk, device->endpoints[1].ip4, device->endpoints[1].port,
	                    (const uint8_t *)&m7, sizeof m7);
	const char *outcome = "";
	if (sent != (int)sizeof m7)
		outcome = " FAILED";
	// Traced here explicitly: a query has no link, so it never passes through
	// link_send and is not covered by the trace there. Without this line the
	// whole query path is invisible in the log.
	hal_debug(LOG_EVERYTHING, "netif: TX query %08x -> %u.%u.%u.%u:%u len=%d%s (retries left %u)\n",
	          (unsigned)get_part_key(lookup.key),
	          (unsigned)( device->endpoints[1].ip4        & 0xff),
	          (unsigned)((device->endpoints[1].ip4 >>  8) & 0xff),
	          (unsigned)((device->endpoints[1].ip4 >> 16) & 0xff),
	          (unsigned)((device->endpoints[1].ip4 >> 24) & 0xff),
	          (unsigned)device->endpoints[1].port, (int)sizeof m7, outcome,
	          (unsigned)lookup.retries_left);
	lookup.next_retry_ms = now_ms() + netif_handshake_retry_ms;
	if (lookup.retries_left)
		lookup.retries_left--;
}

// Hand the answer up and forget it. netif keeps NO cache: if the application
// does not store what it is given here, the next send simply queries again.
static void query_settle_addr(const uint8_t *addr, int addr_len, int status) {
	uint8_t key[KEY_LEN];
	memcpy(key, lookup.key, KEY_LEN);
	lookup.busy = false;
	// Logged for every outcome, the timeout included: a silent timeout is
	// indistinguishable from a query that never left.
	const char *what = "TIMEOUT";
	if (status == QUERY_FOUND)
		what = "FOUND";
	else if (status == QUERY_NOUSER)
		what = "NOUSER";
	hal_debug(LOG_WARNING, "netif: query %08x settled status=%s\n",
	          (unsigned)get_part_key(key), what);
	on_query_response(key, addr, addr_len, status);
}

// ---- link lookup -----------------------------------------------------------
// By key, always. There is no lookup by index or by session_id in the public
// surface, because neither is a stable name for a peer.
static struct link *link_find(const uint8_t peer_key[32]) {
	for (int i = 0; i < NETIF_LINKS; i++)
		if (links[i].state != LINK_FREE &&
		    memcmp(links[i].peer.remote_static_public, peer_key, KEY_LEN) == 0)
			return &links[i];
	return NULL;
}

netif_peer_state netif_peer(const uint8_t peer_key[32]) {
	if (!peer_key)
		return NETIF_PEER_DOWN;
	struct link *l = link_find(peer_key);
	if (!l)
		return NETIF_PEER_DOWN;
	if (l->state == LINK_ALIVE)
		return NETIF_PEER_UP;
	return NETIF_PEER_TRYING;
}

static void link_release(struct link *l, const char *why) {
	if (l->state == LINK_FREE)
		return;
	hal_debug(LOG_WARNING, "netif: link %08x down — %s\n",
	          (unsigned)get_part_key(l->peer.remote_static_public), why);
	// No socket is closed here. There are exactly two, both process-lifetime and
	// shared by every link that derives them (link_socket), so closing one on
	// behalf of a single dying link would break every other link using it.
	memset(l, 0, sizeof *l);              // state = LINK_FREE
}

// Allot a slot for a new link. A free slot is taken on sight; otherwise the
// least-recently-active slot past netif_idle_ms of silence is evicted, whatever
// its state. A pool in which every link is busy refuses, so a live conversation
// is never cut.
static struct link *link_take(void) {
	uint32_t now = now_ms();
	struct link *lru = NULL;
	for (int i = LINK_SERVER + 1; i < NETIF_LINKS; i++) {
		struct link *l = &links[i];
		if (l->state == LINK_FREE)
			return l;
		if ((uint32_t)(now - l->last_activity_ms) < netif_idle_ms)
			continue;
		if (!lru || (int32_t)(l->last_activity_ms - lru->last_activity_ms) < 0)
			lru = l;
	}
	if (!lru)
		return NULL;
	link_release(lru, "evicted: pool full");
	return lru;
}

// ---- transmit --------------------------------------------------------------
// The only two functions that know what an address is. Everything else, this
// file included, treats it as bytes.
static void addr_encode(uint8_t *addr, int *addr_len, uint32_t ip4, uint16_t port);
static bool addr_decode(const uint8_t *addr, int addr_len, uint32_t *ip4, uint16_t *port);

void netif_addr_from_ip4(uint8_t *addr, int *addr_len, uint32_t ip4, uint16_t port) {
	addr_encode(addr, addr_len, ip4, port);
}

bool netif_addr_to_ip4(const uint8_t *addr, int addr_len, uint32_t *ip4, uint16_t *port) {
	return addr_decode(addr, addr_len, ip4, port);
}

static void addr_encode(uint8_t *addr, int *addr_len, uint32_t ip4, uint16_t port) {
	memcpy(addr, &ip4, 4);
	addr[4] = (uint8_t)(port >> 8);
	addr[5] = (uint8_t)(port & 0xff);
	*addr_len = NETIF_ADDR_IP4_LEN;
}

static bool addr_decode(const uint8_t *addr, int addr_len, uint32_t *ip4, uint16_t *port) {
	if (addr_len < NETIF_ADDR_IP4_LEN)
		return false;
	memcpy(ip4, addr, 4);
	*port = (uint16_t)((addr[4] << 8) | addr[5]);
	return *ip4 != 0;
}

// Every outbound byte passes through here, which is why the trace lives here and
// not at each call site: netif calls net_send directly, so without this line the
// whole layer is invisible on the network.
static bool link_send(struct link *l, const void *buf, int len) {
	uint32_t ip4;
	uint16_t port;
	if (!addr_decode(l->addr, l->addr_len, &ip4, &port))
		return false;
	bool ok = net_send(link_socket(l), ip4, port, (const uint8_t *)buf, len) == len;
	int msg_type = -1;
	if (len > 0)
		msg_type = ((const uint8_t *)buf)[0];
	const char *outcome = "";
	if (!ok)
		outcome = " FAILED";
	hal_debug(LOG_EVERYTHING, "netif: TX %u.%u.%u.%u:%u len=%d mt=%d%s\n",
	          (unsigned)(ip4 & 0xff), (unsigned)((ip4 >> 8) & 0xff),
	          (unsigned)((ip4 >> 16) & 0xff), (unsigned)((ip4 >> 24) & 0xff),
	          (unsigned)port, len, msg_type, outcome);
	return ok;
}

static void handshake_send(struct link *l) {
	struct msg1 m1;
	// An activation is the login handshake with the msg_type flipped and the
	// 16-byte code carried in mac2 (secserver/client.c client_activate).
	//
	// Spending mac2 on the code is safe because mac2 and cookies exist to make a
	// handshake expensive to forge at scale, and an activation already carries a
	// scarcer proof of work: an activation code costs something to obtain and is
	// validated before the DH (secserver db_code_valid). So the code does the job
	// mac2 would have done, an activation is never cookie-challenged, and unlike
	// the query it needs no cookie path.
	bool is_activation = (l == &links[LINK_SERVER]) && activation_in_flight;
	uint8_t request_type = MSG_REQUEST_CONNECT;
	if (is_activation)
		request_type = MSG_REQUEST_ACTIVATE;
	peer_handshake_request_generate(&l->peer,
	                                request_type,
	                                l->peer.remote_static_public,
	                                l->peer.session_id, &m1);
	if (is_activation)
		memcpy(m1.mac2, activation_code, NETIF_ACTIVATION_CODE_LEN);
	// A send that never left does not consume a retry: the radio being down is
	// about us, not the peer, and would put us in backoff just as it returns.
	if (!link_send(l, &m1, sizeof m1)) {
		l->next_retry_ms = now_ms() + netif_offline_recheck_ms;
		return;
	}
	l->next_retry_ms = now_ms() + netif_handshake_retry_ms;
	if (l->retries_left)
		l->retries_left--;
}

// ---- bring-up --------------------------------------------------------------
// Open a link to `peer_key` at an address the caller already has. The login uses
// this directly (the server's address is in the config); peer links go through
// link_open(), which resolves first.
// A peer's pre-shared key, when it has one. An all-zero preshared_key is what
// peer_init leaves and what WireGuard means by "none", so a peer without one
// handshakes exactly as it did before this existed.
//
// The SERVER link never has one: it is not a contact, so the app answers false
// and the login is untouched.
static void apply_psk(struct peer *p, const uint8_t peer_key[32]) {
	uint8_t psk[KEY_LEN];
	if (!resolve_psk || !resolve_psk(peer_key, psk))
		return;
	memcpy(p->preshared_key, psk, KEY_LEN);
	crypto_zero(psk, sizeof psk);
	hal_debug(LOG_EVERYTHING, "netif: %08x has a pre-shared key\n",
	          (unsigned)get_part_key((uint8_t *)peer_key));
}

static struct link *link_start(struct link *l, const uint8_t peer_key[32],
                               const uint8_t *addr, int addr_len) {
	memset(l, 0, sizeof *l);
	peer_init(&l->peer);
	memcpy(l->peer.remote_static_public, peer_key, KEY_LEN);
	apply_psk(&l->peer, peer_key);
	l->peer.session_id  = get_fresh_sessionid();
	memcpy(l->addr, addr, (size_t)addr_len);
	l->addr_len         = (uint8_t)addr_len;
	l->state            = LINK_HANDSHAKING;
	l->retries_left     = netif_handshake_retries;
	l->last_activity_ms = now_ms();
	l->refresh_at_ms    = now_ms() + netif_keepalive_ms;
	handshake_send(l);
	return l;
}

// ---- the login ----------------------------------------------------------------

static uint32_t keepalive_at_ms;

// Owns links[LINK_SERVER] entirely; frame_pump's generic loop skips that slot.
// It must: a peer link that stops answering is released, but the login retries
// forever, and the idle reaper would kill it — a login's only inbound is msg2.
static void login_pump(void) {
	struct link *l = &links[LINK_SERVER];
	uint32_t now = now_ms();
	if (device->endpoints[1].ip4 == 0)
		return;                                    // no ingress yet (run Unblock)
	// Adopt an identity that arrived after init. frame_init snapshots the key,
	// but the app may legitimately fill it later — the host CLI applies
	// client.conf after kernel_init (secserver/phone_host.c), and a device gets
	// its key at registration. The device record is the durable source, so if we
	// hold no identity and it does, take it.
	if (is_zero_key(private_key) && !is_zero_key(device->my_private_key)) {
		memcpy(private_key, device->my_private_key, KEY_LEN);
		identity_apply();
		hal_debug(LOG_WARNING, "netif: identity adopted from config -> %08x\n",
		          (unsigned)get_part_key(public_key));
	}
	// Checked every tick rather than once at init: on a fresh device the key
	// arrives at REGISTRATION, long after netif came up.
	bool have_key = false;
	for (int i = 0; i < KEY_LEN; i++) {
		if (private_key[i] != 0) {
			have_key = true;
			break;
		}
	}
	if (!have_key)
		return;                                    // no identity yet (unregistered)

	if (l->state == LINK_FREE) {
		uint8_t addr[NETIF_ADDR_MAX];
		int     alen = 0;
		addr_encode(addr, &alen, device->endpoints[1].ip4, device->endpoints[1].port);
		// The login rides the identity socket: the relay knows us by that
		// endpoint, and every inbound peer msg1 arrives there. link_socket()
		// special-cases this slot, so it holds even though we are the initiator.
		link_start(l, device->server_static_public, addr, alen);
		return;
	}
	if (l->state == LINK_HANDSHAKING) {
		if ((int32_t)(now - l->next_retry_ms) < 0)
			return;
		if (l->retries_left == 0) {
			memset(l, 0, sizeof *l);               // start over, forever
			return;
		}
		handshake_send(l);
		return;
	}
	// Alive. Re-handshake before the keys age out, so the relay's route to us and
	// our keys both stay fresh. Same slot, same session id.
	if ((int32_t)(now - l->handshake_at_ms) > (int32_t)netif_rekey_ms) {
		l->state        = LINK_HANDSHAKING;
		l->retries_left = netif_handshake_retries;
		handshake_send(l);
		return;
	}
	// A 1-byte poke holds the upstream NAT's mapping for the identity socket open
	// between logins, so an inbound peer msg1 can still reach us.
	if ((int32_t)(now - keepalive_at_ms) >= 0) {
		keepalive_at_ms = now + netif_keepalive_ms;
		uint8_t ka = 0xFF;
		hal_debug(LOG_EVERYTHING, "netif: nat keepalive\n");
		link_send(l, &ka, 1);
	}
}

// See netif.h. netif holds the key in RAM only; persisting it is the caller's
// job. Clearing the login slot is the whole of the switchover — login_pump
// rebuilds it next tick under the new identity.
bool netif_setkey(const uint8_t key[32], const char *activation) {
	if (!interface_ready || !key)
		return false;
	if (activation_in_flight)
		return false;                 // one modal identity change at a time
	memcpy(private_key, key, KEY_LEN);
	activation_in_flight = (activation != NULL);
	if (activation_in_flight) {
		// Exactly 16 bytes ride in mac2 — zero-padded if the code is shorter, so a
		// short string can never read past its terminator into whatever follows.
		memset(activation_code, 0, sizeof activation_code);
		size_t n = strlen(activation);
		if (n > NETIF_ACTIVATION_CODE_LEN)
			n = NETIF_ACTIVATION_CODE_LEN;
		memcpy(activation_code, activation, n);
	}
	identity_apply();
	memset(&links[LINK_SERVER], 0, sizeof links[LINK_SERVER]);
	// public_key, never private_key: a userid is derived from the public key, and
	// logging a prefix of the private one would both mislabel the identity and
	// leak secret bytes into a log that gets pasted around.
	const char *note = "";
	if (activation_in_flight)
		note = " (activating)";
	hal_debug(LOG_WARNING, "netif: identity -> %08x%s\n",
	          (unsigned)get_part_key(public_key), note);
	return true;
}

// There is no identity to fall back to, an activation code only being usable on
// a wiped device, so zeroing returns us to exactly that state and login_pump's
// have_key guard idles.
static void identity_clear(void) {
	activation_in_flight = false;
	crypto_zero(activation_code, sizeof activation_code);
	crypto_zero(private_key, sizeof private_key);
	crypto_zero(public_key, sizeof public_key);
	memset(&links[LINK_SERVER], 0, sizeof links[LINK_SERVER]);
}

void netif_relogin(void) {
	if (!interface_ready)
		return;
	memset(&links[LINK_SERVER], 0, sizeof links[LINK_SERVER]);
	hal_debug(LOG_WARNING, "netif: relogin requested\n");
}

static struct link *link_open(const uint8_t peer_key[32]) {
	hal_debug(LOG_EVERYTHING, "netif: link open -> %08x\n",
	          (unsigned)get_part_key((uint8_t *)peer_key));
	// The destination is the peer's own ingress relay. Without it there is
	// nowhere to send, a relay routing only to clients logged in to itself. The
	// app holds the answer, netif keeping no cache, and this backend decodes the
	// address blob because it defined the layout.
	uint8_t addr[NETIF_ADDR_MAX];
	int     addr_len = 0;
	if (!resolve_addr || !resolve_addr(peer_key, addr, &addr_len) || addr_len <= 0) {
		hal_debug(LOG_WARNING, "netif: %08x unresolved — no address; query first\n",
		          (unsigned)get_part_key((uint8_t *)peer_key));
		return NULL;
	}
	struct link *l = link_take();
	if (!l) {
		hal_debug(LOG_ERROR, "netif: pool full, no evictable link\n");
		return NULL;
	}
	// We are originating, so handshake_send sets is_initiator and link_socket()
	// answers the anon socket (THREAT_MODEL.md 6.2/10.4).
	return link_start(l, peer_key, addr, addr_len);
}

// ---- receive ---------------------------------------------------------------
// The protocol demux, and the only content this layer reads: byte 0 names the
// transport above, exactly as IP's protocol number does. A reliable frame goes
// to the reliable transport, which delivers to its app once the bytes are in
// order; everything else is a datagram and goes straight up.
static void deliver(struct link *l, frame_event ev, const uint8_t *data, int len) {
	const struct data_hdr *h = (const struct data_hdr *)data;
	if (ev == FRAME_DATA && len >= DATA_HEADER_LEN && h->transport == DATA_STREAM) {
		stream_process_incoming(l->peer.remote_static_public, data, len);
		return;
	}
	if (on_frame)
		on_frame(l->peer.remote_static_public, ev, data, len);
}

// One line per received packet: the endpoint it came from, the frame type, and
// the header fields that decide where it goes. msg1 carries sender_index, msg2
// both indices, msg4 the receiver_index; every one of them carries the
// session_id the relay keys its route on. Read by memcpy because the packet is a
// byte buffer and this core faults on an unaligned 64-bit load.
static void log_rx_header(int iface, uint32_t src_ip4, uint16_t src_port,
                          const uint8_t *pkt, int len) {
	unsigned a = src_ip4 & 0xff;
	unsigned b = (src_ip4 >>  8) & 0xff;
	unsigned c = (src_ip4 >> 16) & 0xff;
	unsigned d = (src_ip4 >> 24) & 0xff;
	int      type = pkt[0];
	uint64_t sid  = 0;
	uint32_t idx1 = 0;
	uint32_t idx2 = 0;
	if (len >= 12)
		memcpy(&sid, pkt + 4, sizeof sid);
	if (len >= 16)
		memcpy(&idx1, pkt + 12, sizeof idx1);
	if (len >= 20)
		memcpy(&idx2, pkt + 16, sizeof idx2);
	if (type == MSG_REQUEST_CONNECT) {
		hal_debug(LOG_EVERYTHING,
		          "netif: RX if=%d %u.%u.%u.%u:%u len=%d mt=1 msg1 sid=%016llx sender=%08x\n",
		          iface, a, b, c, d, (unsigned)src_port, len,
		          (unsigned long long)sid, (unsigned)idx1);
		return;
	}
	if (type == MSG_RESPONSE_CONNECT) {
		hal_debug(LOG_EVERYTHING,
		          "netif: RX if=%d %u.%u.%u.%u:%u len=%d mt=2 msg2 sid=%016llx sender=%08x receiver=%08x\n",
		          iface, a, b, c, d, (unsigned)src_port, len,
		          (unsigned long long)sid, (unsigned)idx1, (unsigned)idx2);
		return;
	}
	if (type == MSG_DATA) {
		hal_debug(LOG_EVERYTHING,
		          "netif: RX if=%d %u.%u.%u.%u:%u len=%d mt=4 msg4 sid=%016llx receiver=%08x\n",
		          iface, a, b, c, d, (unsigned)src_port, len,
		          (unsigned long long)sid, (unsigned)idx1);
		return;
	}
	hal_debug(LOG_EVERYTHING, "netif: RX if=%d %u.%u.%u.%u:%u len=%d mt=%d\n",
	          iface, a, b, c, d, (unsigned)src_port, len, type);
}

static void rx_packet(int iface, uint32_t src_ip4, uint16_t src_port,
                      uint8_t *pkt, int len) {
	if (len < 1)
		return;
	// The receive counterpart of link_send's trace, and for the same reason:
	// without it, "no reply arrived" and "a reply arrived and we dropped it" look
	// identical in the log. Gated at LOG_EVERYTHING, so it is cheap.
	//
	// The header is dumped, not just the length. session_id is what the relay
	// routes on and it pins each session to an endpoint pair, so a packet the
	// relay refused is only explicable by reading the same field both sides read;
	// sender/receiver_index name the wg session halves.
	log_rx_header(iface, src_ip4, src_port, pkt, len);
	if (ntp_receive(src_port, pkt, len))            // not a wg message at all
		return;
	switch (pkt[0]) {
	case MSG_REQUEST_CONNECT: {                       // inbound msg1
		if (len != (int)sizeof(struct msg1))
			return;
		uint8_t who[KEY_LEN];
		if (peer_handshake_extract_static((struct msg1 *)pkt, who) != 0)
			return;
		struct link *l = link_find(who);
		bool fresh = false;

		// Crossing handshakes: their msg1 arrives while ours is in flight. One
		// struct peer holds one handshake, so processing theirs would overwrite
		// ours. The higher static key is the designated initiator, and both ends
		// compare the same pair, so exactly one yields.
		if (l && l->state == LINK_HANDSHAKING) {
			if (memcmp(public_key, who, KEY_LEN) > 0) {
				hal_debug(LOG_WARNING,
					"netif: %08x crossed handshakes — we initiate, ignoring theirs\n",
					(unsigned)get_part_key(who));
				return;                               // they will converge on our msg2
			}
			hal_debug(LOG_WARNING,
				"netif: %08x crossed handshakes — they initiate, yielding\n",
				(unsigned)get_part_key(who));
			// Its payload was already dropped as FRAME_PENDING, so nothing is lost.
			memset(l, 0, sizeof *l);                  // reuse the slot, now FREE
			fresh = true;
		} else if (!l) {
			l = link_take();
			if (!l)
				return;
			fresh = true;
		}
		// A live link keeps its slot and its tenants through a rekey; only its
		// session and, with it, its endpoint binding are replaced (below).
		if (fresh) {
			peer_init(&l->peer);
			l->last_activity_ms = now_ms();   // memset slot: start its clock now
		}
		uint8_t src[NETIF_ADDR_IP4_LEN];              // return-routability material
		memcpy(src, &src_ip4, 4);
		memcpy(src + 4, &src_port, 2);
		if (peer_handshake_request_process(&l->peer, (struct msg1 *)pkt,
		                                   src, sizeof src, NULL) != 0)
			return;                                   // refused by the admission gate
		// Only now is it known WHO this is: msg1 carries the initiator's static
		// key encrypted, and msg2 is the first message the PSK takes part in.
		apply_psk(&l->peer, l->peer.remote_static_public);
		// The binding follows the session. This msg1 may be the peer rekeying the
		// link — either side may — and a rekey mints a new session, which the
		// relay pins to a new endpoint pair, with our login endpoint as the far
		// side because it resolved us through our login route. So the link must
		// answer, and go on sending, from the socket this arrived on; rebinding
		// only for a fresh slot leaves a link we opened ourselves replying out of
		// the anon socket, an endpoint that session was never bound to, and the
		// relay drops the msg2 and every frame after it.
		//
		// This happens after the handshake is processed, never before: until it
		// authenticates, the source address is an unverified claim, and honouring
		// it would let a spoofed msg1 repoint a live link at an attacker.
		int alen = 0;
		addr_encode(l->addr, &alen, src_ip4, src_port);
		l->addr_len = (uint8_t)alen;
		struct msg2 m2;
		if (peer_response_generate(&l->peer, &m2) != 0)
			return;
		link_send(l, &m2, sizeof m2);
		l->state           = LINK_ALIVE;
		l->handshake_at_ms = now_ms();
		deliver(l, FRAME_PEER_UP, NULL, 0);
		break;
	}
	case MSG_RESPONSE_CONNECT: {                      // msg2: our handshake answered
		if (len != (int)sizeof(struct msg2))
			return;
		for (int i = 0; i < NETIF_LINKS; i++) {
			struct link *l = &links[i];
			if (l->state != LINK_HANDSHAKING)
				continue;
			if (peer_response_process(&l->peer, (struct msg2 *)pkt) != 0)
				continue;
			l->state            = LINK_ALIVE;
			l->handshake_at_ms  = now_ms();
			l->last_activity_ms = now_ms();
			// An activation succeeds by becoming a login. The protocol has no
			// separate "activated" reply, msg2 being the whole answer, so the
			// identity is live from here and the application must persist it.
			if (l == &links[LINK_SERVER] && activation_in_flight) {
				activation_in_flight = false;
				crypto_zero(activation_code, sizeof activation_code);
				hal_debug(LOG_WARNING, "netif: activated as %08x\n",
				          (unsigned)get_part_key(public_key));   // public, never private_key
				on_identity_result(true, private_key, 0);
			}
			deliver(l, FRAME_PEER_UP, NULL, 0);
			break;
		}
		break;
	}
	case MSG_ACTIVATION_FAILED: {                     // msg6: the code was refused
		if (len < (int)sizeof(struct msg_activation_failed))
			return;
		const struct msg_activation_failed *f = (const struct msg_activation_failed *)pkt;
		if (!activation_in_flight)
			return;
		// Correlate on the session id we minted, so a stray or forged msg6 cannot
		// abort someone else's activation — the id is the only thing tying this
		// unauthenticated message to our attempt.
		if (f->session_id != links[LINK_SERVER].peer.session_id)
			return;
		int reason = f->reason;
		uint8_t refused[KEY_LEN];
		memcpy(refused, private_key, KEY_LEN);   // identity_clear zeroes private_key
		hal_debug(LOG_ERROR, "netif: activation refused, reason=%d\n", reason);
		identity_clear();
		on_identity_result(false, refused, reason);
		break;
	}
	case MSG_COOKIE_REPLY: {                          // msg3: DoS challenge
		if (len != (int)sizeof(struct msg3))
			return;
		// The query draws cookies too. It is built like a handshake —
		// peer_query_generate computes a mac2 exactly as msg1 does — but it is not
		// a link, so walking the link pool alone would silently drop its
		// challenge. Every retry would then go out with a zero mac2, be challenged
		// again, and the query would time out having been answered every time.
		if (lookup.busy && peer_cookie_process(&lookup.peer_query.peer, (struct msg3 *)pkt)) {
			// A challenge is a protocol step, not a lost packet, so it must not
			// cost the retry budget: otherwise a cookie-enforcing server can
			// exhaust us before a single mac2-bearing query is ever sent.
			lookup.retries_left = netif_handshake_retries;
			query_send();                             // resend NOW, with mac2
			break;
		}
		// A LINK NEEDS THE SAME TREATMENT, and taking the cookie is only half of
		// it. Storing it and waiting for the retransmit timer spends the budget
		// on msg1s that were ANSWERED -- with a challenge -- so a cookie-enforcing
		// relay exhausts the link before a mac2-bearing msg1 goes out, and the
		// link dies "handshake unanswered" having been answered every time.
		// Device-observed 2026-08-29: one peer pair could not open a link at all
		// in one direction while the reverse worked, and the relay's own log said
		// `on_msg1_to_client: dest ... challenged with cookie` for every attempt.
		for (int i = 0; i < NETIF_LINKS; i++) {
			if (links[i].state == LINK_HANDSHAKING &&
			    peer_cookie_process(&links[i].peer, (struct msg3 *)pkt)) {
				links[i].retries_left = netif_handshake_retries;
				handshake_send(&links[i]);        // resend NOW, with mac2
				break;
			}
		}
		break;
	}
	case MSG_DATA: {                                  // msg4: a frame
		static uint8_t plain[MAX_PACKET_SIZE];
		bool consumed = false;
		for (int i = 0; i < NETIF_LINKS; i++) {
			struct link *l = &links[i];
			// A rekey is not an outage on receive either: a handshaking link
			// whose previous handshake is inside wg's reject window still
			// holds working keys, and its peer is still sending under them.
			// Skipping it here drops every inbound frame for the whole rekey
			// window.
			bool usable = false;
			if (l->state == LINK_ALIVE) {
				usable = true;
			} else if (l->state == LINK_HANDSHAKING && l->handshake_at_ms) {
				if ((uint32_t)(now_ms() - l->handshake_at_ms) < REJECT_AFTER_TIME * 1000UL)
					usable = true;
			}
			if (!usable)
				continue;
			int n = rx_data(plain, &l->peer, (struct msg4 *)pkt, (size_t)len);
			if (n <= 0)
				continue;
			l->last_activity_ms = now_ms();
			// `plain` is BORROWED for the duration of this call — see netif.h.
			// frame_write() re-entering from inside is expected: send-on-receive
			// is the common case, and nothing below iterates links afterwards.
			deliver(l, FRAME_DATA, plain, n);
			consumed = true;
			break;
		}
		// A dropped data frame has to say so, or "no reply came" and "a frame
		// came and we dropped it" are indistinguishable. Throttled to one line a
		// second, media arriving at 25 fps.
		if (!consumed) {
			static uint32_t drop_log_ms;
			uint32_t now = now_ms();
			if ((uint32_t)(now - drop_log_ms) >= 1000) {
				drop_log_ms = now;
				hal_debug(LOG_WARNING, "netif: RX data frame no link decrypts (len=%d)\n", len);
			}
		}
		break;
	}
	case MSG_CONTACT_RESPONSE: {                      // msg8: our query answered
		if (!lookup.busy)
			return;
		uint8_t  status = 0;
		uint8_t  full[KEY_LEN];
		uint32_t ip4 = 0;
		uint16_t port = 0;
		if (!query_decode(pkt, (uint16_t)len, &status, full, &ip4, &port))
			return;      // not for us, or it failed to authenticate: keep waiting
		if (status != 0) {
			query_settle_addr(NULL, 0, QUERY_NOUSER); // a VERDICT about them
			return;
		}
		if (get_part_key(full) != get_part_key(lookup.key))
			return;                                   // answered a different partkey
		memcpy(lookup.key, full, KEY_LEN);           // the key is now complete
		uint8_t addr[NETIF_ADDR_MAX];
		int     alen = 0;
		addr_encode(addr, &alen, ip4, port);
		query_settle_addr(addr, alen, QUERY_FOUND);
		break;
	}
	default:
		break;                                        // not ours; the platform's hook has it
	}
}

static void drain(net_sock *sk, int iface) {
	if (!sk)
		return;
	static uint8_t pkt[MAX_PACKET_SIZE];
	uint32_t ip4;
	uint16_t port;
	// Drain everything queued: voice arrives at 25 fps and one packet per tick
	// overruns the receive buffer.
	for (;;) {
		int n = net_recv(sk, &ip4, &port, pkt, sizeof pkt);
		if (n <= 0)
			return;
		rx_packet(iface, ip4, port, pkt, n);
	}
}

// ---- the API ---------------------------------------------------------------
void frame_init(struct device_record *cfg, netif_on_frame cb,
                netif_resolve_cb resolve, netif_psk_cb psk) {
	memset(links,  0, sizeof links);
	memset(&lookup, 0, sizeof lookup);
	device      = cfg;
	on_frame       = cb;
	resolve_addr  = resolve;
	resolve_psk   = psk;
	identity_socket = net_open(0);       // ephemeral: phone + relay can share a host
	anon_socket     = NULL;              // opened on first use by open_anon_socket()
	interface_ready       = (identity_socket != NULL && device != NULL);
	// Seed wg's static identity. This is why init must follow unlock: without the
	// private key there is no handshake, no query, and no way to authenticate an
	// inbound msg1, so netif would be up with nothing it could do.
	activation_in_flight = false;
	if (device) {
		memcpy(private_key, device->my_private_key, KEY_LEN);
		identity_apply();
	}
	if (!interface_ready)
		hal_debug(LOG_ERROR, "netif: not up (socket=%d cfg=%d)\n",
		          identity_socket != NULL, device != NULL);
}

netif_state frame_pump(void) {
	if (!interface_ready)
		return NETIF_DOWN;
	drain(identity_socket, INTERFACE_IDENTITY);
	drain(anon_socket,     INTERFACE_ANON);
	if ((int32_t)(now_ms() - ntp_at_ms) >= 0)
		ntp_send();
	if (lookup.busy && (int32_t)(now_ms() - lookup.next_retry_ms) >= 0) {
		if (lookup.retries_left == 0)
			query_settle_addr(NULL, 0, QUERY_TIMEOUT);   // about us, not about them
		else
			query_send();
	}
	login_pump();
	for (int i = LINK_SERVER + 1; i < NETIF_LINKS; i++) {   // login_pump owns slot 0
		struct link *l = &links[i];
		if (l->state == LINK_FREE)
			continue;
		uint32_t now = now_ms();
		if (l->state == LINK_HANDSHAKING) {
			if ((int32_t)(now - l->next_retry_ms) < 0)
				continue;
			if (l->retries_left == 0) {
				link_release(l, "handshake unanswered");
				continue;
			}
			handshake_send(l);
			continue;
		}
		// Peer links rekey as well as the login one. Without this a long-lived
		// peer session ages past wg's reject window and the relay's route TTL
		// while both ends keep transmitting into the void. Initiator side only:
		// our fresh msg1 renews the responder's session and re-pins the relay
		// route for both of us, whereas a responder initiating through the relay
		// has no route of its own to ride.
		if (l->state == LINK_ALIVE && l->peer.is_initiator &&
		    (int32_t)(now - l->handshake_at_ms) > (int32_t)netif_rekey_ms) {
			l->state        = LINK_HANDSHAKING;
			l->retries_left = netif_handshake_retries;
			handshake_send(l);
			continue;
		}
		// A link whose keys have aged past wg's reject window is dead whatever
		// its state says. The initiator rekeys at netif_rekey_ms, so only a
		// link whose peer vanished — or the responder side, whose renewals
		// stopped arriving — ever gets here; holding such a link alive makes a
		// zombie that frame_write feeds forever while the relay drops every
		// frame. Aged on inbound traffic, never on handshakes: a peer retrying
		// its way to us restamps handshake_at_ms, not last_activity_ms.
		if (l->state == LINK_ALIVE &&
		    (uint32_t)(now - l->last_activity_ms) >= REJECT_AFTER_TIME * 1000UL) {
			link_release(l, "no traffic");
			continue;
		}
	}
	// The login link IS the login status — there is no second flag to drift out
	// of step with it.
	switch (links[LINK_SERVER].state) {
	case LINK_ALIVE:
		return NETIF_ONLINE;
	case LINK_HANDSHAKING:
		// A rekey is not an outage. A non-zero handshake_at_ms means this link
		// completed a handshake before, so we still hold working keys and are
		// merely refreshing them; reporting JOINING here would flap the UI's
		// online indicator every rekey period. Retry exhaustion clears the slot,
		// which zeroes handshake_at_ms and drops us to DOWN honestly.
		if (links[LINK_SERVER].handshake_at_ms)
			return NETIF_ONLINE;
		return NETIF_JOINING;
	default:
		return NETIF_DOWN;
	}
}

bool remote_query(const uint8_t *key) {
	if (!interface_ready || !key)
		return false;
	if (lookup.busy)
		return false;            // exactly one in flight, which is the rate limit
	memset(&lookup, 0, sizeof lookup);
	memcpy(lookup.key, key, KEY_LEN);
	memcpy(lookup.peer_query.peer.remote_static_public, device->server_static_public, KEY_LEN);
	lookup.busy         = true;
	lookup.retries_left = netif_handshake_retries;
	query_send();
	return true;
}

// Retire a link, on the caller's own evidence that the peer no longer holds it.
// This is not a rekey: we forget the peer entirely, and the next
// netif_open_route() or send builds a fresh handshake, which the peer completes
// into whatever slot it still holds for us or a new one. The app that can see
// nothing coming back is the only thing that can know, silence being the only
// evidence the protocol offers — an unanswerable frame draws no reply and cannot
// even name its sender.
void netif_drop_route(const uint8_t peer_key[32]) {
	if (!interface_ready || !peer_key)
		return;
	struct link *l = link_find(peer_key);
	if (!l)
		return;
	link_release(l, "retired by the app: nothing coming back");
}

// Open the link to this peer if none exists, and do nothing at all if one does.
// No timers, no keepalives and no standing claim — the handshake itself is the
// point, since the peer's PEER_UP fires its pending-message flush toward us. The
// chat screen calls this once at open to drain what the remote holds.
void netif_open_route(const uint8_t peer_key[32]) {
	if (!interface_ready || !peer_key)
		return;
	if (link_find(peer_key))
		return;
	link_open(peer_key);
}

// Keep one destination's NAT mapping and relay route warm with an authenticated
// blank frame — transport type 0, which every peer drops by contract
// (peer_data.h). Which contact deserves this is policy and lives in the app;
// this is only the mechanism. Throttled internally to netif_keepalive_ms, so the
// caller may pump it every tick.
void netif_refresh_route(const uint8_t peer_key[32]) {
	if (!interface_ready || !peer_key)
		return;
	uint32_t now = now_ms();
	uint32_t dest_partkey = get_part_key((uint8_t *)peer_key);
	bool link_seen = false;
	for (int i = LINK_SERVER + 1; i < NETIF_LINKS; i++) {
		struct link *l = &links[i];
		if (l->state == LINK_FREE)
			continue;
		if (get_part_key(l->peer.remote_static_public) != dest_partkey)
			continue;
		link_seen = true;
		if (l->state != LINK_ALIVE)
			continue;
		if ((int32_t)(now - l->refresh_at_ms) < 0)
			return;
		l->refresh_at_ms = now + netif_keepalive_ms;
		uint8_t blank[32];
		fill_random(blank, sizeof blank);
		blank[0] = 0;                      // type 0: reserved, receiver drops
		static uint8_t m4[MAX_PACKET_SIZE];
		int n = tx_data((struct msg4 *)m4, &l->peer, blank, sizeof blank);
		if (n > 0)
			link_send(l, m4, n);
		return;
	}
	// With no link at all, warming the route means opening it: the handshake is
	// itself the prod, since the peer's PEER_UP fires its pending-message flush
	// toward us. Throttled like the blank frames, so a pump-speed caller cannot
	// spam handshakes at an offline peer. One throttle slot suffices, a device
	// tuning to one contact at a time.
	if (!link_seen) {
		static uint32_t open_throttle_pk;
		static uint32_t open_throttle_at_ms;
		if (open_throttle_pk == dest_partkey &&
		    (int32_t)(now - open_throttle_at_ms) < 0)
			return;
		open_throttle_pk    = dest_partkey;
		open_throttle_at_ms = now + netif_keepalive_ms;
		link_open(peer_key);
	}
}

bool netif_route_alive(uint32_t dest_partkey) {
	if (!interface_ready)
		return false;
	uint32_t now = now_ms();
	for (int i = 0; i < NETIF_LINKS; i++) {
		// A rekey is not an outage, but only while the old keys still work. A
		// handshaking link that completed a handshake within wg's reject window
		// is merely refreshing its keys and still carries traffic; past
		// REJECT_AFTER_TIME the old session is dead and "alive" would be a lie,
		// so a bare non-zero handshake_at_ms will not do — that latches on
		// through an arbitrarily long failed rekey. Counting only LINK_ALIVE has
		// the opposite defect: a false "Connecting..." for every rekey window.
		bool usable = false;
		if (links[i].state == LINK_ALIVE) {
			usable = true;
		} else if (links[i].state == LINK_HANDSHAKING && links[i].handshake_at_ms) {
			if ((uint32_t)(now - links[i].handshake_at_ms) < REJECT_AFTER_TIME * 1000UL)
				usable = true;
		}
		if (usable &&
		    get_part_key(links[i].peer.remote_static_public) == dest_partkey)
			return true;
	}
	return false;
}

frame_status frame_write(const uint8_t peer_key[32], const uint8_t *data, int len) {
	if (!interface_ready || !peer_key || !data || len <= 0)
		return FRAME_FAILED;
	struct link *l = link_find(peer_key);
	if (!l) {
		// Bring-up is implicit and the frame is dropped: the interface does not
		// queue the caller's bytes.
		if (link_open(peer_key))
			return FRAME_PENDING;
		return FRAME_FAILED;
	}
	if (l->state != LINK_ALIVE)
		return FRAME_PENDING;
	// tx_data requires a plaintext that is a multiple of 32 bytes and returns -2
	// otherwise, so the frame is padded here with random bytes and the receiver
	// reads the real length from the frame's own len field.
	static uint8_t cleartext[MAX_PACKET_SIZE];
	size_t total = ((size_t)len + 31u) & ~(size_t)31u;
	if (total > sizeof cleartext)
		return FRAME_FAILED;
	memcpy(cleartext, data, (size_t)len);
	if (total > (size_t)len)
		fill_random(cleartext + len, total - (size_t)len);

	static uint8_t m4buf[MAX_PACKET_SIZE];
	int n = tx_data((struct msg4 *)m4buf, &l->peer, cleartext, total);
	if (n <= 0)
		return FRAME_FAILED;
	// Sending proves nothing. Every flow here is two-way — voice, PTT's returned
	// frame, the stream's ack — so a link that works answers.
	if (link_send(l, m4buf, n))
		return FRAME_SENT;
	return FRAME_FAILED;
}
