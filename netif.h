#pragma once
//
// netif.h — exchange frames with a peer identified by its 32-byte public key.
//
// THE MEDIUM IS NOT PART OF THE CONTRACT. UDP over a relay today; a LoRa or
// optical link tomorrow. Nothing above this file may contain the word "relay",
// an ip:port, or a socket — addresses cross as an opaque blob the application
// stores and hands back.
//
// ADDRESSING IS BY FULL KEY, never partkey: a 4-byte collision is an explicit
// threat, so a prefix must never identify a peer at the layer that
// authenticates whole identities.
//
// PUSH, NOT PULL. There is no frame_read(): a "call until empty" contract, got
// wrong once, overruns the receive buffer at 25 fps voice. Two rules for the
// callback — `data` is borrowed and valid only for that call, and frame_write()
// must be safe to call from inside it, because send-on-receive is the norm.
//
// A LINK IS NOT A SOCKET. It has no single owner: call, stream, PTT and message
// share one. "A link exists" therefore never implies "my thing on it exists" —
// ask your own state. Liveness reaches you as FRAME_FAILED or your own timeout,
// which is why there is nothing here to poll.
//
// THE LOGIN AND THE QUERY LIVE HERE. Both are the same retry machine as a
// handshake, carrying a different payload, driven by the same pump — msg7 is no
// more a layer above netif than ARP is a layer above ethernet.
//
// Core 0. Portable C.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	FRAME_DATA = 0,
	FRAME_PEER_UP,
} frame_event;

typedef enum {
	FRAME_SENT = 0,
	FRAME_PENDING,     // no link yet; bring-up started and THIS FRAME WAS DROPPED
	FRAME_FAILED,
} frame_status;

typedef enum {
	NETIF_DOWN = 0,
	NETIF_JOINING,
	NETIF_ONLINE,
} netif_state;

typedef void (*netif_on_frame)(const uint8_t peer_key[32],
                               frame_event ev, const uint8_t *data, int len);

// "Where does this key live?" Answered from the application's own store, at
// link bring-up only. netif keeps no address cache.
typedef bool (*netif_resolve_cb)(const uint8_t peer_key[32],
                                 uint8_t *addr, int *addr_len);

// The pre-shared key for a peer, or false when it has none. Asked the same way
// the address is, and for the same reason: this layer addresses peers by key
// and holds no directory, so the app answers. A peer with no PSK handshakes
// exactly as before -- an all-zero one is what WireGuard means by "none".
typedef bool (*netif_psk_cb)(const uint8_t peer_key[32], uint8_t psk[32]);

#define NETIF_ADDR_MAX 8

// The only two functions above netif.c that may know an address is an ip4:port.
// Exported so the layout has one definition rather than two that drift.
void netif_addr_from_ip4(uint8_t *addr, int *addr_len, uint32_t ip4, uint16_t port);
bool netif_addr_to_ip4(const uint8_t *addr, int addr_len, uint32_t *ip4, uint16_t *port);

// Call once, AFTER the store is unlocked: without the private key netif can
// neither handshake nor authenticate. `cfg` is held as a pointer, so a runtime
// endpoint edit needs no re-init.
struct device_record;
void frame_init(struct device_record *cfg, netif_on_frame cb,
                netif_resolve_cb resolve, netif_psk_cb psk);

// Drains sockets, delivers, and advances every timer: login, keepalive,
// handshake retry, rekey, idle reaping, the query, time sync. Call every tick.
netif_state frame_pump(void);

// Is there a live route to this destination? For deciding whether silence means
// "packets are being lost" or "the peer is gone": a peer that went offline fails
// its rekey, so its route falls away while a lossy-but-present one keeps its.
// netif is the source of truth for that, and nothing else can tell the two
// apart.
//
// Keyed by partkey, like every other route in the system — the relay's table,
// msg1.sender_index, the contact directory. Addressing still takes the full key
// (frame_write); this only asks about one we already hold.
//
// NOT a liveness query for a tenant's own work: a route says nothing about
// whether your call or your stream still exists.
bool netif_route_alive(uint32_t dest_partkey);

// Keep this destination's route warm, throttled internally — the "tuned
// frequency" a push-to-talk app holds on its one active contact. An ALIVE link
// gets an authenticated blank frame (NAT mapping + relay route stay fresh); no
// link at all gets OPENED, the handshake doubling as the wake-up prod (the
// peer's PEER_UP flushes its pending messages toward us). Addressed by the
// full key, like every send. Call freely every tick.
void netif_refresh_route(const uint8_t peer_key[32]);

// Retire this link: forget the peer, so the next open/send handshakes afresh.
// For a caller holding its OWN evidence that the far end no longer has us — an
// app-level ack that stopped coming. Silence is the only such evidence there can
// be: a peer with no session for us cannot answer and cannot even tell who we
// are, so it drops our frames without a word.
void netif_drop_route(const uint8_t peer_key[32]);

// ONE HANDSHAKE, ONE LINK, PER PEER. An outbound handshake to a peer we already
// hold returns that link — an app cannot ask for a second one and cannot force a
// rekey of a live one. (A forced rekey used to exist for PTT's "prove the peer
// is there"; it re-handshook a working link on a NEW session, and since the relay
// pins each session to an endpoint pair, the reply and everything after it left
// from a socket that session was never bound to and the relay dropped it. Proving
// liveness is the app's own returned-frame ack, not a handshake.)
//
// Open the link if absent, nothing if present. The handshake prods the peer to
// flush its pending messages toward us (PEER_UP on their side). No keepalive, no
// standing claim — the chat screen's open-time drain, and PTT's screen-open sync.
void netif_open_route(const uint8_t peer_key[32]);

// How a peer link looks from above, for a screen that wants to say whether the
// person it is about is reachable. READ ONLY: no handshake is started, no clock
// is stamped, nothing is kept alive by asking.
typedef enum {
	NETIF_PEER_DOWN = 0,     // no link
	NETIF_PEER_TRYING,       // handshaking
	NETIF_PEER_UP,           // keys established
} netif_peer_state;
netif_peer_state netif_peer(const uint8_t peer_key[32]);


// The socket is netif's choice: a link we originate goes out anonymously, a
// link the peer originated answers on the identity socket, the login is the
// identity. Nothing above picks.
frame_status frame_write(const uint8_t peer_key[32], const uint8_t *data, int len);

// Complete a partial key and learn where that peer lives. One in flight at a
// time — that single slot is the rate limit. The answer is handed up and
// forgotten; storing it is the application's job.
#define QUERY_FOUND    0
#define QUERY_NOUSER   1   // a verdict about THEM
#define QUERY_TIMEOUT  2   // a statement about US — never confuse the two
bool remote_query(const uint8_t *key);
void on_query_response(const uint8_t key[32], const uint8_t *addr, int addr_len,
                       int status);

// Become `key`. With `activation` non-NULL this registers it, spending the code.
// There is no separate activation protocol: it is the login handshake with the
// msg_type flipped and the code carried in mac2, so success is the login coming
// up and failure is a msg6 reason. Modal — wg holds one static keypair, so a
// refusal leaves the device with NO identity (nothing preceded it; the code is
// only enabled on a wiped device). Persisting the key is the caller's job.
bool netif_setkey(const uint8_t key[32], const char *activation);
void on_identity_result(bool ok, const uint8_t key[32], int reason);

// Re-join now: for what invalidates a login without the link failing — a fresh
// association, a relay switch. Ordinary failure needs no help; the pump retries.
void netif_relogin(void);

// UTC seconds learned from the network, 0 if never obtained. One possible
// source of truth, not the system clock — the platform decides how to combine
// it with an RTC or GPS, which is why this returns 0 rather than guessing.
time_t net_time(void);

#ifdef __cplusplus
}
#endif
