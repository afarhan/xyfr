#ifndef RELAY_TUNNEL_H
#define RELAY_TUNNEL_H

/*
 * relay_tunnel — the framing for a client control packet carried inside a
 * relay<->server msg4. Shared verbatim by relay.c (wrap on the way up,
 * unwrap replies coming down) and server.c (unwrap on ingress, wrap replies).
 *
 * Once a relay has authenticated its own login to the server, it stops
 * forwarding client msg1/msg5/msg7 to the server in the clear and instead
 * tunnels each one as the payload of an msg4 on its authenticated session.
 * The msg4 AEAD tag proves the packet came from that relay; the server unwraps
 * and processes the inner datagram, then wraps its reply back the same way.
 * The relay routes an unwrapped reply to the client with its normal route
 * table (the reply's own session_id is unchanged by wrapping).
 *
 * Plaintext layout (what tx_data encrypts / rx_data returns):
 *     [tag:1 = DATA_RELAY_TUNNEL][inner_len:2 BE][inner datagram][zero-pad -> 32]
 * tx_data enforces a 32-byte-aligned plaintext, hence the pad.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* First byte of the tunnel plaintext. Private to the relay<->server session
 * (a peer session's DATA_* types never reach this path), so any distinctive
 * value works; 'R' keeps dumps readable. */
#define DATA_RELAY_TUNNEL  0x52

/* Wrap `inner` (inner_len bytes) into `out` as tx_data plaintext. Returns the
 * padded length (a multiple of 32) to hand to tx_data, or 0 if it wouldn't
 * fit in out_cap. */
static inline size_t relay_tunnel_wrap(uint8_t *out, size_t out_cap,
                                       const uint8_t *inner, size_t inner_len){
  size_t raw = 3 + inner_len;
  size_t padded = (raw + 31u) & ~(size_t)31u;
  if (padded > out_cap)
    return 0;
  out[0] = DATA_RELAY_TUNNEL;
  out[1] = (uint8_t)(inner_len >> 8);
  out[2] = (uint8_t)(inner_len & 0xff);
  memcpy(out + 3, inner, inner_len);
  if (padded > raw)
    memset(out + raw, 0, padded - raw);
  return padded;
}

/* Inverse of relay_tunnel_wrap over an rx_data plaintext of plain_len bytes.
 * On a well-formed frame sets *inner / *inner_len to the embedded datagram and
 * returns 1; otherwise returns 0. */
static inline int relay_tunnel_unwrap(const uint8_t *plain, size_t plain_len,
                                      const uint8_t **inner, size_t *inner_len){
  if (plain_len < 3 || plain[0] != DATA_RELAY_TUNNEL)
    return 0;
  size_t n = ((size_t)plain[1] << 8) | plain[2];
  if (3 + n > plain_len)
    return 0;
  *inner = plain + 3;
  *inner_len = n;
  return 1;
}

#endif /* RELAY_TUNNEL_H */
