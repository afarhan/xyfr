#pragma once
//
// peer_data.h — the cleartext frame inside a msg4 between two peers.
//
// Every frame starts with the 4-byte common header below, and that is all the
// router reads: transport says datagram or stream, port says which app within
// that transport, len says how many bytes follow (the app's own header and
// payload, not the pad). The frame is then padded with random bytes to a
// multiple of 32 (netif.c). Each transport has its own port space, so datagram
// port 1 and stream port 1 are different apps.
//
// PORT_VOICE frames add call_id(2) and subtype(2), then media. DATA_STREAM
// frames add seq(4), ack(4), window(2), then bytes; that header is struct
// stream_hdr in stream.c.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
struct data_hdr {
	uint8_t  transport;   // DATA_DATAGRAM / DATA_STREAM
	uint8_t  port;        // PORT_* within that transport
	uint16_t len;         // be: bytes after this header
};
#pragma pack(pop)

#define DATA_HEADER_LEN  ((int)sizeof(struct data_hdr))
#define VOICE_HEADER_LEN 4   // call_id + subtype

#define DATA_DATAGRAM    1   // unreliable, delivered on arrival: media
#define DATA_STREAM      9   // reliable byte stream (stream.c)
// Retired transport values, never to be reused: 2 TEXT, 3 BYE, 4 ANSWER,
// 5 CALL_ENDED, 6 TICP, 7 PTT, 8 MESSAGE. An old peer may still send them.

#define PORT_VOICE       1   // datagram: app_call.c (media, call-ended, PTT)
#define PORT_MSG         1   // stream: msg.c
#define PORT_TERM        2   // stream: app_terminal.c
#define PORT_CHANNEL     3   // stream: app_channel.c

// PORT_VOICE subtype: low byte is what the frame is, high byte how the media
// is encoded.
#define VOICE_SUB_MEDIA       0x0000u   // int16 LE PCM, 8 kHz mono
#define VOICE_SUB_CALL_ENDED  0x0001u   // zero-length; sent in reply to voice on a dead call_id
#define VOICE_SUB_PTT         0x0002u   // push-to-talk media: plays on arrival
#define VOICE_SUB_KIND_MASK   0x00FFu
#define VOICE_SUB_CODEC_MASK  0xFF00u

// A voice frame whose call_id is within this many below the last one seen is a
// straggler from a finished call and is answered with CALL_ENDED. Anything else
// is a new call. call_ids start random per peer and wrap.
#define CALL_ID_STALE_WINDOW 5

// Big-endian <-> host. Both targets are little-endian; the guard keeps a
// big-endian host correct.
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint16_t be16(uint16_t v) { return v; }
static inline uint32_t be32(uint32_t v) { return v; }
#else
static inline uint16_t be16(uint16_t v) { return __builtin_bswap16(v); }
static inline uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }
#endif

#ifdef __cplusplus
}
#endif
