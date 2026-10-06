#pragma once
//
// stream.h — a reliable byte stream between two contacts on a port.
//
// A stream is (peer, port). An app binds its port once with stream_listen and
// gets a handle; every call names that handle, so an app cannot reach a port
// it does not hold. A peer is named by userid; the slot holds the key.
//
// A write to a peer with no stream creates one. There is no open, close or
// handshake. One segment is in flight at a time; a write while one is in
// flight returns 0. An unread segment is not acked, so the peer stops.
//
// Apps do not include this: kernel.c owns the bindings and delivers the
// events. The algorithm is in stream.c.
//
// Core 0. Portable C.

#include <stdint.h>
#include <stdbool.h>

#include "peer_data.h"   // PORT_*

#ifdef __cplusplus
extern "C" {
#endif

#define STREAM_SLOTS_DEFAULT 10

typedef uint32_t stream_handle;   // 0 = none

stream_handle stream_listen(uint16_t app_port);   // 0 if another app holds it
void          stream_stop(stream_handle handle);

void stream_init(int slots);
int  stream_slot_count(void);
void stream_pump(void);           // retransmit, reap, and the only place an app is entered

// From the DATA_STREAM demux.
void stream_process_incoming(const uint8_t peer[32], const uint8_t *seg, int len);

// Bytes taken; 0 when a segment is in flight or the peer is not a contact.
int  stream_write(stream_handle handle, uint32_t remote_userid,
                  const uint8_t *data, int len);
int  stream_read(stream_handle handle, uint32_t remote_userid, uint8_t *out, int max);

// Room in bytes. 0 means not now, for every reason.
int  stream_can_read(stream_handle handle, uint32_t remote_userid);
int  stream_can_write(stream_handle handle, uint32_t remote_userid);

bool stream_exists(stream_handle handle, uint32_t remote_userid);

#ifdef __cplusplus
}
#endif
