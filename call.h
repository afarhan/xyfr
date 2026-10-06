#pragma once
//
// call.h - voice calls (app_call.c).
//
// The first inbound voice frame is the call. Nothing else is signalled:
// ringing and answering are local, and a hangup sends nothing - the peer's
// next frame draws CALL_ENDED. A call is named by a call_handle, minted once
// and never reused, so a stale handle fails rather than landing on another
// call. The transmitted call_id is app_call.c's own business.
//
// Peers are remote_userids. Core 0.

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t call_handle;      // 0 = none

enum call_phase {
	CALL_FREE = 0,                 // no call, or a handle that died
	CALL_PHASE_OUTGOING,           // we called; waiting for the peer's first voice
	CALL_PHASE_INCOMING,           // they called; ringing, not yet answered
	CALL_PHASE_ACTIVE,             // media both ways
	CALL_PHASE_ENDED,              // lingers on screen, then freed
};

void call_init(void);

// 0 if no slot is free or the peer is already in a call.
call_handle call_originate(uint32_t remote_userid);

bool call_answer(call_handle call);   // INCOMING -> ACTIVE
bool call_hangup(call_handle call);   // -> ENDED; sends nothing

enum call_phase call_phase_of(call_handle call);

call_handle call_of_peer(uint32_t partkey);   // 0 = that peer is in no call
call_handle call_holding_audio(void);         // 0 = nothing owns mic + speaker
call_handle call_ringing(void);               // 0 = nothing is ringing
uint32_t    call_peer_of(call_handle call);   // partkey, 0 if the handle is stale

// From kernel.c: everything after the common header (call_id, subtype, media).
void call_frame_in(uint32_t remote_userid, const uint8_t *body, int len);

// Timeouts, ENDED linger, ringback and the mic. Every tick.
void call_pump(void);

#ifdef __cplusplus
}
#endif
