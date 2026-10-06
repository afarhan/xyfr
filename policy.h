#pragma once
//
// policy.h — the single source of INBOUND ADMISSION logic.
//
// Two orthogonal device settings drive it (storage.h): device_record.presence
// (Normal/Busy/NoCalls/Offline — reachability) and device_record.allow_policy
// (AllowAll/Contacts — who may handshake at all), plus per-contact flags
// (CONTACT_BLOCKED / CONTACT_STAR). It is consulted at TWO points:
//   - the wg handshake gate (validate_public_key) -> admit_handshake(), which
//     governs BOTH calls and messages (they share one Noise handshake);
//   - real-time MEDIA arrival -> admit_media(), consulted by call.c
//     (voice_handle_inbound) and ptt.c (ptt_handle_inbound), because "it's a
//     call / it's PTT" isn't known until the first DATA frame. Media is
//     CONTACTS-ONLY in all cases; messages are not.
//
// Portable C (device + host), core 0. No UI/hardware access.
//
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// admit_media() verdicts.
#define ADMIT_RING    0   // ring the local speaker + show + answerable (Normal, or Busy+Star)
#define ADMIT_SILENT  1   // accept the call but NO local ring (Busy+non-Star, or NoCalls);
                          //   caller still gets ringback and the call still logs/shows.
#define ADMIT_REJECT  2   // not admitted at all — no call object, no audio, no ringback.

// Handshake accept gate. Returns 1 to accept the inbound handshake, 0 to reject.
// Enforces: presence==Offline -> reject all; per-contact Blocked -> reject;
// allow_policy==Contacts -> require a VALID contact whose full key matches.
int admit_handshake(const uint8_t *public_key);

// REAL-TIME MEDIA arrival gate — inbound voice (call.c voice_handle_inbound) and
// PTT (ptt.c ptt_handle_inbound). Returns ADMIT_*.
//
// CONTACTS ONLY, ALWAYS — independent of allow_policy. A stranger that clears
// admit_handshake (a registered member) may TEXT you: that is asynchronous, read
// when you choose, and bounded by the logbook. It may NOT make your device ring
// or push audio out of your speaker. Those channels put a stranger in your room
// with no user action, so they require a contact relationship, not merely
// membership of the network. Non-contact => ADMIT_REJECT.
int admit_media(uint32_t partkey);

// Per-contact flag tests over contact.settings. false if not a contact.
bool contact_is_star(uint32_t partkey);
bool contact_is_blocked(uint32_t partkey);

#ifdef __cplusplus
}
#endif
