#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// ===================== platform audio HAL =====================
// The ONLY file a port (e.g. the host CLI's ALSA backend) reimplements.
// Callers above this line — the .ino voice dispatch and the call/voice
// layer — talk to this interface and never touch the PWM/ADC drivers or
// the sample ring buffers.
//
// All audio is 8 kHz, 16-bit signed, mono. One transmitted voice frame is 320
// samples (40 ms, matching GSM 06.10 framing).

// ---- lifecycle ----
// Bring up the speaker + microphones and start the sample callbacks. Call
// once at boot, on the core that services the audio callbacks (core 0).
void audio_init(void);

// ---- voice path ----
// Hand a decoded voice frame (int16 little-endian PCM bytes, possibly odd-
// aligned) to the speaker. Enqueued for playback through the jitter buffer.
void audio_play_voice(const uint8_t *pcm_le, int len);

// PTT inbound playback — like audio_play_voice but at the speakerphone gain
// (speaker_volume * speakerphone_boost): a loud walkie-talkie broadcast. Route
// still follows handsfree_active. See ptt.c.
void audio_play_ptt(const uint8_t *pcm_le, int len);

// Microphone samples buffered right now — the caller's frame-size gate
// (e.g. `while (audio_capture_ready() >= 320)`).
int  audio_capture_ready(void);

// Pull up to max_samples of captured mic audio into out[]. Returns the
// count actually copied (may be < max_samples if the buffer drains first).
int  audio_capture_voice(int16_t *out, int max_samples);

// ---- call audio session ----
// The call layer claims the hardware on call start (audio_open) and releases
// it on call end (audio_close). audio_close flushes the speaker jitter buffer
// so the ~200 ms still queued at hangup doesn't play out as a click, and
// re-arms the stall guard; audio_open primes it the same way so a new call
// starts buffering fresh.
void audio_open(void);
void audio_close(void);

// True while the speaker is actively playing (call/PTT audio held, or ringing).
// Poll this before a flash write that would otherwise pause the audio DMA.
bool audio_is_active(void);

// Diagnostic: emit a q_speaker (jitter buffer) health line ~4 Hz while audio is
// flowing, silent when idle. Self-throttled — call every loop().
void audio_qspk_report(void);

// Stop / restart the mic+speaker DMA around a flash write (see audio.cpp).
void audio_dma_pause(void);
void audio_dma_resume(void);

// ---- tones / alerts ----
// RINGBACK FOR THE REMOTE CALLER: fill out[0..n) with the next ringback frame;
// *frame_count is the caller-held cadence counter (2 s on / 4 s off). The
// HAL only synthesises the tone — ringback is SENT to the caller by the call
// layer (the remote caller hears it).
void audio_ringback_frame(int16_t *out, int n, uint16_t *frame_count);

// Local incoming-call RING (alert): plays the ring tone on THIS device's
// built-in speaker at full volume, independent of speaker_volume (so the
// call earpiece can be quiet while an incoming call is loud).
// audio_ring_start is idempotent (call it each tick while ringing; the
// cadence keeps running). audio_ring_stop silences it.
void audio_ring_start(void);
void audio_ring_stop(void);

// ---- runtime tuning (non-static so they stay editable, e.g. via the
// serial harness) ----
extern int  speaker_volume;            // Q8 enqueue gain (256 = unity 1.0), earpiece/normal
extern int  speakerphone_boost;        // Q8 multiplier on speaker_volume for SPEAKERPHONE + PTT (256 = none)
extern int  microphone_gain;           // built-in mic digital gain
extern int  handsfree_gain;            // handsfree mic digital gain
extern int  speaker_level;             // call playback notch 0..10 (maps to speaker_volume)
extern int  mic_muted;                 // 1 = in-call mic mute (zeroed after bias correction)
extern volatile bool handsfree_active; // derived: true = handsfree SPEAKER path (GPIO17)

// Speakerphone VOX — mic-driven arbitration (device-only; see audio.cpp). Active
// only in SPEAKERPHONE mode; runtime-tunable via `vx` (far-end) / `vn` (near-end).
extern int32_t spk_env;         // far-end content envelope (leak ~32 ms)
extern int32_t mic_env;         // near-end mic envelope (leak ~32 ms)
extern int     mic_vox_gain;    // Q8 mic gate (256 = open, 0 = muted)
extern int     spk_gate;        // Q8 speaker gate (256 = open, 0 = ducked under near-end speech)
extern int     vox_spk_open;    // FE (far-end/spk_env) speech: open/close thresholds
extern int     vox_spk_close;
extern int     vox_mic_open;    // NE attack BASE (b) — echo-aware attack = open + spk_env*slope>>8
extern int     vox_mic_slope;   // NE attack SLOPE (a, Q8) — raises attack with the live far-end level
extern int32_t vox_ne_attack;   // last computed effective attack threshold (telemetry)
extern int     vox_mic_close;   // NE release threshold (LOWER — wide hysteresis for voice drop)
extern int     vox_ne_hold;     // NE hold (samples) — stay open after dropping below release
extern int     vox_hang_samples;// FE (far-end) hangover (samples)
extern int     vox_att_shift;   // close/duck-ramp shift (smaller = faster)
extern int     vox_rel_shift;   // open/unduck-ramp shift (larger = slower)
extern int     vox_mic_floor;   // Q8 mic gate floor (0 = hard mute)

// Set the call playback notch (0..10); clamps + updates speaker_volume via the
// notch->Q8 table. The call view's Vol +/- call this; boot applies device_record.volume_notch.
void audio_set_speaker_level(int notch);

// User-selected audio route (persisted in device_record.audio_mode). Set via
// audio_set_mode(); Settings > Audio drives it. See audio.cpp for the
// speaker/mic pin mapping per mode.
enum {
	AUDIO_NORMAL = 0,
	AUDIO_HANDSFREE = 1,
	AUDIO_SPEAKERPHONE = 2
};
extern volatile int audio_mode;
void audio_set_mode(int mode);

#ifdef __cplusplus
}
#endif
