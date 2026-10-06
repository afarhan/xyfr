#pragma once

#include <stdint.h>

// 8 kHz mono S16_LE PCM, 320-sample frames (40 ms) — matches the
// firmware's transmit-side convention in call.cpp:call_voice_tx_pump so
// the same gain / clamp tuning carries over.
#define AUDIO_FRAME_SAMPLES 320

// Open the default capture + playback PCM devices in non-blocking
// mode and prime them. Idempotent: safe to call repeatedly across
// successive calls. Returns 0 on success, <0 on error.
int  audio_alsa_init(void);

// Tear down both PCMs. Idempotent.
void audio_alsa_close(void);

// Non-blocking capture: pulls one AUDIO_FRAME_SAMPLES frame off the
// mic if available. Returns 1 if a frame was filled, 0 if not yet
// (caller should drain again next loop tick), <0 on unrecoverable error.
int  audio_alsa_capture_frame(int16_t buf[AUDIO_FRAME_SAMPLES]);

// Non-blocking playback: writes n_samples mono int16 samples to the
// output. Recovers from underrun (-EPIPE) internally. Returns 0 on
// success, <0 on unrecoverable error.
int  audio_alsa_playback_frame(const int16_t *buf, int n_samples);
