// ALSA capture + playback wrapper for the CLI client. 8 kHz mono S16_LE,
// 320-sample = 40 ms frames, matching the firmware's transmission format
// (call.cpp:call_voice_tx_pump and the DATA_VOICE rx branch in the .ino).
//
// Single-threaded: capture is non-blocking and gets drained from the
// main loop each iteration; playback is also non-blocking and recovers
// from underrun in place. No ring buffer of our own — ALSA's buffer
// (1600 samples = 200 ms) IS the jitter buffer, sized to match the
// firmware's q_speaker stall threshold so behavior is symmetric.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <alsa/asoundlib.h>
#include "audio_alsa.h"

static snd_pcm_t *cap_pcm  = NULL;
static snd_pcm_t *play_pcm = NULL;

// Runtime tuning. Read once from env at init so the CLI doesn't have
// to thread these through. LTP_AUDIO_GAIN is the multiplicative gain
// applied to the captured int16 samples before the int8 downcast that
// happens in the caller — same shape as the firmware's microphone_gain
// (currently 50× in mic_callback). LTP_AUDIO_DEBUG=1 turns on the
// once-per-second peak/RMS meter on stderr so a tester can dial the
// gain by number instead of by ear.
static float capture_gain = 1.0f;
static int   debug_levels = 0;

static int configure_pcm(snd_pcm_t *pcm, snd_pcm_stream_t stream) {
	snd_pcm_hw_params_t *hw;
	snd_pcm_hw_params_alloca(&hw);

	int rc = snd_pcm_hw_params_any(pcm, hw);
	if (rc < 0) {
		fprintf(stderr, "alsa: hw_params_any: %s\n", snd_strerror(rc));
		return rc;
	}

	rc = snd_pcm_hw_params_set_access(pcm, hw, SND_PCM_ACCESS_RW_INTERLEAVED);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_access: %s\n", snd_strerror(rc));
		return rc;
	}
	rc = snd_pcm_hw_params_set_format(pcm, hw, SND_PCM_FORMAT_S16_LE);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_format S16_LE: %s\n", snd_strerror(rc));
		return rc;
	}
	rc = snd_pcm_hw_params_set_channels(pcm, hw, 1);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_channels 1: %s\n", snd_strerror(rc));
		return rc;
	}

	unsigned int rate = 8000;
	int dir = 0;
	rc = snd_pcm_hw_params_set_rate_near(pcm, hw, &rate, &dir);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_rate_near 8000: %s\n", snd_strerror(rc));
		return rc;
	}
	if (rate != 8000)
		fprintf(stderr, "alsa: warning, rate negotiated to %u (wanted 8000)\n", rate);

	snd_pcm_uframes_t period = AUDIO_FRAME_SAMPLES;       // 320 = 40 ms
	dir = 0;
	rc = snd_pcm_hw_params_set_period_size_near(pcm, hw, &period, &dir);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_period_size_near 320: %s\n", snd_strerror(rc));
		return rc;
	}

	snd_pcm_uframes_t bufsz = AUDIO_FRAME_SAMPLES * 5;    // 1600 = 200 ms
	rc = snd_pcm_hw_params_set_buffer_size_near(pcm, hw, &bufsz);
	if (rc < 0) {
		fprintf(stderr, "alsa: set_buffer_size_near 1600: %s\n", snd_strerror(rc));
		return rc;
	}

	rc = snd_pcm_hw_params(pcm, hw);
	if (rc < 0) {
		fprintf(stderr, "alsa: hw_params commit: %s\n", snd_strerror(rc));
		return rc;
	}

	// sw_params: on playback, hold writei until the buffer has filled
	// all the way before starting playback. Without this, ALSA starts
	// draining the buffer the moment we hand it the first frame —
	// since we deliver one frame (40 ms) every 40 ms with no head
	// start, the buffer stays drained and underruns continuously for
	// the first second or so. start_threshold = bufsz makes playback
	// wait for a full 200 ms pre-roll, mirroring the firmware's
	// q_speaker stall threshold (queue.cpp:30).
	if (stream == SND_PCM_STREAM_PLAYBACK) {
		snd_pcm_sw_params_t *sw;
		snd_pcm_sw_params_alloca(&sw);
		rc = snd_pcm_sw_params_current(pcm, sw);
		if (rc < 0) {
			fprintf(stderr, "alsa: sw_params_current: %s\n", snd_strerror(rc));
			return rc;
		}
		rc = snd_pcm_sw_params_set_start_threshold(pcm, sw, bufsz);
		if (rc < 0) {
			fprintf(stderr, "alsa: set_start_threshold: %s\n", snd_strerror(rc));
			return rc;
		}
		rc = snd_pcm_sw_params_set_avail_min(pcm, sw, period);
		if (rc < 0) {
			fprintf(stderr, "alsa: set_avail_min: %s\n", snd_strerror(rc));
			return rc;
		}
		rc = snd_pcm_sw_params(pcm, sw);
		if (rc < 0) {
			fprintf(stderr, "alsa: sw_params commit: %s\n", snd_strerror(rc));
			return rc;
		}
	}

	rc = snd_pcm_prepare(pcm);
	if (rc < 0) {
		fprintf(stderr, "alsa: prepare: %s\n", snd_strerror(rc));
		return rc;
	}

	fprintf(stderr, "alsa: %s ready (rate=%u period=%lu buffer=%lu)\n",
		stream == SND_PCM_STREAM_CAPTURE ? "capture" : "playback",
		rate, (unsigned long)period, (unsigned long)bufsz);
	return 0;
}

int audio_alsa_init(void) {
	if (cap_pcm && play_pcm) return 0;   // already up

	const char *g = getenv("LTP_AUDIO_GAIN");
	if (g) {
		float v = strtof(g, NULL);
		if (v > 0.0f) capture_gain = v;
	}
	debug_levels = getenv("LTP_AUDIO_DEBUG") != NULL;
	fprintf(stderr, "alsa: capture_gain=%.2f debug_levels=%d\n",
		capture_gain, debug_levels);

	int rc = snd_pcm_open(&cap_pcm, "default",
	                      SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK);
	if (rc < 0) {
		fprintf(stderr, "alsa: open capture: %s\n", snd_strerror(rc));
		cap_pcm = NULL;
		return rc;
	}
	rc = configure_pcm(cap_pcm, SND_PCM_STREAM_CAPTURE);
	if (rc < 0) {
		snd_pcm_close(cap_pcm); cap_pcm = NULL;
		return rc;
	}

	rc = snd_pcm_open(&play_pcm, "default",
	                  SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);
	if (rc < 0) {
		fprintf(stderr, "alsa: open playback: %s\n", snd_strerror(rc));
		snd_pcm_close(cap_pcm); cap_pcm = NULL;
		play_pcm = NULL;
		return rc;
	}
	rc = configure_pcm(play_pcm, SND_PCM_STREAM_PLAYBACK);
	if (rc < 0) {
		snd_pcm_close(cap_pcm);  cap_pcm  = NULL;
		snd_pcm_close(play_pcm); play_pcm = NULL;
		return rc;
	}

	// Kick capture so frames start flowing. Playback doesn't auto-start
	// until the first writei lands enough samples to cross the start
	// threshold; that's fine — we always have data to write once a call
	// is up.
	rc = snd_pcm_start(cap_pcm);
	if (rc < 0) {
		fprintf(stderr, "alsa: snd_pcm_start (capture): %s — capture won't deliver frames\n",
			snd_strerror(rc));
		// Don't fail init; capture_frame will keep returning 0 and the
		// user can recover by attempting another call. But make the
		// failure visible.
	}
	return 0;
}

void audio_alsa_close(void) {
	if (cap_pcm)  { snd_pcm_close(cap_pcm);  cap_pcm  = NULL; }
	if (play_pcm) { snd_pcm_close(play_pcm); play_pcm = NULL; }
}

int audio_alsa_capture_frame(int16_t buf[AUDIO_FRAME_SAMPLES]) {
	// All accumulators live across calls so the once-per-second meter
	// reflects every outcome. Always-on so a "no log line" can't be
	// confused with "everything's fine."
	static int frames_ok     = 0;
	static int eagain_count  = 0;
	static int partial_count = 0;   // partial readi → staged, no frame yet
	static int err_count     = 0;
	static int peak          = 0;
	static long long sumsq   = 0;
	static time_t last_log   = 0;

	// Staging buffer: ALSA's "default" device routes through PulseAudio
	// or PipeWire's plug chain, which delivers data in whatever fragment
	// size the underlying hardware prefers — often 96 or 160 samples,
	// not the 320 we asked for. snd_pcm_readi happily returns partial
	// counts, so we accumulate into stage_buf and only hand back a
	// frame once stage_count hits AUDIO_FRAME_SAMPLES.
	static int16_t stage_buf[AUDIO_FRAME_SAMPLES];
	static int     stage_count = 0;

	int rc = 0;
	if (!cap_pcm) {
		err_count++;
		rc = -1;
		goto report;
	}

	int need = AUDIO_FRAME_SAMPLES - stage_count;
	snd_pcm_sframes_t n = snd_pcm_readi(cap_pcm, stage_buf + stage_count, need);
	if (n == -EAGAIN) {
		eagain_count++;
	} else if (n == -EPIPE) {
		fprintf(stderr, "alsa: capture overrun, recovering\n");
		snd_pcm_recover(cap_pcm, n, 1);
		err_count++;
		stage_count = 0;   // recovery loses synchronisation; discard partial
	} else if (n < 0) {
		fprintf(stderr, "alsa: capture error: %s\n", snd_strerror((int)n));
		snd_pcm_recover(cap_pcm, (int)n, 1);
		err_count++;
		stage_count = 0;
	} else {
		stage_count += (int)n;
		if (stage_count < AUDIO_FRAME_SAMPLES) {
			// Partial — accumulated, but not a full frame yet.
			partial_count++;
		} else {
			// Full frame assembled. Apply gain + meter, hand off, reset.
			memcpy(buf, stage_buf, AUDIO_FRAME_SAMPLES * sizeof(int16_t));
			stage_count = 0;
			if (capture_gain != 1.0f) {
				for (int i = 0; i < AUDIO_FRAME_SAMPLES; i++) {
					float s = (float)buf[i] * capture_gain;
					if (s >  32767.0f) s =  32767.0f;
					if (s < -32768.0f) s = -32768.0f;
					buf[i] = (int16_t)s;
				}
			}
			for (int i = 0; i < AUDIO_FRAME_SAMPLES; i++) {
				int a = buf[i] < 0 ? -buf[i] : buf[i];
				if (a > peak) peak = a;
				sumsq += (long long)buf[i] * buf[i];
			}
			frames_ok++;
			rc = 1;
		}
	}

report:
	if (debug_levels) {
		time_t now = time(NULL);
		if (last_log == 0) last_log = now;
		if (now != last_log) {
			long rms = frames_ok > 0
				? (long)sqrt((double)sumsq /
				             (double)(frames_ok * AUDIO_FRAME_SAMPLES))
				: 0;
			// frames_ok = assembled 320-sample frames in the last second;
			// ~25 during a live call. eagain = healthy-not-yet-ready
			// polls. partial = readi returned <320; we stage and wait
			// for the next chunk — normal under PulseAudio/PipeWire.
			// err > 0 means trouble. peak=32768 plus rms/peak > 0.5 is
			// clipping into the int16 saturator — back gain off.
			const char *clip = "";
			if (peak >= 32767 && frames_ok > 0 &&
			    rms * 2 > (long)peak) {
				clip = " CLIP";
			}
			fprintf(stderr,
				"alsa: capture frames=%d peak=%d rms=%ld eagain=%d partial=%d err=%d (gain=%.2f)%s\n",
				frames_ok, peak, rms, eagain_count,
				partial_count, err_count, capture_gain, clip);
			frames_ok = eagain_count = partial_count = err_count = 0;
			peak = 0; sumsq = 0;
			last_log = now;
		}
	}
	return rc;
}

int audio_alsa_playback_frame(const int16_t *buf, int n_samples) {
	if (!play_pcm) return -1;

	// Mirror of the capture meter: confirms we're feeding non-zero data
	// to ALSA. If peak stays at 0 the issue is upstream (peer not sending
	// real audio); if peak is healthy but nothing is heard, the issue is
	// downstream (ALSA sink routed somewhere silent / muted / no hardware).
	if (debug_levels) {
		static int frames = 0, peak = 0;
		static long long sumsq = 0;
		for (int i = 0; i < n_samples; i++) {
			int a = buf[i] < 0 ? -buf[i] : buf[i];
			if (a > peak) peak = a;
			sumsq += (long long)buf[i] * buf[i];
		}
		if (++frames >= 25) {
			long rms = (long)sqrt((double)sumsq /
			                      (double)(frames * n_samples));
			fprintf(stderr, "alsa: playback peak=%d rms=%ld\n", peak, rms);
			frames = 0; peak = 0; sumsq = 0;
		}
	}

	int remaining = n_samples;
	const int16_t *p = buf;
	while (remaining > 0) {
		snd_pcm_sframes_t n = snd_pcm_writei(play_pcm, p, remaining);
		if (n == -EAGAIN) {
			// Output buffer full. Drop the rest of this frame — better
			// to skip 40 ms than to add latency by blocking. With a
			// 200 ms buffer this only fires when something downstream
			// stalled.
			return 0;
		}
		if (n == -EPIPE) {
			fprintf(stderr, "alsa: playback underrun, recovering\n");
			snd_pcm_recover(play_pcm, (int)n, 1);
			continue;
		}
		if (n < 0) {
			fprintf(stderr, "alsa: playback error: %s\n", snd_strerror((int)n));
			snd_pcm_recover(play_pcm, (int)n, 1);
			return -1;
		}
		remaining -= (int)n;
		p         += (int)n;
	}
	return 0;
}
