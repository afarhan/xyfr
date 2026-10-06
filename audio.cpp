#include "debug.h"
// audio.cpp — RP2350 platform audio backend (implements audio.h).
//
// Owns the PWM speaker, the round-robin ADC microphones, both jitter
// queues, the sample callbacks, signal conditioning, handsfree routing,
// and ring / ringback tone synthesis. A port to another platform
// reimplements this file against the same audio.h contract.
//
// Runs on core 0 (the callbacks are registered from setup() → audio_init).
// The queues are single-producer / single-consumer between the main loop
// and the sample callbacks. speaker_callback / mic_callback are
// __not_in_flash_func so they stay in RAM and don't stall on XIP flash
// reads — preserve that attribute (and keep anything they touch in RAM).

#include <Arduino.h>
#include <PWMAudio.h>
#include <ADCInput.h>
#include <string.h>
#include "queue.h"
#include "audio.h"

// ---- hardware ----
// Round-robin both ADCs. Pin-numeric order is A1 (handsfree mic) first,
// then A2 (built-in mic). Each channel still gets the configured sample
// rate (ADCInput scales the clkdiv by popcount of the pin mask) — at
// begin(8000) the ADC runs at 16 kHz, alternating samples.
static ADCInput microphone(A0, A1, A2);   // A0 battery sense + A1/A2 mics, one shared ADC round-robin
static PWMAudio speaker(16, true);

// ---- sample queues (private — never exposed above audio.h) ----
static struct Queue q_microphone;
static struct Queue q_speaker;

// ---- q_speaker buffer-health telemetry (jitter buffer under/overflow) --------
// Instrument the SPEAKER ring so we can SEE, not guess, when it underruns
// (drains empty while primed) vs overflows (fills to MAX_Q and drops samples).
// Updated from the audio ISR (speaker_callback), the enqueue path, and the
// open/close resets; sampled + printed from core 0 (audio_qspk_report), which
// self-throttles and stays silent when no audio is flowing. Volatile because the
// ISR and core 0 both touch them; each counter has a single writer.
volatile uint32_t qspk_underruns = 0;   // primed read found the queue empty (a gap)
volatile uint32_t qspk_drops     = 0;   // enqueue hit MAX_Q -> sample dropped (overflow)
volatile uint32_t qspk_reprimes  = 0;   // q_reset events (stall re-armed at open/close)
volatile uint32_t qspk_reads     = 0;   // primed ISR reads this window
volatile uint32_t qspk_writes     = 0;  // samples enqueued this window
volatile int      qspk_min       = MAX_Q; // min primed count this window
volatile int      qspk_max       = 0;     // max primed count this window

// Enqueue one speaker sample with overflow accounting (used by both play paths).
static inline void qspk_put(int16_t s) {
  if (q_speaker.count == MAX_Q) {
    qspk_drops++;
    return;
  }
  qspk_writes++;
  q_write(&q_speaker, s);
}

// ---- runtime tuning (extern in audio.h) ----
int speaker_volume  = 128;
                           // Applied at ENQUEUE in audio_play_voice (NOT the
                           // ISR), so sub-unity attenuation is possible. Tuned
                           // low for earpiece-held listening. Raise toward 256
                           // (unity) for louder. Per-route (earpiece vs
                           // handsfree) levels are a deferred TODO.
int microphone_gain = 20;  // was 200; cut ~10× (mic was too hot on far end).
int handsfree_gain  = 150; // handsfree mic gain (150 good; 400 clips).
int speakerphone_boost = 4096; // Q8 MULTIPLIER applied to the (notch-controlled)
                           // speaker_volume for SPEAKERPHONE voice AND for PTT
                           // (they are the same loud built-in-speaker path), so the
                           // built-in speaker plays LOUD for arm's-length use YET
                           // the user's volume control (+/- notch) still works.
                           // 256 = no boost; effective gain = speaker_volume*boost/256.
                           // The loud level also raises spk_env (the VOX gate keys
                           // off the OUTPUT level) — intended: louder playback = real
                           // mic coupling to suppress. Live-tune via `sp <n>`.

// ---- call playback notch (0..10) + mic mute (call-view controls) ----
// The call view shows a 0..10 volume notch and a Mute toggle. The notch maps to
// the Q8 speaker_volume via spk_vol_table; the serial `sv <n>` cmd still sets the
// raw Q8 value directly for bench work. mic_muted zeroes the captured mic sample
// AFTER bias correction (the DC-bias tracker keeps running, so unmute is instant
// and clean) — the device still emits (silence) packets, so the call stays up.
int  speaker_level = 5;      // 0..10 notch; device_record.volume_notch persists it
int  mic_muted     = 0;      // 1 = mute (zero mic after bias correction)

// Notch -> Q8 gain. Notch 10 = 256 (unity, the clean digital max); notch 0 = silent.
// Spread a bit perceptually (finer at the quiet end). Retune here if the analog amp
// gain changes — a lower amp gain wants a higher digital ceiling and vice-versa.
static const int spk_vol_table[11] = { 0, 8, 20, 36, 56, 80, 110, 144, 184, 220, 256 };

void audio_set_speaker_level(int notch){
  if (notch < 0)
    notch = 0;
  if (notch > 10)
    notch = 10;
  speaker_level  = notch;
  speaker_volume = spk_vol_table[notch];
}

// Audio routing, user-selected (persisted in device_record.audio_mode). Bias-based
// handsfree plug-detect was removed — a handsfree pre-amp DC-couples its mic to
// A1 and blocks the plug's DC shift, so the plug can't be sensed; the route is a
// menu choice instead (Settings > Audio). The stereo PWM has two channels:
// GPIO16 = left = built-in speaker, GPIO17 = right = handsfree.
//   NORMAL       built-in:  GPIO16 speaker + built-in mic (ADC2)
//   HANDSFREE    accessory: GPIO17 speaker + handsfree mic (ADC1, via its pre-amp)
//   SPEAKERPHONE the SAME route as NORMAL (GPIO16 + built-in mic, right channel
//     zeroed) but louder (speaker_volume * speakerphone_boost) + half-duplex VOX
//     — mute the speaker while you speak and the mic while the peer speaks, so the
//     loud speaker doesn't echo back to the peer. Menu-selectable (Settings >
//     Audio); the VOX arbitration below (mic_vox_gain/spk_gate) runs in the ISRs.
volatile int  audio_mode         = AUDIO_NORMAL;
volatile bool handsfree_active   = false;        // derived: handsfree SPEAKER path (GPIO17)
static volatile bool mic_use_handsfree = false;  // derived: handsfree MIC (ADC1)
volatile bool audio_ready        = false;        // true after audio_init — flash-guard gate
static bool   s_dma_on           = false;        // mic+speaker DMA currently streaming?

// ---- Speakerphone VOX — mic-driven arbitration (SPEAKERPHONE mode) ----
// Two leaky mean-abs envelopes (~32 ms):
//   spk_env = far-end CONTENT — measured on the q_speaker sample BEFORE the
//             speaker duck, so far-end detection survives the duck.
//   mic_env = near-end mic — raw (post-gain, pre-VOX-gate); includes any speaker
//             echo (a SIMPLE threshold for now — tune it above the echo floor).
// Each drives a speech latch (hysteresis + hangover). The arbitration (the
// hardware owner's spec):
//   FE sil, NE sil -> mic OPEN, spk OPEN   (idle)
//   FE spk, NE sil -> mic MUTE, spk OPEN   (listening)
//   FE sil, NE spk -> mic OPEN, spk GATE   (talking)
//   FE spk, NE spk -> mic OPEN, spk MUTE   (double-talk: near-end wins)
// reduces to:  mic muted == (fe_speech AND NOT ne_speech);  spk ducked == ne_speech.
// spk_env measured pre-enqueue is wrong (leads by the ~200 ms q_speaker buffer);
// it must be the played sample. Non-static (runtime-tunable via `vx`/`vn`). Same
// core (0) writes+reads both ISRs, so no volatile.
int32_t spk_env = 0, mic_env = 0;   // far-end content / near-end mic envelopes
int  mic_vox_gain = 256;            // Q8 mic gate (256 open, 0 muted)
int  spk_gate     = 256;            // Q8 speaker gate (256 open, 0 ducked under near-end speech)
bool fe_speech = false, ne_speech = false;  // speech latches (hysteresis)
int32_t fe_hang = 0, ne_hang = 0;           // per-latch hangover countdowns
int vox_spk_open  = 1200;   // FE (far-end) speech: spk_env thresholds
int vox_spk_close = 400;
int vox_mic_open  = 1000;   // NE ATTACK base (b) — the fixed part of the echo-aware attack
                            // threshold: attack = vox_mic_open + (spk_env*vox_mic_slope>>8).
                            // b is the constant margin the near-end must clear ABOVE the echo.
int vox_mic_slope = 16;     // NE ATTACK slope (a, Q8) — raises the attack threshold with the
                            // live far-end level so louder playback (more echo) needs a louder
                            // near-end to trigger. Set ≈ the coupling (echo≈0.06*spk_env → ~16).
int32_t vox_ne_attack = 0;  // last computed effective attack threshold (telemetry only)
int vox_mic_close = 350;    // NE RELEASE threshold — set LOW: while ducked the speaker is muted
                            // so the mic has NO echo, so "silence" is just the ambient floor
                            // (~100-200). A low release keeps the natural mid-sentence voice
                            // drop latched and flips only at true silence. Device-tuned 2026-07-15.
int vox_ne_hold   = 1200;   // NE HOLD (~150 ms) — stay open this long after mic_env drops below
                            // the release level, bridging inter-word gaps. Tune via `vn`.
int vox_hang_samples = 2400;// FE (far-end) hangover (~300 ms)
int vox_att_shift = 3;      // gate close/duck ramp (~1 ms fast attack)
int vox_rel_shift = 9;      // gate open/unduck ramp (~64 ms)
int vox_mic_floor = 0;      // Q8 mic gate floor (0 = hard mute)
#define VOX_ENV_SHIFT 8     // env leak: env += (|x| - env) >> 8  (~32 ms @ 8 kHz)

void audio_set_mode(int mode){
  if (mode < AUDIO_NORMAL || mode > AUDIO_SPEAKERPHONE)
    mode = AUDIO_NORMAL;
  audio_mode        = mode;
  handsfree_active  = (mode == AUDIO_HANDSFREE);  // GPIO17 speaker only for handsfree (Normal/Speakerphone use GPIO16)
  mic_use_handsfree = (mode == AUDIO_HANDSFREE);  // ADC1 mic only for handsfree
  if (mode != AUDIO_SPEAKERPHONE) {               // leaving VOX: fully open mic + speaker, drop stale state
    mic_vox_gain = 256; spk_gate = 256;
    fe_speech = ne_speech = false;
    fe_hang = ne_hang = 0;
  }
}

// ---- internal DSP / detect state ----
int microphone_bias = 0;   // DC of the built-in mic (ADC2)   [non-static: HB diagnostic]
int handsfree_bias  = 0;   // DC of the handsfree-mic line (ADC1) [non-static: HB diagnostic]

// Handsfree plug detection. Measured on the actual device:
//   handsfree plugged in   → ADC1 DC ≈ 1792
//   handsfree unplugged    → ADC1 DC ≈ 3680  (rail isn't a full 4095;
//                                             unconnected pin sits at
//                                             ~2.97 V, not 3.30 V)
// The ~1900-count gap is wide enough that a single threshold halfway
// between is unambiguous — no hysteresis needed. Both ADCs are sampled
// regardless (round-robin); the active route just selects which samples
// reach q_microphone and which speaker channel gets q_speaker.
static const int HANDSFREE_THRESHOLD = 3000;

static int spk_count = 0;
volatile uint32_t mic_count = 0;   // raw samples the mic ISR has pushed to q_microphone (debug: is the ADC still producing?)
volatile int batt_adc_raw = 0;     // latest raw A0 battery sample (12-bit), sampled via the mic ADC round-robin
// Pack mV at full-scale (raw 4095). = VREF_mv(3300) x 2 (undo the ÷2 sense divider).
// BOTH factors are board-dependent (VREF ~2.97 V here; verify the divider), so this is
// a runtime knob: trim via the `bv <n>` serial cmd until the title matches a VOM.
int batt_fullscale_mv = 19609;   // calibrated on-device: 4.10 V pack read as raw ~856
                                 // (= 1.38 V at the old 6600 scale). Divider is ~÷6, not
                                 // ÷2 as first assumed. Re-trim per unit via `bv <n>`.

// GPIO 19 gates the earpiece attenuator. By design it should
// default HIGH (earpiece level), but the divider is presently 100:1 — far
// too deep to recover digitally — so for now it is left LOW (divider
// bypassed) and the earpiece level is trimmed via speaker_volume. Dynamic
// GPIO 19 control activates once the divider is retuned to ~2:1.
#define PIN_ATTENUATOR 19

// GPIO 9 → the PAM8403 power-amp enable ("MUTE" pin on the board, with an external
// pull-down). HIGH = amp on (audible); LOW = amp muted/shut down. The pull-down makes
// the default (undriven) state MUTED, so the amp is silent at boot before firmware
// drives it. Driven by amp_update() (defined near audio_open()). Moved off GPIO 12,
// which is now the Sharp display's EXTCOMIN (10 Hz VCOM). GPIO 12 was the ILI9488
// touch MISO / diode-to-amp on the old wiring; touch is gone on this build.
#define PIN_AMP_EN 9

// ---- ring / ringback shared tone ----
// 800 Hz tone: exactly 10 samples per period at 8 kHz, so a 10-entry table
// loops with no interpolation. Peak ±31163 ≈ full scale. NON-const so it
// lives in RAM (.data) — the speaker ISR reads it for the local ring and
// must not stall on an XIP flash read of a .rodata const.
static int16_t ring_sine[10] = {
	0,  19260,  31163,  31163,  19260,
	0, -19260, -31163, -31163, -19260
};

// ---- dynamics: fast-attack / ~500 ms-release limiters (mic transmit + speaker
// playback). Each pulls a dynamic gain down as the POST-gain sample nears the rail
// so a loud signal ROUNDS instead of square-clipping, then recovers over ~500 ms.
// Keyed on the output envelope, so they engage only when clipping actually threatens
// (transparent otherwise) and sit BEFORE the hard clamp — which becomes a never-hit
// safety net. Integer + RAM-resident (the mic one runs inside the capture ISR).
// Tunable (house style): ceil = limit threshold (headroom below 32767); rel_shift =
// release one-pole (2^12 = 4096 samples ≈ 512 ms @ 8 kHz).
int mic_agc_ceil      = 30000;
int mic_agc_rel_shift = 12;
int spk_agc_ceil      = 30000;
int spk_agc_rel_shift = 12;

static int32_t __not_in_flash_func(agc_step)(int32_t s, int32_t *g, int ceil, int rel_shift) {
	int32_t mag = s < 0 ? -s : s;
	int32_t pk  = (int32_t)(((int64_t)mag * *g) >> 16);
	if (pk > ceil)  // fast attack: this sample -> ceil
		*g = (int32_t)(((int64_t)*g * ceil) / pk);
	else  // slow release toward unity
		*g += (65536 - *g) >> rel_shift;
	return (int32_t)(((int64_t)s * *g) >> 16);
}
static int32_t __not_in_flash_func(mic_agc)(int32_t s) {
	static int32_t g = 65536;   // Q16, persists across the active mic route
	return agc_step(s, &g, mic_agc_ceil, mic_agc_rel_shift);
}
static int32_t __not_in_flash_func(spk_agc)(int32_t s) {
	static int32_t g = 65536;   // Q16, persists across voice/PTT playback
	return agc_step(s, &g, spk_agc_ceil, spk_agc_rel_shift);
}
#define RINGBACK_ATTEN_SHIFT 2     // remote ringback: >>2 ≈ -12 dB (caller's earpiece)

// Local incoming-call ring (alert): same tone, 2 s on / 4 s off, played at
// FULL volume on the built-in speaker — bypasses speaker_volume so the call
// earpiece can be quiet while an incoming call is loud. Cadence counted in
// output samples @ 8 kHz. ring_phase / ring_cadence are owned by the ISR;
// audio_ring_start seeds them before setting ring_active.
#define RING_ON_SAMPLES    (2 * 8000)
#define RING_OFF_SAMPLES   (4 * 8000)
#define RING_CYCLE_SAMPLES (RING_ON_SAMPLES + RING_OFF_SAMPLES)
static volatile bool ring_active = false;
static uint16_t ring_phase   = 0;
static uint32_t ring_cadence = 0;

// ============ sample callbacks (run in RAM, core 0) ============

//funny syntax for keeping this function in RAM and not in flash
void __not_in_flash_func(speaker_callback)() {
  // Stereo PWMAudio: each frame is two interleaved int16s (L, R).
  // GPIO 16 (left)  → built-in speaker.
  // GPIO 17 (right) → handsfree speaker.
  // For call audio we route q_speaker to the channel matching the active
  // mic so that when handsfree is plugged in, the handsfree pair works as a
  // unit and the built-in speaker stays silent; the other channel writes 0
  // to keep the stereo frame aligned without bleeding onto the unused
  // transducer.
  //
  // Call-audio samples are already gain-scaled + int16-clamped at enqueue
  // (audio_play_voice), so here the ISR just copies q_speaker out to the
  // active channel — no per-sample multiply in this RAM/ISR-hot callback.
  while (speaker.availableForWrite() >= 2) {
    if (ring_active) {
      // Local incoming-call alert: full-volume 800 Hz tone on the built-in
      // (left) speaker, independent of speaker_volume and of the handsfree
      // route, so the ring is loud regardless of the call-audio level.
      int16_t rs = (ring_cadence < RING_ON_SAMPLES) ? ring_sine[ring_phase] : 0;
      ring_phase = (ring_phase + 1) % 10;
      if (++ring_cadence >= RING_CYCLE_SAMPLES)
        ring_cadence = 0;
      speaker.write(rs);   // left  = built-in (alert speaker)
      speaker.write(0);    // right = handsfree, silenced
      spk_count++;         // ring is a local alert, not far-end content — don't touch spk_env
      continue;
    }
    // Telemetry: only sample while PRIMED (stall==0) so idle silence (stall==1
    // after a q_reset) doesn't count as an underrun or skew min/max.
    if (!q_speaker.stall) {
      int c = q_speaker.count;
      if (c < qspk_min)
        qspk_min = c;
      if (c > qspk_max)
        qspk_max = c;
      qspk_reads++;
      if (c == 0)
        qspk_underruns++;
    }
    int16_t s = q_read(&q_speaker);   // far-end content (already volume-scaled at enqueue)
    // FE-content envelope, measured on the BUILT-IN (left) path BEFORE the duck,
    // so far-end detection survives ducking. Zero when handsfree owns the audio.
    int16_t content = handsfree_active ? 0 : s;
    { int32_t a = content < 0 ? -content : content; spk_env += (a - spk_env) >> VOX_ENV_SHIFT; }
    // Speaker duck: ramp spk_gate toward 0 while the near-end is speaking (ne_speech
    // is only ever true in SPEAKERPHONE — see mic_callback — so other modes stay
    // fully open). Fast attack to cut the far-end quickly, gentle release.
    int sgt = ne_speech ? 0 : 256;
    { int d = sgt - spk_gate;
      if (d < 0)
        spk_gate += d >> vox_att_shift;
      else if (d > 0) {
        int st = d >> vox_rel_shift;
        if (!st)
          st = 1;
        spk_gate += st;
        }
      }
    int16_t out = (int16_t)(((int32_t)s * spk_gate) >> 8);
    if (handsfree_active) {
      speaker.write(0);     // left  = built-in, silenced
      speaker.write(out);   // right = handsfree (ducked)
    } else {
      speaker.write(out);   // left  = built-in (ducked)
      speaker.write(0);     // right = handsfree, silenced
    }
    spk_count++;
  }
}

//funny syntax for keeping this function in RAM and not in flash
void __not_in_flash_func(mic_callback)(){
  // The ADC round-robins A0 (battery sense), A1 (handsfree mic), A2 (built-in
  // mic) — FIFO order is numeric pin index, so every group of three samples is
  // [A0, A1, A2]. We read a whole group per iteration, which keeps channel
  // alignment even across DMA buffer boundaries (begin() drains the FIFO so the
  // stream starts at A0, and bufferWords is a multiple of 3). A0 feeds the
  // battery readout (latest sample only — a bare analogRead(A0) would tear down
  // this DMA and kill capture, so we sample the pack THROUGH the round-robin
  // instead). A1/A2 each run a one-pole IIR low-pass + DC tracker; only the
  // active route's channel reaches q_microphone.
  //
  // One-pole IIR:  y[n] = (7*x[n] + y[n-1]) >> 3   →  α = 7/8 = 0.875
  // At fs=8 kHz per channel that's a -3 dB cutoff of ~2.5 kHz — attenuates the
  // high-frequency RP2350 ADC noise while leaving the voice band (300–2500 Hz).
  // Seed lpf_hf at the unplugged rail / lpf_bi at mid-rail so warmup doesn't
  // trip the plug-detect threshold.
  static int16_t lpf_hf = 4095;
  static int16_t lpf_bi = 2048;
  int hf_sum = 0, hf_cnt = 0;
  int bi_sum = 0, bi_cnt = 0;
  const int mode = audio_mode;   // read the volatile once per ISR (plan); gate branches on it

  while (microphone.available() >= 3){
    int16_t a0 = microphone.read();   // A0 = battery sense (÷2 divider)
    int16_t a1 = microphone.read();   // A1 = handsfree mic
    int16_t a2 = microphone.read();   // A2 = built-in mic

    batt_adc_raw = a0;                 // latest raw pack sample (12-bit); rb_tick reads this

    lpf_hf = (a1 * 7 + lpf_hf) >> 3;
    hf_sum += lpf_hf;
    hf_cnt++;
    if (mic_use_handsfree) {
      int32_t scaled = mic_muted ? 0 : mic_agc((int32_t)(lpf_hf - handsfree_bias) * handsfree_gain);
      if (scaled > 32767)  // safety net; the AGC keeps us off the rail
        scaled = 32767;
      if (scaled < -32768)
        scaled = -32768;
      q_write(&q_microphone, (int16_t)scaled);
      mic_count++;
    }

    lpf_bi = (a2 * 7 + lpf_bi) >> 3;
    bi_sum += lpf_bi;
    bi_cnt++;
    if (!mic_use_handsfree) {
      // ---- speakerphone VOX: near-end detect + mic-driven arbitration ----
      int32_t raw = (int32_t)(lpf_bi - microphone_bias) * microphone_gain;   // near-end mic, pre-gate
      { int32_t a = raw < 0 ? -raw : raw; if (a > 32767) a = 32767;          // near-end envelope
        mic_env += (a - mic_env) >> VOX_ENV_SHIFT; }
      // Speech latches (hysteresis + hangover). Both false outside SPEAKERPHONE →
      // mic + speaker stay fully open (full-duplex). fe from spk_env, ne from mic_env.
      if (mode == AUDIO_SPEAKERPHONE) {
        // FE (far-end) speech — hysteresis + hangover.
        if (spk_env > vox_spk_open)
          fe_speech = true;
        else if (spk_env < vox_spk_close && fe_hang == 0)
          fe_speech = false;
        if (spk_env > vox_spk_close)
          fe_hang = vox_hang_samples;
        else if (fe_hang > 0)
          fe_hang--;
        // NE (near-end) speech — ATTACK / HOLD / RELEASE with wide hysteresis.
        //   ATTACK  : mic_env crosses UP through the high open threshold → open.
        //   HOLD    : while it stays above the LOW release threshold, reload the
        //             hold; once it drops below, run the hold timer down. So the
        //             natural mid-sentence voice drop (open>drop>close) stays latched.
        //   RELEASE : flip to silence only after mic_env has been below the low
        //             release level for the full hold time.
        // Echo-aware ATTACK threshold: base + a·spk_env. Rises with the live
        // far-end level so the speaker's echo can't self-trigger the mic at high
        // volume; drops toward the base in far-end pauses (no echo → full sensitivity).
        vox_ne_attack = vox_mic_open + ((spk_env * vox_mic_slope) >> 8);
        if (mic_env > vox_ne_attack) {
          ne_speech = true;
          ne_hang = vox_ne_hold;
        }
        else if (ne_speech) {
          // RELEASE is FIXED (not echo-aware): while ducked the speaker is muted, so
          // the mic has no echo — silence is just the ambient floor.
          if (mic_env > vox_mic_close)  // still talking → hold open
            ne_hang = vox_ne_hold;
          else if (ne_hang > 0)  // dropped to silence → run hold
            ne_hang--;
          else  // silent long enough → release
            ne_speech = false;
        }
      } else {
        fe_speech = ne_speech = false; fe_hang = ne_hang = 0;
      }
      // Arbitration: mute the mic ONLY when the far end is talking and we are not
      // (pure listening). Near-end speech always opens the mic (barge-in / talk).
      int target = (fe_speech && !ne_speech) ? vox_mic_floor : 256;
      int32_t d = target - mic_vox_gain;
      if (d < 0)  // fast mute
        mic_vox_gain += d >> vox_att_shift;
      else if (d > 0) {  // slow open
        int32_t st = d >> vox_rel_shift;
        if (!st)
          st = 1;
        mic_vox_gain += st;
      }

      int32_t scaled = (raw * mic_vox_gain) >> 8;   // apply the VOX gate (Q8)
      scaled = mic_agc(scaled);                // limit the post-gate signal off the rail
      if (mic_muted)  // user mute is the OUTER gate (always wins)
        scaled = 0;
      if (scaled > 32767)  // safety net; the AGC keeps us off the rail
        scaled = 32767;
      if (scaled < -32768)
        scaled = -32768;
      q_write(&q_microphone, (int16_t)scaled);
      mic_count++;
    }
  }

  if (hf_cnt)
    handsfree_bias  = hf_sum / hf_cnt;
  if (bi_cnt)
    microphone_bias = bi_sum / bi_cnt;
  // (route is set by audio_set_mode from the user's menu choice, not auto-detected)
}

// ============ lifecycle ============

void audio_init(void) {
  q_init(&q_microphone);
  q_init(&q_speaker);

  // buffer size is 32-bit word count, not the 16-bit samples we use. Must be a
  // multiple of 3 for the 3-channel (A0/A1/A2) round-robin so each buffer starts
  // aligned to A0 (ADCInput::begin rejects a non-multiple-of-3 for 3 inputs).
  microphone.setBuffers(4, 162);

  pinMode(PIN_ATTENUATOR, OUTPUT);
  digitalWrite(PIN_ATTENUATOR, LOW);   // interim: divider bypassed (see note above)

  // Power amp muted at boot (the GPIO 9 "MUTE" pin also has an external pull-down,
  // so it is already LOW/muted before this runs). Driven HIGH only for a call/ring.
  pinMode(PIN_AMP_EN, OUTPUT);
  digitalWrite(PIN_AMP_EN, LOW);       // amp muted until a call/ring needs it

  speaker.onTransmit(speaker_callback);
  speaker.begin(8000);

  microphone.begin(8000);
  microphone.onReceive(mic_callback);

  s_dma_on = true;
  audio_ready = true;   // the flash guard may now quiesce us around writes
}

// Quiesce the free-running mic ADC + speaker PWM DMA. A flash erase (XIP off,
// interrupts disabled) run WHILE these DMAs stream wedges the core, so the flash
// HAL stops them around a write and restarts after. Both idempotent + state-tracked
// so the guard can call them freely (no-op before audio_init / when already in the
// target state).
void audio_dma_pause(void) {
  if (!s_dma_on)
    return;
  microphone.end();
  speaker.end();
  s_dma_on = false;
}

void audio_dma_resume(void) {
  if (s_dma_on || !audio_ready)
    return;
  microphone.setBuffers(4, 162);
  speaker.onTransmit(speaker_callback);
  speaker.begin(8000);
  microphone.begin(8000);
  microphone.onReceive(mic_callback);
  s_dma_on = true;
}

// ============ voice path ============

// Decode int16 LE PCM into q_speaker, byte-by-byte (payload may be
// half-word-misaligned on strict-alignment cores).
void audio_play_voice(const uint8_t *pcm_le, int len) {
  int sample_count = len / 2;
  // SPEAKERPHONE rides the notch-controlled speaker_volume, boosted LOUD; every
  // other mode uses the notch as-is. So the user's +/- volume control still works
  // in speakerphone — it just scales a louder range. Chosen once per frame.
  int vol = (audio_mode == AUDIO_SPEAKERPHONE)
              ? (int)(((int32_t)speaker_volume * speakerphone_boost) >> 8)
              : speaker_volume;
  for (int i = 0; i < sample_count; i++) {
    int16_t sample = (int16_t)((uint16_t)pcm_le[i*2] |
                               ((uint16_t)pcm_le[i*2 + 1] << 8));
    // Scale here (Q8: vol/256) rather than in the ISR, so the speaker callback
    // stays a plain copy and gains < 1.0 are possible.
    int32_t s32 = ((int32_t)sample * vol) >> 8;
    s32 = spk_agc(s32);                   // limit off the rail (rounds peaks vs square-clipping)
    if (s32 >  32767)  // safety net
      s32 =  32767;
    if (s32 < -32768)
      s32 = -32768;
    qspk_put((int16_t)s32);
  }
  static uint32_t voice_rx_count = 0;
  if (++voice_rx_count % 25 == 0)
    Debug.printf("voice rx frames=%u q_speaker.count=%d\n",
      (unsigned)voice_rx_count, q_speaker.count);
}

// PTT inbound IS the speakerphone path: it uses the SAME gain as SPEAKERPHONE
// voice — the notch-controlled speaker_volume boosted by speakerphone_boost — so
// the ONE volume control (the +/- notch) governs both. Route still follows
// handsfree_active in the ISR, so earbuds get it if plugged. Gain computed once
// per frame (Q8: vol/256).
void audio_play_ptt(const uint8_t *pcm_le, int len) {
  int sample_count = len / 2;
  int vol = ((int32_t)speaker_volume * speakerphone_boost) >> 8;
  for (int i = 0; i < sample_count; i++) {
    int16_t sample = (int16_t)((uint16_t)pcm_le[i*2] |
                               ((uint16_t)pcm_le[i*2 + 1] << 8));
    int32_t s32 = ((int32_t)sample * vol) >> 8;
    s32 = spk_agc(s32);                   // limit off the rail (rounds peaks vs square-clipping)
    if (s32 >  32767)  // safety net
      s32 =  32767;
    if (s32 < -32768)
      s32 = -32768;
    qspk_put((int16_t)s32);
  }
}

// q_speaker health line at ~4 Hz WHILE audio flows (silent when idle so it never
// spams). Self-throttled — safe to call every loop(). Window counters reset each
// print so each line reads "what happened in the last ~250 ms":
//   count = live fill now, stall = priming(1)/playing(0)
//   min/max = fill extremes while primed (min->0 == underrun risk, max->MAX_Q(4800) == overflow)
//   under = primed reads that found the ring empty (audible gaps)
//   drop  = samples discarded because the ring was full (overflow)
//   reprime = q_reset events (open/close re-arming the 200 ms prime mid-stream)
void audio_qspk_report(void) {
  static uint32_t next = 0;
  uint32_t now = millis();
  if ((int32_t)(now - next) < 0)
    return;
  next = now + 250;
  uint32_t w = qspk_writes, r = qspk_reads;
  if (w == 0 && r == 0) {            // nothing moved this window — stay quiet
    qspk_min = MAX_Q; qspk_max = 0;
    return;
  }
  Debug.printf("qspk: count=%d stall=%d min=%d max=%d/%d w=%u r=%u under=%u drop=%u reprime=%u\n",
    q_speaker.count, q_speaker.stall, qspk_min, qspk_max, MAX_Q,
    (unsigned)w, (unsigned)r, (unsigned)qspk_underruns, (unsigned)qspk_drops,
    (unsigned)qspk_reprimes);
  qspk_writes = 0; qspk_reads = 0; qspk_underruns = 0; qspk_drops = 0;
  qspk_reprimes = 0; qspk_min = MAX_Q; qspk_max = 0;
}

int audio_capture_ready(void) { return q_microphone.count; }

int audio_capture_voice(int16_t *out, int max_samples) {
  int n = 0;
  while (n < max_samples && q_microphone.count > 0)
    out[n++] = q_read(&q_microphone);
  return n;
}

// ============ power amp (PAM8403) shutdown control ============
// GPIO 9 (the board "MUTE" pin, with an external pull-down) enables the PAM8403.
// HIGH = amp enabled (sound is audible); LOW = amp muted/shut down (idle power
// save, and the default at boot thanks to the pull-down). The amp must be on
// whenever sound is meant to play, which is EITHER of two independent paths: a
// voice call (audio_open..audio_close) OR the local incoming-call ring
// (ring_active). We gate GPIO 9 on the OR of both and hold it across the ring's
// 2 s/4 s cadence so the amp doesn't pop each cycle. (PIN_AMP_EN is #defined up
// near PIN_ATTENUATOR.) Moved off GPIO 12, now the Sharp display's EXTCOMIN.
static bool amp_call_audio = false;   // a voice call holds the device (audio_open/close)

static void amp_update(void) {
  digitalWrite(PIN_AMP_EN, (amp_call_audio || ring_active) ? HIGH : LOW);
}

// True while the speaker is actively playing (a call/PTT holds the audio, or the
// local ring is sounding). Callers that must NOT stall the audio — e.g. a volume
// change deferring its flash persist — poll this to wait for a quiet moment.
bool audio_is_active(void) { return amp_call_audio || ring_active; }

// ============ call audio session ============

void audio_open(void)  { amp_call_audio = true;  amp_update(); q_reset(&q_speaker); qspk_reprimes++; }   // amp on + prime jitter buffer
void audio_close(void) { amp_call_audio = false; amp_update(); q_reset(&q_speaker); qspk_reprimes++; }   // amp off (unless ringing) + flush

// ============ local ring (incoming-call alert) ============

void audio_ring_start(void) {
  if (ring_active)  // idempotent: keep the cadence running
    return;
  ring_phase   = 0;
  ring_cadence = 0;
  ring_active  = true;       // set last: phase/cadence are valid before the ISR acts on it
  amp_update();              // power the amp so the alert is audible
}

void audio_ring_stop(void) { ring_active = false; amp_update(); }   // amp off (unless a call holds it)

// ============ ringback for the remote caller ============
// On/off cadence: 2000 ms on, 4000 ms off (US/Canada-style ring pattern).
// At 40 ms/frame that's 50 frames on, 100 frames off. One frame is 320
// samples; 320/10 = 32 full periods, glitch-free across frame boundaries
// when we always restart at table index 0.

#define RINGBACK_ON_FRAMES   50    //  2.0 s at 40 ms/frame
#define RINGBACK_OFF_FRAMES  100   //  4.0 s
#define RINGBACK_CYCLE_FRAMES (RINGBACK_ON_FRAMES + RINGBACK_OFF_FRAMES)

void audio_ringback_frame(int16_t *out, int n, uint16_t *frame_count) {
  uint32_t pos_in_cycle = (uint32_t)*frame_count % RINGBACK_CYCLE_FRAMES;
  bool tone_on = (pos_in_cycle < RINGBACK_ON_FRAMES);
  (*frame_count)++;

  if (tone_on) {
    for (int i = 0; i < n; i++)
      out[i] = (int16_t)(ring_sine[i % 10] >> RINGBACK_ATTEN_SHIFT);
  } else {
    memset(out, 0, n * sizeof(int16_t));
  }
}
