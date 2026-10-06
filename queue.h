#pragma once

#include <stdint.h>

// Audio sample ring buffer (jitter buffer). Single-producer / single-
// consumer, non-blocking: q_write drops on full, q_read returns 0 on empty.
// A `stall` flag holds reads (returns silence) until the queue has buffered
// >1600 samples, absorbing network jitter on the playback path.
//
// Private to the audio backend (audio.cpp). Callers above audio.h never see
// this type — the audio HAL exposes frame-level play/capture instead.

#define MAX_Q	4800

struct Queue{
	int head;
	int	tail;
	int	count;
	int16_t	data[MAX_Q];
	int  stall;
};

void q_init(struct Queue *p);
void q_write(struct Queue *p, int16_t w);
int16_t q_read(struct Queue *p);

// Flush all buffered samples and re-arm the stall guard (reads stay silent
// until the queue refills past the threshold). `stall` is set first so a
// concurrent q_read from an audio callback/ISR reads silence during the
// reset rather than a torn index.
void q_reset(struct Queue *p);
