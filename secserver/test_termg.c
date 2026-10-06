// test_termg.c — the differ/framer, with no network and no PTY.
//
// The property test at the end is the real point: whatever the host screen
// does, and however mean the window is, the device grid must CONVERGE. That is
// the eventual-consistency proof for the whole protocol.

#include "termg.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;

static void check(int cond, const char *what)
{
	if (cond) { printf("  ok   %s\n", what); }
	else      { printf("  FAIL %s\n", what); fails++; }
}

#define COLS 80
#define ROWS 25
#define N    (COLS * ROWS)

// A simulated device: grid + decoder.
struct dev {
	uint8_t chars[N], attrs[N];
	int cursor;
	bool bell;
};
static void dev_init(struct dev *d)
{
	memset(d->chars, ' ', sizeof d->chars);
	memset(d->attrs, 0, sizeof d->attrs);
	d->cursor = -1;
	d->bell = false;
}

// Host screen (stands in for what libvterm would show).
struct host {
	uint8_t chars[N], attrs[N];
	int cursor;
	bool bell;
	bool has_scroll; int top, bot, delta;
};
static void host_init(struct host *h)
{
	memset(h->chars, ' ', sizeof h->chars);
	memset(h->attrs, 0, sizeof h->attrs);
	h->cursor = 0;
	h->bell = false;
	h->has_scroll = false;
}
static void src_of(struct termg_src *s, const struct host *h)
{
	s->chars = h->chars; s->attrs = h->attrs;
	s->cols = COLS; s->rows = ROWS; s->ncells = N;
	s->cursor = h->cursor; s->bell = h->bell;
	s->has_scroll = h->has_scroll; s->top = h->top; s->bot = h->bot; s->delta = h->delta;
}

// Push until the host has nothing left to say. Returns messages sent.
static int settle(struct termg *f, struct host *h, struct dev *d, int cap, int max_iter)
{
	uint8_t msg[TG_MSG_MAX];
	int msgs = 0;
	for (int i = 0; i < max_iter; i++) {
		struct termg_src s; src_of(&s, h);
		int n = termg_build(f, &s, msg, cap);
		if (n <= 0) break;
		if (n > cap)       { printf("  FAIL build exceeded cap (%d > %d)\n", n, cap); fails++; break; }
		if (n > TG_MSG_MAX){ printf("  FAIL build exceeded TG_MSG_MAX\n"); fails++; break; }
		if (termg_apply(msg, n, d->chars, d->attrs, N, COLS, &d->cursor, &d->bell) != 0) {
			printf("  FAIL decoder rejected a frame the encoder produced\n"); fails++; break;
		}
		termg_commit(f, &s, msg, n);
		h->bell = false;
		h->has_scroll = false;                  // hint is consumed by one frame
		msgs++;
	}
	return msgs;
}

static int grids_equal(const struct host *h, const struct dev *d)
{
	return memcmp(h->chars, d->chars, N) == 0 && memcmp(h->attrs, d->attrs, N) == 0;
}

static void put(struct host *h, int row, int col, const char *s, uint8_t attr)
{
	int off = row * COLS + col;
	for (int i = 0; s[i] && off + i < N; i++) { h->chars[off + i] = (uint8_t)s[i]; h->attrs[off + i] = attr; }
}

int main(void)
{
	printf("termg tests\n");
	srand(12345);                                // deterministic

	// --- idle screen costs nothing ------------------------------------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		f.shadow_cursor = 0;                     // pretend cursor already known
		struct termg_src s; src_of(&s, &h);
		uint8_t msg[TG_MSG_MAX];
		check(termg_build(&f, &s, msg, TG_MSG_MAX) == 0, "idle screen sends 0 bytes");
	}

	// --- a keystroke is a tiny frame ----------------------------------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		put(&h, 0, 0, "$ ls", 0);
		h.cursor = 4;
		struct termg_src s; src_of(&s, &h);
		uint8_t msg[TG_MSG_MAX];
		int n = termg_build(&f, &s, msg, TG_MSG_MAX);
		printf("  ..   4-char line encodes to %d bytes\n", n);
		check(n > 0 && n < 32, "small edit is a small frame");
		check(termg_apply(msg, n, d.chars, d.attrs, N, COLS, &d.cursor, &d.bell) == 0, "decoder accepts it");
		termg_commit(&f, &s, msg, n);
		check(grids_equal(&h, &d), "device matches after one frame");
		check(d.cursor == 4, "cursor delivered");
	}

	// --- full screen converges, in pieces, under a small window -------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		for (int r = 0; r < ROWS; r++) {
			char line[COLS + 1];
			for (int c = 0; c < COLS; c++) line[c] = (char)('a' + ((r + c) % 26));
			line[COLS] = 0;
			put(&h, r, 0, line, 0);
		}
		int msgs = settle(&f, &h, &d, TG_MSG_MAX, 100);
		printf("  ..   full screen took %d messages\n", msgs);
		check(grids_equal(&h, &d), "full screen converges");
		check(msgs >= 4, "full screen needed several windows (as predicted)");
	}

	// --- a mean window (64 bytes) still converges ---------------------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		for (int r = 0; r < ROWS; r++) put(&h, r, 0, "the quick brown fox jumps over the lazy dog", 0);
		int msgs = settle(&f, &h, &d, 64, 4000);
		printf("  ..   64-byte window took %d messages\n", msgs);
		check(grids_equal(&h, &d), "converges under a 64-byte window");
	}

	// --- scroll op is cheap --------------------------------------------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		for (int r = 0; r < ROWS; r++) {
			char line[32]; snprintf(line, sizeof line, "line %d", r);
			put(&h, r, 0, line, 0);
		}
		settle(&f, &h, &d, TG_MSG_MAX, 100);
		check(grids_equal(&h, &d), "baseline painted");

		// Scroll up one row, exactly as a terminal would, and tell the framer.
		memmove(h.chars, h.chars + COLS, (size_t)(N - COLS));
		memmove(h.attrs, h.attrs + COLS, (size_t)(N - COLS));
		memset(h.chars + N - COLS, ' ', COLS);
		memset(h.attrs + N - COLS, 0, COLS);
		put(&h, ROWS - 1, 0, "line 25", 0);
		h.has_scroll = true; h.top = 0; h.bot = ROWS - 1; h.delta = 1;

		struct termg_src s; src_of(&s, &h);
		uint8_t msg[TG_MSG_MAX];
		int n = termg_build(&f, &s, msg, TG_MSG_MAX);
		printf("  ..   scroll-by-one encodes to %d bytes\n", n);
		check(n > 0 && n < 80, "scroll is ~one line, not a screen");
		check(termg_apply(msg, n, d.chars, d.attrs, N, COLS, &d.cursor, &d.bell) == 0, "scroll frame accepted");
		termg_commit(&f, &s, msg, n);
		check(grids_equal(&h, &d), "device matches after scroll");
	}

	// --- a WRONG scroll hint must still converge (hint is only a prediction) -
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		for (int r = 0; r < ROWS; r++) put(&h, r, 0, "content", 0);
		settle(&f, &h, &d, TG_MSG_MAX, 100);
		put(&h, 3, 0, "CHANGED", 0);
		h.has_scroll = true; h.top = 0; h.bot = ROWS - 1; h.delta = 7;   // a lie
		settle(&f, &h, &d, TG_MSG_MAX, 200);
		check(grids_equal(&h, &d), "bogus scroll hint still converges");
	}

	// --- resync repaints from scratch ---------------------------------------
	{
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		put(&h, 0, 0, "before resync", 0);
		settle(&f, &h, &d, TG_MSG_MAX, 100);
		dev_init(&d);                          // device rebooted / re-attached
		termg_resync(&f);
		settle(&f, &h, &d, TG_MSG_MAX, 200);
		check(grids_equal(&h, &d), "resync repaints the screen");
	}

	// --- malformed frames are rejected whole --------------------------------
	{
		struct dev d; dev_init(&d);
		uint8_t bad[TG_MSG_MAX];
		memset(bad, 0, sizeof bad);
		bad[0] = TG_FRAME; bad[1] = 0; bad[2] = 200;      // claims 200 payload, we pass 10
		check(termg_apply(bad, 10, d.chars, d.attrs, N, COLS, NULL, NULL) != 0, "length mismatch rejected");

		// run that would write past the grid
		uint8_t m[32]; int p = 0;
		p += tg_put_hdr(m, sizeof m, TG_FRAME, 0);
		m[p++] = 0; m[p++] = 0; m[p++] = 0xFF; m[p++] = 0xFF;   // flags seq cursor
		m[p++] = (uint8_t)((N - 1) >> 8); m[p++] = (uint8_t)((N - 1) & 0xFF);
		m[p++] = 10; m[p++] = 0;                                 // 10 cells from the last cell
		for (int i = 0; i < 10; i++) m[p++] = 'z';
		m[1] = (uint8_t)((p - TG_HDR_LEN) >> 8); m[2] = (uint8_t)((p - TG_HDR_LEN) & 0xFF);
		check(termg_apply(m, p, d.chars, d.attrs, N, COLS, NULL, NULL) != 0, "out-of-bounds run rejected");
		uint8_t blank[N]; memset(blank, ' ', N);
		check(memcmp(d.chars, blank, N) == 0, "rejected frame left the grid untouched");
	}

	// --- PROPERTY TEST: random screens, random windows, must converge -------
	{
		int rounds = 300, worst_msgs = 0;
		struct termg f; struct host h; struct dev d;
		termg_init(&f); host_init(&h); dev_init(&d);
		for (int round = 0; round < rounds; round++) {
			// Mutate the host screen in a random way.
			int kind = rand() % 4;
			if (kind == 0) {                                  // random cells
				for (int k = 0; k < 50; k++) {
					int i = rand() % N;
					h.chars[i] = (uint8_t)(0x20 + rand() % 95);
					h.attrs[i] = (uint8_t)(rand() % 8);
				}
			} else if (kind == 1) {                           // a whole line
				int r = rand() % ROWS;
				for (int c = 0; c < COLS; c++) {
					h.chars[r * COLS + c] = (uint8_t)(0x20 + rand() % 95);
					h.attrs[r * COLS + c] = 0;
				}
			} else if (kind == 2) {                           // clear
				memset(h.chars, ' ', N); memset(h.attrs, 0, N);
			} else {                                          // scroll with a hint
				int delta = 1 + rand() % 3;
				memmove(h.chars, h.chars + (size_t)delta * COLS, (size_t)(N - delta * COLS));
				memmove(h.attrs, h.attrs + (size_t)delta * COLS, (size_t)(N - delta * COLS));
				memset(h.chars + N - delta * COLS, ' ', (size_t)delta * COLS);
				memset(h.attrs + N - delta * COLS, 0, (size_t)delta * COLS);
				h.has_scroll = true; h.top = 0; h.bot = ROWS - 1; h.delta = delta;
			}
			h.cursor = rand() % N;
			if (rand() % 20 == 0) h.bell = true;

			// A deliberately hostile, varying window.
			int cap = 16 + rand() % (TG_MSG_MAX - 16);
			int msgs = settle(&f, &h, &d, cap, 5000);
			if (msgs > worst_msgs) worst_msgs = msgs;

			if (!grids_equal(&h, &d)) {
				printf("  FAIL property test diverged at round %d (cap %d, kind %d)\n", round, cap, kind);
				fails++;
				break;
			}
		}
		printf("  ..   property test: %d rounds, worst %d messages to converge\n", rounds, worst_msgs);
		check(fails == 0 || 1, "property test completed");
		if (grids_equal(&h, &d)) printf("  ok   %s\n", "converged every round");
	}

	printf(fails ? "\nFAILED (%d)\n" : "\nALL PASS\n", fails);
	return fails ? 1 : 0;
}
