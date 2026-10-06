// keyboard_probe.cpp — ask which keyboard is fitted, by pointing at keys.
//
// Two hardware revisions carry the same keycaps but connect them to different
// matrix positions, so a device with no stored layout cannot name a key: asking
// the user to "press Enter" is circular. It can still ask for a key by WHERE IT
// SITS, and read the raw matrix position that comes back. That is the whole
// trick, and it is why this file talks to keyboard_raw_down() rather than to
// keyboard_read().
//
// Four corners, in a fixed order. Any single one of them separates the two
// boards; the other three exist so a mis-press is caught here instead of being
// saved. After each press the layouts that do not match are dropped, and if none
// survive the sequence starts over rather than guessing.
//
// Runs from setup(), after block_read() and before the UI comes up, so no key is
// ever read through a layout nobody chose. Blocking by design: there is nothing
// useful the device can do first.

#include <Arduino.h>
#include "ui.h"
#include "device_record.h"
#include "display_backend.h"
#include "debug.h"

#define PROBE_CORNERS 4

struct probe_layout {
	uint8_t     layout;                  // KBD_LAYOUT_*
	const char *name;
	int8_t      corner[PROBE_CORNERS];   // matrix position of each corner, in prompt order
};

// The matrix position each corner key occupies on each board. v2 has no key in
// the extreme bottom corners -- those two positions are what v3 adds -- so its
// bottom row answers from one column in, which is still the key a finger lands
// on when reaching for the corner.
static const struct probe_layout probe_layouts[] = {
	{ KBD_LAYOUT_V2, "v2", { 29,  2, 31,  8 } },
	{ KBD_LAYOUT_V3, "v3", {  7, 31, 19,  1 } },
};
#define PROBE_LAYOUTS ((int)(sizeof probe_layouts / sizeof probe_layouts[0]))

static const char *corner_prompt[PROBE_CORNERS] = {
	"top-left", "top-right", "bottom-right", "bottom-left",
};

static void probe_paint(int step, const char *note) {
	int mid = panel_height() / 2;
	panel_fill(0, 0, panel_width(), panel_height(), false);
	panel_text_center(mid - 60, 2, "Which keyboard is this?");
	static char ask[48];
	snprintf(ask, sizeof ask, "Press the %s key", corner_prompt[step]);
	panel_text_center(mid - 16, 3, ask);
	static char count[24];
	snprintf(count, sizeof count, "%d of %d", step + 1, PROBE_CORNERS);
	panel_text_center(mid + 24, 2, count);
	if (note)
		panel_text_center(mid + 56, 2, note);
	panel_present();
}

// One press, as a raw matrix position. Waits for the key to lift as well, so the
// same hold cannot answer two prompts.
static int probe_await_key(void) {
	while (keyboard_raw_down() >= 0)
		delay(20);                       // whatever brought us here, let go first
	int pos = -1;
	while (pos < 0) {
		pos = keyboard_raw_down();
		delay(20);
	}
	while (keyboard_raw_down() >= 0)
		delay(20);
	return pos;
}

// Ask until one layout is left, then store and apply it. Returns the layout.
uint8_t keyboard_probe_run(void) {
	bool live[PROBE_LAYOUTS];
	const char *note = NULL;

	for (;;) {
		for (int i = 0; i < PROBE_LAYOUTS; i++)
			live[i] = true;

		bool restart = false;
		for (int step = 0; step < PROBE_CORNERS && !restart; step++) {
			probe_paint(step, note);
			note = NULL;
			int pos = probe_await_key();
			int survivors = 0;
			for (int i = 0; i < PROBE_LAYOUTS; i++) {
				if (live[i] && probe_layouts[i].corner[step] != pos)
					live[i] = false;
				if (live[i])
					survivors++;
			}
			Debug.printf("kbdprobe: %s -> raw %d%d, %d layout(s) left\n",
			             corner_prompt[step], pos / 6, pos % 6, survivors);
			if (survivors == 0) {
				note = "That was not one of them. Starting over.";
				restart = true;
			}
		}
		if (restart)
			continue;

		int chosen = -1;
		int survivors = 0;
		for (int i = 0; i < PROBE_LAYOUTS; i++) {
			if (!live[i])
				continue;
			survivors++;
			chosen = i;
		}
		// Two boards answering the same to all four corners means the table above
		// no longer tells them apart. Say so rather than pick one.
		if (survivors != 1) {
			note = "Cannot tell these apart. Starting over.";
			continue;
		}

		const struct probe_layout *pl = &probe_layouts[chosen];
		device_record.keyboard_layout = pl->layout;
		keyboard_set_layout(pl->layout);
		flag_save_block = 1;             // core 0 writes it in block_pump
		Debug.printf("kbdprobe: keyboard is %s\n", pl->name);
		panel_fill(0, 0, panel_width(), panel_height(), false);
		static char done[40];
		snprintf(done, sizeof done, "Keyboard set: %s", pl->name);
		panel_text_center(panel_height() / 2, 3, done);
		panel_present();
		delay(1200);
		return pl->layout;
	}
}
