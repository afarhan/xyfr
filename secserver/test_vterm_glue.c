// test_vterm_glue.c — exercise the libvterm wrapper with no network, no PTY.
// Build: make vterm_glue_test && ./vterm_glue_test

#include "vterm_glue.h"

#include <stdio.h>
#include <string.h>

static int fails = 0;

static void feed(struct vterm_glue *g, const char *s)
{
	vg_write(g, (const uint8_t *)s, (int)strlen(s));
}

// Read row `r` as a NUL-terminated string with trailing blanks trimmed.
static void row_text(struct vterm_glue *g, int r, char *out, size_t osz)
{
	const uint8_t *ch = vg_chars(g);
	int cols = vg_cols(g);
	int n = cols < (int)osz - 1 ? cols : (int)osz - 1;
	memcpy(out, ch + r * cols, (size_t)n);
	out[n] = 0;
	for (int i = n - 1; i >= 0 && out[i] == ' '; i--) out[i] = 0;
}

static void expect_row(struct vterm_glue *g, int r, const char *want, const char *what)
{
	char got[VG_COLS_MAX + 1];
	row_text(g, r, got, sizeof got);
	if (strcmp(got, want) != 0) {
		printf("  FAIL %-28s row %d: want [%s] got [%s]\n", what, r, want, got);
		fails++;
	} else {
		printf("  ok   %-28s row %d [%s]\n", what, r, got);
	}
}

static void expect_int(int got, int want, const char *what)
{
	if (got != want) { printf("  FAIL %-28s want %d got %d\n", what, want, got); fails++; }
	else             { printf("  ok   %-28s %d\n", what, got); }
}

int main(void)
{
	printf("vterm_glue tests (libvterm)\n");

	// --- plain text + wrap ---------------------------------------------------
	struct vterm_glue *g = vg_new(80, 25);
	if (!g) { printf("vg_new failed\n"); return 1; }
	feed(g, "hello world");
	expect_row(g, 0, "hello world", "plain text");

	// --- CR/LF ---------------------------------------------------------------
	feed(g, "\r\nsecond line");
	expect_row(g, 1, "second line", "CRLF");

	// --- cursor addressing (CUP) --------------------------------------------
	feed(g, "\x1b[5;3HX");
	expect_row(g, 4, "  X", "CUP ESC[5;3H");

	// --- erase line (EL) -----------------------------------------------------
	feed(g, "\x1b[1;1H\x1b[2K");
	expect_row(g, 0, "", "EL ESC[2K");

	// --- erase display (ED) --------------------------------------------------
	feed(g, "\x1b[2J");
	expect_row(g, 1, "", "ED ESC[2J clears row 1");
	expect_row(g, 4, "", "ED ESC[2J clears row 4");

	// --- SGR reverse survives as an attribute -------------------------------
	feed(g, "\x1b[1;1H\x1b[7mREV\x1b[0m");
	{
		const uint8_t *at = vg_attrs(g);
		expect_int(at[0] & VG_ATTR_REVERSE, VG_ATTR_REVERSE, "SGR 7 -> reverse attr");
		expect_int(at[3] & VG_ATTR_REVERSE, 0,               "SGR 0 clears reverse");
	}

	// --- 256-colour SGR is parsed and DISCARDED, not printed ----------------
	feed(g, "\x1b[2J\x1b[1;1H\x1b[38;5;196mred text\x1b[0m");
	expect_row(g, 0, "red text", "256-colour SGR discarded");

	// --- cursor position + hide/show ----------------------------------------
	feed(g, "\x1b[10;20H");
	expect_int(vg_cursor(g), 9 * 80 + 19, "cursor after CUP");
	feed(g, "\x1b[?25l");
	expect_int(vg_cursor(g), -1, "DECTCEM hide -> -1");
	feed(g, "\x1b[?25h");
	expect_int(vg_cursor(g), 9 * 80 + 19, "DECTCEM show");

	// --- bell is sticky until read ------------------------------------------
	feed(g, "\a");
	expect_int(vg_take_bell(g) ? 1 : 0, 1, "bell latched");
	expect_int(vg_take_bell(g) ? 1 : 0, 0, "bell cleared by read");

	// --- scroll region + scroll hint (the SCROLL op) -----------------------
	{
		struct vterm_glue *s = vg_new(80, 25);
		feed(s, "\x1b[2J");
		for (int i = 1; i <= 25; i++) { char b[32]; snprintf(b, sizeof b, "line%d\r\n", i); feed(s, b); }
		(void)vg_chars(s);
		int top = -1, bot = -1, delta = 0;
		int got = vg_take_scroll(s, &top, &bot, &delta) ? 1 : 0;
		expect_int(got, 1, "scroll hint produced");
		if (got) {
			printf("  ..   scroll top=%d bot=%d delta=%d\n", top, bot, delta);
			if (delta <= 0) { printf("  FAIL scroll delta should be >0 (content up)\n"); fails++; }
		}
		expect_int(vg_take_scroll(s, &top, &bot, &delta) ? 1 : 0, 0, "scroll hint consumed");
		vg_free(s);
	}

	// --- alternate screen (what vi/less use) --------------------------------
	{
		struct vterm_glue *a = vg_new(80, 25);
		feed(a, "\x1b[2J\x1b[1;1Hmain screen");
		expect_row(a, 0, "main screen", "primary screen");
		feed(a, "\x1b[?1049h\x1b[2J\x1b[1;1Halt screen");   // enter alt
		expect_row(a, 0, "alt screen", "alt screen entered");
		feed(a, "\x1b[?1049l");                              // leave alt
		expect_row(a, 0, "main screen", "primary restored on exit");
		vg_free(a);
	}

	// --- UTF-8 becomes '?' rather than multiple cells or garbage ------------
	feed(g, "\x1b[2J\x1b[1;1Hok\xe2\x94\x80ok");             // U+2500 box drawing
	expect_row(g, 0, "ok?ok", "UTF-8 -> single '?' cell");

	// --- vg_write consumes everything (the anti-data-loss property) ---------
	{
		struct vterm_glue *b = vg_new(80, 25);
		char big[8192];
		memset(big, 'x', sizeof big);
		vg_write(b, (const uint8_t *)big, (int)sizeof big);   // must not truncate/crash
		const uint8_t *ch = vg_chars(b);
		expect_int(ch[0], 'x', "large write consumed");
		vg_free(b);
	}

	vg_free(g);
	printf(fails ? "\nFAILED (%d)\n" : "\nALL PASS\n", fails);
	return fails ? 1 : 0;
}
