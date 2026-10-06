// term_host.c — the TERM server: a PTY-backed shell per peer, bridged to a
// stream on PORT_TERM.
//
// A SESSION IS KEYED BY PARTKEY, not by a stream. Streams come and go — an idle
// one is reaped after stream_idle_ms and the peer's next write starts a new one
// at sequence 0 — while the shell outlives all of that. So the device can leave
// and come back and its shell is still there, mid-edit.
//
// THE STREAM IS RAW BYTES BOTH WAYS: keystrokes up, PTY output down, no framing.
// The device parses the PTY's ANSI itself.
//
// NOT YET BUILT, deliberately, until the terminal has been used for a while:
// the foreground/background lifecycle. A shell currently lives until it exits
// or TERM_IDLE_MS passes with nothing heard from its peer. Freezing a
// backgrounded shell, and letting termd.conf choose freeze-vs-drop, is the next
// piece of work — see the discussion in git log.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "hal.h"           // now_ms
#include "../kernel.h"     // kernel_listen_stream, NOTIFY_*
#include "../stream.h"
#include "../peer_data.h"  // PORT_TERM
#include "term_host.h"

// The device's grid at its default font (tui.cpp's 6x12 profile). A font flip
// makes it 60x18 and the shell will wrap wrong until the device can say so —
// that is the size channel, and it is not built yet.
#define TERM_COLS 80
#define TERM_ROWS 25

// One shell per peer. Small: this is a personal terminal server, not a shell host.
#define TERM_MAX 4

// Nothing heard from a peer for this long and the shell is reaped. Deliberately
// generous while the lifecycle is unbuilt — the device sends nothing at all when
// its terminal is backgrounded, so this is currently the ONLY thing that ends an
// abandoned session.
static uint32_t term_idle_ms = 3600000;   // 1 h

struct term_sess {
	bool     in_use;
	int      master_fd;        // PTY master, O_NONBLOCK
	pid_t    pid;
	uint32_t partkey;          // the wg-authenticated peer: the session's identity
	uint32_t last_heard_ms;

	// PTY -> device carry-over. These bytes are ALREADY consumed from the PTY, so
	// dropping them silently corrupts the stream: the shell believes it printed
	// them. Held until the send window can take them.
	uint8_t  out[1024];
	uint16_t out_len, out_off;

	// device -> PTY carry-over, for a short write.
	uint8_t  kb[256];
	uint16_t kb_len, kb_off;

	bool     pty_eof;          // shell gone; flush what is left, then reap
};
static struct term_sess sess[TERM_MAX];

static stream_handle term_stream;

// ---- access control (THREAT_MODEL J-8) -------------------------------------
// DEFAULT DENY. A peer whose wg handshake succeeded is still not entitled to a
// shell running as this user; it has to be named in the config.
#define TERM_ALLOW_MAX 16
static uint32_t term_allow[TERM_ALLOW_MAX];
static int      term_allow_n;

void term_allow_add(uint32_t partkey) {
	if (term_allow_n < TERM_ALLOW_MAX)
		term_allow[term_allow_n++] = partkey;
}

static bool admitted(uint32_t partkey) {
	for (int i = 0; i < term_allow_n; i++) {
		if (term_allow[i] == partkey)
			return true;
	}
	return false;
}

// ---- sessions --------------------------------------------------------------

static struct term_sess *sess_of(uint32_t partkey) {
	for (int i = 0; i < TERM_MAX; i++) {
		if (sess[i].in_use && sess[i].partkey == partkey)
			return &sess[i];
	}
	return NULL;
}

static void sess_free(struct term_sess *t) {
	if (!t || !t->in_use)
		return;
	if (t->master_fd >= 0)
		close(t->master_fd);
	if (t->pid > 0) {
		kill(t->pid, SIGHUP);
		waitpid(t->pid, NULL, WNOHANG);
	}
	memset(t, 0, sizeof *t);
	t->master_fd = -1;
}

// Fork a login shell on a PTY. TERM=xyfr is our own terminfo (secserver/xyfr.ti,
// installed with `tic -x`): it describes exactly the ANSI subset the device
// renders, so ncurses tailors apps to it instead of assuming xterm.
static struct term_sess *sess_open(uint32_t partkey) {
	struct term_sess *t = NULL;
	for (int i = 0; i < TERM_MAX; i++) {
		if (!sess[i].in_use) {
			t = &sess[i];
			break;
		}
	}
	if (!t) {
		printf("term: no free slot for %08x\n", (unsigned)partkey);
		return NULL;
	}
	memset(t, 0, sizeof *t);

	struct winsize ws;
	memset(&ws, 0, sizeof ws);
	ws.ws_col = TERM_COLS;
	ws.ws_row = TERM_ROWS;

	pid_t pid = forkpty(&t->master_fd, NULL, NULL, &ws);
	if (pid < 0) {
		printf("term: forkpty failed: %s\n", strerror(errno));
		return NULL;
	}
	if (pid == 0) {
		setenv("TERM", "xyfr", 1);
		const char *shell = getenv("SHELL");
		if (!shell || !*shell)
			shell = "/bin/bash";
		// A LOGIN interactive shell, so the device gets the same environment ssh
		// would give it -- /etc/profile and ~/.profile, so ~/bin is on PATH.
		execl(shell, shell, "-l", "-i", (char *)NULL);
		_exit(127);
	}
	fcntl(t->master_fd, F_SETFL, O_NONBLOCK);
	t->in_use        = true;
	t->pid           = pid;
	t->partkey       = partkey;
	t->last_heard_ms = now_ms();
	printf("term: shell pid %d for peer %08x\n", pid, (unsigned)partkey);
	return t;
}

// ---- device -> PTY ---------------------------------------------------------

static void kb_drain(struct term_sess *t) {
	while (t->kb_off < t->kb_len) {
		ssize_t w = write(t->master_fd, t->kb + t->kb_off,
		                  (size_t)(t->kb_len - t->kb_off));
		if (w <= 0)
			return;                    // EAGAIN: the rest waits for the next tick
		t->kb_off += (uint16_t)w;
	}
	t->kb_len = 0;
	t->kb_off = 0;
}

static void kb_push(struct term_sess *t, const uint8_t *b, int n) {
	if (n <= 0)
		return;
	if (t->kb_off) {                   // reclaim what has already gone out
		memmove(t->kb, t->kb + t->kb_off, (size_t)(t->kb_len - t->kb_off));
		t->kb_len = (uint16_t)(t->kb_len - t->kb_off);
		t->kb_off = 0;
	}
	int room = (int)sizeof t->kb - t->kb_len;
	if (n > room) {
		printf("term: keystroke FIFO full, dropping %d byte(s)\n", n - room);
		n = room;
	}
	if (n > 0) {
		memcpy(t->kb + t->kb_len, b, (size_t)n);
		t->kb_len += (uint16_t)n;
	}
}

// ---- the app ---------------------------------------------------------------

static int term_app_main(int message, uint32_t param) {
	if (message != NOTIFY_STREAM_DATA)
		return 0;

	// Our own size, not the transport's: stream.h reports room in bytes so a
	// caller never needs the segment size. Level-triggered, so a short read just
	// means we are told again next tick.
	uint8_t buf[512];
	int n = stream_read(term_stream, param, buf, (int)sizeof buf);
	if (n <= 0)
		return 1;

	struct term_sess *t = sess_of(param);
	if (!t) {
		// The first byte from a peer IS the open: there is no handshake to
		// refuse at, so admission is checked here.
		if (!admitted(param)) {
			printf("term: peer %08x not in allow_terminal; ignoring\n",
			       (unsigned)param);
			return 1;
		}
		t = sess_open(param);
		if (!t)
			return 1;
	}
	t->last_heard_ms = now_ms();
	kb_push(t, buf, n);
	kb_drain(t);
	return 1;
}

void term_host_register(void) {
	for (int i = 0; i < TERM_MAX; i++)
		sess[i].master_fd = -1;
	term_stream = kernel_listen_stream(PORT_TERM, term_app_main);
	if (!term_stream)
		printf("term: PORT_TERM already bound — the terminal server is off\n");
}

// ---- pump: PTY -> device, and reaping --------------------------------------

// Push whatever is held, then read more, as long as the window takes it. Held
// bytes go FIRST -- they came out of the PTY earlier and reordering them would
// scramble the shell's output.
static void pty_to_stream(struct term_sess *t) {
	for (;;) {
		if (t->out_off < t->out_len) {
			int room = stream_can_write(term_stream, t->partkey);
			if (room <= 0)
				return;
			int n = t->out_len - t->out_off;
			if (n > room)
				n = room;
			int sent = stream_write(term_stream, t->partkey, t->out + t->out_off, n);
			if (sent <= 0)
				return;
			t->out_off += (uint16_t)sent;
			if (t->out_off < t->out_len)
				return;                // the window took part of it; wait
			t->out_len = 0;
			t->out_off = 0;
		}
		if (t->pty_eof)
			return;
		ssize_t got = read(t->master_fd, t->out, sizeof t->out);
		if (got > 0) {
			t->out_len = (uint16_t)got;
			t->out_off = 0;
			continue;
		}
		if (got == 0 || (got < 0 && errno != EAGAIN && errno != EWOULDBLOCK))
			t->pty_eof = true;         // the shell exited
		return;
	}
}

void term_pump(void) {
	uint32_t now = now_ms();
	for (int i = 0; i < TERM_MAX; i++) {
		struct term_sess *t = &sess[i];
		if (!t->in_use)
			continue;

		kb_drain(t);
		pty_to_stream(t);

		// The shell is gone: say so in the terminal itself rather than inventing
		// a control message, then reap once the last output is away.
		if (t->pty_eof && t->out_off >= t->out_len) {
			static const char bye[] = "\r\n[session ended]\r\n";
			stream_write(term_stream, t->partkey, (const uint8_t *)bye,
			             (int)sizeof bye - 1);
			printf("term: shell pid %d for %08x exited\n", t->pid, (unsigned)t->partkey);
			sess_free(t);
			continue;
		}
		if ((uint32_t)(now - t->last_heard_ms) >= term_idle_ms) {
			printf("term: %08x idle, reaping shell pid %d\n",
			       (unsigned)t->partkey, t->pid);
			sess_free(t);
		}
	}
}

// The lifecycle knobs the config still sets. Their policy is the piece that is
// parked; accepting them keeps termd.conf working meanwhile.
void term_set_persistent(int on) {
	(void)on;                          // a session already survives its stream
}

void term_set_persist_timeout_secs(int secs) {
	if (secs > 0)
		term_idle_ms = (uint32_t)secs * 1000u;
}

// ---- client modes: not ported ----------------------------------------------
// `./phone term` / `./phone termg` were the host-as-client halves. The DEVICE is
// the client now, so these stay stubbed until something needs host-to-host.

void term_client_start(const uint8_t peer_pubkey[32], const char *command) {
	(void)peer_pubkey;
	(void)command;
	fprintf(stderr, "term: the host client is not ported; the device is the client\n");
}
int  term_client_running(void)                   { return 0; }
void term_client_feed(const uint8_t *b, int len) { (void)b; (void)len; }

void termg_client_start(const uint8_t peer_pubkey[32], const char *command) {
	(void)peer_pubkey;
	(void)command;
	fprintf(stderr, "term: TERMG is retired; the device speaks ANSI over the stream\n");
}
int  termg_client_running(void)                   { return 0; }
void termg_client_feed(const uint8_t *b, int len) { (void)b; (void)len; }
