// logstamp — see logstamp.h. Line-aware UTC timestamping of stdout + stderr for
// the host daemons (server / relay / termd / phone), installed once from main().
//
// Mechanism: redirect fd 1 and fd 2 through a pipe each, drained by a small
// thread that prefixes every line with a UTC stamp and writes it to the ORIGINAL
// sink (the shell's redirected file / the tty). This works at the raw fd level,
// deliberately NOT via fopencookie + a reassigned stdout FILE* — that path is
// broken on the droplet's glibc 2.19 (it separates newlines from their text and
// flushes them out of order). The pipe/thread design has no stdio dependency, so
// it behaves identically on ancient and modern glibc, and it also stamps raw
// write(2) output and anything else that lands on fd 1/2.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "logstamp.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>

struct ls_stream {
	int in_fd;    // read end of the pipe (the daemon's fd 1/2 write into it)
	int out_fd;   // dup of the ORIGINAL fd — the real sink (file / tty)
	int at_bol;   // 1 => next byte begins a fresh line and needs a stamp
};

static void ls_emit_stamp(int fd) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	time_t t = tv.tv_sec;
	struct tm g;
	gmtime_r(&t, &g);
	char ts[40];
	int n = snprintf(ts, sizeof ts, "%04d-%02d-%02d %02d:%02d:%02d.%03ldZ ",
	                 g.tm_year + 1900, g.tm_mon + 1, g.tm_mday,
	                 g.tm_hour, g.tm_min, g.tm_sec, (long)(tv.tv_usec / 1000));
	if (n > 0) {
		ssize_t w = write(fd, ts, (size_t)n);
		(void)w;
	}
}

// Split the bytes on '\n', emitting a stamp at each line start. at_bol persists
// across reads, so a line delivered in pieces is stamped exactly once.
static void ls_split(struct ls_stream *s, const char *buf, size_t n) {
	size_t i = 0;
	while (i < n) {
		if (s->at_bol) {
			ls_emit_stamp(s->out_fd);
			s->at_bol = 0;
		}
		size_t start = i;
		while (i < n && buf[i] != '\n')
			i++;
		if (i < n) {
			i++;                 // include the newline in this segment
			s->at_bol = 1;
		}
		ssize_t w = write(s->out_fd, buf + start, i - start);
		(void)w;
	}
}

static void *ls_pump(void *arg) {
	struct ls_stream *s = (struct ls_stream *)arg;
	char buf[4096];
	for (;;) {
		ssize_t r = read(s->in_fd, buf, sizeof buf);
		if (r <= 0)
			break;               // writer closed (process exiting) or error
		ls_split(s, buf, (size_t)r);
	}
	return NULL;
}

// Route one fd (1 or 2) through a pipe drained by a stamping thread. Returns 0
// on success; on any failure leaves the fd untouched (unstamped, but working).
static int ls_hook(int fd) {
	int p[2];
	if (pipe(p) != 0)
		return -1;
	int saved = dup(fd);             // the real sink the shell set up
	if (saved < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	struct ls_stream *s = (struct ls_stream *)malloc(sizeof *s);
	if (!s) {
		close(p[0]);
		close(p[1]);
		close(saved);
		return -1;
	}
	s->in_fd = p[0];
	s->out_fd = saved;
	s->at_bol = 1;
	pthread_t th;
	if (pthread_create(&th, NULL, ls_pump, s) != 0) {
		close(p[0]);
		close(p[1]);
		close(saved);
		free(s);
		return -1;
	}
	pthread_detach(th);
	dup2(p[1], fd);                  // fd now writes into the pipe
	close(p[1]);                     // the dup'd fd is the only writer we keep
	return 0;
}

void logstamp_install(void) {
	// fd 1/2 become pipes, which glibc would otherwise fully-buffer (logs would
	// look idle until a 4 KB flush). Unbuffer stdio so each line reaches the pipe
	// promptly; the stamping thread does the line framing.
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	ls_hook(1);
	ls_hook(2);
}
