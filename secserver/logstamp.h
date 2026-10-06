#pragma once
// logstamp — prefix every stdout/stderr line of a host daemon with a UTC
// wall-clock timestamp, process-wide, without touching the hundreds of
// printf / RLOG / hal_debug call sites. Call logstamp_install() once, as the
// first thing in main(), before anything logs.
//
// It replaces the stdout/stderr FILE* (glibc exposes them as assignable
// lvalues) with a fopencookie stream whose write callback emits
// "YYYY-MM-DD HH:MM:SS.mmmZ " at each line start. The line-start state persists
// across writes, so a line assembled by several printf calls is stamped exactly
// once — at its true beginning, not mid-line.

#ifdef __cplusplus
extern "C" {
#endif

void logstamp_install(void);

#ifdef __cplusplus
}
#endif
