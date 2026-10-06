#pragma once
// term_host — the host-only TERM application: a wg-native remote terminal.
//
//   SERVER: registers a "TERM" app on the app router. An inbound TERM
//   stream forks a PTY running a shell (or the requested command) and bridges
//   the PTY master fd <-> the reliable stream. Only the host does this; the
//   device is a client and never registers a TERM responder.
//
//   CLIENT: `./phone term <64hex-key> [command]` originates a wg session to a
//   TERM server, opens a stream, puts the local tty in raw mode, and bridges
//   local stdin/stdout <-> the stream — a poor-man's ssh over wg.
//
// All the transport calls happen on the stack (core-0) thread; term_client_feed()
// is the one producer the console (main) thread drives, over a lock-free ring.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---- server ----
void term_host_register(void);   // register the TERM app (from phone_host main)

// THREAT_MODEL J-8: permit partkey to open a terminal. DEFAULT DENY -- a peer
// not added here is refused even though its wg handshake succeeded. Fed from
// `allow_terminal=<8hex>` lines in client.conf.
void term_allow_add(uint32_t partkey);

// Persistent sessions (termd.conf `persistent=1`, default off): a stream close
// keeps the shell alive instead of reaping it, and the same peer reconnecting
// re-attaches to the running shell (resume vi mid-edit) with a full repaint. A
// detached shell with no reconnect is reaped after the timeout (default 1 h;
// termd.conf `persist_timeout_secs`).
void term_set_persistent(int on);
void term_set_persist_timeout_secs(int secs);

// ---- pump (stack thread, each tick) ----
// Drains server PTY masters -> streams, reaps exited shells, and drains the
// client stdin ring -> its stream. Cheap no-op for whichever role is idle.
void term_pump(void);

// ---- client mode (legacy raw byte stream) ----
void term_client_start(const uint8_t peer_pubkey[32], const char *command);
int  term_client_running(void);                       // 1 until the stream ends
void term_client_feed(const uint8_t *bytes, int len); // main thread: raw stdin -> ring

// ---- client mode (TERMG grid) ----
// `./phone termg <64hex-key> [command]`. The host emulates the terminal and
// sends changed cells; this renders that grid to the local tty using the SAME
// decoder the device runs, so the protocol is testable host-to-host.
void termg_client_start(const uint8_t peer_pubkey[32], const char *command);
int  termg_client_running(void);
void termg_client_feed(const uint8_t *bytes, int len);

#ifdef __cplusplus
}
#endif
