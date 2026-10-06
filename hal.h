#pragma once
//
// hal.h — the platform porting interface for the portable `kernel` stack.
//
// The portable stack (kernel.c + session / requests / call / contacts /
// storage / cmdq / text, declared in their narrow headers) is platform-
// independent and reaches the outside world ONLY through the functions declared
// here. Porting the stack to a new platform means implementing this one header;
// nothing else changes.
//
// Two backends exist:
//   - device  : Arduino / RP2350 — net over WiFiUDP, fs over LittleFS, time over
//               millis(), debug over the non-blocking Serial `Debug` object.
//   - host CLI : Linux — net over BSD UDP sockets, fs over POSIX (rooted at
//               ./fsroot), time over a monotonic clock, debug over stdio.
//
// All HAL calls run on the stack core/thread (the kernel). They are NOT required
// to be thread-safe; the one cross-thread channel (cmdq) is a separate lock-free
// SPSC ring (cmdq.h).

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================ net: UDP datagrams ============================
//
// Opaque UDP socket handle. `net_sock*` replaces the old `WiFiUDP*` that used to
// thread through session/requests — it keeps Arduino types out of the core.
//
// Addresses are host-order uint32 IPv4 (octet 0 in the high byte, as the transmitted
// carries them) + uint16 port. The relay endpoint and per-session source-port
// anonymity model are unchanged; only the socket type is abstracted.
typedef struct net_sock net_sock;

// Open a UDP socket bound to `port`; port 0 means "ephemeral" — the OS picks a
// free source port. Used for both the login socket and per-session sockets: an
// ephemeral source port (0) keeps a session origination unlinkable from our
// login identity at the relay (THREAT_MODEL.md §10.4). Returns NULL on failure.
net_sock *net_open(uint16_t port);

// Close and free a socket (safe on NULL).
void net_close(net_sock *s);

// The local port the socket is bound to (diagnostics/logging).
uint16_t net_local_port(net_sock *s);

// Send one datagram to (ip4, port). Returns bytes sent, or <0 on error.
int net_send(net_sock *s, uint32_t ip4, uint16_t port,
             const uint8_t *buf, int len);

// Simulated inbound packet loss, in PERCENT. 0 (the default) is off. It is a
// runtime global so a soak can turn it on, change it and turn it off without a
// reflash, and so a reboot always comes back with the radio honest.
//
// It is applied in net_recv, on the RECEIVING side only. Every peer drops its
// own inbound, so each direction of a path crosses exactly one drop point and
// the end-to-end loss rate IS this number; dropping on send as well would
// compound the two into roughly half the traffic.
extern int net_loss_pct;

// Non-blocking receive of one datagram. On a packet: fills *src_ip4/*src_port,
// copies up to `max` bytes into buf, returns the byte count. Returns 0 if no
// datagram is waiting, <0 on error. Callers loop until 0 to drain the socket.
int net_recv(net_sock *s, uint32_t *src_ip4, uint16_t *src_port,
             uint8_t *buf, int max);

// ================================== time ===================================

// Monotonic milliseconds since boot (wraps at 2^32 ms ≈ 49 days; all timers use
// wrap-safe (int32_t)(a-b) comparisons). Device: millis(). Host: monotonic clock.
uint32_t now_ms(void);

// Wall-clock UTC seconds. Device: millis()/1000 + NTP correction. Host: time().
// Used for contact-log record timestamps.
time_t now_seconds(void);

// Cooperative sleep (the loop's ~5 ms pacing). Device: delay(). Host: usleep().
void hal_delay_ms(uint32_t ms);

// ================================== debug ==================================

// Verbosity levels — the first arg to hal_debug(). Ascending severity; a
// message is emitted only when its level >= the runtime floor hal_log_level.
#define LOG_EVERYTHING  0   // routine flow + packet/telemetry detail
#define LOG_WARNING     1   // recoverable/expected-but-notable (defers, drops, timeouts)
#define LOG_ERROR       2   // an operation failed (alloc/send/parse/lookup)
#define LOG_CRITICAL    3   // reserved for unrecoverable conditions

// Runtime verbosity floor: hal_debug() prints only if debug_level >= this.
// LOG_EVERYTHING (0) = print all; raise it to quiet the log. Tunable global.
extern int hal_log_level;

// printf-style diagnostic line, gated by `debug_level` (LOG_*). MUST NOT block:
// device drops the write when the Serial TX buffer is full (see the
// blocking-Serial wedge history); host writes to stderr. Pervasive throughout
// the core — keep it cheap.
void hal_debug(int debug_level, const char *fmt, ...);

// ============================ rng (CSPRNG) =================================
//
// hal_rand() is THE platform cryptographic RNG — the single entropy source the
// whole stack draws from (ephemeral keys, nonces, stream ISNs, session-ids). It
// MUST be a real hardware-backed CSPRNG per platform: device → RP2350 hardware
// RNG (get_rand_32); host → getrandom() / /dev/urandom. NEVER libc rand(): an
// unseeded rand() is the J-1 CRITICAL flaw in THREAT_MODEL.md (predictable keys
// on the Linux relay/server).
//
// wg.c's fill_random() (declared in wg.h, the byte-buffer filler built on this)
// calls hal_rand() instead of rand() — a user-authorized one-time exception to
// the do-not-edit-wg.c rule (wg.c had the lone rand() site; crypto.c has none).
// This replaces the implicit libc rand() symbol-override that ui.cpp installed.
// get_fresh_sessionid() stays in wg.c (built on fill_random).
uint32_t hal_rand(void);

// ============================ scratch arena ================================
//
// A SINGLE shared scratch block for the big, mutually-exclusive, transient
// operations (web restore, DoH/TLS, backup) — none of which run at once (all
// core-0, each either a dedicated boot mode or a blocking foreground op). Device:
// ONE static buffer behind a busy flag — hal_malloc returns it iff free AND the
// request fits (else NULL); hal_free releases it. Host: real malloc/free (desktops
// are not RAM-bound). Callers MUST null-check the result and hal_free exactly what
// they got. NOT for long-lived or nested allocations — one holder at a time.
#define HAL_SCRATCH_SIZE 65536u
void *hal_malloc(size_t n);
void  hal_free(void *p);

// =============================== fs: storage ===============================
//
// A tiny POSIX-flavored file API wrapping the platform store. Device: LittleFS.
// Host: real files rooted under ./fsroot (so "/c/<id>.bin" → ./fsroot/c/<id>.bin),
// which makes contacts + the message log host-native and debuggable under
// gdb/valgrind/ASan. Paths are absolute ("/device_record.bin", "/c/<userid>.bin").
typedef struct fs_file fs_file;
typedef struct fs_dir  fs_dir;

enum {
	FS_RDONLY = 0,   // open existing for read              (LittleFS "r")
	FS_RDWR   = 1,   // open existing for read+write (rmw)   (LittleFS "r+")
	FS_WRITE  = 2,   // create/truncate for write           (LittleFS "w")
	FS_APPEND = 3,   // open/create for write at end-of-file (LittleFS "a")
};

// Mount/prepare the backing store (idempotent). Device: LittleFS.begin().
// Host: ensure the ./fsroot base dir exists. Returns true once ready.
bool fs_init(void);

// Open `path` in one of the FS_* modes. Returns NULL on failure.
fs_file *fs_open(const char *path, int mode);

// Read/write up to `len` bytes. Return bytes transferred, 0 at EOF (read), or
// <0 on error.
int  fs_read(fs_file *f, void *buf, int len);
int  fs_write(fs_file *f, const void *buf, int len);

// Seek to absolute offset `off` (SEEK_SET). Returns the new offset, or <0.
int  fs_seek(fs_file *f, int off);

// Total file size in bytes, or <0 on error.
int  fs_size(fs_file *f);

// Close (safe on NULL).
void fs_close(fs_file *f);

bool fs_exists(const char *path);
bool fs_remove(const char *path);
bool fs_mkdir(const char *path);
bool fs_rename(const char *from, const char *to);

// Directory iteration (for contact_ls / block_dump). Open a dir, then call
// fs_readdir until it returns false. Each call fills `name` (NUL-terminated, up
// to name_max), *size (bytes), *is_dir. fs_closedir releases the handle.
fs_dir *fs_opendir(const char *path);
bool    fs_readdir(fs_dir *d, char *name, int name_max, int *size, bool *is_dir);
void    fs_closedir(fs_dir *d);

#ifdef __cplusplus
}
#endif
