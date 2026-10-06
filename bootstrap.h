// Domain-fenced server resolution via DoH. Used when the device suspects
// it is being blocked: fetch_new_ip() asks Cloudflare/Google for the live
// endpoints listed in a TXT record, caches the result in
// device_record.doh_endpoints, and persists it. Triggered from a user menu
// action, not from wifi_poll() -- it blocks core 0 for several seconds.
// Sets phone_state to PS_UNBLOCKING for the duration; wifi_poll's next
// tick restores the previous state.

#pragma once

// CYW43 / lwIP / BearSSL all live on core 0. Calling them from core 1
// (LVGL event handlers) hangs the connect because the chip is not
// addressed by the right core. UI code MUST go through the request/poll
// pair below; only wifi_poll() (core 0) calls fetch_new_ip() directly.

// Core 0 only. Run DoH against config.xyfr.net TXT, cache the result
// in device_record.doh_endpoints, persist via block_write(). Returns true on success.
bool fetch_new_ip();

// Core 1 (UI). Mark a resolve as pending; wifi_poll() will pick it up
// on its next tick and run fetch_new_ip() from core 0.
void request_fetch_new_ip();

// Core 0. Called from wifi_poll(); runs fetch_new_ip() if a request is
// pending, then clears the request flag.
void bootstrap_pump();

// Core 1 (UI). True between request_fetch_new_ip() and the moment core 0
// finishes the resolve. Poll from an LVGL timer.
bool fetch_new_ip_pending();

// Core 1 (UI). Result of the most recent completed resolve.
bool fetch_new_ip_last_ok();

// Result code for wait_on_flag. 0 = pending, 1 = success, 2 = failed.
// Set by bootstrap_pump on core 0 when the resolve completes; reset to
// 0 by the UI before invoking request_fetch_new_ip().
extern volatile int doh_result;

// Progress stage for the Unblock UI. bootstrap_pump() advances it one step per
// call so the UI can render each step. The DoH fetch itself blocks core 0, so
// the screen sits on DOH_FETCHING while it runs (which is also the diagnostic:
// if it never leaves FETCHING, the DoH is where it stalls). On DOH_APPLIED the
// pump also triggers a re-login to the freshly-set relay.
enum {
	DOH_IDLE = 0,
	DOH_FETCHING,
	DOH_RECEIVED,
	DOH_APPLIED,
	DOH_FAILED
};
extern volatile int doh_stage;

// Clear the cached result so the next fetch_new_ip() (or check that
// inspects device_record.doh_endpoints) sees an empty cache.
void bootstrap_invalidate();

// Parse a single "A.B.C.D" or "A.B.C.D:PORT" into ip4 (octet-0-low, per struct
// server_endpoint) + port. *port is untouched if ":PORT" is omitted (caller
// supplies a default). Returns false on any malformed/out-of-range input. Used by
// the manual Relay IP entry screen (app_home.c — hence the C linkage). Pure
// parse — no core-0 side effects.
#ifdef __cplusplus
extern "C" {
#endif
bool parse_ip_port(const char *s, uint32_t *ip4, uint16_t *port);
#ifdef __cplusplus
}
#endif
