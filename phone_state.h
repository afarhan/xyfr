#pragma once
//
// phone_state.h — the UI-state contract that CROSSES the C/C++ boundary.
//
// These four things (the WiFi states, the phone_state enum, and the two
// functions the portable core calls back into the platform with) are the only
// part of ui.h that plain-C code needs. ui.h is C++ and can never be included
// from kernel.c, so before this header existed each C caller re-declared
// what it needed and re-#defined the constants locally. That had produced:
//
//   * THREE definitions of WIFI_ONLINE == 2 -- ui.h, kernel.c,
//     contact_lookup.c -- plus two host stubs returning a bare literal 2.
//   * `#define PS_SIGNED_IN 5  // mirrors enum phone_state (ui.h)` in
//     kernel.c. Insert one value into that enum and this silently starts
//     naming a different state, with nothing to catch it.
//   * phone_state_set declared `void (int)` in C and `void (enum phone_state)`
//     in C++. Compatible in practice, which is why it survived.
//
// A contract that is copied is not a contract. This is the single copy.
//
#ifdef __cplusplus
extern "C" {
#endif

// WiFi link state, as reported by wifi_get_status(). Kept as #defines rather
// than an enum because the host stubs and the portable core compare the raw
// int, and kernel.c logs it as %d.
#define WIFI_OFFLINE    0
#define WIFI_CONNECTING 1
#define WIFI_ONLINE     2
#define WIFI_FAILED     3   // tried every AP and none took us; not the same as
                            // OFFLINE, which is nothing configured to try

// Coarse-grained system state. Set by core 0 (wifi_poll, fetch_new_ip, call
// setup); read by core 1 to drive the UI without blocking. Add new values as
// features land — keep them ordered by lifecycle stage, and note that the
// order is now load-bearing for ONE reason only: it is the enum itself that
// every caller sees, so appending is safe and inserting is a real change.
enum phone_state {
	PS_OFFLINE = 0,
	PS_WIFI_CONNECTING,
	PS_WIFI_CONNECTED,
	PS_UNBLOCKING,
	PS_SIGNING_IN,
	PS_SIGNED_IN,
	PS_CALLING,
	PS_INCOMING,
	PS_CONNECTED,
	PS_HANGING_UP,
	PS_WIFI_FAILED,
};

// The two platform hooks the portable core calls. Device implementations live
// in wifi_ui.cpp / ui.cpp; the host binaries stub them (phone_host.c,
// termd_host.c).
int  wifi_get_status(void);            // one of WIFI_*
void phone_state_set(enum phone_state s);

#ifdef __cplusplus
}
#endif
