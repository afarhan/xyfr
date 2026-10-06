#pragma once
//
// restore_net — poll-mode (cyw43_arch_lwip_poll) restore path, bundled in the
// phone firmware. arduino-pico brings the radio up in threadsafe_background (tsb)
// at boot; tsb races flash erases and wedges. The restore path therefore tears
// tsb down (cyw43_arch_deinit) and re-brings the radio up in POLL mode, where
// flash erases run between explicit cyw43_arch_poll() calls without wedging
// (proven standalone, 512/512 sectors live). It then runs a raw-lwIP TCP server
// on :80, receives the backup stream, and writes the FS region a sector at a time.
//
// The tsb->poll switch reuses the COMMON (arch-agnostic) cyw43_arch helpers
// (cyw43_arch_poll / _async_context / _set_async_context) plus the vendored
// async_context_poll.c — the poll-arch cyw43_arch_init() symbol would collide
// with arduino's tsb one, so we drive the layer below it.
//
// Device-only / core 0. Hardwired at boot for now (see RESTORE_BOOT_TEST in the
// .ino); the Shift+Num boot chord + RAM-survive flag come later.
//
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void restore_boot(void);    // setup(): tsb->poll switch, connect, start :80 server
bool restore_active(void);  // true once restore mode owns the device
void restore_loop(void);    // loop(): cyw43_arch_poll + drain ring -> flash + progress

// Reboot-surviving entry: a menu/serial action calls restore_request_reboot()
// (sets a watchdog-scratch flag + warm-reboots); setup() calls restore_boot_requested()
// to detect+consume it and branch into restore. A power cycle clears the flag.
void restore_request_reboot(void);
bool restore_boot_requested(void);

// Firmware-update mode reuses restore's poll-mode server. Same warm-reboot
// entry, a DISTINCT scratch magic: firmware_request_reboot() enters it,
// firmware_boot_requested() detects+consumes it (and sets the internal firmware
// flag) so restore_boot()/restore_loop() run in firmware-staging mode instead.
void firmware_request_reboot(void);
bool firmware_boot_requested(void);

// BOOTSEL from the menu (Security, shown while Developer Mode is on): reboot
// straight into the UF2 bootloader, for a unit whose BOOTSEL button cannot be
// reached. A power cycle exits the bootloader with the flash untouched.
void bootsel_reboot(void);

#ifdef __cplusplus
}
#endif
