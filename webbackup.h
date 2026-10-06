#pragma once
//
// webbackup.h — full-device BACKUP over a temporary on-device HTTP server.
//
// A deliberate maintenance mode: stands up a WiFiServer on port 80, shows the
// device IP on screen, and serves a one-page UI to DOWNLOAD a backup. The backup
// is the WHOLE encrypted FS region (all sectors: keystore bootblock + settings +
// contacts + logbook), already encrypted at rest, then framed PER-SECTOR under
// the FIXED firmware AEAD key (BK_OUTER_KEY, backup_format.h) and base64'd into a
// text file. The fixed key is integrity-only and migration-friendly — a backup
// restores on ANY Xyfr device; confidentiality comes from the inner at-rest
// encryption (the disk key).
//
// While backup mode is active the normal kernel / store pumps are suspended
// (see loop() in the .ino) so nothing writes the store underneath the server;
// only the web server + UI run. Device-only; single-thread / core 0.
//
// RESTORE is a SEPARATE flow (restore_net.cpp): it must write flash while
// receiving, which needs poll-mode cyw43 (this tsb WiFiServer would wedge), so it
// runs as its own reboot-into-restore mode. This file is backup-only.
//
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void backup_mode_enter(void);   // start the server + show the screen (no-op if WiFi offline)
void backup_mode_exit(void);    // stop the server, clear the flag (caller navigates home)
bool backup_mode_active(void);  // true while the server owns the device
void backup_pump(void);         // poll the server; service one client. Call from loop().

#ifdef __cplusplus
}
#endif
