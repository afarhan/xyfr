#pragma once

#if !defined(ARDUINO)
// ---- Host (Linux) build: route Debug to stdout. ----
// Same call surface (printf / print / println) the shared firmware code uses,
// minus Serial/Print. Lets shared files (e.g. test_contacts.cpp) compile and
// run on host. The device branch below is used when building for Arduino.
#include <cstdio>
#include <cstdarg>
class DebugClass {
public:
  bool enabled = true;
  void printf(const char *fmt, ...) {
    if (!enabled)
      return;
    va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap);
  }
  void print(const char *s)   { if (enabled) ::fputs(s, stdout); }
  void println(const char *s) { if (enabled) ::printf("%s\n", s); }
  void println()              { if (enabled) ::putchar('\n'); }
};
extern DebugClass Debug;

#else
#include <Arduino.h>
#include <time.h>
#include <cstdio>

// ui.cpp — NTP-synced UTC epoch seconds. NOTE: before NTP it still returns a
// large value (millis()/1000 + a 2026-05-01 fallback), so it is NOT a real
// clock until net_time() is non-zero — hence the gate in emit_stamp below.
extern "C" time_t get_current_time_seconds(void);
extern "C" time_t net_time(void);  // netif.c — UTC seconds, 0 until the network knows

// All firmware debug/telemetry logging goes through Debug instead of Serial.
//
// Debug is NON-BLOCKING: it DROPS output when the USB-CDC TX buffer is full,
// so a connected serial monitor can never wedge the device. (The real
// SerialUSB::write busy-waits up to ~1 s — and longer via a cross-core timer
// race — whenever a host has the port open and the buffer is full, which
// blocks the core that printed. High-volume telemetry then froze whichever
// phone was on the serial monitor.) A hardware terminal must never hang
// because someone opened its serial port.
//
// Set Debug.enabled = false to silence all debug output entirely (the "NULL"
// mode). Essential serial I/O (Serial.begin/read/available, the command
// parser) stays on the real Serial object.
class DebugClass : public Print {
public:
  bool enabled = true;
  size_t write(uint8_t c) override { return write(&c, 1); }
  // Every line is prefixed with a wall-clock stamp (see emit_stamp). We split the
  // buffer on '\n' so a stamp is emitted at each true line start, even when a
  // single line is written across several calls (Print::printf, print_key-style
  // byte-at-a-time output): at_bol persists across calls, so the run between two
  // newlines gets exactly one stamp. Still non-blocking — any segment that won't
  // fit the TX buffer is dropped whole, never waited on.
  size_t write(const uint8_t *buf, size_t len) override {
    if (!enabled)  // NULL mode: swallow
      return len;
    size_t i = 0;
    while (i < len) {
      if (at_bol) {
        emit_stamp();
        at_bol = false;
      }
      size_t start = i;
      while (i < len && buf[i] != '\n')
        i++;
      if (i < len) {
        i++;                                        // include the newline in this segment
        at_bol = true;
      }
      size_t seg = i - start;
      if ((int)seg <= Serial.availableForWrite())
        Serial.write(buf + start, seg);             // room: non-blocking write
      // else: drop this segment, never block
    }
    return len;
  }
  int availableForWrite() override { return Serial.availableForWrite(); }
private:
  bool at_bol = true;                               // next byte begins a fresh line
  // HH:MM:SS once NTP has synced, else "+<uptime>s". Dropped whole if the TX
  // buffer lacks room, same non-blocking contract as the payload write.
  void emit_stamp() {
    char ts[24];
    int n;
    if (net_time()) {
      time_t secs = get_current_time_seconds();
      struct tm tm;
      gmtime_r(&secs, &tm);
      n = snprintf(ts, sizeof ts, "%02d:%02d:%02d ", tm.tm_hour, tm.tm_min, tm.tm_sec);
    } else {
      n = snprintf(ts, sizeof ts, "+%lus ", (unsigned long)(millis() / 1000));
    }
    if (n > 0 && n <= Serial.availableForWrite())
      Serial.write((const uint8_t *)ts, (size_t)n);
  }
};

extern DebugClass Debug;
#endif  // !ARDUINO
