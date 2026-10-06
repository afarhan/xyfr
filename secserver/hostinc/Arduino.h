#pragma once
// Minimal host shim so shared firmware files that #include <Arduino.h> compile
// on Linux. Only what the shared test/code needs here: delay() + base types.
// On the device the real Arduino.h is used; on host this is found first via
// -Ihostinc. (Part of the device↔CLI unification — see ../../hal.h.)
#include <stdint.h>
#include <stddef.h>
#include <time.h>

// No Serial to wait on under a normal process; make delay() a no-op so the
// shared test runs fast. (Timing-sensitive code uses the time HAL, not delay.)
static inline void delay(unsigned long ms) { (void)ms; }
