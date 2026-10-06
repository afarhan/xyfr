#include "debug.h"

// The one Debug instance. See debug.h: non-blocking logging that drops on a
// full USB-CDC buffer so a serial monitor can never wedge the device.
DebugClass Debug;
