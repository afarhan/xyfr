#pragma once

#include <Adafruit_GFX.h>
#include <SPI.h>

// Driver for the Sharp LS032B7DD02 memory LCD — 336(H) x 536(V) native,
// 1-bit reflective, "Normally White". This is the LARGE-panel serial protocol
// (datasheet LD-2023X13 §6-6), NOT the small protocol that Adafruit_SharpMem
// speaks. One line write on SI (MSB-first, latched on SCLK rising, SPI MODE 0):
//
//   [M0 M1 M2][3 dummy][AG0..AG9 = 10-bit gate addr, LSB-first, 1-based]
//   [D0..D335 = 336 line-data bits, Hi=white Lo=black][16-clk transfer period]
//
// In multi-line update the transfer period of line N carries line N+1's
// address (6 dummy + 10 addr). We stream the whole frame as:
//   line 1:  header(M0=1, addr=1) + 336 data
//   line k:  header(dummy,   addr=k) + 336 data        (k = 2..536)
//   tail:    16 dummy bits
// Each header is exactly 16 bits = 2 bytes; each line is 336 bits = 42 bytes.
//
// Wiring is the stock Adafruit 2.7" Sharp Memory breakout, unchanged from the
// 400x240 panel it replaced: host drives SCK/MOSI/SCS only (3.3V into a
// 74HC4050 level shifter; the board makes 5V for the glass). SCS is ACTIVE-HIGH
// and must stay high for the whole frame, so it is a plain GPIO we manage, not
// a hardware-SPI chip select. EXTMODE is tied low => serial VCOM: we toggle the
// M1 bit on a steady cadence (toggleVCOM) to invert COM. EXTCOMIN tied low,
// DISP held high — neither needs a GPIO.
//
// The panel is natively portrait; call setRotation(1) for the 536x336 landscape
// the UI uses. drawPixel() (and therefore Adafruit_GFX text/shapes and both
// view backends) inherit the rotation transform.

#define LS032_NATIVE_W   336
#define LS032_NATIVE_H   536
#define LS032_LINE_BYTES (LS032_NATIVE_W / 8)              // 42
#define LS032_FB_BYTES   (LS032_LINE_BYTES * LS032_NATIVE_H) // 22512

// SPI clock for the panel. Datasheet fSCLK max = 2 MHz; this is a runtime knob
// (not a #define) so it can be pushed higher to speed up full repaints — watch
// for artefacts above ~2 MHz. Read fresh on every transaction.
extern uint32_t sharp_spi_hz;

class Sharp_LS032 : public Adafruit_GFX {
public:
	// spi: the hardware SPI peripheral whose SCK/MOSI land on these pins
	// (GPIO10/11 => SPI1 on the RP2350). cs is the active-high SCS GPIO.
	Sharp_LS032(SPIClassRP2040 *spi, uint8_t sck, uint8_t mosi, uint8_t cs);

	void begin();
	void drawPixel(int16_t x, int16_t y, uint16_t color) override;
	void clearDisplay();    // local framebuffer -> all white; marks the whole panel dirty
	void clearScreen();     // hardware all-clear command (white, immediate)
	void refresh();         // push only the dirty native-line band over SPI
	void toggleVCOM();      // invert COM (HOLD frame, no data) — call ~1 Hz

private:
	SPIClassRP2040 *_spi;
	uint8_t   _sck;
	uint8_t   _mosi;
	uint8_t   _cs;          // active-HIGH, driven manually (not SPI's CS)
	bool      _vcom;        // M1 bit; flipped only by toggleVCOM()
	// Dirty native-line band (1-based, inclusive) accumulated by drawPixel and
	// consumed by refresh(); lo > hi means "nothing changed". refresh() pushes
	// only [lo..hi], so a small UI change costs a few lines, not all 536.
	uint16_t  _dirtyLo, _dirtyHi;
	uint8_t   _fb[LS032_FB_BYTES];

	void beginTxn();
	void endTxn();
	static uint16_t headerBits(uint16_t line, bool first, bool vcom);
};
