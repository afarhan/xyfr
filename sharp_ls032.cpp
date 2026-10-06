#include "sharp_ls032.h"
#include <string.h>

// Mode/flag bits inside the 16-bit header (bit15 = first bit sent).
#define LS032_M0 0x8000   // mode flag: 1 = data update, 0 = hold
#define LS032_M1 0x4000   // frame inversion (VCOM) flag
#define LS032_M2 0x2000   // all-clear flag
// bits 12..10 are dummy; bits 9..0 are the gate address, AG0 (LSB) at bit 9.

uint32_t sharp_spi_hz = 2000000;   // datasheet fSCLK max; tunable (see header)

Sharp_LS032::Sharp_LS032(SPIClassRP2040 *spi, uint8_t sck, uint8_t mosi, uint8_t cs)
	: Adafruit_GFX(LS032_NATIVE_W, LS032_NATIVE_H),
	  _spi(spi), _sck(sck), _mosi(mosi), _cs(cs), _vcom(false),
	  _dirtyLo(0xFFFF), _dirtyHi(0) {}

void Sharp_LS032::begin() {
	pinMode(_cs, OUTPUT);
	digitalWrite(_cs, LOW);          // SCS idles low
	_spi->setSCK(_sck);
	_spi->setTX(_mosi);
	_spi->begin();
	clearDisplay();
}

// Build a line's 16-bit header: [M0 M1 M2][3 dummy][AG0..AG9]. AG0 (LSB of the
// 1-based line number) sits at bit 9, AG9 at bit 0 (sent AG0..AG9 first). The
// first line of a frame carries M0=1 (data update); later lines' headers are
// the transfer period's 6 dummy + 10 address, i.e. M0/M1/M2 left clear.
uint16_t Sharp_LS032::headerBits(uint16_t line, bool first, bool vcom) {
	uint16_t h = 0;
	if (first) {
		h |= LS032_M0;
		if (vcom)
			h |= LS032_M1;
	}
	for (int k = 0; k < 10; k++)
		if ((line >> k) & 1)
			h |= (1 << (9 - k));
	return h;
}

void Sharp_LS032::beginTxn() {
	_spi->beginTransaction(SPISettings(sharp_spi_hz, MSBFIRST, SPI_MODE0));
	digitalWrite(_cs, HIGH);         // SCS active-high; tsSCS >= 3us
	delayMicroseconds(3);
}

void Sharp_LS032::endTxn() {
	delayMicroseconds(1);            // thSCS >= 1us
	digitalWrite(_cs, LOW);
	_spi->endTransaction();
}

void Sharp_LS032::drawPixel(int16_t x, int16_t y, uint16_t color) {
	// Map rotated/logical coords into the native 336x536 buffer (same transform
	// Adafruit_GFX subclasses use; WIDTH/HEIGHT are the native dimensions).
	int16_t t;
	switch (rotation) {
		case 1: t = x; x = y; y = t; x = WIDTH  - 1 - x; break;
		case 2: x = WIDTH - 1 - x;   y = HEIGHT - 1 - y; break;
		case 3: t = x; x = y; y = t; y = HEIGHT - 1 - y; break;
	}
	if (x < 0 || x >= LS032_NATIVE_W || y < 0 || y >= LS032_NATIVE_H)
		return;

	uint8_t *p = &_fb[y * LS032_LINE_BYTES + (x >> 3)];
	uint8_t  mask = 0x80 >> (x & 7);    // MSB = leftmost native column (D0)
	if (color)  // Hi = white (Normally White panel)
		*p |= mask;
	else  // Lo = black
		*p &= ~mask;

	uint16_t line = (uint16_t)y + 1;    // gate lines are 1-based
	if (line < _dirtyLo)
		_dirtyLo = line;
	if (line > _dirtyHi)
		_dirtyHi = line;
}

void Sharp_LS032::clearDisplay() {
	memset(_fb, 0xFF, sizeof(_fb));     // all white
	_dirtyLo = 1; _dirtyHi = LS032_NATIVE_H;   // whole panel needs repainting
}

void Sharp_LS032::refresh() {
	if (_dirtyLo > _dirtyHi)  // nothing changed
		return;
	uint16_t lo = _dirtyLo, hi = _dirtyHi;
	_dirtyLo = 0xFFFF; _dirtyHi = 0;            // band consumed

	// One block transfer per line (header + 42 data bytes) — far less overhead
	// than the old byte-at-a-time clocking. SCS is held high across the whole
	// multi-line write; only lines [lo..hi] are sent (multi-line update mode).
	uint8_t buf[2 + LS032_LINE_BYTES];
	beginTxn();
	for (uint16_t line = lo; line <= hi; line++) {
		uint16_t h = headerBits(line, line == lo, _vcom);
		buf[0] = (uint8_t)(h >> 8);
		buf[1] = (uint8_t)(h & 0xFF);
		memcpy(buf + 2, &_fb[(line - 1) * LS032_LINE_BYTES], LS032_LINE_BYTES);
		_spi->transfer(buf, sizeof(buf));       // in-place; clobbers the scratch copy only
	}
	uint8_t tail[2] = { 0, 0 };                 // 16-bit final transfer period
	_spi->transfer(tail, sizeof(tail));
	endTxn();
}

void Sharp_LS032::toggleVCOM() {
	_vcom = !_vcom;
	beginTxn();
	uint8_t buf[2];
	uint16_t h = _vcom ? LS032_M1 : 0;          // HOLD frame: M0=0, M2=0
	buf[0] = (uint8_t)(h >> 8); buf[1] = (uint8_t)(h & 0xFF);
	_spi->transfer(buf, sizeof(buf));
	endTxn();
}

void Sharp_LS032::clearScreen() {
	beginTxn();
	uint8_t buf[2];
	uint16_t h = LS032_M2 | (_vcom ? LS032_M1 : 0);  // all-clear: M0=0, M2=1
	buf[0] = (uint8_t)(h >> 8); buf[1] = (uint8_t)(h & 0xFF);
	_spi->transfer(buf, sizeof(buf));
	endTxn();
}
