// fs_littlefs.cpp — device (RP2350) backend for the fs HAL declared in hal.h.
// Wraps the arduino-pico LittleFS File/Dir API. The portable contacts.cpp /
// storage.cpp call fs_*; only this file (and fs_posix.c on host) differ.
//
// LittleFS uses the same low-level flash path as EEPROM (noInterrupts +
// idleOtherCore + flash erase/program) and is not cyw43-aware — callers that run
// while WiFi is up must coordinate with the radio (the existing storage rule).

#include <Arduino.h>
#include <LittleFS.h>
#include "hal.h"

struct fs_file {
	File f;
};
struct fs_dir {
	Dir d;
};

static bool s_mounted = false;

bool fs_init(void) {
	if (s_mounted)
		return true;
	if (LittleFS.begin()) {
		s_mounted = true;
		return true;
	}
	return false;
}

static const char *mode_str(int mode) {
	switch (mode) {
		case FS_RDONLY: return "r";
		case FS_RDWR:   return "r+";
		case FS_WRITE:  return "w";
		case FS_APPEND: return "a";
		default:        return nullptr;
	}
}

fs_file *fs_open(const char *path, int mode) {
	const char *m = mode_str(mode);
	if (!m)
		return nullptr;
	File f = LittleFS.open(path, m);
	if (!f)
		return nullptr;
	fs_file *h = new fs_file{ f };
	return h;
}

int fs_read(fs_file *f, void *buf, int len) {
	if (!f || len < 0)
		return -1;
	return f->f.read((uint8_t *)buf, (size_t)len);
}

int fs_write(fs_file *f, const void *buf, int len) {
	if (!f || len < 0)
		return -1;
	return (int)f->f.write((const uint8_t *)buf, (size_t)len);
}

int fs_seek(fs_file *f, int off) {
	if (!f || !f->f.seek((uint32_t)off, SeekSet))
		return -1;
	return (int)f->f.position();
}

int fs_size(fs_file *f) {
	if (!f)
		return -1;
	return (int)f->f.size();
}

void fs_close(fs_file *f) {
	if (!f)
		return;
	f->f.close();
	delete f;
}

bool fs_exists(const char *path) { return LittleFS.exists(path); }
bool fs_remove(const char *path) { return LittleFS.remove(path); }
bool fs_mkdir(const char *path)  { return LittleFS.mkdir(path); }
bool fs_rename(const char *from, const char *to) { return LittleFS.rename(from, to); }

fs_dir *fs_opendir(const char *path) {
	Dir d = LittleFS.openDir(path);
	fs_dir *h = new fs_dir{ d };
	return h;
}

bool fs_readdir(fs_dir *d, char *name, int name_max, int *size, bool *is_dir) {
	if (!d)
		return false;
	if (!d->d.next())
		return false;
	snprintf(name, (size_t)name_max, "%s", d->d.fileName().c_str());
	if (is_dir)
		*is_dir = d->d.isDirectory();
	if (size)
		*size   = (int)d->d.fileSize();
	return true;
}

void fs_closedir(fs_dir *d) {
	if (d)
		delete d;
}
