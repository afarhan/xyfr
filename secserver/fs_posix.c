// fs_posix.c — host (Linux) backend for the fs HAL declared in ../hal.h.
//
// Maps the device's absolute LittleFS paths ("/device_record.bin", "/c/<id>.bin") onto
// real files under a base directory (default "./fsroot", overridable with the
// FSROOT env var). This makes contacts + the message log host-native, so
// test_contacts() and the msg:// store run on Linux under gdb/valgrind/ASan.
//
// Part of the device↔CLI unification: the same contacts.cpp/storage.cpp call
// fs_*; only this backend differs from the LittleFS one.

#include "hal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

struct fs_file {
	FILE *fp;
};
struct fs_dir {
	DIR *dp;
	char base[512];
};

static const char *fs_root(void) {
	const char *r = getenv("FSROOT");
	return (r && *r) ? r : "fsroot";
}

// Join the device-absolute `path` ("/c/x.bin") onto the host root → out.
static void map_path(const char *path, char *out, size_t outsz) {
	if (!path) path = "/";
	if (path[0] != '/') snprintf(out, outsz, "%s/%s", fs_root(), path);
	else                snprintf(out, outsz, "%s%s",  fs_root(), path);
}

bool fs_init(void) {
	// Ensure the root exists; OK if it already does.
	if (mkdir(fs_root(), 0755) != 0 && errno != EEXIST) return false;
	struct stat st;
	return stat(fs_root(), &st) == 0 && S_ISDIR(st.st_mode);
}

fs_file *fs_open(const char *path, int mode) {
	const char *m;
	switch (mode) {
		case FS_RDONLY: m = "rb";  break;
		case FS_RDWR:   m = "r+b"; break;  // existing file (rmw)
		case FS_WRITE:  m = "wb";  break;  // create/truncate
		case FS_APPEND: m = "ab";  break;  // create/append
		default: return NULL;
	}
	char full[512];
	map_path(path, full, sizeof(full));
	FILE *fp = fopen(full, m);
	if (!fp) return NULL;
	fs_file *f = (fs_file *)malloc(sizeof(*f));
	if (!f) { fclose(fp); return NULL; }
	f->fp = fp;
	return f;
}

int fs_read(fs_file *f, void *buf, int len) {
	if (!f || len < 0) return -1;
	size_t n = fread(buf, 1, (size_t)len, f->fp);
	return (int)n;   // 0 at EOF
}

int fs_write(fs_file *f, const void *buf, int len) {
	if (!f || len < 0) return -1;
	size_t n = fwrite(buf, 1, (size_t)len, f->fp);
	return (int)n;
}

int fs_seek(fs_file *f, int off) {
	if (!f || fseek(f->fp, (long)off, SEEK_SET) != 0) return -1;
	return (int)ftell(f->fp);
}

int fs_size(fs_file *f) {
	if (!f) return -1;
	long cur = ftell(f->fp);
	if (cur < 0 || fseek(f->fp, 0, SEEK_END) != 0) return -1;
	long sz = ftell(f->fp);
	fseek(f->fp, cur, SEEK_SET);
	return (int)sz;
}

void fs_close(fs_file *f) {
	if (!f) return;
	if (f->fp) fclose(f->fp);
	free(f);
}

bool fs_exists(const char *path) {
	char full[512];
	map_path(path, full, sizeof(full));
	return access(full, F_OK) == 0;
}

bool fs_remove(const char *path) {
	char full[512];
	map_path(path, full, sizeof(full));
	return remove(full) == 0;
}

bool fs_mkdir(const char *path) {
	char full[512];
	map_path(path, full, sizeof(full));
	if (mkdir(full, 0755) == 0) return true;
	return errno == EEXIST;
}

bool fs_rename(const char *from, const char *to) {
	char ffrom[512], fto[512];
	map_path(from, ffrom, sizeof(ffrom));
	map_path(to,   fto,   sizeof(fto));
	return rename(ffrom, fto) == 0;
}

fs_dir *fs_opendir(const char *path) {
	char full[512];
	map_path(path, full, sizeof(full));
	DIR *dp = opendir(full);
	if (!dp) return NULL;
	fs_dir *d = (fs_dir *)malloc(sizeof(*d));
	if (!d) { closedir(dp); return NULL; }
	d->dp = dp;
	snprintf(d->base, sizeof(d->base), "%s", full);
	return d;
}

bool fs_readdir(fs_dir *d, char *name, int name_max, int *size, bool *is_dir) {
	if (!d) return false;
	struct dirent *e;
	while ((e = readdir(d->dp)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
		snprintf(name, (size_t)name_max, "%s", e->d_name);
		char child[1024];
		snprintf(child, sizeof(child), "%s/%s", d->base, e->d_name);
		struct stat st;
		bool dir = false;
		int sz = 0;
		if (stat(child, &st) == 0) { dir = S_ISDIR(st.st_mode); sz = (int)st.st_size; }
		if (is_dir) *is_dir = dir;
		if (size)   *size   = sz;
		return true;
	}
	return false;
}

void fs_closedir(fs_dir *d) {
	if (!d) return;
	if (d->dp) closedir(d->dp);
	free(d);
}
