#pragma once
//
// diskkey.h — the DISK-KEY phrase helper. The disk key is the at-rest encryption
// passphrase (keystore KEK). We present it to the user as 8 words drawn from the
// BIP-39 word list (88 bits) — system-generated so it can't be a weak human
// choice — and feed the phrase string straight to the KDF as the passphrase (no
// checksum needed; the AEAD tag verifies on unlock). Device UI helper, plain C.
//
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#define DISKKEY_WORDS  8
// 8 words, each up to 8 chars + a separating space, + NUL.
#define DISKKEY_BUFSZ  (DISKKEY_WORDS * (8 + 1) + 1)

// Fill `out` (>= DISKKEY_BUFSZ) with a fresh 8-word phrase (88 bits via hal_rand).
void diskkey_generate(char *out, size_t out_size);

// Compare `typed` against `canonical` word-by-word, rewriting `typed` in place with
// a '*' inserted before each word that differs from (or is missing/extra vs) the
// canonical phrase. Returns the mismatch count (0 = exact match). `typed_size` must
// leave room for up to DISKKEY_WORDS marker bytes.
int diskkey_mark_errors(const char *canonical, char *typed, size_t typed_size);

#ifdef __cplusplus
}
#endif
