// diskkey.c — 8-word disk-key phrase generate + confirm (see diskkey.h).

#include "diskkey.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "bip39.h"   // bip39_word_at (the 2048-word list)
#include "hal.h"     // hal_rand (CSPRNG)

void diskkey_generate(char *out, size_t out_size) {
	if (!out || out_size == 0)
		return;
	out[0] = 0;
	size_t used = 0;
	for (int w = 0; w < DISKKEY_WORDS; w++) {
		uint16_t idx = (uint16_t)(hal_rand() & 0x7FF);   // 0..2047 — uniform 11 bits
		char word[BIP39_MAX_WORD_LEN + 1];
		bip39_word_at(idx, word);
		size_t word_len = strlen(word);
		size_t separator = 1;              // every word but the first needs a space
		if (w == 0)
			separator = 0;
		if (used + separator + word_len + 1 > out_size)  // keep room for the NUL
			break;
		if (w)
			out[used++] = ' ';
		memcpy(out + used, word, word_len);
		used += word_len;
		out[used] = 0;
	}
}

// Return the i-th whitespace-separated word of s (ptr + length via *len), or NULL
// past the end.
static const char *nth_word(const char *s, int i, size_t *len) {
	while (*s == ' ')
		s++;
	for (int k = 0; k < i; k++) {
		while (*s && *s != ' ')
			s++;
		while (*s == ' ')
			s++;
	}
	if (!*s) {
		*len = 0;
		return NULL;
	}
	const char *start = s;
	while (*s && *s != ' ')
		s++;
	*len = (size_t)(s - start);
	return start;
}

int diskkey_mark_errors(const char *canonical, char *typed, size_t typed_size) {
	char out[DISKKEY_BUFSZ + DISKKEY_WORDS + 8];
	size_t out_pos = 0;
	int mismatches = 0;
	size_t word_len;

	int typed_words = 0;
	while (nth_word(typed, typed_words, &word_len))
		typed_words++;

	for (int i = 0; i < typed_words; i++) {
		size_t typed_len, canonical_len;
		const char *typed_word     = nth_word(typed, i, &typed_len);
		const char *canonical_word = nth_word(canonical, i, &canonical_len);
		bool bad = (canonical_word == NULL) || (typed_len != canonical_len) ||
		           (memcmp(typed_word, canonical_word, typed_len) != 0);
		if (i && out_pos < sizeof out - 1)
			out[out_pos++] = ' ';
		if (bad) {
			mismatches++;
			if (out_pos < sizeof out - 1)
				out[out_pos++] = '*';
		}
		for (size_t k = 0; k < typed_len && out_pos < sizeof out - 1; k++)
			out[out_pos++] = typed_word[k];
	}
	// Words the user left out (canonical longer than typed) are mismatches too.
	for (int i = typed_words; nth_word(canonical, i, &word_len); i++)
		mismatches++;

	out[out_pos] = 0;
	if (typed_size) {
		strncpy(typed, out, typed_size - 1);
		typed[typed_size - 1] = 0;
	}
	return mismatches;
}
