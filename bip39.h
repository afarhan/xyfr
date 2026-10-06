#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIP39_ENTROPY_BYTES   32
#define BIP39_WORD_COUNT      24
#define BIP39_MAX_WORD_LEN     8
#define BIP39_MNEMONIC_BUFSZ ((BIP39_MAX_WORD_LEN + 1) * BIP39_WORD_COUNT)

#define BIP39_OK              0
#define BIP39_ERR_BUF        -1
#define BIP39_ERR_CHECKSUM   -2
#define BIP39_ERR_WORD_COUNT -3
#define BIP39_ERR_BAD_WORD   -4

int bip39_encode(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                 char *out, size_t out_size);

int bip39_decode(const char *mnemonic,
                 uint8_t entropy[BIP39_ENTROPY_BYTES]);

int  bip39_word_at(uint16_t index, char out[BIP39_MAX_WORD_LEN + 1]);
int  bip39_word_index(const char *word, size_t len);

// Compare a user-retyped mnemonic against the canonical encoding of
// `entropy`. Returns BIP39_OK on full match. On the first wrong word,
// returns the 1-based word index (1..BIP39_WORD_COUNT) and inserts a
// '*' character into `mnemonic` immediately before the offending word
// so the caller can show the user where the typo is. `mnemonic_size`
// must be the full byte size of the caller's buffer; the function
// won't write past it (returns BIP39_ERR_BUF if there's no room for
// the asterisk). Returns BIP39_ERR_WORD_COUNT if the user typed too
// few or too many words.
int  bip39_check(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                 char *mnemonic, size_t mnemonic_size);

// Mark a retyped mnemonic for on-screen display: insert a '*' immediately
// before (a) every word that is not in the BIP-39 wordlist and (b) the first
// word that differs from the canonical encoding of `entropy` (a valid-but-wrong
// word). A word that is both is marked once. Returns the number of '*' inserted
// (0 = nothing to flag), or BIP39_ERR_BUF if there is no room. `mnemonic_size`
// must be the full buffer size, with room for up to BIP39_WORD_COUNT extra bytes.
//
// Pass entropy == NULL when there is no reference key -- importing a phrase the
// device has never seen, where no word can be called "wrong", only unknown. Then
// (b) is skipped and only out-of-wordlist words are marked.
int  bip39_mark_errors(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                       char *mnemonic, size_t mnemonic_size);

#ifdef __cplusplus
}
#endif
