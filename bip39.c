#include "bip39.h"

#include <string.h>

extern const char bip39_wordlist[2048][BIP39_MAX_WORD_LEN + 1];

static uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4]   << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] <<  8) |
                (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=state[0], b=state[1], c=state[2], d=state[3];
    uint32_t e=state[4], f=state[5], g=state[6], h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void sha256(uint8_t out[32], const uint8_t *data, size_t len) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    size_t pos = 0;
    while (len - pos >= 64) {
        sha256_compress(state, data + pos);
        pos += 64;
    }
    uint8_t block[64];
    size_t rem = len - pos;
    memcpy(block, data + pos, rem);
    block[rem] = 0x80;
    if (rem + 1 > 56) {
        memset(block + rem + 1, 0, 64 - rem - 1);
        sha256_compress(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem + 1, 0, 56 - rem - 1);
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) {
        block[63 - i] = (uint8_t)(bits & 0xff);
        bits >>= 8;
    }
    sha256_compress(state, block);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(state[i] >> 24);
        out[i*4+1] = (uint8_t)(state[i] >> 16);
        out[i*4+2] = (uint8_t)(state[i] >>  8);
        out[i*4+3] = (uint8_t) state[i];
    }
}

static uint16_t extract11(const uint8_t *buf, int word_index) {
    int bit_off  = word_index * 11;
    int byte_idx = bit_off >> 3;
    int bit_idx  = bit_off & 7;
    uint32_t v = ((uint32_t)buf[byte_idx]     << 16) |
                 ((uint32_t)buf[byte_idx + 1] <<  8) |
                  (uint32_t)buf[byte_idx + 2];
    return (uint16_t)((v >> (24 - 11 - bit_idx)) & 0x7ff);
}

static void pack11(uint8_t *buf, int word_index, uint16_t value) {
    int bit_off  = word_index * 11;
    int byte_idx = bit_off >> 3;
    int bit_idx  = bit_off & 7;
    uint32_t shifted = (uint32_t)(value & 0x7ff) << (24 - 11 - bit_idx);
    buf[byte_idx]     |= (uint8_t)((shifted >> 16) & 0xff);
    buf[byte_idx + 1] |= (uint8_t)((shifted >>  8) & 0xff);
    buf[byte_idx + 2] |= (uint8_t)( shifted        & 0xff);
}

int bip39_word_at(uint16_t index, char out[BIP39_MAX_WORD_LEN + 1]) {
    if (index >= 2048 || out == NULL)
      return BIP39_ERR_BAD_WORD;
    const char *src = bip39_wordlist[index];
    size_t i = 0;
    while (i < BIP39_MAX_WORD_LEN && src[i] != '\0') {
        out[i] = src[i];
        i++;
    }
    out[i] = '\0';
    return (int)i;
}

int bip39_word_index(const char *word, size_t len) {
    if (word == NULL || len == 0 || len > BIP39_MAX_WORD_LEN)
      return BIP39_ERR_BAD_WORD;
    int lo = 0, hi = 2048;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        const char *w = bip39_wordlist[mid];
        int cmp = 0;
        for (size_t i = 0; i < len; i++) {
            unsigned char a = (unsigned char)w[i];
            unsigned char b = (unsigned char)word[i];
            if (a != b) {
              if ((a < b))
                cmp = -1;
              else
                cmp = 1;
              break;
            }
            if (a == '\0')
              break;
        }
        if (cmp == 0) {
            char tail = w[len];
            if (tail == '\0')
              return mid;
            cmp = 1;
        }
        if (cmp < 0)
          lo = mid + 1;
        else
          hi = mid;
    }
    return BIP39_ERR_BAD_WORD;
}

int bip39_encode(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                 char *out, size_t out_size) {
    if (entropy == NULL || out == NULL)
      return BIP39_ERR_BUF;

    uint8_t hash[32];
    sha256(hash, entropy, BIP39_ENTROPY_BYTES);

    uint8_t buf[34];
    memcpy(buf, entropy, BIP39_ENTROPY_BYTES);
    buf[32] = hash[0];
    buf[33] = 0;

    size_t pos = 0;
    for (int i = 0; i < BIP39_WORD_COUNT; i++) {
        uint16_t idx = extract11(buf, i);
        const char *w = bip39_wordlist[idx];
        size_t wlen = 0;
        while (wlen < BIP39_MAX_WORD_LEN && w[wlen] != '\0')
          wlen++;
        size_t need = wlen + (i < BIP39_WORD_COUNT - 1 ? 1 : 0);
        if (pos + need + 1 > out_size)
          return BIP39_ERR_BUF;
        memcpy(out + pos, w, wlen);
        pos += wlen;
        if (i < BIP39_WORD_COUNT - 1)
          out[pos++] = ' ';
    }
    out[pos] = '\0';
    return (int)pos;
}

static int is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int bip39_decode(const char *mnemonic,
                 uint8_t entropy[BIP39_ENTROPY_BYTES]) {
    if (mnemonic == NULL || entropy == NULL)
      return BIP39_ERR_BUF;

    uint8_t buf[34] = {0};
    int word_count = 0;
    const char *p = mnemonic;

    for (;;) {
        while (is_ws(*p))
          p++;
        if (*p == '\0')
          break;
        if (word_count >= BIP39_WORD_COUNT)
          return BIP39_ERR_WORD_COUNT;

        const char *start = p;
        while (*p != '\0' && !is_ws(*p))
          p++;
        size_t wlen = (size_t)(p - start);

        int idx = bip39_word_index(start, wlen);
        if (idx < 0)
          return BIP39_ERR_BAD_WORD;

        pack11(buf, word_count, (uint16_t)idx);
        word_count++;
    }

    if (word_count != BIP39_WORD_COUNT)
      return BIP39_ERR_WORD_COUNT;

    uint8_t hash[32];
    sha256(hash, buf, BIP39_ENTROPY_BYTES);
    if (hash[0] != buf[32])
      return BIP39_ERR_CHECKSUM;

    memcpy(entropy, buf, BIP39_ENTROPY_BYTES);
    return BIP39_OK;
}

int bip39_check(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                char *mnemonic, size_t mnemonic_size) {
    if (entropy == NULL || mnemonic == NULL || mnemonic_size == 0)
        return BIP39_ERR_BUF;

    char canonical[BIP39_MNEMONIC_BUFSZ];
    int rc = bip39_encode(entropy, canonical, sizeof(canonical));
    if (rc < 0)
      return rc;

    char       *p  = mnemonic;
    const char *cp = canonical;
    int word_index = 0;

    for (;;) {
        while (is_ws(*p))
          p++;
        while (is_ws(*cp))
          cp++;

        int user_done  = (*p  == '\0');
        int canon_done = (*cp == '\0');
        if (user_done && canon_done)
          return BIP39_OK;
        if (user_done || canon_done)
          return BIP39_ERR_WORD_COUNT;

        word_index++;
        char       *user_start  = p;
        const char *canon_start = cp;

        while (*p  != '\0' && !is_ws(*p))
          p++;
        while (*cp != '\0' && !is_ws(*cp))
          cp++;

        size_t user_len  = (size_t)(p  - user_start);
        size_t canon_len = (size_t)(cp - canon_start);

        if (user_len != canon_len ||
            memcmp(user_start, canon_start, user_len) != 0) {
            // Insert '*' immediately before the wrong word so the caller
            // can render the typo position visually.
            size_t off      = (size_t)(user_start - mnemonic);
            size_t tail_len = 0;
            while (user_start[tail_len] != '\0')
              tail_len++;
            if (off + tail_len + 2 > mnemonic_size)
                return BIP39_ERR_BUF;
            memmove(user_start + 1, user_start, tail_len + 1);
            *user_start = '*';
            return word_index;
        }
    }
}

int bip39_mark_errors(const uint8_t entropy[BIP39_ENTROPY_BYTES],
                      char *mnemonic, size_t mnemonic_size) {
    if (mnemonic == NULL || mnemonic_size == 0)
        return BIP39_ERR_BUF;

    // entropy == NULL: the caller has no reference key (importing an unknown
    // phrase), so there is no "intended" word to compare against. Skip pass 1
    // and mark only words that are absent from the wordlist.
    int first_mismatch = -1;
    if (entropy != NULL) {
    char canonical[BIP39_MNEMONIC_BUFSZ];
    int rc = bip39_encode(entropy, canonical, sizeof(canonical));
    if (rc < 0)
      return rc;

    // Pass 1: 0-based index of the first word that differs from the canonical
    // phrase, comparing token-by-token up to the shorter of the two.
    {
        const char *p = mnemonic, *cp = canonical;
        int idx = 0;
        for (;;) {
            while (is_ws(*p))
              p++;
            while (is_ws(*cp))
              cp++;
            if (*p == '\0' || *cp == '\0')
              break;
            const char *us = p, *cs = cp;
            while (*p  != '\0' && !is_ws(*p))
              p++;
            while (*cp != '\0' && !is_ws(*cp))
              cp++;
            size_t ul = (size_t)(p - us), cl = (size_t)(cp - cs);
            if (ul != cl || memcmp(us, cs, ul) != 0) {
              first_mismatch = idx;
              break;
            }
            idx++;
        }
    }
    }

    // Pass 2: collect the start offset of each word to mark — not in the
    // wordlist, or the first positional mismatch (a valid-but-wrong word).
    size_t mark_off[BIP39_WORD_COUNT + 4];
    int    n_marks = 0;
    {
        char *p = mnemonic;
        int idx = 0;
        while (n_marks < (int)(sizeof mark_off / sizeof mark_off[0])) {
            while (is_ws(*p))
              p++;
            if (*p == '\0')
              break;
            char *ws = p;
            while (*p != '\0' && !is_ws(*p))
              p++;
            size_t wl = (size_t)(p - ws);
            int in_dict = (bip39_word_index(ws, wl) >= 0);
            if (!in_dict || idx == first_mismatch)
                mark_off[n_marks++] = (size_t)(ws - mnemonic);
            idx++;
        }
    }
    if (n_marks == 0)
      return 0;

    size_t len = 0;
    while (mnemonic[len] != '\0')
      len++;
    if (len + (size_t)n_marks + 1 > mnemonic_size)
      return BIP39_ERR_BUF;

    // Insert from the last mark to the first so earlier offsets stay valid.
    for (int m = n_marks - 1; m >= 0; m--) {
        size_t off = mark_off[m];
        size_t tail = 0;
        while (mnemonic[off + tail] != '\0')
          tail++;
        memmove(mnemonic + off + 1, mnemonic + off, tail + 1);
        mnemonic[off] = '*';
    }
    return n_marks;
}
