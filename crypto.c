/* Copyright 2008, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * curve25519-donna: Curve25519 elliptic curve, public key function
 *
 * http://code.google.com/p/curve25519-donna/
 *
 * Adam Langley <agl@imperialviolet.org>
 *
 * Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>
 *
 * More information about curve25519 can be found here
 *   http://cr.yp.to/ecdh.html
 *
 * djb's sample implementation of curve25519 is written in a special assembly
 * language called qhasm and uses the floating point registers.
 *
 * This is, almost, a clean room reimplementation from the curve25519 paper. It
 * uses many of the tricks described therein. Only the crecip function is taken
 * from the sample implementation. */

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "wg.h"

// Taken from https://github.com/floodyberry/poly1305-donna - public domain or MIT
/*
	poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition
*/

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

// X25519 IMPLEMENTATION
#define wireguard_x25519(a,b,c)	x25519(a,b,c,1)

// CHACHA20POLY1305 IMPLEMENTATION
#define wireguard_aead_encrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_aead_decrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_encrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_decrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)

#ifndef ROTR32
#define ROTR32(x, y)  (((x) >> (y)) ^ ((x) << (32 - (y))))
#endif

// Mixing function G.
#define B2S_G(a, b, c, d, x, y) {   \
	v[a] = v[a] + v[b] + x;         \
	v[d] = ROTR32(v[d] ^ v[a], 16); \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 12); \
	v[a] = v[a] + v[b] + y;         \
	v[d] = ROTR32(v[d] ^ v[a], 8);  \
	v[c] = v[c] + v[d];             \
	v[b] = ROTR32(v[b] ^ v[c], 7); }

// Initialization Vector.
static const uint32_t blake2s_iv[8] =
{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

// Compression function. "last" flag indicates last block.
static void blake2s_compress(blake2s_ctx *ctx, int last)
{
	const uint8_t sigma[10][16] = {
		{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
		{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
		{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
		{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
		{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
		{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
		{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
		{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
		{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
		{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 }
	};
	int i;
	uint32_t v[16], m[16];

	for (i = 0; i < 8; i++) {           // init work variables
	   v[i] = ctx->h[i];
	   v[i + 8] = blake2s_iv[i];
	}

	v[12] ^= ctx->t[0];                 // low 32 bits of offset
	v[13] ^= ctx->t[1];                 // high 32 bits
	if (last)                           // last block flag set ?
		v[14] = ~v[14];
	for (i = 0; i < 16; i++)            // get little-endian words
		m[i] = U8TO32_LITTLE(&ctx->b[4 * i]);

	for (i = 0; i < 10; i++) {          // ten rounds
		B2S_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
		B2S_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
		B2S_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
		B2S_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
		B2S_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
		B2S_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
		B2S_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
		B2S_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
	}

	for( i = 0; i < 8; ++i )
		ctx->h[i] ^= v[i] ^ v[i + 8];
}

void crypto_zero(void *dest, size_t len) {
	volatile uint8_t *p = (uint8_t *)dest;
	while (len--) {
		*p++ = 0;
	}
}

bool crypto_equal(const void *a, const void *b, size_t size) {
	uint8_t neq = 0;
	while (size > 0) {
		neq |= *(uint8_t *)a ^ *(uint8_t *)b;
		a += 1;
		b += 1;
		size -= 1;
	}
	return (neq) ? false : true;
}

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 32 gives the digest size in bytes.
//      Secret key (also <= 32 bytes) is optional (keylen = 0).
int blake2s_init(blake2s_ctx *ctx, size_t outlen,
	const void *key, size_t keylen)     // (keylen=0: no key)
{
	size_t i;

	if (outlen == 0 || outlen > 32 || keylen > 32)
	return -1;                      // illegal parameters

	for (i = 0; i < 8; i++)             // state, "param block"
		ctx->h[i] = blake2s_iv[i];
	ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

	ctx->t[0] = 0;                      // input count low word
	ctx->t[1] = 0;                      // input count high word
	ctx->c = 0;                         // pointer within buffer
	ctx->outlen = outlen;

	for (i = keylen; i < 64; i++)       // zero input block
		ctx->b[i] = 0;
	if (keylen > 0) {
		blake2s_update(ctx, key, keylen);
		ctx->c = 64;                    // at the end
	}

	return 0;
}

// Add "inlen" bytes from "in" into the hash.
void blake2s_update(blake2s_ctx *ctx,
	const void *in, size_t inlen)       // data bytes
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		if (ctx->c == 64) {             // buffer full ?
			ctx->t[0] += ctx->c;        // add counters
			if (ctx->t[0] < ctx->c)     // carry overflow ?
				ctx->t[1]++;            // high word
			blake2s_compress(ctx, 0);   // compress (not last)
			ctx->c = 0;                 // counter to zero
		}
		ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
	}
}

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2s_final(blake2s_ctx *ctx, void *out)
{
	size_t i;

	ctx->t[0] += ctx->c;                // mark last block offset
	if (ctx->t[0] < ctx->c)             // carry overflow
		ctx->t[1]++;                    // high word

	while (ctx->c < 64)                 // fill up with zeros
		ctx->b[ctx->c++] = 0;
	blake2s_compress(ctx, 1);           // final block flag = 1

	// little endian convert and store
	for (i = 0; i < ctx->outlen; i++) {
		((uint8_t *) out)[i] =
		(ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
	}
}

// Convenience function for all-in-one computation.
int blake2s(void *out, size_t outlen,
	const void *key, size_t keylen,
	const void *in, size_t inlen)
{
	blake2s_ctx ctx;
	if (blake2s_init(&ctx, outlen, key, keylen))
		return -1;
	blake2s_update(&ctx, in, inlen);
	blake2s_final(&ctx, out);

	return 0;
}

// Endian / unaligned helper macros
#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((uint8_t)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U8TO64_LITTLE(p) \
  (((uint64_t)((p)[0])      ) | \
   ((uint64_t)((p)[1]) <<  8) | \
   ((uint64_t)((p)[2]) << 16) | \
   ((uint64_t)((p)[3]) << 24) | \
   ((uint64_t)((p)[4]) << 32) | \
   ((uint64_t)((p)[5]) << 40) | \
   ((uint64_t)((p)[6]) << 48) | \
   ((uint64_t)((p)[7]) << 56))

#define U16TO8_BIG(p, v) \
  do { \
    (p)[1] = U8V((v)      ); \
    (p)[0] = U8V((v) >>  8); \
  } while (0)

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define U32TO8_BIG(p, v) \
  do { \
    (p)[3] = U8V((v)      ); \
    (p)[2] = U8V((v) >>  8); \
    (p)[1] = U8V((v) >> 16); \
    (p)[0] = U8V((v) >> 24); \
  } while (0)

#define U64TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
    (p)[4] = U8V((v) >> 32); \
    (p)[5] = U8V((v) >> 40); \
    (p)[6] = U8V((v) >> 48); \
    (p)[7] = U8V((v) >> 56); \
} while (0)

#define U64TO8_BIG(p, v) \
  do { \
    (p)[7] = U8V((v)      ); \
    (p)[6] = U8V((v) >>  8); \
    (p)[5] = U8V((v) >> 16); \
    (p)[4] = U8V((v) >> 24); \
    (p)[3] = U8V((v) >> 32); \
    (p)[2] = U8V((v) >> 40); \
    (p)[1] = U8V((v) >> 48); \
    (p)[0] = U8V((v) >> 56); \
} while (0)


void crypto_zero(void *dest, size_t len);
bool crypto_equal(const void *a, const void *b, size_t size);

#define CHACHA20_BLOCK_SIZE		(64)
#define CHACHA20_KEY_SIZE		(32)

void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce);
void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len);
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key);
#ifdef _MSC_VER
#define inline __inline
#endif

typedef uint8_t u8;
typedef int32_t s32;
typedef int64_t limb;

// 2.3.  The ChaCha20 Block Function
// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
static const uint32_t CHACHA20_CONSTANT_1 = 0x61707865;
static const uint32_t CHACHA20_CONSTANT_2 = 0x3320646e;
static const uint32_t CHACHA20_CONSTANT_3 = 0x79622d32;
static const uint32_t CHACHA20_CONSTANT_4 = 0x6b206574;

#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

// 2.1. The ChaCha Quarter Round
// 1.  a += b; d ^= a; d <<<= 16;
// 2.  c += d; b ^= c; b <<<= 12;
// 3.  a += b; d ^= a; d <<<= 8;
// 4.  c += d; b ^= c; b <<<= 7;

#define QUARTERROUND(a, b, c, d)       \
    a += b;  d ^= a;  d = ROTL32(d, 16);  \
    c += d;  b ^= c;  b = ROTL32(b, 12);  \
    a += b;  d ^= a;  d = ROTL32(d,  8);  \
    c += d;  b ^= c;  b = ROTL32(b,  7)

static inline void INNER_BLOCK(uint32_t *block) {
	QUARTERROUND(block[0], block[4], block[ 8], block[12]); // column 0
	QUARTERROUND(block[1], block[5], block[ 9], block[13]); // column 1
	QUARTERROUND(block[2], block[6], block[10], block[14]); // column 2
	QUARTERROUND(block[3], block[7], block[11], block[15]); // column 3
	QUARTERROUND(block[0], block[5], block[10], block[15]); // diagonal 1
	QUARTERROUND(block[1], block[6], block[11], block[12]); // diagonal 2
	QUARTERROUND(block[2], block[7], block[ 8], block[13]); // diagonal 3
	QUARTERROUND(block[3], block[4], block[ 9], block[14]); // diagonal 4
}

#define TWENTY_ROUNDS(x) ( \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x), \
	INNER_BLOCK(x) \
)

// 2.3.  The ChaCha20 Block Function
// chacha20_block(key, counter, nonce):
//  state = constants | key | counter | nonce
//  working_state = state
//	for i=1 upto 10
//   inner_block(working_state)
//  end
//	state += working_state
//	return serialize(state)
// end
static void chacha20_block(struct chacha20_ctx *ctx, uint8_t *stream) {
	uint32_t working_state[16];
	int i;

	for (i = 0; i < 16; ++i) {
		working_state[i] = ctx->state[i];
	}

	TWENTY_ROUNDS(working_state);

	for (i = 0; i < 16; ++i) {
		U32TO8_LITTLE(stream + (4 * i), PLUS(working_state[i], ctx->state[i]));
	}
}

void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
	uint8_t output[CHACHA20_BLOCK_SIZE];
	uint32_t i;

	if (len) {
		for (;;) {
			chacha20_block(ctx, output);
			// Word 12 is a block counter
			ctx->state[12] = PLUSONE(ctx->state[12]);
			if (len <= 64) {
				for (i = 0;i < len;++i) {
					out[i] = in[i] ^ output[i];
			    }
			    return;
			}
			for (i = 0;i < 64;++i) {
				out[i] = in[i] ^ output[i];
			}
			len -= 64;
			out += 64;
			in += 64;
		}
	}
}


// 2.3.  The ChaCha20 Block Function
// The first four words (0-3) are constants: 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
// The next eight words (4-11) are taken from the 256-bit key by reading the bytes in little-endian order, in 4-byte chunks.
// Word 12 is a block counter.  Since each block is 64-byte, a 32-bit word is enough for 256 gigabytes of data.
// Words 13-15 are a nonce, which should not be repeated for the same key.
// For wireguard: "nonce being composed of 32 bits of zeros followed by the 64-bit little-endian value of counter." where counter comes from the Wireguard layer and is separate from the block counter in word 12
void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, const uint64_t nonce) {
	ctx->state[0] = CHACHA20_CONSTANT_1;
	ctx->state[1] = CHACHA20_CONSTANT_2;
	ctx->state[2] = CHACHA20_CONSTANT_3;
	ctx->state[3] = CHACHA20_CONSTANT_4;
	ctx->state[4] = U8TO32_LITTLE(key + 0);
	ctx->state[5] = U8TO32_LITTLE(key + 4);
	ctx->state[6] = U8TO32_LITTLE(key + 8);
	ctx->state[7] = U8TO32_LITTLE(key + 12);
	ctx->state[8] = U8TO32_LITTLE(key + 16);
	ctx->state[9] = U8TO32_LITTLE(key + 20);
	ctx->state[10] = U8TO32_LITTLE(key + 24);
	ctx->state[11] = U8TO32_LITTLE(key + 28);
	ctx->state[12] = 0;
	ctx->state[13] = 0;
	ctx->state[14] = nonce & 0xFFFFFFFF;
	ctx->state[15] = nonce >> 32;
}

// 2.2. HChaCha20
// HChaCha20 is initialized the same way as the ChaCha cipher, except that HChaCha20 uses a 128-bit nonce and has no counter.
// After initialization, proceed through the ChaCha rounds as usual.
// Once the 20 ChaCha rounds have been completed, the first 128 bits and last 128 bits of the ChaCha state (both little-endian) are concatenated, and this 256-bit subkey is returned.
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key) {
	uint32_t state[16];
	state[0] = CHACHA20_CONSTANT_1;
	state[1] = CHACHA20_CONSTANT_2;
	state[2] = CHACHA20_CONSTANT_3;
	state[3] = CHACHA20_CONSTANT_4;
	state[4] = U8TO32_LITTLE(key + 0);
	state[5] = U8TO32_LITTLE(key + 4);
	state[6] = U8TO32_LITTLE(key + 8);
	state[7] = U8TO32_LITTLE(key + 12);
	state[8] = U8TO32_LITTLE(key + 16);
	state[9] = U8TO32_LITTLE(key + 20);
	state[10] = U8TO32_LITTLE(key + 24);
	state[11] = U8TO32_LITTLE(key + 28);
	state[12] = U8TO32_LITTLE(nonce +  0);
	state[13] = U8TO32_LITTLE(nonce +  4);
	state[14] = U8TO32_LITTLE(nonce +  8);
	state[15] = U8TO32_LITTLE(nonce + 12);

	TWENTY_ROUNDS(state);

	// Concatenate first/last 128 bits into 256bit output (as little endian)
	U32TO8_LITTLE(out + 0, state[0]);
	U32TO8_LITTLE(out + 4, state[1]);
	U32TO8_LITTLE(out + 8, state[2]);
	U32TO8_LITTLE(out + 12, state[3]);
	U32TO8_LITTLE(out + 16, state[12]);
	U32TO8_LITTLE(out + 20, state[13]);
	U32TO8_LITTLE(out + 24, state[14]);
	U32TO8_LITTLE(out + 28, state[15]);
}

void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

static const uint8_t zero[CHACHA20_BLOCK_SIZE] = { 0 };
#define POLY1305_KEY_SIZE		32
#define POLY1305_MAC_SIZE		16

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long r[5];
	unsigned long h[5];
	unsigned long pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian */
static unsigned long
U8TO32(const unsigned char *p) {
	return
		(((unsigned long)(p[0] & 0xff)      ) |
	     ((unsigned long)(p[1] & 0xff) <<  8) |
         ((unsigned long)(p[2] & 0xff) << 16) |
         ((unsigned long)(p[3] & 0xff) << 24));
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(unsigned char *p, unsigned long v) {
	p[0] = (v      ) & 0xff;
	p[1] = (v >>  8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

void
poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	st->r[0] = (U8TO32(&key[ 0])     ) & 0x3ffffff;
	st->r[1] = (U8TO32(&key[ 3]) >> 2) & 0x3ffff03;
	st->r[2] = (U8TO32(&key[ 6]) >> 4) & 0x3ffc0ff;
	st->r[3] = (U8TO32(&key[ 9]) >> 6) & 0x3f03fff;
	st->r[4] = (U8TO32(&key[12]) >> 8) & 0x00fffff;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;

	/* save pad for later */
	st->pad[0] = U8TO32(&key[16]);
	st->pad[1] = U8TO32(&key[20]);
	st->pad[2] = U8TO32(&key[24]);
	st->pad[3] = U8TO32(&key[28]);

	st->leftover = 0;
	st->final = 0;
}

static void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
	const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
	unsigned long r0,r1,r2,r3,r4;
	unsigned long s1,s2,s3,s4;
	unsigned long h0,h1,h2,h3,h4;
	unsigned long long d0,d1,d2,d3,d4;
	unsigned long c;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];
	r3 = st->r[3];
	r4 = st->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	while (bytes >= poly1305_block_size) {
		/* h += m[i] */
		h0 += (U8TO32(m+ 0)     ) & 0x3ffffff;
		h1 += (U8TO32(m+ 3) >> 2) & 0x3ffffff;
		h2 += (U8TO32(m+ 6) >> 4) & 0x3ffffff;
		h3 += (U8TO32(m+ 9) >> 6) & 0x3ffffff;
		h4 += (U8TO32(m+12) >> 8) | hibit;

		/* h *= r */
		d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
		d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
		d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
		d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
		d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

		/* (partial) h %= p */
		              c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
		d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
		d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
		d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
		d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
		h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
		h1 += c;

		m += poly1305_block_size;
		bytes -= poly1305_block_size;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
	st->h[3] = h3;
	st->h[4] = h4;
}

POLY1305_NOINLINE void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	unsigned long h0,h1,h2,h3,h4,c;
	unsigned long g0,g1,g2,g3,g4;
	unsigned long long f;
	unsigned long mask;

	/* process the remaining block */
	if (st->leftover) {
		size_t i = st->leftover;
		st->buffer[i++] = 1;
		for (; i < poly1305_block_size; i++)
			st->buffer[i] = 0;
		st->final = 1;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];
	h3 = st->h[3];
	h4 = st->h[4];

	             c = h1 >> 26; h1 = h1 & 0x3ffffff;
	h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
	h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
	h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
	h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
	h1 +=     c;

	/* compute h + -p */
	g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
	g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
	g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
	g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

	/* mac = (h + pad) % (2^128) */
	f = (unsigned long long)h0 + st->pad[0]            ; h0 = (unsigned long)f;
	f = (unsigned long long)h1 + st->pad[1] + (f >> 32); h1 = (unsigned long)f;
	f = (unsigned long long)h2 + st->pad[2] + (f >> 32); h2 = (unsigned long)f;
	f = (unsigned long long)h3 + st->pad[3] + (f >> 32); h3 = (unsigned long)f;

	U32TO8(mac +  0, h0);
	U32TO8(mac +  4, h1);
	U32TO8(mac +  8, h2);
	U32TO8(mac + 12, h3);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->h[3] = 0;
	st->h[4] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->r[3] = 0;
	st->r[4] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
	st->pad[2] = 0;
	st->pad[3] = 0;
}


void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
	poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
	size_t i;

	/* handle leftover */
	if (st->leftover) {
		size_t want = (poly1305_block_size - st->leftover);
		if (want > bytes)
			want = bytes;
		for (i = 0; i < want; i++)
			st->buffer[st->leftover + i] = m[i];
		bytes -= want;
		m += want;
		st->leftover += want;
		if (st->leftover < poly1305_block_size)
			return;
		poly1305_blocks(st, st->buffer, poly1305_block_size);
		st->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= poly1305_block_size) {
		size_t want = (bytes & ~(poly1305_block_size - 1));
		poly1305_blocks(st, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		for (i = 0; i < bytes; i++)
			st->buffer[st->leftover + i] = m[i];
		st->leftover += bytes;
	}
}


// 2.6.  Generating the Poly1305 Key Using ChaCha20
static void generate_poly1305_key(struct poly1305_context *poly1305_state, struct chacha20_ctx *chacha20_state, const uint8_t *key, uint64_t nonce) {
	uint8_t block[POLY1305_KEY_SIZE] = {0};

	// The method is to call the block function with the following parameters:
	// - The 256-bit session integrity key is used as the ChaCha20 key.
	// - The block counter is set to zero.
	// - The protocol will specify a 96-bit or 64-bit nonce
	chacha20_init(chacha20_state, key, nonce);

	// We take the first 256 bits or the serialized state, and use those as the one-time Poly1305 key
	chacha20(chacha20_state, block, block, sizeof(block));

	poly1305_init(poly1305_state, block);

	crypto_zero(&block, sizeof(block));
}
// 2.8.  AEAD Construction (Encryption)
void chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key) {
	struct poly1305_context poly1305_state;
	struct chacha20_ctx chacha20_state;
	uint8_t block[8];
	size_t padded_len;

	// First, a Poly1305 one-time key is generated from the 256-bit key and nonce using the procedure described in Section 2.6.
	generate_poly1305_key(&poly1305_state, &chacha20_state, key, nonce);

	// Next, the ChaCha20 encryption function is called to encrypt the plaintext, using the same key and nonce, and with the initial counter set to 1.
	chacha20(&chacha20_state, dst, src, src_len);

	// Finally, the Poly1305 function is called with the Poly1305 key calculated above, and a message constructed as a concatenation of the following:
	// - The AAD
	poly1305_update(&poly1305_state, ad, ad_len);
	// - padding1 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16
	padded_len = (ad_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
	poly1305_update(&poly1305_state, zero, padded_len - ad_len);
	// - The ciphertext
	poly1305_update(&poly1305_state, dst, src_len);
	// - padding2 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16.
	padded_len = (src_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
	poly1305_update(&poly1305_state, zero, padded_len - src_len);
	// - The length of the additional data in octets (as a 64-bit little-endian integer)
	U64TO8_LITTLE(block, (uint64_t)ad_len);
	poly1305_update(&poly1305_state, block, sizeof(block));
	// - The length of the ciphertext in octets (as a 64-bit little-endian integer).
	U64TO8_LITTLE(block, (uint64_t)src_len);
	poly1305_update(&poly1305_state, block, sizeof(block));

	// The output from the AEAD is twofold:
	// - A ciphertext of the same length as the plaintext. (above, output of chacha20 into dst)
	// - A 128-bit tag, which is the output of the Poly1305 function. (append to dst)
	poly1305_finish(&poly1305_state, dst + src_len);

	// Make sure we leave nothing sensitive on the stack
	crypto_zero(&chacha20_state, sizeof(chacha20_state));
	crypto_zero(&block, sizeof(block));
}

// 2.8.  AEAD Construction (Decryption)
bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key) {
	struct poly1305_context poly1305_state;
	struct chacha20_ctx chacha20_state;
	uint8_t block[8];
	uint8_t mac[POLY1305_MAC_SIZE];
	size_t padded_len;
	int dst_len;
	bool result = false;

	// Decryption is similar [to encryption] with the following differences:
	// - The roles of ciphertext and plaintext are reversed, so the ChaCha20 encryption function is applied to the ciphertext, producing the plaintext.
	// - The Poly1305 function is still run on the AAD and the ciphertext, not the plaintext.
	// - The calculated tag is bitwise compared to the received tag.  The message is authenticated if and only if the tags match.

	if (src_len >= POLY1305_MAC_SIZE) {
		dst_len = src_len - POLY1305_MAC_SIZE;

		// First, a Poly1305 one-time key is generated from the 256-bit key and nonce using the procedure described in Section 2.6.
		generate_poly1305_key(&poly1305_state, &chacha20_state, key, nonce);

		// Calculate the MAC before attempting decryption

		// the Poly1305 function is called with the Poly1305 key calculated above, and a message constructed as a concatenation of the following:
		// - The AAD
		poly1305_update(&poly1305_state, ad, ad_len);
		// - padding1 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16
		padded_len = (ad_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
		poly1305_update(&poly1305_state, zero, padded_len - ad_len);
		// - The ciphertext (note the Poly1305 function is still run on the AAD and the ciphertext, not the plaintext)
		poly1305_update(&poly1305_state, src, dst_len);
		// - padding2 -- the padding is up to 15 zero bytes, and it brings the total length so far to an integral multiple of 16.
		padded_len = (dst_len + 15) & 0xFFFFFFF0; // Round up to next 16 bytes
		poly1305_update(&poly1305_state, zero, padded_len - dst_len);
		// - The length of the additional data in octets (as a 64-bit little-endian integer)
		U64TO8_LITTLE(block, (uint64_t)ad_len);
		poly1305_update(&poly1305_state, block, sizeof(block));
		// - The length of the ciphertext in octets (as a 64-bit little-endian integer).
		U64TO8_LITTLE(block, (uint64_t)dst_len);
		poly1305_update(&poly1305_state, block, sizeof(block));

		// The output from the AEAD is twofold:
		// - A plaintext of the same length as the ciphertext. (below, output of chacha20 into dst)
		// - A 128-bit tag, which is the output of the Poly1305 function. (into mac for checking against passed mac)
		poly1305_finish(&poly1305_state, mac);


		if (crypto_equal(mac, src + dst_len, POLY1305_MAC_SIZE)) {
			// mac is correct - do the decryption
			// Next, the ChaCha20 encryption function is called to decrypt the ciphertext, using the same key and nonce, and with the initial counter set to 1.
			chacha20(&chacha20_state, dst, src, dst_len);
			result = true;
		}
	}
	return result;
}

// AEAD_XChaCha20_Poly1305
// XChaCha20-Poly1305 is a variant of the ChaCha20-Poly1305 AEAD construction as defined in [RFC7539] that uses a 192-bit nonce instead of a 96-bit nonce.
// The algorithm for XChaCha20-Poly1305 is as follows:
// 1. Calculate a subkey from the first 16 bytes of the nonce and the key, using HChaCha20 (Section 2.2).
// 2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL bytes) with AEAD_CHACHA20_POLY1305 from [RFC7539] as normal. The definition for XChaCha20 is given in Section 2.3.
void xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
	uint8_t subkey[CHACHA20_KEY_SIZE];
	uint64_t new_nonce;

	new_nonce = U8TO64_LITTLE(nonce + 16);

	hchacha20(subkey, nonce, key);
	chacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);

	crypto_zero(subkey, sizeof(subkey));
}

bool xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key) {
	uint8_t subkey[CHACHA20_KEY_SIZE];
	uint64_t new_nonce;
	bool result;

	new_nonce = U8TO64_LITTLE(nonce + 16);

	hchacha20(subkey, nonce, key);
	result = chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, new_nonce, subkey);

	crypto_zero(subkey, sizeof(subkey));
	return result;
}

/* Field element representation:
 *
 * Field elements are written as an array of signed, 64-bit limbs, least
 * significant first. The value of the field element is:
 *   x[0] + 2^26·x[1] + x^51·x[2] + 2^102·x[3] + ...
 *
 * i.e. the limbs are 26, 25, 26, 25, ... bits wide. */

/* Sum two numbers: output += in */
static void fsum(limb *output, const limb *in) {
  unsigned i;
  for (i = 0; i < 10; i += 2) {
    output[0+i] = output[0+i] + in[0+i];
    output[1+i] = output[1+i] + in[1+i];
  }
}

/* Find the difference of two numbers: output = in - output
 * (note the order of the arguments!). */
static void fdifference(limb *output, const limb *in) {
  unsigned i;
  for (i = 0; i < 10; ++i) {
    output[i] = in[i] - output[i];
  }
}

/* Multiply a number by a scalar: output = in * scalar */
static void fscalar_product(limb *output, const limb *in, const limb scalar) {
  unsigned i;
  for (i = 0; i < 10; ++i) {
    output[i] = in[i] * scalar;
  }
}

/* Multiply two numbers: output = in2 * in
 *
 * output must be distinct to both inputs. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
static void fproduct(limb *output, const limb *in2, const limb *in) {
  output[0] =       ((limb) ((s32) in2[0])) * ((s32) in[0]);
  output[1] =       ((limb) ((s32) in2[0])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[0]);
  output[2] =  2 *  ((limb) ((s32) in2[1])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[0]);
  output[3] =       ((limb) ((s32) in2[1])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[0]);
  output[4] =       ((limb) ((s32) in2[2])) * ((s32) in[2]) +
               2 * (((limb) ((s32) in2[1])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[0])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[0]);
  output[5] =       ((limb) ((s32) in2[2])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[0]);
  output[6] =  2 * (((limb) ((s32) in2[3])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[2])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[0]);
  output[7] =       ((limb) ((s32) in2[3])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[0]);
  output[8] =       ((limb) ((s32) in2[4])) * ((s32) in[4]) +
               2 * (((limb) ((s32) in2[3])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[2])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[0]);
  output[9] =       ((limb) ((s32) in2[4])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[2]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[1]) +
                    ((limb) ((s32) in2[0])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[0]);
  output[10] = 2 * (((limb) ((s32) in2[5])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[1])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[1])) +
                    ((limb) ((s32) in2[4])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[2]);
  output[11] =      ((limb) ((s32) in2[5])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[4]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[3]) +
                    ((limb) ((s32) in2[2])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[2]);
  output[12] =      ((limb) ((s32) in2[6])) * ((s32) in[6]) +
               2 * (((limb) ((s32) in2[5])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[3])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[3])) +
                    ((limb) ((s32) in2[4])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[4]);
  output[13] =      ((limb) ((s32) in2[6])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[7])) * ((s32) in[6]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[5]) +
                    ((limb) ((s32) in2[4])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[4]);
  output[14] = 2 * (((limb) ((s32) in2[7])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[5])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[5])) +
                    ((limb) ((s32) in2[6])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[6]);
  output[15] =      ((limb) ((s32) in2[7])) * ((s32) in[8]) +
                    ((limb) ((s32) in2[8])) * ((s32) in[7]) +
                    ((limb) ((s32) in2[6])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[6]);
  output[16] =      ((limb) ((s32) in2[8])) * ((s32) in[8]) +
               2 * (((limb) ((s32) in2[7])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[7]));
  output[17] =      ((limb) ((s32) in2[8])) * ((s32) in[9]) +
                    ((limb) ((s32) in2[9])) * ((s32) in[8]);
  output[18] = 2 *  ((limb) ((s32) in2[9])) * ((s32) in[9]);
}

/* Reduce a long form to a short form by taking the input mod 2^255 - 19.
 *
 * On entry: |output[i]| < 14*2^54
 * On exit: |output[0..8]| < 280*2^54 */
static void freduce_degree(limb *output) {
  /* Each of these shifts and adds ends up multiplying the value by 19.
   *
   * For output[0..8], the absolute entry value is < 14*2^54 and we add, at
   * most, 19*14*2^54 thus, on exit, |output[0..8]| < 280*2^54. */
  output[8] += output[18] << 4;
  output[8] += output[18] << 1;
  output[8] += output[18];
  output[7] += output[17] << 4;
  output[7] += output[17] << 1;
  output[7] += output[17];
  output[6] += output[16] << 4;
  output[6] += output[16] << 1;
  output[6] += output[16];
  output[5] += output[15] << 4;
  output[5] += output[15] << 1;
  output[5] += output[15];
  output[4] += output[14] << 4;
  output[4] += output[14] << 1;
  output[4] += output[14];
  output[3] += output[13] << 4;
  output[3] += output[13] << 1;
  output[3] += output[13];
  output[2] += output[12] << 4;
  output[2] += output[12] << 1;
  output[2] += output[12];
  output[1] += output[11] << 4;
  output[1] += output[11] << 1;
  output[1] += output[11];
  output[0] += output[10] << 4;
  output[0] += output[10] << 1;
  output[0] += output[10];
}

#if (-1 & 3) != 3
#error "This code only works on a two's complement system"
#endif

/* return v / 2^26, using only shifts and adds.
 *
 * On entry: v can take any value. */
static inline limb
div_by_2_26(const limb v)
{
  /* High word of v; no shift needed. */
  const uint32_t highword = (uint32_t) (((uint64_t) v) >> 32);
  /* Set to all 1s if v was negative; else set to 0s. */
  const int32_t sign = ((int32_t) highword) >> 31;
  /* Set to 0x3ffffff if v was negative; else set to 0. */
  const int32_t roundoff = ((uint32_t) sign) >> 6;
  /* Should return v / (1<<26) */
  return (v + roundoff) >> 26;
}

/* return v / (2^25), using only shifts and adds.
 *
 * On entry: v can take any value. */
static inline limb
div_by_2_25(const limb v)
{
  /* High word of v; no shift needed*/
  const uint32_t highword = (uint32_t) (((uint64_t) v) >> 32);
  /* Set to all 1s if v was negative; else set to 0s. */
  const int32_t sign = ((int32_t) highword) >> 31;
  /* Set to 0x1ffffff if v was negative; else set to 0. */
  const int32_t roundoff = ((uint32_t) sign) >> 7;
  /* Should return v / (1<<25) */
  return (v + roundoff) >> 25;
}

/* Reduce all coefficients of the short form input so that |x| < 2^26.
 *
 * On entry: |output[i]| < 280*2^54 */
static void freduce_coefficients(limb *output) {
  unsigned i;

  output[10] = 0;

  for (i = 0; i < 10; i += 2) {
    limb over = div_by_2_26(output[i]);
    /* The entry condition (that |output[i]| < 280*2^54) means that over is, at
     * most, 280*2^28 in the first iteration of this loop. This is added to the
     * next limb and we can approximate the resulting bound of that limb by
     * 281*2^54. */
    output[i] -= over << 26;
    output[i+1] += over;

    /* For the first iteration, |output[i+1]| < 281*2^54, thus |over| <
     * 281*2^29. When this is added to the next limb, the resulting bound can
     * be approximated as 281*2^54.
     *
     * For subsequent iterations of the loop, 281*2^54 remains a conservative
     * bound and no overflow occurs. */
    over = div_by_2_25(output[i+1]);
    output[i+1] -= over << 25;
    output[i+2] += over;
  }
  /* Now |output[10]| < 281*2^29 and all other coefficients are reduced. */
  output[0] += output[10] << 4;
  output[0] += output[10] << 1;
  output[0] += output[10];

  output[10] = 0;

  /* Now output[1..9] are reduced, and |output[0]| < 2^26 + 19*281*2^29
   * So |over| will be no more than 2^16. */
  {
    limb over = div_by_2_26(output[0]);
    output[0] -= over << 26;
    output[1] += over;
  }

  /* Now output[0,2..9] are reduced, and |output[1]| < 2^25 + 2^16 < 2^26. The
   * bound on |output[1]| is sufficient to meet our needs. */
}

/* A helpful wrapper around fproduct: output = in * in2.
 *
 * On entry: |in[i]| < 2^27 and |in2[i]| < 2^27.
 *
 * output must be distinct to both inputs. The output is reduced degree
 * (indeed, one need only provide storage for 10 limbs) and |output[i]| < 2^26. */
static void
fmul(limb *output, const limb *in, const limb *in2) {
  limb t[19];
  fproduct(t, in, in2);
  /* |t[i]| < 14*2^54 */
  freduce_degree(t);
  freduce_coefficients(t);
  /* |t[i]| < 2^26 */
  memcpy(output, t, sizeof(limb) * 10);
}

/* Square a number: output = in**2
 *
 * output must be distinct from the input. The inputs are reduced coefficient
 * form, the output is not.
 *
 * output[x] <= 14 * the largest product of the input limbs. */
static void fsquare_inner(limb *output, const limb *in) {
  output[0] =       ((limb) ((s32) in[0])) * ((s32) in[0]);
  output[1] =  2 *  ((limb) ((s32) in[0])) * ((s32) in[1]);
  output[2] =  2 * (((limb) ((s32) in[1])) * ((s32) in[1]) +
                    ((limb) ((s32) in[0])) * ((s32) in[2]));
  output[3] =  2 * (((limb) ((s32) in[1])) * ((s32) in[2]) +
                    ((limb) ((s32) in[0])) * ((s32) in[3]));
  output[4] =       ((limb) ((s32) in[2])) * ((s32) in[2]) +
               4 *  ((limb) ((s32) in[1])) * ((s32) in[3]) +
               2 *  ((limb) ((s32) in[0])) * ((s32) in[4]);
  output[5] =  2 * (((limb) ((s32) in[2])) * ((s32) in[3]) +
                    ((limb) ((s32) in[1])) * ((s32) in[4]) +
                    ((limb) ((s32) in[0])) * ((s32) in[5]));
  output[6] =  2 * (((limb) ((s32) in[3])) * ((s32) in[3]) +
                    ((limb) ((s32) in[2])) * ((s32) in[4]) +
                    ((limb) ((s32) in[0])) * ((s32) in[6]) +
               2 *  ((limb) ((s32) in[1])) * ((s32) in[5]));
  output[7] =  2 * (((limb) ((s32) in[3])) * ((s32) in[4]) +
                    ((limb) ((s32) in[2])) * ((s32) in[5]) +
                    ((limb) ((s32) in[1])) * ((s32) in[6]) +
                    ((limb) ((s32) in[0])) * ((s32) in[7]));
  output[8] =       ((limb) ((s32) in[4])) * ((s32) in[4]) +
               2 * (((limb) ((s32) in[2])) * ((s32) in[6]) +
                    ((limb) ((s32) in[0])) * ((s32) in[8]) +
               2 * (((limb) ((s32) in[1])) * ((s32) in[7]) +
                    ((limb) ((s32) in[3])) * ((s32) in[5])));
  output[9] =  2 * (((limb) ((s32) in[4])) * ((s32) in[5]) +
                    ((limb) ((s32) in[3])) * ((s32) in[6]) +
                    ((limb) ((s32) in[2])) * ((s32) in[7]) +
                    ((limb) ((s32) in[1])) * ((s32) in[8]) +
                    ((limb) ((s32) in[0])) * ((s32) in[9]));
  output[10] = 2 * (((limb) ((s32) in[5])) * ((s32) in[5]) +
                    ((limb) ((s32) in[4])) * ((s32) in[6]) +
                    ((limb) ((s32) in[2])) * ((s32) in[8]) +
               2 * (((limb) ((s32) in[3])) * ((s32) in[7]) +
                    ((limb) ((s32) in[1])) * ((s32) in[9])));
  output[11] = 2 * (((limb) ((s32) in[5])) * ((s32) in[6]) +
                    ((limb) ((s32) in[4])) * ((s32) in[7]) +
                    ((limb) ((s32) in[3])) * ((s32) in[8]) +
                    ((limb) ((s32) in[2])) * ((s32) in[9]));
  output[12] =      ((limb) ((s32) in[6])) * ((s32) in[6]) +
               2 * (((limb) ((s32) in[4])) * ((s32) in[8]) +
               2 * (((limb) ((s32) in[5])) * ((s32) in[7]) +
                    ((limb) ((s32) in[3])) * ((s32) in[9])));
  output[13] = 2 * (((limb) ((s32) in[6])) * ((s32) in[7]) +
                    ((limb) ((s32) in[5])) * ((s32) in[8]) +
                    ((limb) ((s32) in[4])) * ((s32) in[9]));
  output[14] = 2 * (((limb) ((s32) in[7])) * ((s32) in[7]) +
                    ((limb) ((s32) in[6])) * ((s32) in[8]) +
               2 *  ((limb) ((s32) in[5])) * ((s32) in[9]));
  output[15] = 2 * (((limb) ((s32) in[7])) * ((s32) in[8]) +
                    ((limb) ((s32) in[6])) * ((s32) in[9]));
  output[16] =      ((limb) ((s32) in[8])) * ((s32) in[8]) +
               4 *  ((limb) ((s32) in[7])) * ((s32) in[9]);
  output[17] = 2 *  ((limb) ((s32) in[8])) * ((s32) in[9]);
  output[18] = 2 *  ((limb) ((s32) in[9])) * ((s32) in[9]);
}

/* fsquare sets output = in^2.
 *
 * On entry: The |in| argument is in reduced coefficients form and |in[i]| <
 * 2^27.
 *
 * On exit: The |output| argument is in reduced coefficients form (indeed, one
 * need only provide storage for 10 limbs) and |out[i]| < 2^26. */
static void
fsquare(limb *output, const limb *in) {
  limb t[19];
  fsquare_inner(t, in);
  /* |t[i]| < 14*2^54 because the largest product of two limbs will be <
   * 2^(27+27) and fsquare_inner adds together, at most, 14 of those
   * products. */
  freduce_degree(t);
  freduce_coefficients(t);
  /* |t[i]| < 2^26 */
  memcpy(output, t, sizeof(limb) * 10);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void
fexpand(limb *output, const u8 *input) {
#define F(n,start,shift,mask) \
  output[n] = ((((limb) input[start + 0]) | \
                ((limb) input[start + 1]) << 8 | \
                ((limb) input[start + 2]) << 16 | \
                ((limb) input[start + 3]) << 24) >> shift) & mask;
  F(0, 0, 0, 0x3ffffff);
  F(1, 3, 2, 0x1ffffff);
  F(2, 6, 3, 0x3ffffff);
  F(3, 9, 5, 0x1ffffff);
  F(4, 12, 6, 0x3ffffff);
  F(5, 16, 0, 0x1ffffff);
  F(6, 19, 1, 0x3ffffff);
  F(7, 22, 3, 0x1ffffff);
  F(8, 25, 4, 0x3ffffff);
  F(9, 28, 6, 0x1ffffff);
#undef F
}

#if (-32 >> 1) != -16
#error "This code only works when >> does sign-extension on negative numbers"
#endif

/* s32_eq returns 0xffffffff iff a == b and zero otherwise. */
static s32 s32_eq(s32 a, s32 b) {
  a = ~(a ^ b);
  a &= a << 16;
  a &= a << 8;
  a &= a << 4;
  a &= a << 2;
  a &= a << 1;
  return a >> 31;
}

/* s32_gte returns 0xffffffff if a >= b and zero otherwise, where a and b are
 * both non-negative. */
static s32 s32_gte(s32 a, s32 b) {
  a -= b;
  /* a >= 0 iff a >= b. */
  return ~(a >> 31);
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array.
 *
 * On entry: |input_limbs[i]| < 2^26 */
static void
fcontract(u8 *output, limb *input_limbs) {
  int i;
  int j;
  s32 input[10];
  s32 mask;

  /* |input_limbs[i]| < 2^26, so it's valid to convert to an s32. */
  for (i = 0; i < 10; i++) {
    input[i] = input_limbs[i];
  }

  for (j = 0; j < 2; ++j) {
    for (i = 0; i < 9; ++i) {
      if ((i & 1) == 1) {
        /* This calculation is a time-invariant way to make input[i]
         * non-negative by borrowing from the next-larger limb. */
        const s32 mask = input[i] >> 31;
        const s32 carry = -((input[i] & mask) >> 25);
        input[i] = input[i] + (carry << 25);
        input[i+1] = input[i+1] - carry;
      } else {
        const s32 mask = input[i] >> 31;
        const s32 carry = -((input[i] & mask) >> 26);
        input[i] = input[i] + (carry << 26);
        input[i+1] = input[i+1] - carry;
      }
    }

    /* There's no greater limb for input[9] to borrow from, but we can multiply
     * by 19 and borrow from input[0], which is valid mod 2^255-19. */
    {
      const s32 mask = input[9] >> 31;
      const s32 carry = -((input[9] & mask) >> 25);
      input[9] = input[9] + (carry << 25);
      input[0] = input[0] - (carry * 19);
    }

    /* After the first iteration, input[1..9] are non-negative and fit within
     * 25 or 26 bits, depending on position. However, input[0] may be
     * negative. */
  }

  /* The first borrow-propagation pass above ended with every limb
     except (possibly) input[0] non-negative.

     If input[0] was negative after the first pass, then it was because of a
     carry from input[9]. On entry, input[9] < 2^26 so the carry was, at most,
     one, since (2**26-1) >> 25 = 1. Thus input[0] >= -19.

     In the second pass, each limb is decreased by at most one. Thus the second
     borrow-propagation pass could only have wrapped around to decrease
     input[0] again if the first pass left input[0] negative *and* input[1]
     through input[9] were all zero.  In that case, input[1] is now 2^25 - 1,
     and this last borrow-propagation step will leave input[1] non-negative. */
  {
    const s32 mask = input[0] >> 31;
    const s32 carry = -((input[0] & mask) >> 26);
    input[0] = input[0] + (carry << 26);
    input[1] = input[1] - carry;
  }

  /* All input[i] are now non-negative. However, there might be values between
   * 2^25 and 2^26 in a limb which is, nominally, 25 bits wide. */
  for (j = 0; j < 2; j++) {
    for (i = 0; i < 9; i++) {
      if ((i & 1) == 1) {
        const s32 carry = input[i] >> 25;
        input[i] &= 0x1ffffff;
        input[i+1] += carry;
      } else {
        const s32 carry = input[i] >> 26;
        input[i] &= 0x3ffffff;
        input[i+1] += carry;
      }
    }

    {
      const s32 carry = input[9] >> 25;
      input[9] &= 0x1ffffff;
      input[0] += 19*carry;
    }
  }

  /* If the first carry-chain pass, just above, ended up with a carry from
   * input[9], and that caused input[0] to be out-of-bounds, then input[0] was
   * < 2^26 + 2*19, because the carry was, at most, two.
   *
   * If the second pass carried from input[9] again then input[0] is < 2*19 and
   * the input[9] -> input[0] carry didn't push input[0] out of bounds. */

  /* It still remains the case that input might be between 2^255-19 and 2^255.
   * In this case, input[1..9] must take their maximum value and input[0] must
   * be >= (2^255-19) & 0x3ffffff, which is 0x3ffffed. */
  mask = s32_gte(input[0], 0x3ffffed);
  for (i = 1; i < 10; i++) {
    if ((i & 1) == 1) {
      mask &= s32_eq(input[i], 0x1ffffff);
    } else {
      mask &= s32_eq(input[i], 0x3ffffff);
    }
  }

  /* mask is either 0xffffffff (if input >= 2^255-19) and zero otherwise. Thus
   * this conditionally subtracts 2^255-19. */
  input[0] -= mask & 0x3ffffed;

  for (i = 1; i < 10; i++) {
    if ((i & 1) == 1) {
      input[i] -= mask & 0x1ffffff;
    } else {
      input[i] -= mask & 0x3ffffff;
    }
  }

  input[1] <<= 2;
  input[2] <<= 3;
  input[3] <<= 5;
  input[4] <<= 6;
  input[6] <<= 1;
  input[7] <<= 3;
  input[8] <<= 4;
  input[9] <<= 6;
#define F(i, s) \
  output[s+0] |=  input[i] & 0xff; \
  output[s+1]  = (input[i] >> 8) & 0xff; \
  output[s+2]  = (input[i] >> 16) & 0xff; \
  output[s+3]  = (input[i] >> 24) & 0xff;
  output[0] = 0;
  output[16] = 0;
  F(0,0);
  F(1,3);
  F(2,6);
  F(3,9);
  F(4,12);
  F(5,16);
  F(6,19);
  F(7,22);
  F(8,25);
  F(9,28);
#undef F
}

/* Input: Q, Q', Q-Q'
 * Output: 2Q, Q+Q'
 *
 *   x2 z3: long form
 *   x3 z3: long form
 *   x z: short form, destroyed
 *   xprime zprime: short form, destroyed
 *   qmqp: short form, preserved
 *
 * On entry and exit, the absolute value of the limbs of all inputs and outputs
 * are < 2^26. */
static void fmonty(limb *x2, limb *z2,  /* output 2Q */
                   limb *x3, limb *z3,  /* output Q + Q' */
                   limb *x, limb *z,    /* input Q */
                   limb *xprime, limb *zprime,  /* input Q' */
                   const limb *qmqp /* input Q - Q' */) {
  limb origx[10], origxprime[10], zzz[19], xx[19], zz[19], xxprime[19],
        zzprime[19], zzzprime[19], xxxprime[19];

  memcpy(origx, x, 10 * sizeof(limb));
  fsum(x, z);
  /* |x[i]| < 2^27 */
  fdifference(z, origx);  /* does x - z */
  /* |z[i]| < 2^27 */

  memcpy(origxprime, xprime, sizeof(limb) * 10);
  fsum(xprime, zprime);
  /* |xprime[i]| < 2^27 */
  fdifference(zprime, origxprime);
  /* |zprime[i]| < 2^27 */
  fproduct(xxprime, xprime, z);
  /* |xxprime[i]| < 14*2^54: the largest product of two limbs will be <
   * 2^(27+27) and fproduct adds together, at most, 14 of those products.
   * (Approximating that to 2^58 doesn't work out.) */
  fproduct(zzprime, x, zprime);
  /* |zzprime[i]| < 14*2^54 */
  freduce_degree(xxprime);
  freduce_coefficients(xxprime);
  /* |xxprime[i]| < 2^26 */
  freduce_degree(zzprime);
  freduce_coefficients(zzprime);
  /* |zzprime[i]| < 2^26 */
  memcpy(origxprime, xxprime, sizeof(limb) * 10);
  fsum(xxprime, zzprime);
  /* |xxprime[i]| < 2^27 */
  fdifference(zzprime, origxprime);
  /* |zzprime[i]| < 2^27 */
  fsquare(xxxprime, xxprime);
  /* |xxxprime[i]| < 2^26 */
  fsquare(zzzprime, zzprime);
  /* |zzzprime[i]| < 2^26 */
  fproduct(zzprime, zzzprime, qmqp);
  /* |zzprime[i]| < 14*2^52 */
  freduce_degree(zzprime);
  freduce_coefficients(zzprime);
  /* |zzprime[i]| < 2^26 */
  memcpy(x3, xxxprime, sizeof(limb) * 10);
  memcpy(z3, zzprime, sizeof(limb) * 10);

  fsquare(xx, x);
  /* |xx[i]| < 2^26 */
  fsquare(zz, z);
  /* |zz[i]| < 2^26 */
  fproduct(x2, xx, zz);
  /* |x2[i]| < 14*2^52 */
  freduce_degree(x2);
  freduce_coefficients(x2);
  /* |x2[i]| < 2^26 */
  fdifference(zz, xx);  // does zz = xx - zz
  /* |zz[i]| < 2^27 */
  memset(zzz + 10, 0, sizeof(limb) * 9);
  fscalar_product(zzz, zz, 121665);
  /* |zzz[i]| < 2^(27+17) */
  /* No need to call freduce_degree here:
     fscalar_product doesn't increase the degree of its input. */
  freduce_coefficients(zzz);
  /* |zzz[i]| < 2^26 */
  fsum(zzz, xx);
  /* |zzz[i]| < 2^27 */
  fproduct(z2, zz, zzz);
  /* |z2[i]| < 14*2^(26+27) */
  freduce_degree(z2);
  freduce_coefficients(z2);
  /* |z2|i| < 2^26 */
}

/* Conditionally swap two reduced-form limb arrays if 'iswap' is 1, but leave
 * them unchanged if 'iswap' is 0.  Runs in data-invariant time to avoid
 * side-channel attacks.
 *
 * NOTE that this function requires that 'iswap' be 1 or 0; other values give
 * wrong results.  Also, the two limb arrays must be in reduced-coefficient,
 * reduced-degree form: the values in a[10..19] or b[10..19] aren't swapped,
 * and all all values in a[0..9],b[0..9] must have magnitude less than
 * INT32_MAX. */
static void
swap_conditional(limb a[19], limb b[19], limb iswap) {
  unsigned i;
  const s32 swap = (s32) -iswap;

  for (i = 0; i < 10; ++i) {
    const s32 x = swap & ( ((s32)a[i]) ^ ((s32)b[i]) );
    a[i] = ((s32)a[i]) ^ x;
    b[i] = ((s32)b[i]) ^ x;
  }
}

/* Calculates nQ where Q is the x-coordinate of a point on the curve
 *
 *   resultx/resultz: the x coordinate of the resulting curve point (short form)
 *   n: a little endian, 32-byte number
 *   q: a point of the curve (short form) */
static void
cmult(limb *resultx, limb *resultz, const u8 *n, const limb *q) {
  limb a[19] = {0}, b[19] = {1}, c[19] = {1}, d[19] = {0};
  limb *nqpqx = a, *nqpqz = b, *nqx = c, *nqz = d, *t;
  limb e[19] = {0}, f[19] = {1}, g[19] = {0}, h[19] = {1};
  limb *nqpqx2 = e, *nqpqz2 = f, *nqx2 = g, *nqz2 = h;

  unsigned i, j;

  memcpy(nqpqx, q, sizeof(limb) * 10);

  for (i = 0; i < 32; ++i) {
    u8 byte = n[31 - i];
    for (j = 0; j < 8; ++j) {
      const limb bit = byte >> 7;

      swap_conditional(nqx, nqpqx, bit);
      swap_conditional(nqz, nqpqz, bit);
      fmonty(nqx2, nqz2,
             nqpqx2, nqpqz2,
             nqx, nqz,
             nqpqx, nqpqz,
             q);
      swap_conditional(nqx2, nqpqx2, bit);
      swap_conditional(nqz2, nqpqz2, bit);

      t = nqx;
      nqx = nqx2;
      nqx2 = t;
      t = nqz;
      nqz = nqz2;
      nqz2 = t;
      t = nqpqx;
      nqpqx = nqpqx2;
      nqpqx2 = t;
      t = nqpqz;
      nqpqz = nqpqz2;
      nqpqz2 = t;

      byte <<= 1;
    }
  }

  memcpy(resultx, nqx, sizeof(limb) * 10);
  memcpy(resultz, nqz, sizeof(limb) * 10);
}

// -----------------------------------------------------------------------------
// Shamelessly copied from djb's code
// -----------------------------------------------------------------------------
static void
crecip(limb *out, const limb *z) {
  limb z2[10];
  limb z9[10];
  limb z11[10];
  limb z2_5_0[10];
  limb z2_10_0[10];
  limb z2_20_0[10];
  limb z2_50_0[10];
  limb z2_100_0[10];
  limb t0[10];
  limb t1[10];
  int i;

  /* 2 */ fsquare(z2,z);
  /* 4 */ fsquare(t1,z2);
  /* 8 */ fsquare(t0,t1);
  /* 9 */ fmul(z9,t0,z);
  /* 11 */ fmul(z11,z9,z2);
  /* 22 */ fsquare(t0,z11);
  /* 2^5 - 2^0 = 31 */ fmul(z2_5_0,t0,z9);

  /* 2^6 - 2^1 */ fsquare(t0,z2_5_0);
  /* 2^7 - 2^2 */ fsquare(t1,t0);
  /* 2^8 - 2^3 */ fsquare(t0,t1);
  /* 2^9 - 2^4 */ fsquare(t1,t0);
  /* 2^10 - 2^5 */ fsquare(t0,t1);
  /* 2^10 - 2^0 */ fmul(z2_10_0,t0,z2_5_0);

  /* 2^11 - 2^1 */ fsquare(t0,z2_10_0);
  /* 2^12 - 2^2 */ fsquare(t1,t0);
  /* 2^20 - 2^10 */ for (i = 2;i < 10;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^20 - 2^0 */ fmul(z2_20_0,t1,z2_10_0);

  /* 2^21 - 2^1 */ fsquare(t0,z2_20_0);
  /* 2^22 - 2^2 */ fsquare(t1,t0);
  /* 2^40 - 2^20 */ for (i = 2;i < 20;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^40 - 2^0 */ fmul(t0,t1,z2_20_0);

  /* 2^41 - 2^1 */ fsquare(t1,t0);
  /* 2^42 - 2^2 */ fsquare(t0,t1);
  /* 2^50 - 2^10 */ for (i = 2;i < 10;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
  /* 2^50 - 2^0 */ fmul(z2_50_0,t0,z2_10_0);

  /* 2^51 - 2^1 */ fsquare(t0,z2_50_0);
  /* 2^52 - 2^2 */ fsquare(t1,t0);
  /* 2^100 - 2^50 */ for (i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^100 - 2^0 */ fmul(z2_100_0,t1,z2_50_0);

  /* 2^101 - 2^1 */ fsquare(t1,z2_100_0);
  /* 2^102 - 2^2 */ fsquare(t0,t1);
  /* 2^200 - 2^100 */ for (i = 2;i < 100;i += 2) { fsquare(t1,t0); fsquare(t0,t1); }
  /* 2^200 - 2^0 */ fmul(t1,t0,z2_100_0);

  /* 2^201 - 2^1 */ fsquare(t0,t1);
  /* 2^202 - 2^2 */ fsquare(t1,t0);
  /* 2^250 - 2^50 */ for (i = 2;i < 50;i += 2) { fsquare(t0,t1); fsquare(t1,t0); }
  /* 2^250 - 2^0 */ fmul(t0,t1,z2_50_0);

  /* 2^251 - 2^1 */ fsquare(t1,t0);
  /* 2^252 - 2^2 */ fsquare(t0,t1);
  /* 2^253 - 2^3 */ fsquare(t1,t0);
  /* 2^254 - 2^4 */ fsquare(t0,t1);
  /* 2^255 - 2^5 */ fsquare(t1,t0);
  /* 2^255 - 21 */ fmul(out,t1,z11);
}

int
curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint) {
  limb bp[10], x[10], z[11], zmone[10];
  uint8_t e[32];
  int i;

  for (i = 0; i < 32; ++i) e[i] = secret[i];
  e[0] &= 248;
  e[31] &= 127;
  e[31] |= 64;

  fexpand(bp, basepoint);
  cmult(x, z, e, bp);
  crecip(zmone, z);
  fmul(z, x, zmone);
  fcontract(mypublic, z);
  return 0;
}

int curve25519(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint){
	return curve25519_donna(mypublic, secret, basepoint);
}

