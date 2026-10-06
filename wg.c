#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#include "wg.h"
#include "hal.h"   /* hal_rand() — platform CSPRNG (user-authorized one-time exception; see fill_random) */

/* Debug control: set DEBUG to 0 to remove all printf calls in this file */
#ifndef DEBUG
#define DEBUG 0
#endif

#if DEBUG
#define WG_PRINTF(...) printf(__VA_ARGS__)
#else
/* when DEBUG==0, disable printf in this file by defining it away */
#define WG_PRINTF(...) ((void)0)
#define printf(...) ((void)0)
#endif

int curve25519(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
const unsigned char basepoint[KEY_LEN] = {9};
uint32_t next_sender_id = 0;
bool ask_for_mac2 = true;
bool skip_check_mac2 = false;

// For HMAC calculation
#define WIREGUARD_BLAKE2S_BLOCK_SIZE (64)

// 5.4 Messages
// Constants
static const uint8_t CONSTRUCTION[37] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"; // The UTF-8 string literal "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", 37 bytes of output
static const uint8_t IDENTIFIER[34] = "WireGuard v1 zx2c4 Jason@zx2c4.com"; // The UTF-8 string literal "WireGuard v1 zx2c4 Jason@zx2c4.com", 34 bytes of output
static const uint8_t LABEL_MAC1[8] = "mac1----"; // Label-Mac1 The UTF-8 string literal "mac1----", 8 bytes of output.
static const uint8_t LABEL_COOKIE[8] = "cookie--"; // Label-Cookie The UTF-8 string literal "cookie--", 8 bytes of output

static const uint8_t zero_key[KEY_LEN] = { 0 };

// Calculated in wireguard_init
static uint8_t construction_hash[HASH_LEN];
static uint8_t identifier_hash[HASH_LEN];

static uint8_t my_static_public[KEY_LEN];
static uint8_t my_static_private[KEY_LEN];

//a global cookie to challenge the initiators for mac2
//this is reviewed every COOKIE_SECRET_MAX_AGE seconds
static uint8_t device_cookie_secret[HASH_LEN];
static time_t time_device_cookie_expires = 0;
//previous secret, kept one generation so a cookie issued just before a rotation
//still verifies (an initiator attaches mac2 for COOKIE_SECRET_MAX_AGE of its own).
//seeded RANDOM on first use: an all-zero prev would be a key an attacker knows,
//and could forge mac2 against.
static uint8_t device_cookie_secret_prev[HASH_LEN];

void fill_random(uint8_t *buff, int length){
  int i;
	/* hal_rand() is the platform CSPRNG (kernel getrandom on host, hardware RNG
	   on device) — replaces the unseeded libc rand() that made host processes
	   emit identical session_id/key streams (threat-model J-1). User-authorized
	   one-time exception to the wg.c do-not-edit rule. */
	for (i = 0; i < length; i++)
		*buff++ = (uint8_t)hal_rand();
}

void dump_key(const uint8_t *key, int length){
	while(length--)
		printf("%02x", *key++);
	printf("\n");
}

void dump_msg1(const struct msg1 *m1){
	printf(" header:");dump_key((uint8_t *)m1, 4);
	printf(" sender:");dump_key((uint8_t *)&(m1->sender_index), 4);
  printf("session:");dump_key((uint8_t *)&(m1->session_id), 8);
	printf(" ephmrl:");dump_key(m1->ephemeral_key, sizeof(m1->ephemeral_key)); 
	printf(" static:");dump_key(m1->enc_static, sizeof(m1->enc_static));
	printf(" timest:");dump_key(m1->enc_timestamp, sizeof(m1->enc_timestamp));
	printf("   mac1:");dump_key(m1->mac1, sizeof(m1->mac1));
  printf("   mac2:");dump_key(m1->mac2, sizeof(m1->mac2));
}


void dump_msg2(const struct msg2 *m2){
	printf(" header:");dump_key((uint8_t *)m2, 4);
	printf(" sender:");dump_key((uint8_t *)&(m2->sender_index), 4);
  printf("session:");dump_key((uint8_t *)&(m2->session_id), 8);
  printf(" recver:");dump_key((uint8_t *)&(m2->receiver_index), 4);
	printf(" ephmrl:");dump_key(m2->ephemeral_key, sizeof(m2->ephemeral_key)); 
	printf("  empty:");dump_key(m2->enc_empty, sizeof(m2->enc_empty));
	printf("   mac1:");dump_key(m2->mac1, sizeof(m2->mac1));
}

void dump_msg4(const struct msg4 *m4){
	printf(" header:");dump_key((uint8_t *)m4, 4);
	printf(" recver:");dump_key((uint8_t *)&(m4->receiver_index), 4);
  printf("session:");dump_key((uint8_t *)&(m4->session_id), 8);
	printf("counter:");dump_key(m4->counter, sizeof(m4->counter));
	printf("enc_pkt:");dump_key(m4->enc_packet, 32);
}

void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	// Get timestamp. Note that the timestamp must be synced by NTP, 
	//  or at least preserved in NVS, not to go back after reset.
	// Otherwise, the WireGuard remote peer rejects handshake.
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t millis = (tv.tv_sec * 1000LL + (tv.tv_usec / 1000LL));

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
	uint32_t nanos = (millis % 1000) * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

void wireguard_init(uint8_t *static_private) {
	//generate the my static public from the private key
	memcpy(my_static_private, static_private, KEY_LEN);
	curve25519(my_static_public, my_static_private, basepoint);
	printf("my private key:"); dump_key(my_static_private, KEY_LEN);
	printf("my public key :"); dump_key(my_static_public, KEY_LEN);

	blake2s_ctx ctx;
	// Pre-calculate chaining key hash
	blake2s_init(&ctx, HASH_LEN, NULL, 0);
	blake2s_update(&ctx, CONSTRUCTION, sizeof(CONSTRUCTION));
	blake2s_final(&ctx, construction_hash);
	// Pre-calculate initial handshake hash - uses construction_hash calculated above
	blake2s_init(&ctx, HASH_LEN, NULL, 0);
	blake2s_update(&ctx, construction_hash, sizeof(construction_hash));
	blake2s_update(&ctx, IDENTIFIER, sizeof(IDENTIFIER));
	blake2s_final(&ctx, identifier_hash);
}


static void wireguard_mac(uint8_t *dst, const void *message, size_t len, const uint8_t *key, size_t keylen) {
	blake2s(dst, COOKIE_LEN, key, keylen, message, len);
}

static void wireguard_mac_key(uint8_t *key, const uint8_t *public_key, const uint8_t *label, size_t label_len) {
	blake2s_ctx ctx;
	blake2s_init(&ctx, WIREGUARD_SESSION_KEY_LEN, NULL, 0);
	blake2s_update(&ctx, label, label_len);
	blake2s_update(&ctx, public_key, WIREGUARD_PUBLIC_KEY_LEN);
	blake2s_final(&ctx, key);
}

static void wireguard_mix_hash(uint8_t *hash, const uint8_t *src, size_t src_len) {
	blake2s_ctx ctx;
	blake2s_init(&ctx, HASH_LEN, NULL, 0);
	blake2s_update(&ctx, hash, HASH_LEN);
	blake2s_update(&ctx, src, src_len);
	blake2s_final(&ctx, hash);
}

static void wireguard_hmac(uint8_t *digest, const uint8_t *key, size_t key_len, const uint8_t *text, size_t text_len) {
	// Adapted from appendix example in RFC2104 to use BLAKE2S instead of MD5 - https://tools.ietf.org/html/rfc2104
	blake2s_ctx ctx;
	uint8_t k_ipad[WIREGUARD_BLAKE2S_BLOCK_SIZE]; // inner padding - key XORd with ipad
	uint8_t k_opad[WIREGUARD_BLAKE2S_BLOCK_SIZE]; // outer padding - key XORd with opad

	uint8_t tk[HASH_LEN];
	int i;
	// if key is longer than BLAKE2S_BLOCK_SIZE bytes reset it to key=BLAKE2S(key)
	if (key_len > WIREGUARD_BLAKE2S_BLOCK_SIZE) {
		blake2s_ctx tctx;
		blake2s_init(&tctx, HASH_LEN, NULL, 0);
		blake2s_update(&tctx, key, key_len);
		blake2s_final(&tctx, tk);
		key = tk;
		key_len = HASH_LEN;
	}

	// the HMAC transform looks like:
	// HASH(K XOR opad, HASH(K XOR ipad, text))
	// where K is an n byte key
	// ipad is the byte 0x36 repeated BLAKE2S_BLOCK_SIZE times
	// opad is the byte 0x5c repeated BLAKE2S_BLOCK_SIZE times
	// and text is the data being protected
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	// XOR key with ipad and opad values
	for (i=0; i < WIREGUARD_BLAKE2S_BLOCK_SIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	// perform inner HASH
	blake2s_init(&ctx, HASH_LEN, NULL, 0); // init context for 1st pass
	blake2s_update(&ctx, k_ipad, WIREGUARD_BLAKE2S_BLOCK_SIZE); // start with inner pad
	blake2s_update(&ctx, text, text_len); // then text of datagram
	blake2s_final(&ctx, digest); // finish up 1st pass

	// perform outer HASH
	blake2s_init(&ctx, HASH_LEN, NULL, 0); // init context for 2nd pass
	blake2s_update(&ctx, k_opad, WIREGUARD_BLAKE2S_BLOCK_SIZE); // start with outer pad
	blake2s_update(&ctx, digest, HASH_LEN); // then results of 1st hash
	blake2s_final(&ctx, digest); // finish up 2nd pass
}

void wireguard_kdf1(uint8_t *tau1, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
	uint8_t tau0[HASH_LEN];
	uint8_t output[HASH_LEN + 1];

	// tau0 = Hmac(key, input)
	wireguard_hmac(tau0, chaining_key, HASH_LEN, data, data_len);
	// tau1 := Hmac(tau0, 0x1)
	output[0] = 1;
	wireguard_hmac(output, tau0, HASH_LEN, output, 1);
	memcpy(tau1, output, HASH_LEN);

	// Wipe intermediates
	crypto_zero(tau0, sizeof(tau0));
	crypto_zero(output, sizeof(output));
}

static void wireguard_kdf2(uint8_t *tau1, uint8_t *tau2, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
	uint8_t tau0[HASH_LEN];
	uint8_t output[HASH_LEN + 1];

	// tau0 = Hmac(key, input)
	wireguard_hmac(tau0, chaining_key,HASH_LEN, data, data_len);
	// tau1 := Hmac(tau0, 0x1)
	output[0] = 1;
	wireguard_hmac(output, tau0, HASH_LEN, output, 1);
	memcpy(tau1, output, HASH_LEN);

	// tau2 := Hmac(tau0,tau1 || 0x2)
	output[HASH_LEN] = 2;
	wireguard_hmac(output, tau0, HASH_LEN, output, HASH_LEN + 1);
	memcpy(tau2, output, HASH_LEN);

	// Wipe intermediates
	crypto_zero(tau0, sizeof(tau0));
	crypto_zero(output, sizeof(output));
}

static void wireguard_kdf3(uint8_t *tau1, uint8_t *tau2, uint8_t *tau3, const uint8_t *chaining_key, const uint8_t *data, size_t data_len) {
	uint8_t tau0[HASH_LEN];
	uint8_t output[HASH_LEN + 1];

	// tau0 = Hmac(key, input)
	wireguard_hmac(tau0, chaining_key,HASH_LEN, data, data_len);
	// tau1 := Hmac(tau0, 0x1)
	output[0] = 1;
	wireguard_hmac(output, tau0, HASH_LEN, output, 1);
	memcpy(tau1, output, HASH_LEN);

	// tau2 := Hmac(tau0,tau1 || 0x2)
	output[HASH_LEN] = 2;
	wireguard_hmac(output, tau0, HASH_LEN, output, HASH_LEN + 1);
	memcpy(tau2, output, HASH_LEN);

	// tau3 := Hmac(tau0,tau1,tau2 || 0x3)
	output[HASH_LEN] = 3;
	wireguard_hmac(output, tau0, HASH_LEN, output, HASH_LEN + 1);
	memcpy(tau3, output, HASH_LEN);

	// Wipe intermediates
	crypto_zero(tau0, sizeof(tau0));
	crypto_zero(output, sizeof(output));
}
// Anti-replay sliding window over the received AEAD counter (RFC 2401,
// Appendix C), scoped to the current receiving_key. Returns true if `seq`
// is fresh — and records it; false if it is a replay or has fallen out the
// back of the window. The window is empty when replay_bitmap==0 (peer_init
// and every receiving_key re-derivation leave it so), which makes the first
// frame of a keypair — counter 0 included — always accepted and the seed of
// the window. Must be called only after the frame's AEAD tag has verified,
// so the counter it records is authentic. (threat-model J-2)
static bool peer_check_replay(struct peer *p, uint64_t seq) {
	const uint32_t WINDOW = 32;   // bits available in replay_bitmap
	uint32_t diff;

	if (p->replay_bitmap == 0) {
		// nothing seen yet on this key — accept and seed the window
		p->replay_counter = seq;
		p->replay_bitmap  = 1;
		return true;
	}
	if (seq > p->replay_counter) {
		// newer than anything seen — slide the window forward
		diff = (uint32_t)(seq - p->replay_counter);
		if (diff < WINDOW)
			p->replay_bitmap = (p->replay_bitmap << diff) | 1;
		else
			p->replay_bitmap = 1;               // jumped clean past the window
		p->replay_counter = seq;
		return true;
	}
	diff = (uint32_t)(p->replay_counter - seq);
	if (diff >= WINDOW)
		return false;                           // too old — behind the window
	if (p->replay_bitmap & ((uint32_t)1 << diff))
		return false;                           // already seen — replay
	p->replay_bitmap |= ((uint32_t)1 << diff);  // in-window, out of order, fresh
	return true;
}

//derive a cookie from a given secret (no rotation)
static void derive_peer_cookie(uint8_t *cookie, const uint8_t *secret, uint8_t *source_addr_port, size_t source_length) {
	blake2s_ctx ctx;

	// Mac(key, input) Keyed-Blake2s(key, input, 16), the keyed MAC variant of the BLAKE2s hash function, returning 16 bytes of output
	blake2s_init(&ctx, COOKIE_LEN, secret, HASH_LEN);
	// 5.4.7 Under Load: Cookie Reply Message
	// Mix in the IP address and port - have the IP layer pass this in as byte array to avoid using Lwip specific APIs in this module
	if ((source_addr_port) && (source_length > 0)) {
		blake2s_update(&ctx, source_addr_port, source_length);
	}
	blake2s_final(&ctx, cookie);
}

//cookie functions used to throttle the incoming requests
static void generate_peer_cookie(uint8_t *cookie, uint8_t *source_addr_port, size_t source_length) {
	if (get_current_time_seconds() > time_device_cookie_expires) {
		//retire the outgoing secret one generation; on the very first call there is
		//none, so seed prev random rather than leave it a known all-zero key
		if (time_device_cookie_expires != 0)
			memcpy(device_cookie_secret_prev, device_cookie_secret, HASH_LEN);
		else
			fill_random(device_cookie_secret_prev, HASH_LEN);
		// Generate new random bytes
    fill_random(device_cookie_secret, HASH_LEN);
	  time_device_cookie_expires =  get_current_time_seconds() + COOKIE_SECRET_MAX_AGE;
	}

	derive_peer_cookie(cookie, device_cookie_secret, source_addr_port, source_length);
}

void peer_create_cookie_reply(struct msg3 *m, uint8_t *key, const uint8_t *mac1, uint32_t index, uint64_t session_id, 
	uint8_t *source_addr_port, size_t source_length) {
	uint8_t cookie[COOKIE_LEN];
  uint8_t label_cookie_key[KEY_LEN];

	crypto_zero(m, sizeof(struct msg3));
	m->msg_type = 3;
	m->receiver_index = index;
	m->session_id = session_id;
  fill_random(m->nonce, COOKIE_NONCE_LEN);
  
	generate_peer_cookie(cookie, source_addr_port, source_length);
  printf("generated cookie: "); dump_key(cookie, COOKIE_LEN);
	wireguard_mac_key(label_cookie_key, key, LABEL_COOKIE, sizeof(LABEL_COOKIE));
 
	wireguard_xaead_encrypt(m->enc_cookie, cookie, COOKIE_LEN, mac1, COOKIE_LEN, m->nonce, label_cookie_key);
}

bool check_mac2(const uint8_t *data, size_t len, uint8_t *source_addr_port, size_t source_length, const uint8_t *mac2) {
	bool result = false;
	uint8_t cookie[COOKIE_LEN];
	uint8_t calculated[COOKIE_LEN];

  if (skip_check_mac2)
    return true;
  
	generate_peer_cookie(cookie, source_addr_port, source_length);
  printf("check_mac2 generated cookie: "); dump_key(cookie, COOKIE_LEN);

	wireguard_mac(calculated, data, len, cookie, COOKIE_LEN);
	if (crypto_equal(calculated, mac2, COOKIE_LEN)) {
		result = true;
	}
	//accept the previous generation too: a cookie issued just before a rotation
	if (!result) {
		derive_peer_cookie(cookie, device_cookie_secret_prev, source_addr_port, source_length);
		wireguard_mac(calculated, data, len, cookie, COOKIE_LEN);
		if (crypto_equal(calculated, mac2, COOKIE_LEN)) {
			result = true;
		}
	}
	return result;
}

void peer_refresh_ephemeral(struct peer *p){
	memcpy(p->prev_ephemeral_private, p->ephemeral_private, KEY_LEN);
	memcpy(p->prev_ephemeral_public, p->ephemeral_public, KEY_LEN);
	fill_random(p->ephemeral_private, KEY_LEN);
	curve25519(p->ephemeral_public, p->ephemeral_private, basepoint);
}

void peer_handshake_request_generate(struct peer *p, uint8_t msg_type, const uint8_t *remote_static_public, uint64_t session_id, struct msg1 *m){
	uint8_t hash[HASH_LEN];
	uint8_t key[KEY_LEN];
	uint8_t shared_ss[KEY_LEN];
	uint8_t shared_es[KEY_LEN];
	uint8_t timestamp[TAI64N_LEN];
	uint8_t label_mac1_key[KEY_LEN];
  uint8_t new_session_id[8];

	//generate your own ephemeral key pair
	crypto_zero(m, sizeof(struct msg1));
	m->msg_type = msg_type;
	m->sender_index = get_part_key(remote_static_public); 
	fill_random(p->ephemeral_private, KEY_LEN);
  fill_random(new_session_id, sizeof(new_session_id));
  m->session_id = session_id;
  p->session_id = session_id;
	curve25519(p->ephemeral_public, p->ephemeral_private, basepoint);
	memcpy(p->remote_static_public, remote_static_public, KEY_LEN);

	//generate the es shared key
	curve25519(shared_es, p->ephemeral_private, remote_static_public);
	memcpy(m->ephemeral_key, p->ephemeral_public, KEY_LEN);

	memcpy(p->chaining_key, construction_hash, HASH_LEN); //Ci:= Hash(Construction) (precalculated hash)
	wireguard_kdf1(p->chaining_key, p->chaining_key, m->ephemeral_key, KEY_LEN); // Ci := Kdf1(Ci, Epubi)
	wireguard_kdf2(p->chaining_key, key, p->chaining_key, shared_es, KEY_LEN);

	memcpy(hash, identifier_hash, HASH_LEN); // Hi := Hash(Ci || Identifier
	wireguard_mix_hash(hash, remote_static_public, KEY_LEN); // Hi := Hash(Hi || Spubr)
	wireguard_mix_hash(hash, m->ephemeral_key, WIREGUARD_PUBLIC_KEY_LEN);//Hi:=Hash(Hi||msg.ephmrl)
																																			 
	wireguard_aead_encrypt(m->enc_static, my_static_public, KEY_LEN, hash, HASH_LEN, 0, key); 
	wireguard_mix_hash(hash, m->enc_static, sizeof(m->enc_static));

	//printf("Req hash:");dump_key(hash, KEY_LEN);
	// (Ci,k) := Kdf2(Ci,DH(Sprivi,Spubr))
	// note DH(Sprivi,Spubr) is precomputed per peer
	//generate the ss shared key
	curve25519(shared_ss, my_static_private, remote_static_public);
	wireguard_kdf2(p->chaining_key, key, p->chaining_key, shared_ss, KEY_LEN);

	// msg.timestamp := AEAD(k, 0, Timestamp(), Hi)
	wireguard_tai64n_now(timestamp);
	printf("time is : "); dump_key(timestamp, sizeof(timestamp));
	wireguard_aead_encrypt(m->enc_timestamp, timestamp, TAI64N_LEN, hash, HASH_LEN, 0, key);

	// Hi := Hash(Hi || msg.timestamp)
	wireguard_mix_hash(hash, m->enc_timestamp, sizeof(m->enc_timestamp));

	wireguard_mac_key(label_mac1_key, p->remote_static_public, LABEL_MAC1, sizeof(LABEL_MAC1));
	wireguard_mac(m->mac1, m, sizeof(struct msg1)-(2*COOKIE_LEN), label_mac1_key, KEY_LEN);
	memcpy(p->hash, hash, HASH_LEN);

  //
  if (p->cookie_date  + COOKIE_SECRET_MAX_AGE < get_current_time_seconds()){
    crypto_zero(m->mac2, COOKIE_LEN);
    printf("skipping mac2 cookie - no valid cookie\n");
  } else {
    // msg.mac2 := Mac(Lm, msgB)
    wireguard_mac(m->mac2, m, (sizeof(struct msg1)-(COOKIE_LEN)), p->cookie, COOKIE_LEN);
    printf("added mac2 cookie to request:"); dump_key(m->mac2, COOKIE_LEN);
  }
 
	printf("chaining key %d ", __LINE__);dump_key(p->chaining_key, KEY_LEN);
	p->is_initiator = true;
  //store the mac1 in case we are challanged by a cookie, it is needed to validate the cookie reply
  memcpy(p->handshake_mac1, m->mac1, COOKIE_LEN);
  p->handshake_mac1_valid = true;
	crypto_zero(hash, HASH_LEN);
	crypto_zero(key, KEY_LEN);
	crypto_zero(timestamp,TAI64N_LEN);
	crypto_zero(label_mac1_key, KEY_LEN);
	dump_msg1(m);
}

bool peer_cookie_process(struct peer *peer, const struct msg3 *src) {
	uint8_t cookie[COOKIE_LEN];
  uint8_t label_cookie_key[KEY_LEN];
  
	bool result = false;

	if (peer->handshake_mac1_valid) {
    wireguard_mac_key(label_cookie_key, peer->remote_static_public, LABEL_COOKIE, sizeof(LABEL_COOKIE));
		result = wireguard_xaead_decrypt(cookie, src->enc_cookie, sizeof(src->enc_cookie), 
      peer->handshake_mac1, COOKIE_LEN, src->nonce, label_cookie_key);

		if (result) {
			// 5.4.7 Under Load: Cookie Reply Message
			// Upon receiving this message, if it is valid, the only thing the recipient of this message should do is store the cookie along with the time at which it was received
      printf("valid cookie received:");
			memcpy(peer->cookie, cookie, COOKIE_LEN);
      dump_key(peer->cookie, COOKIE_LEN);
			peer->cookie_date = get_current_time_seconds();
			peer->handshake_mac1_valid = false;
		}
	} else {
    printf("cookie reply invalid - no valid mac1 stored\n");
		// We didn't send any initiation packet so we shouldn't be getting a cookie reply!
	}
	return result;
}

// Extract the remote static public key from a msg1 without touching peer state.
// Used when we need the public key before the user is known to the DB (activation).
// Performs only the AEAD-decrypt of enc_static; mac1/mac2 are NOT validated here.
// Returns 0 on success, REQUEST_AUTH_FAILED if the AEAD tag does not verify.
int peer_handshake_extract_static(const struct msg1 *m1, uint8_t *out_static_public){
  uint8_t hash[HASH_LEN];
  uint8_t key[KEY_LEN];
  uint8_t shared_es[KEY_LEN];
  uint8_t chaining_key[KEY_LEN];
  int status = 0;

  curve25519(shared_es, my_static_private, m1->ephemeral_key);

  memcpy(chaining_key, construction_hash, HASH_LEN);
  wireguard_kdf1(chaining_key, chaining_key, m1->ephemeral_key, KEY_LEN);
  wireguard_kdf2(chaining_key, key, chaining_key, shared_es, KEY_LEN);

  memcpy(hash, identifier_hash, HASH_LEN);
  wireguard_mix_hash(hash, my_static_public, KEY_LEN);
  wireguard_mix_hash(hash, m1->ephemeral_key, WIREGUARD_PUBLIC_KEY_LEN);

  if(!wireguard_aead_decrypt(out_static_public, m1->enc_static, KEY_LEN + AUTHTAG_LEN, hash, HASH_LEN, 0, key)){
    status = REQUEST_AUTH_FAILED;
  }

  crypto_zero(hash, HASH_LEN);
  crypto_zero(key, KEY_LEN);
  crypto_zero(shared_es, KEY_LEN);
  crypto_zero(chaining_key, KEY_LEN);
  return status;
}

int peer_handshake_request_process(struct peer *p, const struct msg1 *m1, uint8_t *source_addr_port, size_t source_length, void *ctx){
	uint8_t hash[HASH_LEN];
	uint8_t key[KEY_LEN];
	uint8_t mac1[COOKIE_LEN];
	uint8_t label_mac1_key[COOKIE_LEN];
	uint8_t dh[KEY_LEN];
	uint8_t shared_ss[KEY_LEN];
	uint8_t shared_es[KEY_LEN];
	uint8_t chaining_key[KEY_LEN];
	uint8_t remote_static_public[KEY_LEN];
  int status = 0;

  // if the mac2 is zero, and the cookie is required, reject the request
  if(!memcmp(m1->mac2, zero_key, COOKIE_LEN)){
    if (ask_for_mac2) 
      return REQUEST_MAC2_REQUIRED;
    //if the cookie is not required, continue processing
    printf("mac2 cookie not present - continue processing\n");
  }
  //mac2 is present
  else{
    if (check_mac2((const uint8_t *)m1, sizeof(struct msg1)-COOKIE_LEN, source_addr_port, source_length, m1->mac2) == false) {
      printf("mac2 cookie mismatched - reply to our challenge\n");
      return -1;
    }
    printf("mac2 cookie matched\n");
  }

	wireguard_mac_key(label_mac1_key, my_static_public, LABEL_MAC1, sizeof(LABEL_MAC1));
	wireguard_mac(mac1, m1, sizeof(struct msg1)-(2*COOKIE_LEN), label_mac1_key, KEY_LEN);

	//printf("recalculated mac1:"); dump_key(mac1, COOKIE_LEN);
	if (!crypto_equal(mac1, m1->mac1, COOKIE_LEN)){   // constant-time compare (M-4)
		printf("FAIL! mac1 mismatched, invalid request\n");
    status = -2;
		goto clearup;
	}

	curve25519(shared_es, my_static_private, m1->ephemeral_key);

	memcpy(chaining_key, construction_hash, HASH_LEN); //Ci:= Hash(Construction) (precalculated hash)
	wireguard_kdf1(chaining_key, chaining_key, m1->ephemeral_key, KEY_LEN); // Ci := Kdf1(Ci, Epubi)
	wireguard_kdf2(chaining_key, key, chaining_key, shared_es, KEY_LEN);

	memcpy(hash, identifier_hash, HASH_LEN); // Hi := Hash(Ci || Identifier
	wireguard_mix_hash(hash, my_static_public, KEY_LEN); // Hi := Hash(Hi || Spubr)
	wireguard_mix_hash(hash, m1->ephemeral_key, WIREGUARD_PUBLIC_KEY_LEN);//Hi:=Hash(Hi||msg.ephmrl)

	// drop the unauthenticated packets
	if(!wireguard_aead_decrypt(remote_static_public, m1->enc_static, 48, hash, HASH_LEN, 0, key)){
		printf("FAIL! Request authentication failed\n");
    status = -3;
		goto clearup;
	}

  if (!validate_public_key(remote_static_public, ctx)){
    printf("FAIL! invalid public key in request\n");
    status = -4;
		goto clearup;
  }
	wireguard_mix_hash(hash, m1->enc_static, sizeof(m1->enc_static));
	curve25519(shared_ss, my_static_private, remote_static_public);
	wireguard_kdf2(chaining_key, key, chaining_key, shared_ss, KEY_LEN);

	uint8_t timestamp[TAI64N_LEN];
	if(!wireguard_aead_decrypt(timestamp, m1->enc_timestamp, sizeof(m1->enc_timestamp), hash, HASH_LEN, 0, key)){
		printf("FAIL! timestamp authentication failed\n");
	  status = -5;
		goto clearup;
	}
  //check the timestamp to avoid replay attacks TBD

	wireguard_mix_hash(hash, m1->enc_timestamp, sizeof(m1->enc_timestamp));

	//TBD : get a peer struct allocated
  crypto_zero(p, sizeof(struct peer));
	p->is_initiator = 0;
	memcpy(p->remote_static_public, remote_static_public, KEY_LEN);
	printf("remote_static_public ");dump_key(p->remote_static_public, KEY_LEN);
	memcpy(p->remote_ephemeral_public, m1->ephemeral_key, KEY_LEN);
	memcpy(p->hash, hash, HASH_LEN);
	memcpy(p->chaining_key, chaining_key, HASH_LEN); //Ci:= Hash(Construction) (precalculated hash)
	p->remote_index = m1->sender_index;
  p->session_id = m1->session_id;

clearup:
	crypto_zero(hash, HASH_LEN);
	crypto_zero(key, KEY_LEN);
	crypto_zero(mac1, COOKIE_LEN);
	crypto_zero(label_mac1_key, COOKIE_LEN);
	crypto_zero(dh, KEY_LEN);
	crypto_zero(chaining_key, KEY_LEN);
	crypto_zero(remote_static_public, KEY_LEN);

	return status;
}

//assumes that the request was authetnicated and proper
int peer_response_generate(struct peer *p, struct msg2 *m2){
	uint8_t tau[HASH_LEN];
	uint8_t hash[HASH_LEN];
	uint8_t chaining_key[KEY_LEN];
	uint8_t ephemeral_private[KEY_LEN], dh[KEY_LEN], key[KEY_LEN];

	if (p->is_initiator)
		return -1;

	memcpy(hash, p->hash, HASH_LEN);
	memcpy(chaining_key, p->chaining_key, KEY_LEN);

	crypto_zero(m2, sizeof(struct msg2));
	crypto_zero(tau, sizeof(tau));
	
	//generate the ephemeral key pair
	fill_random(ephemeral_private, KEY_LEN);
	curve25519(m2->ephemeral_key, ephemeral_private, basepoint);
	if (!memcmp(m2->ephemeral_key, zero_key, KEY_LEN))
		return -2;
	//1. Cr += kdf1(Cr, Epubr)
	//1. Hr = Hash(Hr || msg.ephemeral)
//	printf("chaining key %d ", __LINE__);dump_key(p->chaining_key, KEY_LEN);
	wireguard_kdf1(chaining_key, chaining_key, m2->ephemeral_key, KEY_LEN);
	wireguard_mix_hash(hash, m2->ephemeral_key, KEY_LEN);

	//2. Cr := KDF1(Cr, DH(Eprivr, Epubi))
	curve25519(dh, ephemeral_private, p->remote_ephemeral_public);
	if (!memcmp(dh, zero_key, KEY_LEN))
		return -3;
	wireguard_kdf1(chaining_key, chaining_key, dh, KEY_LEN);
//	printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

  //3: Cr := KDF1(Cr, DH(Eprivr, Spubi))
	curve25519(dh, ephemeral_private, p->remote_static_public);
	if (!memcmp(dh, zero_key, KEY_LEN))
		return -4;
	wireguard_kdf1(chaining_key, chaining_key, dh, KEY_LEN);
//	printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

  //4. (Cr, tau, k) := Kdf3(Cr, 0)
  printf("preshared key:"); dump_key(p->preshared_key, KEY_LEN);
  wireguard_kdf3(chaining_key, tau, key, chaining_key, p->preshared_key, KEY_LEN);
//	printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

  //Hr := Hash(Hr | t)
	wireguard_mix_hash(hash, tau, HASH_LEN);
	//msg.empty := AEAD(k,0,E,Hr)
	//printf("encrypting enc_empty with: \n"); dump_key(key, KEY_LEN);
  printf("aead_encrypt:"); dump_key(hash, HASH_LEN);
  printf("aead key:"); dump_key(key, KEY_LEN);
	wireguard_aead_encrypt(m2->enc_empty, NULL, 0,  hash, HASH_LEN, 0, key);
	wireguard_mix_hash(hash, m2->enc_empty, sizeof(m2->enc_empty));

	//finish the other mandatory fields before generating the mac1
	m2->msg_type = 2;
	m2->sender_index = get_part_key(p->remote_static_public); 
	m2->receiver_index = p->remote_index;
  m2->session_id = p->session_id;

	uint8_t label_mac1_key[COOKIE_LEN];
	wireguard_mac_key(label_mac1_key, my_static_public, LABEL_MAC1, sizeof(LABEL_MAC1));
	wireguard_mac(m2->mac1, m2, sizeof(struct msg2) - (2*COOKIE_LEN), label_mac1_key, KEY_LEN); 
	//MSG2 is ready to be sent now
	memcpy(p->hash, hash, HASH_LEN);
	memcpy(p->chaining_key, chaining_key, KEY_LEN); 
	//printf("chaining key %d ", __LINE__);dump_key(p->chaining_key, KEY_LEN);

	//generate the sending/receving keys
	if (p->is_initiator)
		wireguard_kdf2(p->sending_key, p->receiving_key, p->chaining_key, NULL, 0);
	else
		wireguard_kdf2(p->receiving_key, p->sending_key, p->chaining_key, NULL, 0);

  printf("sending_key:"); dump_key(p->sending_key, KEY_LEN);
  printf("receiving_key:"); dump_key(p->receiving_key, KEY_LEN);

	p->sending_counter = 0;
	p->replay_counter = 0; p->replay_bitmap = 0;   // fresh receive window for the new key (J-2)
	crypto_zero(tau, HASH_LEN);
	crypto_zero(hash, HASH_LEN);
	crypto_zero(chaining_key, KEY_LEN);
	crypto_zero(ephemeral_private, KEY_LEN);
	crypto_zero(dh, KEY_LEN);
	crypto_zero(key, KEY_LEN);
	return 0;
}

int peer_response_process(struct peer *p, struct msg2 *m2){
	uint8_t tau[HASH_LEN], hash[HASH_LEN];
	uint8_t chaining_key[HASH_LEN];
	uint8_t ephemeral_private[KEY_LEN], dh[KEY_LEN], key[KEY_LEN], preshared_key[KEY_LEN];
	uint8_t label_mac1_key[COOKIE_LEN];
	uint8_t mac1[COOKIE_LEN];

	if (!p->is_initiator)
			return -1;
	crypto_zero(tau, sizeof(tau));

  if (p->session_id != m2->session_id){
    printf("FAIL! session id mismatch\n");
    return -2;
  }
	//check that the mac1 is proper
	wireguard_mac_key(label_mac1_key, p->remote_static_public, LABEL_MAC1, sizeof(LABEL_MAC1));
	wireguard_mac(mac1, m2, sizeof(struct msg2)-(2*COOKIE_LEN), label_mac1_key, KEY_LEN);
	if (!crypto_equal(mac1, m2->mac1, COOKIE_LEN)){   // constant-time compare (M-4)
		printf("FAIL! mac1 mismatched, invalid request\n");
		return -3;
	}

	memcpy(hash, p->hash, HASH_LEN);
	memcpy(chaining_key, p->chaining_key, KEY_LEN);
//	printf("chaining key %d ", __LINE__);dump_key(p->chaining_key, KEY_LEN);

  memcpy(ephemeral_private, p->ephemeral_private, KEY_LEN);
	memcpy(preshared_key, p->preshared_key, KEY_LEN);
	//1. Cr += kdf1(Cr, Epubr)
	//1. Hr = Hash(Hr || msg.ephemeral)
	wireguard_kdf1(chaining_key, chaining_key, m2->ephemeral_key, KEY_LEN);
//  printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);
  wireguard_mix_hash(hash, m2->ephemeral_key, KEY_LEN);

//  printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

	//2. Cr := KDF1(Cr, DH(Eprivr, Epubi))
	curve25519(dh, ephemeral_private, m2->ephemeral_key);
	if (!memcmp(dh, zero_key, KEY_LEN))
		return -4;
//  printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

  wireguard_kdf1(chaining_key, chaining_key, dh, KEY_LEN);
	//3. Cr := KDF1(Cr, DH(Sprivi, Epubr))
	//curve25519(dh, ephemeral_private, p->remote_static_public);
	curve25519(dh, my_static_private, m2->ephemeral_key);
	if(!memcmp(dh, zero_key, KEY_LEN))return -5;
	wireguard_kdf1(chaining_key, chaining_key, dh, KEY_LEN);
//  printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);

	//4. (Cr,tau, k) := kdf3(Cr, 0)
//  printf("preshared key:"); dump_key(p->preshared_key, KEY_LEN);
	wireguard_kdf3(chaining_key, tau, key, chaining_key, p->preshared_key, KEY_LEN);
//  printf("chaining key %d ", __LINE__);dump_key(chaining_key, KEY_LEN);
  wireguard_mix_hash(hash, tau, HASH_LEN);
	//printf("encrypting enc_empty with: \n"); dump_key(key, KEY_LEN);
  printf("aead_decrypt:"); dump_key(hash, HASH_LEN);
  printf("aead key:"); dump_key(key, KEY_LEN);

  if (!wireguard_aead_decrypt(NULL, m2->enc_empty, sizeof(m2->enc_empty), hash, HASH_LEN, 0, key)){
		printf("BAD KEY!!!!!!!!!!!!\n");
		return -5;
	}
	wireguard_mix_hash(hash, m2->enc_empty, sizeof(m2->enc_empty));

	memcpy(p->chaining_key, chaining_key, KEY_LEN);
	memcpy(p->hash, hash, HASH_LEN);
	p->remote_index = m2->sender_index;
	if (p->is_initiator)
		wireguard_kdf2(p->sending_key, p->receiving_key, p->chaining_key, NULL, 0);
	else
		wireguard_kdf2(p->receiving_key, p->sending_key, p->chaining_key, NULL, 0);

  printf("sending_key:"); dump_key(p->sending_key, KEY_LEN);
  printf("receiving_key:"); dump_key(p->receiving_key, KEY_LEN);

	crypto_zero(tau, HASH_LEN);
	crypto_zero(hash, HASH_LEN);
	crypto_zero(chaining_key, HASH_LEN);
	crypto_zero(ephemeral_private, KEY_LEN); 
	crypto_zero(dh,KEY_LEN);
	crypto_zero(key, KEY_LEN);
	crypto_zero(preshared_key, KEY_LEN);
	crypto_zero(label_mac1_key, COOKIE_LEN);
	crypto_zero(mac1, COOKIE_LEN);
	p->sending_counter = 0;
	p->replay_counter = 0; p->replay_bitmap = 0;   // fresh receive window for the new key (J-2)
	return 0;
}

int tx_data(struct msg4 *m4, struct peer *dst, uint8_t *data, size_t length){
	if (length >= MAX_PACKET_SIZE - sizeof(struct msg4) - AUTHTAG_LEN)
		return -1;

  if (length % 32 != 0)
    return -2; // enforce 32 byte alignment of the encrypted payload to mitigate some side channel attacks
	m4->msg_type = 4;
	m4->receiver_index = dst->remote_index;
  m4->session_id = dst->session_id;
	U64TO8_LITTLE(m4->counter, dst->sending_counter);
	printf("using encryption key:\n");dump_key(dst->sending_key, 10);
	wireguard_aead_encrypt(m4->enc_packet, data, length, NULL, 0, 
			dst->sending_counter, dst->sending_key);
	dst->sending_counter++;
	return sizeof(struct msg4) + length + AUTHTAG_LEN;
}

int rx_data(uint8_t *buff_out, struct peer *src, const struct msg4 *m4, size_t msg4_length){
	uint64_t nonce;
	/* Reject a short msg4 before the length subtraction below underflows
	   size_t into a multi-GB ciphertext length (threat-model M-1). */
	if (msg4_length < sizeof(struct msg4) + AUTHTAG_LEN)
		return -1;
	nonce = U8TO64_LITTLE(m4->counter);
	printf("using decryption key:\n");dump_key(src->receiving_key, 10);
	int r = wireguard_aead_decrypt(buff_out, m4->enc_packet, msg4_length - sizeof(struct msg4), NULL, 0, nonce, src->receiving_key);
  if (r == false)
    return -1;
  // Frame is authentic (AEAD verified) — reject counter replays (J-2).
  if (!peer_check_replay(src, nonce))
    return -3;
  return msg4_length - sizeof(struct msg4) - AUTHTAG_LEN;
}

void dump_peer(struct peer *p){
	printf("own static private:\n  ");
	dump_key(my_static_private, KEY_LEN);
	printf("own static public:\n  ");
	dump_key(my_static_public, KEY_LEN);
	
	printf("own ephemeral private:\n  ");
	dump_key(p->ephemeral_private, KEY_LEN);
	printf("own ephemeral public:\n  ");
	dump_key(p->ephemeral_public, KEY_LEN);
	
	printf("hash  val:\n   ");
	dump_key(p->hash, KEY_LEN);
	printf("chaining key:\n   ");
	dump_key(p->chaining_key, KEY_LEN);
	printf("tx key:\n   ");
	dump_key(p->sending_key, KEY_LEN);
	printf("rx key:\n   ");
	dump_key(p->receiving_key, KEY_LEN);

}

void peer_init(struct peer *p){
	crypto_zero(p, sizeof(struct peer));
	p->my_next_index = 786;
}

void wireguard_ask_mac2(bool ask){
  ask_for_mac2 = ask;
}

void wireguard_skip_mac2_check(bool skip){
  skip_check_mac2 = skip;
}

void wireguard_my_static_public(uint8_t *public_key){
  memcpy(public_key, my_static_public, KEY_LEN);
} 

uint32_t get_part_key(const uint8_t *key){
    return ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | ((uint32_t)key[3]);
}

uint64_t get_fresh_sessionid(){
  uint64_t session_id;
  fill_random((uint8_t *)&session_id, sizeof(session_id));
  return session_id;
}

// === Anonymous userid->pubkey lookup (msg7 / msg8) =========================
//
// Single-DH AEAD. Layered on top of the wg-shaped header so relay.c can
// route msg7/msg8 by session_id without parsing the payload.
//
//   K = HKDF(blake2s("ltp/contact/v1"),
//            DH(client_eph_priv, server_static_pub))
//   nonce_request  = 0   (client -> server)
//   nonce_response = 1   (server -> client)
//
// mac2 cookie POW gating is enforced at the relay (mirroring
// on_msg1_to_server). mac1 is verified at the server / client.

static const uint8_t QUERY_INFO[14] = "ltp/contact/v1";

static void derive_query_key(const uint8_t *dh_out, uint8_t *out_K) {
  uint8_t info_hash[HASH_LEN];
  blake2s(info_hash, HASH_LEN, NULL, 0, QUERY_INFO, sizeof(QUERY_INFO));
  wireguard_kdf1(out_K, info_hash, dh_out, KEY_LEN);
  crypto_zero(info_hash, HASH_LEN);
}

void peer_query_generate(struct query *q,
                         uint8_t  msg_type,
                         uint64_t session_id,
                         uint32_t sender_index,
                         const uint8_t *payload,
                         size_t  payload_len,
                         void   *out_msg) {
  uint8_t label_mac1_key[KEY_LEN];

  if (msg_type == MSG_CONTACT_REQUEST) {
    struct msg_contact_request *m = (struct msg_contact_request *)out_msg;
    crypto_zero(m, sizeof(*m));
    m->msg_type     = MSG_CONTACT_REQUEST;
    m->session_id   = session_id;
    m->sender_index = sender_index;

    // Fresh ephemeral keypair for this query.
    fill_random(q->ephemeral_private, KEY_LEN);
    curve25519(q->ephemeral_public, q->ephemeral_private, basepoint);
    memcpy(m->ephemeral_public, q->ephemeral_public, KEY_LEN);

    // K = HKDF(info, DH(eph_priv, server_static_pub))
    uint8_t dh[KEY_LEN];
    curve25519(dh, q->ephemeral_private, q->peer.remote_static_public);
    derive_query_key(dh, q->shared_secret);
    crypto_zero(dh, KEY_LEN);

    // Encrypt payload (partkey, 4 bytes) under K, nonce=0.
    wireguard_aead_encrypt(m->enc_query, payload, payload_len,
                           NULL, 0, 0, q->shared_secret);

    // mac1 over [0..68) using the server's static pub as the mac1 key
    // — this is what relay.c also sees and what the server validates.
    wireguard_mac_key(label_mac1_key, q->peer.remote_static_public,
                      LABEL_MAC1, sizeof(LABEL_MAC1));
    wireguard_mac(m->mac1, m,
                  sizeof(struct msg_contact_request) - (2 * COOKIE_LEN),
                  label_mac1_key, KEY_LEN);

    // mac2: zero on the first send. If the relay later issues a cookie
    // (msg3), peer_cookie_process stores it on q->peer; the regenerate
    // hook in request_table will call us again and we'll fold it in.
    if (q->peer.cookie_date + COOKIE_SECRET_MAX_AGE
        < get_current_time_seconds()) {
      crypto_zero(m->mac2, COOKIE_LEN);
    } else {
      wireguard_mac(m->mac2, m,
                    sizeof(struct msg_contact_request) - COOKIE_LEN,
                    q->peer.cookie, COOKIE_LEN);
    }

    // Stash mac1 so peer_cookie_process can validate the cookie reply.
    memcpy(q->peer.handshake_mac1, m->mac1, COOKIE_LEN);
    q->peer.handshake_mac1_valid = true;
    q->session_id = session_id;
  } else if (msg_type == MSG_CONTACT_RESPONSE) {
    struct msg_contact_response *m = (struct msg_contact_response *)out_msg;
    crypto_zero(m, sizeof(*m));
    m->msg_type       = MSG_CONTACT_RESPONSE;
    m->session_id     = session_id;
    m->sender_index   = sender_index;
    m->receiver_index = 0;

    // Encrypt the response (status||pubkey, 33 bytes) under the K we
    // already derived from msg7, nonce=1.
    wireguard_aead_encrypt(m->enc_response, payload, payload_len,
                           NULL, 0, 1, q->shared_secret);

    // mac1 over [0..69) using my own static pub (server side).
    wireguard_mac_key(label_mac1_key, my_static_public,
                      LABEL_MAC1, sizeof(LABEL_MAC1));
    wireguard_mac(m->mac1, m,
                  sizeof(struct msg_contact_response) - COOKIE_LEN,
                  label_mac1_key, KEY_LEN);
  }

  crypto_zero(label_mac1_key, KEY_LEN);
}

int peer_query_process(struct query *q,
                       const void *msg,
                       size_t  msg_len,
                       const uint8_t *source_address,
                       size_t  address_length,
                       uint8_t *out_payload,
                       size_t *out_payload_len) {
  uint8_t label_mac1_key[KEY_LEN];
  uint8_t mac_calc[COOKIE_LEN];
  int rc = REQUEST_AUTH_FAILED;

  (void)source_address;
  (void)address_length;

  const uint8_t *type = (const uint8_t *)msg;
  if (msg_len < 1) return REQUEST_MAC1_INVALID;

  if (*type == MSG_CONTACT_REQUEST) {
    if (msg_len < sizeof(struct msg_contact_request))
      return REQUEST_MAC1_INVALID;
    const struct msg_contact_request *m = (const struct msg_contact_request *)msg;

    // mac1 verified against my own static pub (server).
    wireguard_mac_key(label_mac1_key, my_static_public,
                      LABEL_MAC1, sizeof(LABEL_MAC1));
    wireguard_mac(mac_calc, m,
                  sizeof(struct msg_contact_request) - (2 * COOKIE_LEN),
                  label_mac1_key, KEY_LEN);
    if (!crypto_equal(mac_calc, m->mac1, COOKIE_LEN)) {
      rc = REQUEST_MAC1_INVALID;
      goto out;
    }

    // Recover K from DH(my_static_priv, m->ephemeral_public).
    memcpy(q->ephemeral_public, m->ephemeral_public, KEY_LEN);
    uint8_t dh[KEY_LEN];
    curve25519(dh, my_static_private, q->ephemeral_public);
    derive_query_key(dh, q->shared_secret);
    crypto_zero(dh, KEY_LEN);

    // Decrypt the 4-byte partkey under nonce=0.
    if (!wireguard_aead_decrypt(out_payload, m->enc_query,
                                sizeof(m->enc_query),
                                NULL, 0, 0, q->shared_secret)) {
      rc = REQUEST_AUTH_FAILED;
      goto out;
    }
    if (out_payload_len) *out_payload_len = QUERY_REQUEST_PAYLOAD_LEN;
    q->session_id = m->session_id;
    rc = REQUEST_SUCCESS;
  } else if (*type == MSG_CONTACT_RESPONSE) {
    if (msg_len < sizeof(struct msg_contact_response))
      return REQUEST_MAC1_INVALID;
    const struct msg_contact_response *m = (const struct msg_contact_response *)msg;

    // mac1 verified against the server's static pub (client side).
    wireguard_mac_key(label_mac1_key, q->peer.remote_static_public,
                      LABEL_MAC1, sizeof(LABEL_MAC1));
    wireguard_mac(mac_calc, m,
                  sizeof(struct msg_contact_response) - COOKIE_LEN,
                  label_mac1_key, KEY_LEN);
    if (!crypto_equal(mac_calc, m->mac1, COOKIE_LEN)) {
      rc = REQUEST_MAC1_INVALID;
      goto out;
    }

    // Decrypt under K already derived in peer_query_generate(msg7),
    // nonce=1.
    if (!wireguard_aead_decrypt(out_payload, m->enc_response,
                                sizeof(m->enc_response),
                                NULL, 0, 1, q->shared_secret)) {
      rc = REQUEST_AUTH_FAILED;
      goto out;
    }
    if (out_payload_len) *out_payload_len = QUERY_RESPONSE_PAYLOAD_LEN;
    rc = REQUEST_SUCCESS;
  } else {
    rc = REQUEST_MAC1_INVALID;
  }

out:
  crypto_zero(label_mac1_key, KEY_LEN);
  crypto_zero(mac_calc, COOKIE_LEN);
  return rc;
}
