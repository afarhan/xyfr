#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define KEY_LEN 32
#define AUTHTAG_LEN 16

#define PUBLIC_PORT 43210
void crypto_zero(void *data, size_t length);
bool wireguard_base64_decode(const char *str, uint8_t *out, size_t *outlen);
bool wireguard_base64_encode(const uint8_t *in, size_t inlen, char *out, size_t *outlen); 
// Taken from RFC7693 - https://tools.ietf.org/html/rfc7693
// BLAKE2s Hashing Context and API Prototypes

#define BLAKE2S_BLOCK_SIZE 64

// state context
typedef struct {
    uint8_t b[64];                      // input buffer
    uint32_t h[8];                      // chained state
    uint32_t t[2];                      // total number of bytes
    size_t c;                           // pointer for b[]
    size_t outlen;                      // digest size
} blake2s_ctx;

// Initialize the hashing context "ctx" with optional key "key".
//      1 <= outlen <= 32 gives the digest size in bytes.
//      Secret key (also <= 32 bytes) is optional (keylen = 0).
int blake2s_init(blake2s_ctx *ctx, size_t outlen,
    const void *key, size_t keylen);    // secret key

// Add "inlen" bytes from "in" into the hash.
void blake2s_update(blake2s_ctx *ctx,   // context
    const void *in, size_t inlen);      // data to be hashed

// Generate the message digest (size given in init).
//      Result placed in "out".
void blake2s_final(blake2s_ctx *ctx, void *out);

// All-in-one convenience function.
int blake2s(void *out, size_t outlen,   // return buffer for digest
    const void *key, size_t keylen,     // optional secret key
    const void *in, size_t inlen);      // data to be hashed


void chacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key);
bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, uint64_t nonce, const uint8_t *key);

// Xaead(key, nonce, plain text, auth text) XChaCha20Poly1305 AEAD, with a 24-byte random nonce, instantiated using HChaCha20 [6] and ChaCha20Poly1305.
// AEAD_XChaCha20_Poly1305 as described in https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
void xchacha20poly1305_encrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key);
bool xchacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, size_t src_len, const uint8_t *ad, size_t ad_len, const uint8_t *nonce, const uint8_t *key);
// X25519 IMPLEMENTATION
//#include "crypto/refc/x25519.h"
#define wireguard_x25519(a,b,c)	x25519(a,b,c,1)


// CHACHA20POLY1305 IMPLEMENTATION
//#include "crypto/refc/chacha20poly1305.h"
#define wireguard_aead_encrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_aead_decrypt(dst,src,srclen,ad,adlen,nonce,key) chacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_encrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_encrypt(dst,src,srclen,ad,adlen,nonce,key)
#define wireguard_xaead_decrypt(dst,src,srclen,ad,adlen,nonce,key) xchacha20poly1305_decrypt(dst,src,srclen,ad,adlen,nonce,key)

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

struct chacha20_ctx {
	uint32_t state[16];
};

// tai64n contains 64-bit seconds and 32-bit nano offset (12 bytes)
#define TAI64N_LEN		(12)
// Auth algorithm is chacha20pol1305 which is 128bit (16 byte) authenticator
#define WIREGUARD_AUTHTAG_LEN		(16)
// Hash algorithm is blake2s which makes 32 byte hashes
#define HASH_LEN			(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PUBLIC_KEY_LEN	(32)
// Public key algo is curve22519 which uses 32 byte keys
#define WIREGUARD_PRIVATE_KEY_LEN	(32)
// Symmetric session keys are chacha20/poly1305 which uses 32 byte keys
#define WIREGUARD_SESSION_KEY_LEN	(32)
#define MAX_PACKET_SIZE 1200


#define COOKIE_LEN		(16)
#define COOKIE_SECRET_MAX_AGE		(2 * 60)
#define COOKIE_NONCE_LEN			(24)

// Timers / Limits
#define REKEY_AFTER_MESSAGES		(1ULL << 60)
#define REJECT_AFTER_MESSAGES		(0xFFFFFFFFFFFFFFFFULL - (1ULL << 13))
#define REKEY_AFTER_TIME			(120)
#define REJECT_AFTER_TIME			(180)
#define REKEY_TIMEOUT				(5)
#define KEEPALIVE_TIMEOUT			(10)

#define MSG_REQUEST_CONNECT    (1)
#define MSG_RESPONSE_CONNECT   (2)
#define MSG_COOKIE_REPLY       (3)
#define MSG_DATA               (4)
#define MSG_REQUEST_ACTIVATE   (5)
#define MSG_ACTIVATION_FAILED  (6)
#define MSG_CONTACT_REQUEST    (7)
#define MSG_CONTACT_RESPONSE   (8)

// Anonymous userid -> pubkey lookup payload sizes.
#define QUERY_REQUEST_PAYLOAD_LEN  4    // partkey (BE)
#define QUERY_RESPONSE_PAYLOAD_LEN (1 + KEY_LEN + 4 + 2)   // status || pubkey || relay_ip4 || relay_port

#define ACTIVATION_REASON_UNKNOWN_CODE    1
#define ACTIVATION_REASON_CODE_USED       2
#define ACTIVATION_REASON_USER_EXISTS     3
#define ACTIVATION_REASON_INTERNAL        4

#pragma pack(push, 1)

struct msg4{
	uint8_t msg_type;
	uint8_t reserved[3];
  uint64_t session_id;
  uint32_t receiver_index;
	uint8_t counter[8];
	uint8_t enc_packet[];
};

struct msg1 {
	uint8_t msg_type;
	uint8_t reserved[3];
  uint64_t session_id;
	uint32_t sender_index;
	uint8_t ephemeral_key[KEY_LEN];
	uint8_t enc_static[KEY_LEN+AUTHTAG_LEN];
	uint8_t enc_timestamp[TAI64N_LEN+AUTHTAG_LEN];
	uint8_t mac1[COOKIE_LEN];
	uint8_t mac2[COOKIE_LEN];
};

struct msg3 {
  uint8_t msg_type;
  uint8_t reserved[3];
  uint64_t session_id;
  uint32_t receiver_index;
  uint8_t nonce[COOKIE_NONCE_LEN];
	uint8_t enc_cookie[COOKIE_LEN+AUTHTAG_LEN];
};

struct msg2 {
	uint8_t msg_type;
	uint8_t reserved[3];
  uint64_t session_id;
	uint32_t sender_index;
	uint32_t receiver_index;
	uint8_t ephemeral_key[KEY_LEN];
	uint8_t enc_empty[0+AUTHTAG_LEN];
	uint8_t mac1[COOKIE_LEN];
	uint8_t mac2[COOKIE_LEN];
};

struct msg_activation_failed {
  uint8_t  msg_type;          // = MSG_ACTIVATION_FAILED
  uint8_t  reason;            // ACTIVATION_REASON_*
  uint8_t  reserved[2];
  uint64_t session_id;        // echoed from msg1.session_id so client can correlate
  uint32_t receiver_index;    // echoed from msg1.sender_index
};

// Anonymous userid->pubkey lookup. First 16 bytes layout-identical to
// msg1 so relay.c can route by session_id (offset 4) without touching
// payload. Single-DH AEAD: K = HKDF(DH(client_eph_priv, server_static_pub)).
struct msg_contact_request {
  uint8_t  msg_type;                       // = MSG_CONTACT_REQUEST   off 0
  uint8_t  reserved[3];                    //                          off 1
  uint64_t session_id;                     //                          off 4
  uint32_t sender_index;                   // = server_partkey         off 12
  uint8_t  ephemeral_public[KEY_LEN];      // 32                       off 16
  uint8_t  enc_query[QUERY_REQUEST_PAYLOAD_LEN + AUTHTAG_LEN];   // 20  off 48
  uint8_t  mac1[COOKIE_LEN];               // 16                       off 68
  uint8_t  mac2[COOKIE_LEN];               // 16                       off 84
};   // total: 100 bytes

// First 20 bytes layout-identical to msg2 so relay.c routes the reply
// by session_id back to the client_endpoint.
struct msg_contact_response {
  uint8_t  msg_type;                       // = MSG_CONTACT_RESPONSE   off 0
  uint8_t  reserved[3];                    //                          off 1
  uint64_t session_id;                     // echoes request           off 4
  uint32_t sender_index;                   // = server_partkey         off 12
  uint32_t receiver_index;                 // = 0                      off 16
  uint8_t  enc_response[QUERY_RESPONSE_PAYLOAD_LEN + AUTHTAG_LEN]; // 55 off 20
  uint8_t  mac1[COOKIE_LEN];               // 16                       off 75
};   // total: 91 bytes (still <= msg7's 100; anti-amplification preserved)

#pragma pack(pop)

struct peer {
  bool is_initiator;

  uint8_t ephemeral_private[KEY_LEN];
	uint8_t ephemeral_public[KEY_LEN];

	uint8_t prev_ephemeral_private[KEY_LEN];
	uint8_t prev_ephemeral_public[KEY_LEN];

	uint8_t remote_static_public[KEY_LEN];
	uint8_t remote_ephemeral_public[KEY_LEN];

	uint8_t initiator_hash[KEY_LEN];
	uint8_t chaining_key[KEY_LEN];
	uint8_t hash[HASH_LEN];

	uint32_t remote_index;
	uint32_t my_next_index;
	
  uint8_t preshared_key[KEY_LEN];

  // cookie from the responder to challenge the initiator for mac
  uint8_t handshake_mac1[COOKIE_LEN];
  bool handshake_mac1_valid;
  uint8_t cookie[COOKIE_LEN];
  time_t cookie_date;

  uint64_t session_id;
  uint64_t sending_counter;
	uint8_t sending_key[KEY_LEN];
	uint8_t receiving_key[KEY_LEN];

  // Anti-replay over the received AEAD counter (m4->counter), scoped to the
  // current receiving_key. The window is empty when replay_bitmap==0; it is
  // reset to empty wherever receiving_key is (re)derived, so a rekey's
  // counter-restart is not mistaken for a replay. (threat-model J-2)
  uint64_t replay_counter;
  uint32_t replay_bitmap;

  uint32_t src_ip;
  uint16_t src_port;
};

// Per-lookup state for the anonymous userid->pubkey protocol. Borrows
// peer's identity / cookie state but keeps query-specific ephemerals +
// derived shared secret in its own struct so login and the lookup can
// run side-by-side without clobbering each other's keys.
struct request;   // forward decl; defined in requests.h
struct query {
  struct peer peer;                       // server's identity + cookie state
  uint8_t  ephemeral_private[KEY_LEN];    // fresh per request (client side)
  uint8_t  ephemeral_public[KEY_LEN];     // copied from msg7 on the server
  uint8_t  shared_secret[KEY_LEN];        // K = HKDF(DH(...))

  // Pump-side bookkeeping (not used inside wg.c functions).
  uint64_t session_id;
  uint32_t partkey;
  struct request *req;
};

extern const unsigned char basepoint[];
int curve25519(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);
void wireguard_init(uint8_t *my_static_private);
void wireguard_my_static_public(uint8_t *my_static_public);
void wireguard_ask_mac2(bool ask);
void wireguard_skip_mac2_check(bool skip);
bool check_mac2(const uint8_t *data, size_t len, uint8_t *source_addr_port, size_t source_length, const uint8_t *mac2);
void dump_key(const uint8_t *key, int length);
void peer_init(struct peer *p);
void peer_handshake_request_generate(struct peer *p, uint8_t msg_type, const uint8_t *remote_static_public, uint64_t session_id, struct msg1 *m);
int peer_handshake_request_process(struct peer *p, const struct msg1 *m1, uint8_t *source_address, size_t address_length, void *ctx);
int peer_handshake_extract_static(const struct msg1 *m1, uint8_t *out_static_public);
void peer_create_cookie_reply(struct msg3 *m, uint8_t *key, const uint8_t *mac1, uint32_t index, uint64_t session_id,
	uint8_t *source_addr_port, size_t source_length);
bool peer_cookie_process(struct peer *p, const struct msg3 *m3);
// ctx: opaque per-call cookie threaded from peer_handshake_request_process to
// this admission callback (NULL where the caller has no context). Lets the app
// branch admission policy per call — e.g. a server accepting a DIRECT relay
// login vs a client login TUNNELED through a relay — without a shared global.
int validate_public_key(const uint8_t *public_key, void *ctx);
int tx_data(struct msg4 *m4, struct peer *dst, uint8_t *buff_in, size_t data_length);
int rx_data(uint8_t *data_out, struct peer *src, const struct msg4 *m4, size_t msg4_length);

struct peer *get_peer_by_index(uint32_t index);
struct peer *get_peer_by_public_key(const uint8_t *public_key);
struct peer *get_peer_by_addrport(uint8_t *addrport, size_t length);
uint32_t get_part_key(const uint8_t *key);

int peer_response_generate(struct peer *p, struct msg2 *m2);
int peer_response_process(struct peer *p, struct msg2 *m2);
uint64_t get_fresh_sessionid();

// Anonymous userid->pubkey lookup. msg_type = MSG_CONTACT_REQUEST builds
// msg7 (out_msg = struct msg_contact_request *). msg_type =
// MSG_CONTACT_RESPONSE builds msg8 (out_msg = struct msg_contact_response *).
// Generating the request derives a fresh ephemeral keypair into q->ephemeral_*
// and stashes K into q->shared_secret; generating the response uses the K
// already populated by an earlier peer_query_process(msg7) on this side.
// mac2 is left zero on msg7 — relay.c issues a cookie reply and the
// request_table regenerate hook calls back here on retry.
void peer_query_generate(struct query *q,
                         uint8_t  msg_type,
                         uint64_t session_id,
                         uint32_t sender_index,
                         const uint8_t *payload,
                         size_t  payload_len,
                         void   *out_msg);

// Inverse of peer_query_generate. msg7 (server side) writes 4 bytes of
// partkey to out_payload; msg8 (client side) writes 39 bytes of
// status||pubkey||relay_endpoint. mac2 is NOT verified for msg7 — that's
// the relay's job. source_address / address_length are accepted for
// parity with peer_handshake_request_process; v1 leaves cookie work to
// the relay and these can be NULL/0.
int peer_query_process(struct query *q,
                       const void *msg,
                       size_t  msg_len,
                       const uint8_t *source_address,
                       size_t  address_length,
                       uint8_t *out_payload,
                       size_t *out_payload_len);

#define REQUEST_SUCCESS			(0)
#define REQUEST_MAC2_MISMATCH 		(-1)
#define REQUEST_MAC2_REQUIRED	(-100)
#define REQUEST_MAC1_INVALID	(-2)
#define REQUEST_AUTH_FAILED  (-3)
#define REQUEST_INVALID_KEY  (-4)
#define REQUEST_INVALID_TIMESTAMP (-5)


//implement these as per your own implemenatation 
//returns 1 if the user is allowed to connect, else zero
extern int validate_user(uint8_t *remote_user_key);
void fill_random(uint8_t *buff, int length);
time_t get_current_time_seconds();


void key2wl(const uint8_t *key, int keylen, char *output, int maxlen);

#ifdef __cplusplus
}
#endif
