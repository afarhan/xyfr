struct user{
	uint8_t public_key[KEY_LEN];
	time_t expires_on;
	uint32_t	src_ip;
	uint16_t src_port;
	uint8_t hash[HASH_LEN];
	uint8_t chaining_key[KEY_LEN];
};

// activation.status state machine
#define ACTIVATION_AVAILABLE 0  // minted, not sold, not used
#define ACTIVATION_SOLD      1  // claimed for a customer; still activatable
#define ACTIVATION_USED      2  // consumed by db_activate_user

void hex2bytes(const char *src, uint8_t *dest, size_t src_len);
void bytes2hex(uint8_t *src, size_t src_len, char *hex);
int db_init();
bool db_get_user(struct user *p,  uint8_t *partial_key);
int db_activate_user(uint8_t *user_key, const char *activation_code, uint64_t session_id, time_t expires_on);

// Cheap pre-DH gate on the activation path (indexed PK lookup). Returns
// 1 = valid (unused, or used within the retransmit window), 2 = used (spent),
// 0 = unknown, -1 = error. See db.c.
int db_code_valid(const char *activation_code);
bool db_add_activation(char *activation);
int db_get_next_activation(char *out);
int db_set_activation_request_id(const char *code, const char *request_id);
int db_show_user(uint32_t part_key);

// Print every users row where (partkey & mask) == prefix. Pass mask=0 to
// dump all rows. Returns 0 on success, -1 on db error, -2 if no row matched.
int db_show_users_range(uint32_t prefix, uint32_t mask);
int db_update_user(uint8_t *key, uint32_t ip4, uint16_t port);
int db_validate_user(const uint8_t *key);
bool db_get_pubkey_by_partkey(uint32_t partkey, uint8_t out[KEY_LEN]);

// Like db_get_pubkey_by_partkey, but also returns the relay endpoint
// (= users.src_ip / users.src_port — written by db_update_user on every
// authenticated handshake, so it reflects the relay the user last logged
// in from). out_ip4 / out_port are zeroed on miss.
bool db_get_endpoint_by_partkey(uint32_t partkey,
                                uint8_t  out_pubkey[KEY_LEN],
                                uint32_t *out_ip4,
                                uint16_t *out_port);
