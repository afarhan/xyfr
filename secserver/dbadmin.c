#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include "wg.h"
#include "db.h"
#include "hal.h"   // hal_rand() — platform CSPRNG (getrandom on Linux)

// Usage:
//   dbadmin activation <n>              add n new activation codes (16 random lowercase letters each)
//   dbadmin activation                  print the next AVAILABLE activation code
//   dbadmin sell <code> <sold_to>       mark an AVAILABLE activation code as SOLD to <sold_to>
//   dbadmin new <hex_key> <code>        register a user with an activation code, expires +365d
//   dbadmin add <hex_key> <yyyy-mm-dd>  admin-add a user with an explicit expiry date (UTC)
//   dbadmin show <partkey>              print the users row for the given partkey
//   dbadmin show all                    dump every users row
//   dbadmin show <hex-prefix>           dump every row whose high bits match (4..7 hex chars)

static void usage(const char *p){
	fprintf(stderr,
		"Usage:\n"
		"  %s activation <n>                  add n random 16-letter activation codes\n"
		"  %s activation                      print the next AVAILABLE activation code\n"
		"  %s sell <code> <sold_to>           mark an activation code as SOLD to <sold_to>\n"
		"  %s new <hex_key> <code>            register user (64-hex public key) with activation code, expires +365d\n"
		"  %s add <hex_key> <yyyy-mm-dd>      admin-add user (64-hex public key) with explicit UTC expiry date\n"
		"  %s show <partkey>                  print user row (8 hex chars, 0xHEX, or decimal)\n"
		"  %s show all                        dump every users row\n"
		"  %s show <prefix>                   dump rows whose high bits match (4..7 hex chars)\n",
		p, p, p, p, p, p, p, p);
}

// Fill out with 16 random lowercase letters plus a terminator.
// Entropy comes from hal_rand() (the kernel CSPRNG) — never unseeded libc
// rand() (threat-model J-1).
static void gen_activation_code(char *out){
	uint8_t buf[16];
	int i;
	for (i = 0; i < 16; i++) buf[i] = (uint8_t)hal_rand();
	for (i = 0; i < 16; i++) out[i] = 'a' + (buf[i] % 26);
	out[16] = '\0';
}

static int cmd_activation(int argc, char **argv){
	if (argc == 2) {
		// no count: print next unused code
		char code[17];
		int r = db_get_next_activation(code);
		if (r == 0) {
			printf("%.4s-%.4s-%.4s-%.4s\n", code, code + 4, code + 8, code + 12);
			return 0;
		}
		if (r == -2) {
			fprintf(stderr, "no unused activation codes\n");
			return 1;
		}
		fprintf(stderr, "db error\n");
		return 1;
	}

	long n = strtol(argv[2], NULL, 10);
	if (n <= 0) {
		fprintf(stderr, "count must be a positive integer\n");
		return 2;
	}

	int added = 0;
	long i;
	for (i = 0; i < n; i++) {
		char code[17];
		gen_activation_code(code);
		if (db_add_activation(code)) {
			printf("%.4s-%.4s-%.4s-%.4s\n", code, code + 4, code + 8, code + 12);
			added++;
		} else {
			// likely a primary-key collision; retry once
			gen_activation_code(code);
			if (db_add_activation(code)) {
				printf("%s\n", code);
				added++;
			} else {
				fprintf(stderr, "failed to insert activation code\n");
			}
		}
	}
	fprintf(stderr, "added %d activation code(s)\n", added);
	return added == n ? 0 : 1;
}

static int is_valid_activation_code(const char *s){
	int i;
	if (strlen(s) != 16) return 0;
	for (i = 0; i < 16; i++) {
		if (!isalnum((unsigned char)s[i])) return 0;
	}
	return 1;
}

static int cmd_sell(int argc, char **argv){
	if (argc != 4) { usage(argv[0]); return 2; }
	const char *code = argv[2];
	const char *sold_to = argv[3];

	if (!is_valid_activation_code(code)) {
		fprintf(stderr, "activation code must be 16 alphanumeric characters\n");
		return 2;
	}
	size_t slen = strlen(sold_to);
	if (slen == 0 || slen > 32) {
		fprintf(stderr, "sold_to must be 1..32 characters\n");
		return 2;
	}

	int r = db_set_activation_request_id(code, sold_to);
	if (r == 0) {
		printf("sold: %s -> %s\n", code, sold_to);
		return 0;
	}
	if (r == -2) {
		fprintf(stderr, "code '%s' is unknown, already sold, or already used\n", code);
		return 4;
	}
	fprintf(stderr, "db_set_activation_request_id failed (code %d)\n", r);
	return 5;
}

// Parse "YYYY-MM-DD" as a UTC midnight timestamp. Returns 0 on success.
static int parse_yyyy_mm_dd(const char *s, time_t *out){
	int yr, mo, dy;
	char extra;
	if (sscanf(s, "%d-%d-%d%c", &yr, &mo, &dy, &extra) != 3) return -1;
	if (yr < 1970 || yr > 2100 || mo < 1 || mo > 12 || dy < 1 || dy > 31) return -1;
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = yr - 1900;
	tm.tm_mon  = mo - 1;
	tm.tm_mday = dy;
	time_t t = timegm(&tm);
	if (t == (time_t)-1) return -1;
	*out = t;
	return 0;
}

static int cmd_new(int argc, char **argv){
	if (argc != 4) { usage(argv[0]); return 2; }
	const char *hex = argv[2];
	const char *code = argv[3];

	if (strlen(hex) != 64) {
		fprintf(stderr, "public_key_hex must be 64 hex characters (32 bytes)\n");
		return 2;
	}
	if (!is_valid_activation_code(code)) {
		fprintf(stderr, "activation code must be 16 alphanumeric characters\n");
		return 2;
	}

	uint8_t key[KEY_LEN];
	hex2bytes(hex, key, strlen(hex));

	time_t expires_on = time(NULL) + 31557600; // +365.25 days

	int r = db_activate_user(key, code, 0, expires_on);
	if (r == 1) {
		uint32_t part_key = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
		                    ((uint32_t)key[2] << 8)  | ((uint32_t)key[3]);
		printf("user added: partkey=%08x expires_on=%lld activation=%s\n",
			part_key, (long long)expires_on, code);
		return 0;
	}
	if (r == 2) {
		fprintf(stderr, "activation code '%s' is unknown\n", code);
		return 4;
	}
	if (r == 0) {
		fprintf(stderr, "activation code '%s' has already been used\n", code);
		return 4;
	}
	fprintf(stderr, "db_activate_user failed (code %d)\n", r);
	return 5;
}

static int cmd_add(int argc, char **argv){
	if (argc != 4) { usage(argv[0]); return 2; }
	const char *hex = argv[2];
	const char *date = argv[3];

	if (strlen(hex) != 64) {
		fprintf(stderr, "public_key_hex must be 64 hex characters (32 bytes)\n");
		return 2;
	}
	time_t expires_on;
	if (parse_yyyy_mm_dd(date, &expires_on) != 0) {
		fprintf(stderr, "expiry must be YYYY-MM-DD (got '%s')\n", date);
		return 2;
	}

	uint8_t key[KEY_LEN];
	hex2bytes(hex, key, strlen(hex));

	int r = db_activate_user(key, NULL, 0, expires_on);
	if (r == 1) {
		uint32_t part_key = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) |
		                    ((uint32_t)key[2] << 8)  | ((uint32_t)key[3]);
		printf("user added: partkey=%08x expires_on=%lld (%s UTC)\n",
			part_key, (long long)expires_on, date);
		return 0;
	}
	fprintf(stderr, "db_activate_user failed (code %d)\n", r);
	return 5;
}

// Parse a partkey string. Accepts:
//   - 8 hex chars (e.g. "deadbeef")
//   - 0x-prefixed hex (e.g. "0xdeadbeef")
//   - decimal
// Returns 0 on success.
static int parse_partkey(const char *s, uint32_t *out){
	if (!s || !*s) return -1;
	size_t len = strlen(s);
	if (len == 8) {
		int all_hex = 1;
		size_t i;
		for (i = 0; i < 8; i++) {
			if (!isxdigit((unsigned char)s[i])) { all_hex = 0; break; }
		}
		if (all_hex) {
			char *end = NULL;
			unsigned long v = strtoul(s, &end, 16);
			if (end && *end == '\0') { *out = (uint32_t)v; return 0; }
		}
	}
	char *end = NULL;
	unsigned long v = strtoul(s, &end, 0);
	if (!end || *end != '\0') return -1;
	*out = (uint32_t)v;
	return 0;
}

// Try to parse argv[2] as a 4..7 character hex prefix (no 0x). Returns
// 0 and fills *prefix / *mask on success; -1 if the string isn't a pure
// hex run of that length (caller falls through to exact-match parsing).
static int parse_hex_prefix(const char *s, uint32_t *prefix, uint32_t *mask){
	size_t len = strlen(s);
	if (len < 4 || len > 7) return -1;
	for (size_t i = 0; i < len; i++)
		if (!isxdigit((unsigned char)s[i])) return -1;
	char *end = NULL;
	unsigned long v = strtoul(s, &end, 16);
	if (!end || *end != '\0') return -1;
	int shift = 32 - 4 * (int)len;
	*prefix = (uint32_t)v << shift;
	*mask   = (0xffffffffu >> shift) << shift;
	return 0;
}

static int cmd_show(int argc, char **argv){
	if (argc != 3) { usage(argv[0]); return 2; }
	const char *arg = argv[2];

	// "all" — dump every users row.
	if (strcmp(arg, "all") == 0) {
		int r = db_show_users_range(0, 0);
		if (r == -2) { fprintf(stderr, "no users\n"); return 4; }
		if (r != 0)  { fprintf(stderr, "db error\n"); return 5; }
		return 0;
	}

	// 4..7 hex chars — high-bit prefix match.
	uint32_t prefix, mask;
	if (parse_hex_prefix(arg, &prefix, &mask) == 0) {
		int r = db_show_users_range(prefix, mask);
		if (r == -2) {
			fprintf(stderr, "no users matching prefix '%s' "
				"(mask=%08x prefix=%08x)\n", arg, mask, prefix);
			return 4;
		}
		if (r != 0) { fprintf(stderr, "db error\n"); return 5; }
		return 0;
	}

	// Exact match: 8 hex chars, 0xHEX, or decimal.
	uint32_t part_key;
	if (parse_partkey(arg, &part_key) != 0) {
		fprintf(stderr, "invalid partkey '%s'\n", arg);
		return 2;
	}
	int r = db_show_user(part_key);
	if (r == -2) {
		fprintf(stderr, "no user with partkey %08x\n", part_key);
		return 4;
	}
	if (r != 0) {
		fprintf(stderr, "db error\n");
		return 5;
	}
	return 0;
}

int main(int argc, char **argv){
	if (argc < 2) { usage(argv[0]); return 2; }

	if (db_init() != 0){
		fprintf(stderr, "db_init failed\n");
		return 3;
	}

	if (strcmp(argv[1], "activation") == 0) return cmd_activation(argc, argv);
	if (strcmp(argv[1], "sell") == 0)       return cmd_sell(argc, argv);
	if (strcmp(argv[1], "new") == 0)        return cmd_new(argc, argv);
	if (strcmp(argv[1], "add") == 0)        return cmd_add(argc, argv);
	if (strcmp(argv[1], "show") == 0)       return cmd_show(argc, argv);

	usage(argv[0]);
	return 2;
}
