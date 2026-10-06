// SQLite3 backend for the user / activation tables. The DB lives in a
// single file (./ltp.db) opened with WAL journaling so multiple worker
// threads can share readers freely while one writer at a time commits.
//
// Concurrency model:
//   - One sqlite3 * connection per thread, stashed in pthread-local
//     storage (the same shape that the previous MySQL backend used).
//   - Each thread calls db_init() once at startup. pthread_once
//     guarantees the TLS key is created exactly once, regardless of
//     how many threads land here at the same moment.
//   - Every prepared statement is cached lazily on the first call from
//     each thread and lives for the lifetime of the process. There is
//     no finalize path — these handles are tiny and the connection
//     outlives them anyway.
//
// Schema is bootstrapped (CREATE TABLE IF NOT EXISTS) on every
// connection open, so a fresh DB file works without `sqlite3 ltp.db < init_db.sql`.

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <sqlite3.h>
#include "wg.h"
#include "db.h"

#define DB_PATH "ltp.db"

static pthread_key_t     pthread_key;
static pthread_once_t    db_key_once = PTHREAD_ONCE_INIT;

// Per-thread DB state. Holds the connection plus prepared-statement
// handles for every distinct query so they aren't re-parsed per call.
struct db_state {
	sqlite3 *conn;
	sqlite3_stmt *update_user_stmt;        // db_update_user (HOT)
	sqlite3_stmt *validate_user_stmt;      // db_validate_user (HOT)
	sqlite3_stmt *get_user_stmt;
	sqlite3_stmt *count_users_stmt;        // db_activate_user existence check
	sqlite3_stmt *insert_user_stmt;        // db_activate_user new-user insert
	sqlite3_stmt *update_expiry_stmt;      // db_activate_user stacking update
	sqlite3_stmt *check_idempotent_stmt;   // db_activate_user retransmit window
	sqlite3_stmt *check_activation_stmt;   // db_activate_user code-state check
	sqlite3_stmt *code_valid_stmt;        // db_code_valid cheap pre-DH gate
	sqlite3_stmt *mark_used_stmt;          // db_activate_user mark USED
	sqlite3_stmt *add_activation_stmt;
	sqlite3_stmt *next_activation_stmt;
	sqlite3_stmt *mark_sold_stmt;          // db_set_activation_request_id
	sqlite3_stmt *show_user_stmt;
	sqlite3_stmt *get_pubkey_stmt;         // db_get_pubkey_by_partkey
	sqlite3_stmt *get_endpoint_stmt;       // db_get_endpoint_by_partkey
};

// ---- hex helpers (unchanged from the MySQL backend; exported via db.h) ----

int hex_char_to_int(char c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

void hex2bytes(const char *src, uint8_t *dest, size_t src_len) {
	size_t i;
	for (i = 0; i < src_len; i += 2) {
		int high_nibble = hex_char_to_int(src[i]);
		int low_nibble  = hex_char_to_int(src[i + 1]);
		if (high_nibble == -1 || low_nibble == -1) {
			fprintf(stderr, "Invalid hex character found\n");
			return;
		}
		dest[i / 2] = (uint8_t)((high_nibble << 4) | low_nibble);
	}
}

void bytes2hex(uint8_t *src, size_t src_len, char *hex) {
	const char h[] = "0123456789ABCDEF";
	while (src_len--) {
		int lower  = *src & 0x0f;
		int higher = (*src & 0xf0) >> 4;
		*hex++ = h[higher];
		*hex++ = h[lower];
		src++;
	}
	*hex = 0;
}

// ---- internal helpers ----

static void make_pthread_key(void) {
	pthread_key_create(&pthread_key, NULL);
}

static struct db_state *db_state(void) {
	return (struct db_state *)pthread_getspecific(pthread_key);
}

static sqlite3_stmt *prep(sqlite3 *db, const char *sql) {
	sqlite3_stmt *stmt;
	if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
		printf("sqlite prepare failed: %s\n  query: %s\n",
			sqlite3_errmsg(db), sql);
		return NULL;
	}
	return stmt;
}

static uint32_t partkey_from_key(const uint8_t *k) {
	return ((uint32_t)k[0] << 24) | ((uint32_t)k[1] << 16) |
	       ((uint32_t)k[2] <<  8) |  (uint32_t)k[3];
}

// ---- init ----

int db_init() {
	pthread_once(&db_key_once, make_pthread_key);

	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(DB_PATH, &db,
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (rc != SQLITE_OK) {
		printf("**sqlite3_open_v2(%s) failed: %s\n",
			DB_PATH, db ? sqlite3_errmsg(db) : "out of memory");
		if (db) sqlite3_close(db);
		return -1;
	}

	// 5s busy timeout so concurrent writers retry instead of erroring.
	sqlite3_busy_timeout(db, 5000);

	// PLAIN ROLLBACK JOURNAL, not WAL. WAL buys concurrent readers alongside one
	// writer, which this workload does not need — the server is single-threaded
	// over one connection and dbadmin runs for milliseconds — and it costs a
	// second and third file (-wal, -shm) carrying lock state ACROSS restarts.
	// Setting DELETE here converts a WAL database ONLY when this is the sole open
	// connection. With a second writer attached the switch is refused, the pragma
	// still reports success, and the database silently stays in WAL — which is why
	// the mode is read back below.
	//
	// synchronous=FULL, not NORMAL: NORMAL is only safe in WAL mode, where a
	// commit is durable at the next checkpoint. Under a rollback journal it can
	// lose the last transactions on power loss, and this table is the record of
	// who may use the network.
	char *err = NULL;
	if (sqlite3_exec(db,
		"PRAGMA journal_mode=DELETE;"
		"PRAGMA synchronous=FULL;"
		"PRAGMA temp_store=MEMORY;",
		NULL, NULL, &err) != SQLITE_OK) {
		printf("**sqlite pragmas failed: %s\n", err ? err : "(unknown)");
		sqlite3_free(err);
		sqlite3_close(db);
		return -2;
	}

	// journal_mode reports the mode it ENDED UP IN as a result row; it does not
	// error when the switch is refused, so sqlite3_exec above returns SQLITE_OK
	// even when the database stays in WAL. Read it back or never find out.
	sqlite3_stmt *jm = NULL;
	if (sqlite3_prepare_v2(db, "PRAGMA journal_mode;", -1, &jm, NULL) == SQLITE_OK
	    && sqlite3_step(jm) == SQLITE_ROW) {
		const char *mode = (const char *)sqlite3_column_text(jm, 0);
		if (mode && sqlite3_stricmp(mode, "delete") != 0)
			printf("**sqlite journal_mode is '%s', not 'delete' -- another "
			       "connection holds %s; stop every writer and reopen\n", mode, DB_PATH);
	}
	sqlite3_finalize(jm);

	// schema bootstrap — idempotent on subsequent opens.
	const char *schema =
		"CREATE TABLE IF NOT EXISTS users ("
		"  partkey INTEGER PRIMARY KEY,"
		"  id INTEGER,"
		"  public_key BLOB NOT NULL,"
		"  src_ip INTEGER,"
		"  src_port INTEGER,"
		"  expires_on INTEGER NOT NULL DEFAULT 0"
		");"
		"CREATE TABLE IF NOT EXISTS activation ("
		"  activation_code TEXT NOT NULL PRIMARY KEY,"
		"  request_id TEXT,"
		"  status INTEGER DEFAULT 0,"
		"  updated_at INTEGER NOT NULL DEFAULT 0,"
		"  recharge_amount INTEGER"
		");";
	if (sqlite3_exec(db, schema, NULL, NULL, &err) != SQLITE_OK) {
		printf("**schema bootstrap failed: %s\n", err ? err : "(unknown)");
		sqlite3_free(err);
		sqlite3_close(db);
		return -3;
	}

	struct db_state *s = calloc(1, sizeof(*s));
	if (!s) {
		printf("**db_state alloc failed\n");
		sqlite3_close(db);
		return -4;
	}
	s->conn = db;
	pthread_setspecific(pthread_key, s);
	puts("sqlite3 ready");
	return 0;
}

// ---- queries ----

bool db_get_user(struct user *p, uint8_t *partial_key) {
	if (!p || !partial_key) return false;
	struct db_state *s = db_state();
	if (!s || !s->conn) return false;

	if (!s->get_user_stmt) {
		s->get_user_stmt = prep(s->conn,
			"SELECT public_key, src_ip, src_port, expires_on "
			"FROM users WHERE partkey = ? LIMIT 1");
		if (!s->get_user_stmt) return false;
	}
	sqlite3_stmt *st = s->get_user_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)partkey_from_key(partial_key));

	if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_reset(st); return false; }

	memset(p, 0, sizeof(*p));
	int len = sqlite3_column_bytes(st, 0);
	const void *blob = sqlite3_column_blob(st, 0);
	if (blob && len > 0) {
		size_t copy_len = (size_t)len < KEY_LEN ? (size_t)len : KEY_LEN;
		memcpy(p->public_key, blob, copy_len);
	}
	p->src_ip     = (uint32_t)sqlite3_column_int64(st, 1);
	p->src_port   = (uint16_t)sqlite3_column_int(st, 2);
	p->expires_on = (time_t)  sqlite3_column_int64(st, 3);
	sqlite3_reset(st);   // release the read snapshot before returning (see db_code_valid)
	return true;
}

// Insert or extend a user, optionally consuming an activation code.
//
//   user_key        — 32-byte public key (partkey is its first 4 bytes, big-endian).
//   activation_code — if non-NULL, the row in `activation` must exist with
//                     status IN (AVAILABLE, SOLD); it gets marked USED on success.
//                     Pass NULL for admin-driven adds that bypass the activation
//                     table entirely.
//   session_id      — 64-bit random id from the originating msg1. Stored as the
//                     retransmit token. We DO NOT record the activator's
//                     identity in the activation row — that would link a user
//                     to a specific code, a privacy regression. session_id is
//                     opaque random and rotates per client session. Pass 0
//                     from admin paths; the retransmit check is then disabled.
//   expires_on      — target unix-epoch expiry. New rows get this value; existing
//                     rows get a stacked +1y if still valid (matches MySQL behavior).
//
// Returns 1 on success, 0 if activation_code exists but is already used, 2 if
// activation_code is unknown (no such row), -1..-6 on internal errors.

#define ACTIVATION_RETRANSMIT_WINDOW_SECONDS 60

// db_code_valid — is this code activatable RIGHT NOW, decided cheaply (one
// indexed primary-key probe) BEFORE the server runs the Curve25519 DH?
//
// This is the pre-DH gate for the activation path (THREAT_MODEL M-5 / J-7). The
// code sits in the msg1 mac2 field in the clear, so we can grade it with a
// single B-tree lookup instead of a scalar-mult. Critically it rejects a SPENT
// code before the DH: a USED code grants no DH, so an attacker who obtained one
// valid code (bought, or sniffed off the network) cannot REPLAY it to burn CPU --
// each code is worth exactly one DH and is consumed by that activation, which is
// the outcome we WANT (a spent code is a paid sale). Only an unused code can
// ever reach the DH.
//
// The one exception is the retransmit window: the firmware re-sends the SAME
// activation msg1 (same code) when the msg2 reply is lost (regen_activation), so
// a code marked USED moments ago is a legitimate retry, not a replay. Such a
// code stays VALID for ACTIVATION_RETRANSMIT_WINDOW_SECONDS so the retry reaches
// the DH and db_activate_user's idempotency check completes it. Past that window
// a USED code is spent for good -- matching the authoritative grading in
// db_activate_user, and bounding any attacker replay to that same short window.
//
// Returns: 1 valid (AVAILABLE/SOLD, or USED within the retransmit window),
//          2 used (USED and past the window -- spent / a replay),
//          0 unknown (no such code), -1 internal error.
int db_code_valid(const char *activation_code) {
	struct db_state *s = db_state();
	if (!s || !s->conn || !activation_code) return -1;
	if (!s->code_valid_stmt) {
		s->code_valid_stmt = prep(s->conn,
			"SELECT status, updated_at FROM activation WHERE activation_code=?");
		if (!s->code_valid_stmt) return -1;
	}
	sqlite3_stmt *st = s->code_valid_stmt;
	sqlite3_reset(st);
	sqlite3_bind_text(st, 1, activation_code, -1, SQLITE_STATIC);
	int step = sqlite3_step(st);
	if (step == SQLITE_DONE) { sqlite3_reset(st); return 0; }  // no such code -> unknown
	if (step != SQLITE_ROW)  { sqlite3_reset(st); return -1; }
	int          status  = sqlite3_column_int(st, 0);
	sqlite3_int64 updated = sqlite3_column_int64(st, 1);
	// Release the read snapshot NOW: a lingering stepped SELECT keeps a WAL read
	// transaction open, so the connection's NEXT write must upgrade a stale snapshot
	// -> SQLITE_BUSY_SNAPSHOT ("database is locked", NOT retried by the busy-timeout).
	sqlite3_reset(st);
	if (status == ACTIVATION_AVAILABLE || status == ACTIVATION_SOLD)
		return 1;                           // unused -> activatable
	if (status == ACTIVATION_USED) {
		sqlite3_int64 cutoff = (sqlite3_int64)time(NULL) -
			ACTIVATION_RETRANSMIT_WINDOW_SECONDS;
		if (updated > cutoff) return 1;     // just used -> a lost-reply retry
	}
	return 2;                                   // spent / replay -> no DH
}

int db_activate_user(uint8_t *user_key, const char *activation_code,
                     uint64_t session_id, time_t expires_on) {
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;

	uint32_t part_key = partkey_from_key(user_key);
	char session_hex[17];
	snprintf(session_hex, sizeof(session_hex),
		"%016llx", (unsigned long long)session_id);

	// Activation is a read-modify-write (check the code, check the user, INSERT
	// the user, mark the code USED) that MUST be atomic. Run it as ONE
	// BEGIN IMMEDIATE transaction: the write lock is taken up front, so every
	// step shares one consistent, serialized view. This removes the actual bug
	// (loose autocommit steps), not just its symptom -- no stale read snapshot
	// can reach the INSERT (the BUSY_SNAPSHOT that reports "database is locked"
	// and that the busy-timeout will NOT retry), and the code-check/mark-USED is
	// atomic so two racing activations can't double-spend one code (TOCTOU).
	// A genuine writer conflict now surfaces as plain SQLITE_BUSY, which the 5 s
	// busy-timeout retries. EVERY exit below MUST reach COMMIT or the
	// out_rollback label -- a bare return would leak the open transaction and
	// reintroduce the very lock we are fixing.
	if (sqlite3_exec(s->conn, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
		printf("sqlite activation BEGIN failed: %s\n",
			sqlite3_errmsg(s->conn));
		return -1;
	}

	int rc = -1;

	if (activation_code) {
		// Idempotency: same code recently marked USED is a retransmit.
		//
		// We deliberately do NOT match request_id here. The wg layer
		// rotates session_id on every regenerate (fresh ephemeral, fresh
		// sid per retry), so the retransmit's session_hex differs from
		// what the first msg1 wrote into request_id. Matching on it
		// would defeat the whole point of the idempotency window.
		//
		// Privacy is preserved — we still DO NOT bind activation_code to
		// the activator's pubkey. The check answers "has this code been
		// USED in the last N seconds?" without needing the user identity.
		//
		// Caveat: two distinct legitimate users colliding on the same
		// code within the window would both see success here, but only
		// the first writes the users row — the second can't actually
		// authenticate, so this is a UX wart at most, not a security
		// hole.
		//
		// session_id == 0 disables the check (admin paths).
		if (session_id != 0) {
			if (!s->check_idempotent_stmt) {
				s->check_idempotent_stmt = prep(s->conn,
					"SELECT COUNT(*) FROM activation "
					"WHERE activation_code=? AND status=? "
					"AND updated_at > ?");
				if (!s->check_idempotent_stmt) {
					rc = -1;
					goto out_rollback;
				}
			}
			sqlite3_stmt *st = s->check_idempotent_stmt;
			sqlite3_reset(st);
			sqlite3_bind_text(st, 1, activation_code, -1, SQLITE_STATIC);
			sqlite3_bind_int (st, 2, ACTIVATION_USED);
			sqlite3_bind_int64(st, 3,
				(sqlite3_int64)((unsigned long long)time(NULL) -
				                ACTIVATION_RETRANSMIT_WINDOW_SECONDS));
			if (sqlite3_step(st) != SQLITE_ROW) {
				rc = -1;
				goto out_rollback;
			}
			int recent = sqlite3_column_int(st, 0);
			sqlite3_reset(st);
			if (recent > 0) {
				printf("activation idempotent retransmit (code=%s)\n",
					activation_code);
				rc = 1;
				goto out_rollback;
			}
		}

		// Code must be AVAILABLE or SOLD. Fetch the status rather than counting
		// the usable states, so "no such code" (a typo) stays distinguishable
		// from "already used" -- a COUNT collapsed both into 0 and every typo
		// was reported to the user as "this code has already been used".
		if (!s->check_activation_stmt) {
			s->check_activation_stmt = prep(s->conn,
				"SELECT status FROM activation WHERE activation_code=?");
			if (!s->check_activation_stmt) {
				rc = -1;
				goto out_rollback;
			}
		}
		sqlite3_stmt *st = s->check_activation_stmt;
		sqlite3_reset(st);
		sqlite3_bind_text(st, 1, activation_code, -1, SQLITE_STATIC);
		int step = sqlite3_step(st);
		if (step == SQLITE_DONE) {
			sqlite3_reset(st);
			rc = 2;          // no such code -> unknown
			goto out_rollback;
		}
		if (step != SQLITE_ROW) {
			sqlite3_reset(st);
			rc = -1;
			goto out_rollback;
		}
		int code_status = sqlite3_column_int(st, 0);
		sqlite3_reset(st);
		if (code_status != ACTIVATION_AVAILABLE && code_status != ACTIVATION_SOLD) {
			rc = 0;                                // exists but spent -> used
			goto out_rollback;
		}
	}

	// Does the user already exist?
	if (!s->count_users_stmt) {
		s->count_users_stmt = prep(s->conn,
			"SELECT COUNT(*) FROM users WHERE partkey=?");
		if (!s->count_users_stmt) {
			rc = -2;
			goto out_rollback;
		}
	}
	sqlite3_reset(s->count_users_stmt);
	sqlite3_bind_int64(s->count_users_stmt, 1, (sqlite3_int64)part_key);
	if (sqlite3_step(s->count_users_stmt) != SQLITE_ROW) {
		sqlite3_reset(s->count_users_stmt);
		rc = -2;
		goto out_rollback;
	}
	int user_count = sqlite3_column_int(s->count_users_stmt, 0);
	sqlite3_reset(s->count_users_stmt);

	if (user_count == 0) {
		// New user.
		if (!s->insert_user_stmt) {
			s->insert_user_stmt = prep(s->conn,
				"INSERT INTO users (partkey, public_key, expires_on) "
				"VALUES (?, ?, ?)");
			if (!s->insert_user_stmt) {
				rc = -4;
				goto out_rollback;
			}
		}
		sqlite3_stmt *st = s->insert_user_stmt;
		sqlite3_reset(st);
		sqlite3_bind_int64(st, 1, (sqlite3_int64)part_key);
		sqlite3_bind_blob (st, 2, user_key, KEY_LEN, SQLITE_STATIC);
		sqlite3_bind_int64(st, 3, (sqlite3_int64)expires_on);
		if (sqlite3_step(st) != SQLITE_DONE) {
			printf("sqlite insert user failed: %s\n",
				sqlite3_errmsg(s->conn));
			rc = -4;
			goto out_rollback;
		}
	} else if (user_count == 1) {
		// Existing user: stack +1y if still valid, else reset to caller value.
		// 31557600 == 365.25d, matching the constant used at the call sites.
		if (!s->update_expiry_stmt) {
			s->update_expiry_stmt = prep(s->conn,
				"UPDATE users SET expires_on = CASE "
				"WHEN expires_on > ? THEN expires_on + 31557600 "
				"ELSE ? END WHERE partkey = ?");
			if (!s->update_expiry_stmt) {
				rc = -4;
				goto out_rollback;
			}
		}
		sqlite3_stmt *st = s->update_expiry_stmt;
		sqlite3_reset(st);
		sqlite3_bind_int64(st, 1, (sqlite3_int64)time(NULL));
		sqlite3_bind_int64(st, 2, (sqlite3_int64)expires_on);
		sqlite3_bind_int64(st, 3, (sqlite3_int64)part_key);
		if (sqlite3_step(st) != SQLITE_DONE) {
			printf("sqlite update expiry failed: %s\n",
				sqlite3_errmsg(s->conn));
			rc = -4;
			goto out_rollback;
		}
	} else {
		rc = -5;
		goto out_rollback;
	}

	if (activation_code) {
		// Store the SESSION id (opaque random number from msg1) as
		// request_id, NOT the activator's identity. Sufficient for
		// detecting a retransmit but unrecoverable as activator-id.
		// Any prior sold_to value is overwritten — deliberate, so the
		// row carries no sold-to → activated-by linkage.
		if (!s->mark_used_stmt) {
			s->mark_used_stmt = prep(s->conn,
				"UPDATE activation SET status=?, request_id=?, updated_at=? "
				"WHERE activation_code=?");
			if (!s->mark_used_stmt) {
				rc = -6;
				goto out_rollback;
			}
		}
		sqlite3_stmt *st = s->mark_used_stmt;
		sqlite3_reset(st);
		sqlite3_bind_int  (st, 1, ACTIVATION_USED);
		sqlite3_bind_text (st, 2, session_hex, -1, SQLITE_STATIC);
		sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
		sqlite3_bind_text (st, 4, activation_code, -1, SQLITE_STATIC);
		if (sqlite3_step(st) != SQLITE_DONE) {
			printf("sqlite mark USED failed: %s\n",
				sqlite3_errmsg(s->conn));
			rc = -6;
			goto out_rollback;
		}
	}

	if (sqlite3_exec(s->conn, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
		printf("sqlite activation COMMIT failed: %s\n",
			sqlite3_errmsg(s->conn));
		rc = -1;
		goto out_rollback;
	}
	return 1;

out_rollback:
	sqlite3_exec(s->conn, "ROLLBACK", NULL, NULL, NULL);
	return rc;
}

bool db_add_activation(char *activation) {
	struct db_state *s = db_state();
	if (!s || !s->conn) return false;
	if (!s->add_activation_stmt) {
		s->add_activation_stmt = prep(s->conn,
			"INSERT INTO activation (activation_code, status, updated_at) "
			"VALUES (?, ?, ?)");
		if (!s->add_activation_stmt) return false;
	}
	sqlite3_stmt *st = s->add_activation_stmt;
	sqlite3_reset(st);
	sqlite3_bind_text (st, 1, activation, -1, SQLITE_STATIC);
	sqlite3_bind_int  (st, 2, ACTIVATION_AVAILABLE);
	sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
	return sqlite3_step(st) == SQLITE_DONE;
}

// Find the next AVAILABLE activation code (oldest-first by updated_at).
// On success copies the 16-char code (plus terminating null) into out and returns 0.
// Returns -1 on db error, -2 if no such code exists.
int db_get_next_activation(char *out) {
	if (!out) return -1;
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;
	if (!s->next_activation_stmt) {
		s->next_activation_stmt = prep(s->conn,
			"SELECT activation_code FROM activation "
			"WHERE status = ? "
			"ORDER BY updated_at ASC LIMIT 1");
		if (!s->next_activation_stmt) return -1;
	}
	sqlite3_stmt *st = s->next_activation_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int(st, 1, ACTIVATION_AVAILABLE);
	int rc = sqlite3_step(st);
	if (rc == SQLITE_DONE) { sqlite3_reset(st); return -2; }
	if (rc != SQLITE_ROW)  { sqlite3_reset(st); return -1; }
	const unsigned char *code = sqlite3_column_text(st, 0);
	if (!code) { sqlite3_reset(st); return -2; }
	strncpy(out, (const char *)code, 16);
	out[16] = '\0';
	sqlite3_reset(st);   // release the read snapshot before returning (see db_code_valid)
	return 0;
}

// Mark an AVAILABLE activation code as SOLD to `request_id`. Atomic: a code
// that's already SOLD or USED cannot be re-sold. Returns 0 on success, -1 on
// db error, -2 if no row was updated (code missing or no longer AVAILABLE).
int db_set_activation_request_id(const char *code, const char *request_id) {
	if (!code || !request_id) return -1;
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;
	if (!s->mark_sold_stmt) {
		s->mark_sold_stmt = prep(s->conn,
			"UPDATE activation SET request_id=?, status=?, updated_at=? "
			"WHERE activation_code=? AND status=?");
		if (!s->mark_sold_stmt) return -1;
	}
	sqlite3_stmt *st = s->mark_sold_stmt;
	sqlite3_reset(st);
	sqlite3_bind_text (st, 1, request_id, -1, SQLITE_STATIC);
	sqlite3_bind_int  (st, 2, ACTIVATION_SOLD);
	sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
	sqlite3_bind_text (st, 4, code, -1, SQLITE_STATIC);
	sqlite3_bind_int  (st, 5, ACTIVATION_AVAILABLE);
	if (sqlite3_step(st) != SQLITE_DONE) {
		printf("sqlite mark SOLD failed: %s\n", sqlite3_errmsg(s->conn));
		return -1;
	}
	return sqlite3_changes(s->conn) == 0 ? -2 : 0;
}

int db_validate_user(const uint8_t *key) {
	if (!key) return -1;
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;
	if (!s->validate_user_stmt) {
		s->validate_user_stmt = prep(s->conn,
			"SELECT public_key FROM users "
			"WHERE partkey = ? AND expires_on > ? LIMIT 1");
		if (!s->validate_user_stmt) return -1;
	}
	sqlite3_stmt *st = s->validate_user_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)partkey_from_key(key));
	sqlite3_bind_int64(st, 2, (sqlite3_int64)time(NULL));
	int rc = sqlite3_step(st);
	if (rc == SQLITE_DONE) { sqlite3_reset(st); return -2; }  // no such (live) user
	if (rc != SQLITE_ROW)  { sqlite3_reset(st); return -1; }  // db error

	int len = sqlite3_column_bytes(st, 0);
	const void *blob = sqlite3_column_blob(st, 0);
	int result = (!blob || len != KEY_LEN) ? -3
	           : (memcmp(blob, key, KEY_LEN) == 0 ? 0 : -3);
	sqlite3_reset(st);   // release the read snapshot before returning (see db_code_valid)
	return result;
}

// Print all fields of the users row matching part_key. Returns 0 on success,
// -1 on db error, -2 if no such user.
int db_show_user(uint32_t part_key) {
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;
	if (!s->show_user_stmt) {
		s->show_user_stmt = prep(s->conn,
			"SELECT partkey, id, public_key, src_ip, src_port, expires_on "
			"FROM users WHERE partkey = ? LIMIT 1");
		if (!s->show_user_stmt) return -1;
	}
	sqlite3_stmt *st = s->show_user_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)part_key);
	int rc = sqlite3_step(st);
	if (rc == SQLITE_DONE) return -2;
	if (rc != SQLITE_ROW)  return -1;

	printf("partkey:    %08x\n", part_key);
	if (sqlite3_column_type(st, 1) != SQLITE_NULL)
		printf("id:         %lld\n",
			(long long)sqlite3_column_int64(st, 1));
	else
		printf("id:         (null)\n");

	int klen = sqlite3_column_bytes(st, 2);
	const void *kblob = sqlite3_column_blob(st, 2);
	if (kblob && klen > 0) {
		char hex[KEY_LEN * 2 + 1];
		size_t copy_len = (size_t)klen < KEY_LEN ? (size_t)klen : KEY_LEN;
		bytes2hex((uint8_t *)kblob, copy_len, hex);
		for (char *p = hex; *p; p++) *p = tolower((unsigned char)*p);
		printf("public_key: %s\n", hex);
	} else {
		printf("public_key: (null)\n");
	}

	if (sqlite3_column_type(st, 3) != SQLITE_NULL) {
		uint32_t ip = (uint32_t)sqlite3_column_int64(st, 3);
		printf("src_ip:     %u.%u.%u.%u\n",
			ip & 0xff, (ip >> 8) & 0xff,
			(ip >> 16) & 0xff, (ip >> 24) & 0xff);
	} else {
		printf("src_ip:     (null)\n");
	}

	if (sqlite3_column_type(st, 4) != SQLITE_NULL)
		printf("src_port:   %d\n", sqlite3_column_int(st, 4));
	else
		printf("src_port:   (null)\n");

	if (sqlite3_column_type(st, 5) != SQLITE_NULL) {
		time_t t = (time_t)sqlite3_column_int64(st, 5);
		struct tm tm;
		char buf[32];
		gmtime_r(&t, &tm);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
		printf("expires_on: %lld (%s)\n", (long long)t, buf);
	} else {
		printf("expires_on: (null)\n");
	}
	return 0;
}

// Admin-only range dump. Collects matching partkeys first so we don't
// re-enter db_show_user's prepared statement while it owns a row cursor.
int db_show_users_range(uint32_t prefix, uint32_t mask) {
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(s->conn,
		"SELECT partkey FROM users WHERE (partkey & ?) = ? "
		"ORDER BY partkey",
		-1, &st, NULL) != SQLITE_OK) {
		printf("sqlite show_users_range prepare failed: %s\n",
			sqlite3_errmsg(s->conn));
		return -1;
	}
	sqlite3_bind_int64(st, 1, (sqlite3_int64)mask);
	sqlite3_bind_int64(st, 2, (sqlite3_int64)prefix);

	uint32_t buf[256];
	int n = 0;
	int rc;
	while ((rc = sqlite3_step(st)) == SQLITE_ROW
	       && n < (int)(sizeof(buf) / sizeof(buf[0]))) {
		buf[n++] = (uint32_t)sqlite3_column_int64(st, 0);
	}
	sqlite3_finalize(st);

	if (n == 0) return -2;
	for (int i = 0; i < n; i++) {
		if (i > 0) printf("---\n");
		db_show_user(buf[i]);
	}
	return 0;
}

// Update the user's source ip/port on every authenticated msg1.
// Hot path — uses a per-thread prepared statement, lazy-init on first call.
int db_update_user(uint8_t *key, uint32_t ip4, uint16_t port) {
	if (!key) return -1;
	struct db_state *s = db_state();
	if (!s || !s->conn) return -1;
	if (!s->update_user_stmt) {
		s->update_user_stmt = prep(s->conn,
			"UPDATE users SET src_ip = ?, src_port = ? WHERE partkey = ?");
		if (!s->update_user_stmt) return -1;
	}
	sqlite3_stmt *st = s->update_user_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)ip4);
	sqlite3_bind_int  (st, 2, (int)port);
	sqlite3_bind_int64(st, 3, (sqlite3_int64)partkey_from_key(key));
	if (sqlite3_step(st) != SQLITE_DONE) {
		// Extended code, not just the message: SQLITE_BUSY (5) and
		// SQLITE_BUSY_SNAPSHOT (517) both print as "database is locked" and mean
		// very different things — one is contention, the other is this connection
		// holding a stale read snapshot.
		printf("sqlite update_user failed: %s (extended=%d)\n",
		       sqlite3_errmsg(s->conn), sqlite3_extended_errcode(s->conn));
		sqlite3_reset(st);
		return -1;
	}
	sqlite3_reset(st);   // every sibling in this file resets on every path
	return 0;
}

// Anonymous userid -> pubkey lookup. Returns true and writes 32 bytes of
// public_key when partkey matches a row; false otherwise. No expiry
// filter: pending lookups are best-effort and an expired user is still
// reachable peer-to-peer if their key is known.
bool db_get_pubkey_by_partkey(uint32_t partkey, uint8_t out[KEY_LEN]) {
	if (!out) return false;
	struct db_state *s = db_state();
	if (!s || !s->conn) return false;

	if (!s->get_pubkey_stmt) {
		s->get_pubkey_stmt = prep(s->conn,
			"SELECT public_key FROM users WHERE partkey = ? LIMIT 1");
		if (!s->get_pubkey_stmt) return false;
	}
	sqlite3_stmt *st = s->get_pubkey_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)partkey);

	if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_reset(st); return false; }

	const void *blob = sqlite3_column_blob(st, 0);
	int len = sqlite3_column_bytes(st, 0);
	if (!blob || len != KEY_LEN) { sqlite3_reset(st); return false; }
	memcpy(out, blob, KEY_LEN);
	sqlite3_reset(st);
	return true;
}

bool db_get_endpoint_by_partkey(uint32_t partkey,
                                uint8_t  out_pubkey[KEY_LEN],
                                uint32_t *out_ip4,
                                uint16_t *out_port) {
	if (!out_pubkey) return false;
	if (out_ip4)  *out_ip4  = 0;
	if (out_port) *out_port = 0;
	struct db_state *s = db_state();
	if (!s || !s->conn) return false;

	if (!s->get_endpoint_stmt) {
		s->get_endpoint_stmt = prep(s->conn,
			"SELECT public_key, src_ip, src_port "
			"FROM users WHERE partkey = ? LIMIT 1");
		if (!s->get_endpoint_stmt) return false;
	}
	sqlite3_stmt *st = s->get_endpoint_stmt;
	sqlite3_reset(st);
	sqlite3_bind_int64(st, 1, (sqlite3_int64)partkey);

	if (sqlite3_step(st) != SQLITE_ROW) { sqlite3_reset(st); return false; }

	const void *blob = sqlite3_column_blob(st, 0);
	int len = sqlite3_column_bytes(st, 0);
	if (!blob || len != KEY_LEN) { sqlite3_reset(st); return false; }
	memcpy(out_pubkey, blob, KEY_LEN);

	if (out_ip4 && sqlite3_column_type(st, 1) != SQLITE_NULL)
		*out_ip4 = (uint32_t)sqlite3_column_int64(st, 1);
	if (out_port && sqlite3_column_type(st, 2) != SQLITE_NULL)
		*out_port = (uint16_t)sqlite3_column_int(st, 2);
	sqlite3_reset(st);   // release the read snapshot before returning (see db_code_valid)
	return true;
}
