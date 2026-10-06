-- Reference schema (SQLite dialect). db_init() in db.c runs the same
-- CREATE TABLE IF NOT EXISTS statements automatically on every open, so
-- a fresh ltp.db file works without applying this script. Kept here as
-- documentation and for ops who want to inspect/build a DB by hand:
--   sqlite3 ltp.db < init_db.sql

CREATE TABLE IF NOT EXISTS users (
  partkey     INTEGER PRIMARY KEY,
  id          INTEGER,
  public_key  BLOB NOT NULL,
  src_ip      INTEGER,
  src_port    INTEGER,
  expires_on  INTEGER NOT NULL DEFAULT 0   -- unix epoch seconds
);

-- status: 0=AVAILABLE (mintable, returned by db_get_next_activation),
--         1=SOLD     (claimed for a customer; still activatable),
--         2=USED     (consumed by db_activate_user)
-- updated_at is unix-epoch seconds; written explicitly by db.c on every
-- UPDATE (no MySQL-style auto-update trigger in SQLite).
CREATE TABLE IF NOT EXISTS activation (
  activation_code  TEXT NOT NULL PRIMARY KEY,
  request_id       TEXT,
  status           INTEGER DEFAULT 0,
  updated_at       INTEGER NOT NULL DEFAULT 0,
  recharge_amount  INTEGER
);
