-- Exact legacy schema: the legacy schema-2 server, schema2.

CREATE TABLE agents (address TEXT PRIMARY KEY, kind TEXT NOT NULL, principal TEXT, mailbox INTEGER NOT NULL,
  created_at TEXT NOT NULL, retired_at TEXT);
CREATE TABLE agent_keys (key TEXT PRIMARY KEY, address TEXT NOT NULL, added TEXT NOT NULL, revoked TEXT,
  seq INTEGER NOT NULL);
CREATE INDEX agent_keys_address ON agent_keys (address);
CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT NOT NULL, from_address TEXT NOT NULL, public INTEGER NOT NULL,
  carrier TEXT NOT NULL, claims TEXT NOT NULL, received_at TEXT NOT NULL, expires INTEGER NOT NULL,
  kept INTEGER NOT NULL);
CREATE INDEX messages_expires ON messages (expires);
CREATE TABLE message_parts (id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, PRIMARY KEY (id, sha256));
CREATE INDEX message_parts_sha ON message_parts (sha256);
CREATE TABLE arrivals (id TEXT NOT NULL, recipient TEXT NOT NULL, hints TEXT NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (id, recipient));
CREATE INDEX arrivals_due ON arrivals (due);
CREATE TABLE inbox (cursor INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL, id TEXT NOT NULL,
  received_at TEXT NOT NULL, event INTEGER NOT NULL, UNIQUE (address, id));
CREATE INDEX inbox_id ON inbox (id);
CREATE INDEX inbox_events ON inbox (cursor) WHERE event = 1;
CREATE TABLE deliveries (id TEXT NOT NULL, domain TEXT NOT NULL, recipients TEXT NOT NULL, hints TEXT NOT NULL,
  server TEXT, status TEXT NOT NULL, reason TEXT, attempts INTEGER NOT NULL, next_attempt INTEGER NOT NULL,
  created_at TEXT NOT NULL, deadline TEXT NOT NULL, lease TEXT, PRIMARY KEY (id, domain));
CREATE INDEX deliveries_due ON deliveries (status, next_attempt);
CREATE TABLE parts (sha256 TEXT NOT NULL, source TEXT NOT NULL, fetched INTEGER NOT NULL, size INTEGER NOT NULL,
  bytes BLOB NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (sha256, source));
CREATE TABLE fetches (sha256 TEXT NOT NULL, carrier TEXT NOT NULL, size INTEGER NOT NULL, attempts INTEGER NOT NULL,
  due INTEGER NOT NULL, PRIMARY KEY (sha256, carrier));
CREATE INDEX fetches_due ON fetches (due);
CREATE TABLE marks (scope TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY (scope, id));
CREATE TABLE counters (scope TEXT NOT NULL, id TEXT NOT NULL, n INTEGER NOT NULL, expires INTEGER NOT NULL,
  PRIMARY KEY (scope, id));
CREATE TABLE vals (scope TEXT NOT NULL, id TEXT NOT NULL, value TEXT NOT NULL, expires INTEGER,
  PRIMARY KEY (scope, id));
PRAGMA user_version = 2;
