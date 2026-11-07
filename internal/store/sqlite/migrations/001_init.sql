-- Mesmo modelo do driver Postgres, adaptado ao SQLite:
--   datas em INTEGER (microssegundos Unix, a mesma precisão da cadeia de hashes),
--   JSON em TEXT, IPs em TEXT normalizado, bytea em BLOB.

CREATE TABLE data_keys (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scope        TEXT NOT NULL,
    period       TEXT NOT NULL,
    wrapped      BLOB,                -- NULL = destruída (crypto-shredding)
    created_at   INTEGER NOT NULL,
    destroyed_at INTEGER,
    UNIQUE (scope, period)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE admin_sessions (
    token_hash BLOB PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       INTEGER NOT NULL,
    admin_id INTEGER REFERENCES admins ON DELETE SET NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    mime       TEXT NOT NULL,
    data       BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE sites (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    slug              TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    controller        TEXT NOT NULL DEFAULT '',
    controller_config BLOB,
    session_minutes   INTEGER NOT NULL DEFAULT 480,
    theme             TEXT NOT NULL DEFAULT '{}',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE fields (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id     INTEGER NOT NULL REFERENCES sites ON DELETE CASCADE,
    key         TEXT NOT NULL,
    label       TEXT NOT NULL,
    type        TEXT NOT NULL,
    placeholder TEXT NOT NULL DEFAULT '',
    purpose     TEXT NOT NULL DEFAULT '',
    protection  TEXT NOT NULL,
    required    INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    position    INTEGER NOT NULL DEFAULT 0,
    UNIQUE (site_id, key)
);

CREATE TABLE terms (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_by INTEGER REFERENCES admins ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (site_id, version)
);

CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id    INTEGER NOT NULL REFERENCES sites,
    terms_id   INTEGER NOT NULL REFERENCES terms,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ssid       TEXT NOT NULL DEFAULT '',
    data_plain TEXT NOT NULL DEFAULT '{}',
    payload    BLOB NOT NULL
);
CREATE INDEX sessions_created_at ON sessions (created_at);
CREATE INDEX sessions_site_created ON sessions (site_id, created_at);

CREATE TABLE session_index (
    kind       TEXT NOT NULL,
    bidx       BLOB NOT NULL,
    session_id INTEGER NOT NULL REFERENCES sessions ON DELETE CASCADE,
    PRIMARY KEY (kind, bidx, session_id)
);
CREATE INDEX session_index_session ON session_index (session_id);

CREATE TABLE log_sources (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    sender_ip  TEXT NOT NULL UNIQUE,
    parser     TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

-- source_id sem FK de propósito: faz parte do hash e sobrevive à remoção da fonte.
CREATE TABLE log_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at  INTEGER NOT NULL,
    source_id    INTEGER NOT NULL,
    src_ip_bidx  BLOB NOT NULL,
    src_mac_bidx BLOB,
    payload      BLOB NOT NULL,
    prev_hash    BLOB NOT NULL,
    hash         BLOB NOT NULL
);
CREATE INDEX log_events_received_at ON log_events (received_at);
CREATE INDEX log_events_src_ip ON log_events (src_ip_bidx, received_at);
CREATE INDEX log_events_src_mac ON log_events (src_mac_bidx, received_at) WHERE src_mac_bidx IS NOT NULL;
