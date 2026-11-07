-- Chaves de dados (DEKs) por escopo e mês, cifradas pela chave mestra.
-- wrapped NULL = chave destruída pela política de retenção (crypto-shredding).
CREATE TABLE data_keys (
    id           serial PRIMARY KEY,
    scope        text NOT NULL,
    period       text NOT NULL,
    wrapped      bytea,
    created_at   timestamptz NOT NULL DEFAULT now(),
    destroyed_at timestamptz,
    UNIQUE (scope, period)
);

CREATE TABLE settings (
    key   text PRIMARY KEY,
    value jsonb NOT NULL
);

CREATE TABLE admins (
    id            bigserial PRIMARY KEY,
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
    token_hash bytea PRIMARY KEY,
    admin_id   bigint NOT NULL REFERENCES admins ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE TABLE audit_log (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    admin_id bigint REFERENCES admins ON DELETE SET NULL,
    action   text NOT NULL,
    detail   jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE assets (
    id         bigserial PRIMARY KEY,
    mime       text NOT NULL,
    data       bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    id                bigserial PRIMARY KEY,
    slug              text NOT NULL UNIQUE,
    name              text NOT NULL,
    controller        text NOT NULL DEFAULT '',
    controller_config bytea,
    session_minutes   integer NOT NULL DEFAULT 480,
    theme             jsonb NOT NULL DEFAULT '{}',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE fields (
    id          bigserial PRIMARY KEY,
    site_id     bigint NOT NULL REFERENCES sites ON DELETE CASCADE,
    key         text NOT NULL,
    label       text NOT NULL,
    type        text NOT NULL,
    placeholder text NOT NULL DEFAULT '',
    purpose     text NOT NULL DEFAULT '',
    protection  text NOT NULL,
    required    boolean NOT NULL DEFAULT false,
    enabled     boolean NOT NULL DEFAULT true,
    position    integer NOT NULL DEFAULT 0,
    UNIQUE (site_id, key)
);

CREATE TABLE terms (
    id         bigserial PRIMARY KEY,
    site_id    bigint NOT NULL REFERENCES sites ON DELETE CASCADE,
    version    integer NOT NULL,
    title      text NOT NULL,
    body       text NOT NULL,
    created_by bigint REFERENCES admins ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, version)
);

-- Uma linha por acesso liberado. Campos cifrados ficam em payload;
-- session_index guarda índices cegos para busca por igualdade.
CREATE TABLE sessions (
    id         bigserial PRIMARY KEY,
    site_id    bigint NOT NULL REFERENCES sites,
    terms_id   bigint NOT NULL REFERENCES terms,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    ssid       text NOT NULL DEFAULT '',
    data_plain jsonb NOT NULL DEFAULT '{}',
    payload    bytea NOT NULL
);
CREATE INDEX sessions_created_at ON sessions (created_at);
CREATE INDEX sessions_site_created ON sessions (site_id, created_at);

CREATE TABLE session_index (
    kind       text NOT NULL,
    bidx       bytea NOT NULL,
    session_id bigint NOT NULL REFERENCES sessions ON DELETE CASCADE,
    PRIMARY KEY (kind, bidx, session_id)
);
CREATE INDEX session_index_session ON session_index (session_id);

CREATE TABLE log_sources (
    id         bigserial PRIMARY KEY,
    name       text NOT NULL,
    sender_ip  inet NOT NULL UNIQUE,
    parser     text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Eventos de firewall/DHCP encadeados por hash (prev_hash -> hash), para que
-- qualquer alteração seja detectável. source_id não tem FK de propósito: faz
-- parte do hash e precisa sobreviver à remoção da fonte.
CREATE TABLE log_events (
    id           bigserial PRIMARY KEY,
    received_at  timestamptz NOT NULL,
    source_id    bigint NOT NULL,
    src_ip_bidx  bytea NOT NULL,
    src_mac_bidx bytea,
    payload      bytea NOT NULL,
    prev_hash    bytea NOT NULL,
    hash         bytea NOT NULL
);
CREATE INDEX log_events_received_at ON log_events (received_at);
CREATE INDEX log_events_src_ip ON log_events (src_ip_bidx, received_at);
CREATE INDEX log_events_src_mac ON log_events (src_mac_bidx, received_at) WHERE src_mac_bidx IS NOT NULL;
