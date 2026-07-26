-- +goose Up
-- +goose TransactionBegin

-- pow_usage records generic-mode sign usage.
CREATE TABLE IF NOT EXISTS pow_usage (
    id          TEXT PRIMARY KEY,
    mode        TEXT NOT NULL,
    path        TEXT NOT NULL,
    sign        TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    uses        INTEGER NOT NULL DEFAULT 0,
    max_uses    INTEGER NOT NULL,
    first_ip    TEXT,
    last_ip     TEXT,
    user_agent  TEXT,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pow_usage_expires_at
    ON pow_usage(expires_at);

CREATE INDEX IF NOT EXISTS idx_pow_usage_path
    ON pow_usage(path);

-- risk_counter: reserved, currently unused.
--
-- counter_driver accepts only memory and redis. A postgres implementation
-- existed but was unreachable and had no expiry, so this table would have
-- grown without bound. It is kept so an existing database still matches
-- this migration; add a cleanup loop before wiring any code to it.
CREATE TABLE IF NOT EXISTS risk_counter (
    name         TEXT NOT NULL,
    key          TEXT NOT NULL,
    bucket_start BIGINT NOT NULL,
    value        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (name, key, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_risk_counter_expires_at
    ON risk_counter(bucket_start);

-- admin_audit_log records admin API actions.
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    action      TEXT NOT NULL,
    actor       TEXT NOT NULL,
    request_id  TEXT,
    summary     TEXT,
    payload     JSONB,
    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at
    ON admin_audit_log(created_at);

CREATE INDEX IF NOT EXISTS idx_admin_audit_log_action
    ON admin_audit_log(action);

-- +goose TransactionCommit

-- +goose Down

DROP TABLE IF EXISTS admin_audit_log;
DROP TABLE IF EXISTS risk_counter;
DROP TABLE IF EXISTS pow_usage;
