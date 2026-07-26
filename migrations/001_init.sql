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

-- +goose TransactionCommit

-- +goose Down

DROP TABLE IF EXISTS pow_usage;
