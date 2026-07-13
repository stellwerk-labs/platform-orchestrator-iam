-- +goose Up

CREATE TABLE session_tokens (
    sha256_hash bytea primary key not null check (octet_length(sha256_hash) = 32),
    provider identity_provider not null,
    user_id uuid not null references users(id) on delete cascade,
    created_at timestamp without time zone not null,
    expires_at timestamp without time zone not null check (expires_at > created_at)
);

CREATE INDEX ON session_tokens(created_at);
CREATE INDEX ON session_tokens(expires_at);

-- +goose Down

DROP TABLE IF EXISTS session_tokens;
