-- +goose Up

CREATE TABLE service_user_tokens (
    id uuid primary key not null,
    org_id text not null,
    display_name text not null check (btrim(display_name) != ''),
    generated_at timestamp without time zone not null,
    current_token_expires_at timestamp without time zone not null check (current_token_expires_at > generated_at),
    current_token_sha256_hash bytea not null check (octet_length(current_token_sha256_hash) = 32)
);

CREATE INDEX ON service_user_tokens (org_id);
CREATE INDEX ON service_user_tokens (generated_at);
CREATE INDEX ON service_user_tokens (current_token_sha256_hash);

-- +goose Down

DROP TABLE IF EXISTS service_user_tokens;
