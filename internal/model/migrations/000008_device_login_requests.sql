-- +goose Up

CREATE TABLE device_login_requests (
    id uuid primary key not null,
    verification_code_hash bytea not null,
    created_at timestamp without time zone not null,
    expires_at timestamp without time zone not null,
    user_agent text not null,
    polling_token_hash bytea not null,
    decision text null,
    decided_by uuid null
);

-- must be able to look up by code hash
CREATE INDEX ON device_login_requests(verification_code_hash);

ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'devicelogin';

-- +goose Down

DROP TABLE IF EXISTS device_login_requests;
