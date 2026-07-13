-- +goose Up

CREATE TABLE users (
    id uuid primary key not null,
    display_name text not null check (btrim(display_name) != ''),
    created_at timestamp without time zone not null,
    last_logged_in_at timestamp without time zone
);

CREATE TYPE identity_provider AS ENUM ('testuser');

CREATE TABLE identities (
    provider identity_provider not null,
    provider_user_id text not null check (btrim(provider_user_id) != ''),
    user_id uuid not null references users(id) on delete cascade,
    primary key (provider, provider_user_id)
);

-- +goose Down

DROP TABLE IF EXISTS identities;
DROP TYPE identity_provider;
DROP TABLE IF EXISTS users;
