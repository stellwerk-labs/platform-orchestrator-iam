-- +goose Up

ALTER TYPE identity_provider ADD VALUE IF NOT EXISTS 'scim';

CREATE TABLE scim_users (
    id uuid PRIMARY KEY NOT NULL,
    org_id text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_name text NOT NULL CHECK (btrim(user_name) != ''),
    external_id text,
    active boolean NOT NULL DEFAULT true,
    created_at timestamp WITHOUT TIME ZONE NOT NULL,
    updated_at timestamp WITHOUT TIME ZONE NOT NULL,
    CONSTRAINT unique_scim_user_name UNIQUE (org_id, user_name),
    CONSTRAINT unique_scim_user_user UNIQUE (org_id, user_id)
);

CREATE TABLE scim_groups (
    id uuid PRIMARY KEY NOT NULL,
    org_id text NOT NULL,
    display_name text NOT NULL CHECK (btrim(display_name) != ''),
    external_id text,
    created_at timestamp WITHOUT TIME ZONE NOT NULL,
    updated_at timestamp WITHOUT TIME ZONE NOT NULL,
    CONSTRAINT unique_scim_group_name UNIQUE (org_id, display_name)
);

CREATE TABLE scim_group_members (
    group_id uuid NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    scim_user_id uuid NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, scim_user_id)
);

-- +goose Down

DROP TABLE IF EXISTS scim_group_members;
DROP TABLE IF EXISTS scim_groups;
DROP TABLE IF EXISTS scim_users;
-- Postgres cannot remove enum values safely; 'scim' identity_provider value is left in place.
