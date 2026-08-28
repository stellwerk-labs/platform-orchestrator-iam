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
    CONSTRAINT unique_scim_user_user UNIQUE (org_id, user_id),
    -- Redundant with the primary key, but required as a composite foreign key
    -- target so group membership can be pinned to one org (see below).
    CONSTRAINT scim_users_id_org UNIQUE (id, org_id)
);

CREATE TABLE scim_groups (
    id uuid PRIMARY KEY NOT NULL,
    org_id text NOT NULL,
    display_name text NOT NULL CHECK (btrim(display_name) != ''),
    external_id text,
    created_at timestamp WITHOUT TIME ZONE NOT NULL,
    updated_at timestamp WITHOUT TIME ZONE NOT NULL,
    CONSTRAINT unique_scim_group_name UNIQUE (org_id, display_name),
    CONSTRAINT scim_groups_id_org UNIQUE (id, org_id)
);

-- org_id is carried on the membership row so both foreign keys can be
-- composite. That makes cross-tenant membership unrepresentable: a row cannot
-- reference a group in one org and a user in another. Without it, a SCIM client
-- scoped to org A could attach org B's users to its groups, which turns into
-- privilege escalation as soon as groups start granting roles.
CREATE TABLE scim_group_members (
    group_id uuid NOT NULL,
    org_id text NOT NULL,
    scim_user_id uuid NOT NULL,
    PRIMARY KEY (group_id, scim_user_id),
    CONSTRAINT scim_group_members_group FOREIGN KEY (group_id, org_id)
        REFERENCES scim_groups (id, org_id) ON DELETE CASCADE,
    CONSTRAINT scim_group_members_user FOREIGN KEY (scim_user_id, org_id)
        REFERENCES scim_users (id, org_id) ON DELETE CASCADE
);

-- +goose Down

DROP TABLE IF EXISTS scim_group_members;
DROP TABLE IF EXISTS scim_groups;
DROP TABLE IF EXISTS scim_users;
-- Postgres cannot remove enum values safely; 'scim' identity_provider value is left in place.
