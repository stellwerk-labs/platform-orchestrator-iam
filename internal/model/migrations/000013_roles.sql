-- +goose Up

CREATE TABLE roles (
    id uuid not null,
    org_id text not null,
    display_name text not null check (btrim(display_name) != ''),
    created_at timestamp without time zone not null,
    created_by uuid not null default 'ffffffff-ffff-ffff-ffff-ffffffffffff',
    permissions text[] not null default '{}',
    primary key (org_id, id),
    CONSTRAINT unique_roles UNIQUE (org_id, display_name)
);

-- Create Admin and Viewer roles for each distinct org from memberships
INSERT INTO roles (id, org_id, display_name, created_at, permissions)
SELECT
    gen_random_uuid() as id,
    org_id,
    'Admin' as display_name,
    now() as created_at,
    ARRAY['manage_all'] as permissions
FROM (
    SELECT DISTINCT org_id
    FROM memberships
) distinct_orgs;

INSERT INTO roles (id, org_id, display_name, created_at, permissions)
SELECT
    gen_random_uuid() as id,
    org_id,
    'Viewer' as display_name,
    now() as created_at,
    ARRAY['read_all'] as permissions
FROM (
    SELECT DISTINCT org_id
    FROM memberships
) distinct_orgs;



-- +goose Down

DROP TABLE IF EXISTS roles;


