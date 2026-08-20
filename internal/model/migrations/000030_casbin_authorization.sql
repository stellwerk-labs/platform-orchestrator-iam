-- +goose Up

ALTER TABLE roles ADD COLUMN is_system boolean NOT NULL DEFAULT false;

UPDATE roles
SET is_system = true
WHERE display_name IN ('Admin', 'Deployer', 'Viewer');

-- Older role memberships predate the dedicated role column. Their subject already
-- contains the role UUID, so make them visible to the PostgreSQL policy query.
UPDATE memberships
SET role = subject::uuid
WHERE subject_type = 'role' AND role IS NULL;

CREATE TABLE authorization_resources (
    resource text PRIMARY KEY,
    resource_type text NOT NULL CHECK (resource_type IN ('organization', 'project', 'env')),
    resource_id text NOT NULL,
    org_id text NOT NULL,
    parent_resource text NULL REFERENCES authorization_resources(resource) ON DELETE CASCADE,
    CONSTRAINT authorization_resource_shape CHECK (resource = resource_type || ':' || resource_id),
    CONSTRAINT authorization_resource_parent CHECK (parent_resource IS NULL OR parent_resource <> resource)
);

CREATE INDEX idx_authorization_resources_org_id ON authorization_resources (org_id);
CREATE INDEX idx_authorization_resources_parent ON authorization_resources (parent_resource);

INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
SELECT DISTINCT 'organization:' || org_id, 'organization', org_id, org_id, NULL
FROM roles
ON CONFLICT (resource) DO NOTHING;

-- Preserve the resources known by the previous authorization projection. Environments initially
-- inherit from their organization until the normal scope sync records their project parent.
INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
SELECT DISTINCT scope,
       split_part(scope, ':', 1),
       split_part(scope, ':', 2),
       org_id,
       'organization:' || org_id
FROM scoped_roles
WHERE split_part(scope, ':', 1) IN ('project', 'env')
ON CONFLICT (resource) DO NOTHING;

DROP TABLE scoped_roles;
DROP TABLE org_zed_tokens;

-- +goose Down

CREATE TABLE org_zed_tokens (
    org_id text PRIMARY KEY,
    zed_token text
);

CREATE TABLE scoped_roles (
    id uuid NOT NULL PRIMARY KEY,
    org_id text NOT NULL,
    scope text NOT NULL,
    org_role_id uuid NOT NULL,
    CONSTRAINT unique_scope_per_org UNIQUE (org_id, org_role_id, scope),
    CONSTRAINT fk_scoped_roles_org_role_org_id FOREIGN KEY (org_role_id, org_id) REFERENCES roles(id, org_id) ON DELETE CASCADE
);

CREATE INDEX idx_scoped_roles_org_id ON scoped_roles (org_id);

INSERT INTO scoped_roles (id, org_id, scope, org_role_id)
SELECT gen_random_uuid(), org_id, scope, role_id
FROM (
    SELECT org_id, scope, role AS role_id
    FROM memberships
    WHERE subject_type = 'role' AND role IS NOT NULL AND scope <> ''
    UNION
    SELECT org_id, scope, role_id
    FROM service_user_roles
    WHERE scope <> ''
) assigned_scopes;

DROP TABLE authorization_resources;
ALTER TABLE roles DROP COLUMN is_system;
