-- +goose Up

ALTER TABLE memberships ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS unique_membership;
ALTER TABLE memberships ADD CONSTRAINT unique_membership_scope UNIQUE (user_id, org_id, subject_type, subject, scope);

-- need to be able lookup memberships by org and scope efficiently
CREATE INDEX idx_org_subject ON memberships (org_id, scope);

ALTER TABLE service_user_roles ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE service_user_roles DROP CONSTRAINT service_user_roles_pkey;
ALTER TABLE service_user_roles ADD PRIMARY KEY (org_id, service_user_id, role_id, scope);

-- need to be able lookup service user service by org and scope efficiently
CREATE INDEX idx_service_user_roles_scope ON service_user_roles (org_id, scope);


-- +goose Down
ALTER TABLE memberships DROP CONSTRAINT IF EXISTS unique_membership_scope;
ALTER TABLE memberships ADD CONSTRAINT unique_membership UNIQUE (user_id, org_id, subject_type, subject);
ALTER TABLE memberships DROP COLUMN scope IF EXISTS;
ALTER TABLE memberships DROP INDEX IF EXISTS idx_org_subject;

ALTER TABLE service_user_roles DROP CONSTRAINT IF EXISTS service_user_roles_pkey;
ALTER TABLE service_user_roles ADD PRIMARY KEY (org_id, service_user_id, role_id);
ALTER TABLE service_user_roles DROP COLUMN scope IF EXISTS;
ALTER TABLE service_user_roles DROP INDEX IF EXISTS idx_service_user_roles_scope;
