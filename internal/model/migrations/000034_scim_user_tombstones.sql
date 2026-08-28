-- +goose Up

-- A SCIM DELETE used to remove the scim_users row, which destroyed the only
-- record that SCIM governs this user in this org — the next SSO login looked
-- like a never-provisioned user and JIT-granted a fresh membership. Deletes
-- now tombstone the row (deleted_at set) so the SSO gate can tell "never
-- governed" apart from "governed and removed".
ALTER TABLE scim_users ADD COLUMN deleted_at timestamp WITHOUT TIME ZONE NULL;

-- Uniqueness only applies to live rows: a tombstone must never block
-- re-provisioning the same person (same userName or same global user).
-- The composite UNIQUE (id, org_id) stays untouched — the scim_group_members
-- foreign keys depend on it.
ALTER TABLE scim_users DROP CONSTRAINT unique_scim_user_name;
ALTER TABLE scim_users DROP CONSTRAINT unique_scim_user_user;
CREATE UNIQUE INDEX unique_scim_user_name ON scim_users (org_id, user_name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX unique_scim_user_user ON scim_users (org_id, user_id) WHERE deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS unique_scim_user_name;
DROP INDEX IF EXISTS unique_scim_user_user;
-- Tombstones may duplicate a live row's user_name/user_id, which the full
-- constraints below cannot represent; the old schema had no tombstones anyway.
DELETE FROM scim_users WHERE deleted_at IS NOT NULL;
ALTER TABLE scim_users ADD CONSTRAINT unique_scim_user_name UNIQUE (org_id, user_name);
ALTER TABLE scim_users ADD CONSTRAINT unique_scim_user_user UNIQUE (org_id, user_id);
ALTER TABLE scim_users DROP COLUMN deleted_at;
