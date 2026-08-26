-- +goose Up

-- Maps a SCIM group display name to the org role its members should hold.
-- Keyed on display name (not group id) so an operator can configure a mapping
-- before the group ever syncs from the IDP. Comparison is case-insensitive
-- (see the unique index below); the name is stored as the operator typed it.
-- Consequence: renaming a group in the IDP silently breaks its mapping — the
-- mapping keeps the old name and stops matching anything.
CREATE TABLE scim_group_role_mappings (
    org_id text NOT NULL,
    group_display_name text NOT NULL CHECK (btrim(group_display_name) != ''),
    role_id uuid NOT NULL,
    created_at timestamp WITHOUT TIME ZONE NOT NULL,
    PRIMARY KEY (org_id, group_display_name),
    CONSTRAINT scim_group_role_mappings_role FOREIGN KEY (org_id, role_id) REFERENCES roles (org_id, id) ON DELETE CASCADE
);

-- Matching is case-insensitive, so "Engineers" and "engineers" must not be
-- able to coexist as two different mappings. Also the upsert conflict target.
CREATE UNIQUE INDEX unique_scim_group_role_mapping_name
    ON scim_group_role_mappings (org_id, LOWER(group_display_name));

-- Memberships this feature created, so reconciliation never touches grants a human made.
CREATE TABLE scim_managed_memberships (
    membership_id uuid PRIMARY KEY NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    scim_user_id uuid NOT NULL REFERENCES scim_users(id) ON DELETE CASCADE
);

CREATE INDEX idx_scim_managed_memberships_user ON scim_managed_memberships (scim_user_id);

-- +goose Down

DROP TABLE IF EXISTS scim_managed_memberships;
DROP TABLE IF EXISTS scim_group_role_mappings;
