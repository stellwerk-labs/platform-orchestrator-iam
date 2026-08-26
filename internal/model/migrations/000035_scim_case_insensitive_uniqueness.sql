-- +goose Up

-- /Schemas advertises userName and group displayName with caseExact=false
-- (RFC 7643 §7), but uniqueness and lookups were byte-wise, so an IDP could
-- create both "Alice" and "alice" as distinct resources. Uniqueness and
-- lookups become case-insensitive here; values are still STORED as supplied,
-- only compared folded.
--
-- Before swapping the indexes, hunt for rows that already collide when case
-- is folded. CREATE UNIQUE INDEX would abort on them anyway, but with a
-- useless one-row error; an operator needs the full list of colliding rows to
-- decide which duplicates to merge or delete.

-- +goose StatementBegin
DO $$
DECLARE
    collision record;
    details text := '';
BEGIN
    FOR collision IN
        SELECT org_id, LOWER(user_name) AS folded,
               array_agg(id ORDER BY created_at) AS ids,
               array_agg(user_name ORDER BY created_at) AS names
        FROM scim_users
        WHERE deleted_at IS NULL
        GROUP BY org_id, LOWER(user_name)
        HAVING COUNT(*) > 1
    LOOP
        details := details || format(E'\n  org %s userName %s: ids %s (stored as %s)',
            collision.org_id, collision.folded, collision.ids, collision.names);
    END LOOP;
    IF details <> '' THEN
        RAISE EXCEPTION USING MESSAGE = format(
            'migration 000035 aborted: live scim_users rows differ only in userName case, '
            'but SCIM advertises userName as caseExact=false, so they are duplicates of one resource. '
            'Merge or delete the colliding rows listed below, then re-run the migration.%s', details);
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    collision record;
    details text := '';
BEGIN
    FOR collision IN
        SELECT org_id, LOWER(display_name) AS folded,
               array_agg(id ORDER BY created_at) AS ids,
               array_agg(display_name ORDER BY created_at) AS names
        FROM scim_groups
        GROUP BY org_id, LOWER(display_name)
        HAVING COUNT(*) > 1
    LOOP
        details := details || format(E'\n  org %s displayName %s: ids %s (stored as %s)',
            collision.org_id, collision.folded, collision.ids, collision.names);
    END LOOP;
    IF details <> '' THEN
        RAISE EXCEPTION USING MESSAGE = format(
            'migration 000035 aborted: scim_groups rows differ only in displayName case, '
            'but SCIM advertises displayName as caseExact=false, so they are duplicates of one resource. '
            'Merge or delete the colliding rows listed below, then re-run the migration.%s', details);
    END IF;
END $$;
-- +goose StatementEnd

-- The index names are load-bearing: the Go layer maps pq unique violations to
-- 409s by constraint name (unique_scim_user_name / unique_scim_group_name).
-- The tombstone predicate from 000034 stays: a tombstoned row must never block
-- re-provisioning the same person.
DROP INDEX unique_scim_user_name;
CREATE UNIQUE INDEX unique_scim_user_name ON scim_users (org_id, LOWER(user_name)) WHERE deleted_at IS NULL;

ALTER TABLE scim_groups DROP CONSTRAINT unique_scim_group_name;
CREATE UNIQUE INDEX unique_scim_group_name ON scim_groups (org_id, LOWER(display_name));

-- +goose Down

-- The case-sensitive shapes are strictly weaker, so this can never fail.
DROP INDEX unique_scim_user_name;
CREATE UNIQUE INDEX unique_scim_user_name ON scim_users (org_id, user_name) WHERE deleted_at IS NULL;

DROP INDEX unique_scim_group_name;
ALTER TABLE scim_groups ADD CONSTRAINT unique_scim_group_name UNIQUE (org_id, display_name);
