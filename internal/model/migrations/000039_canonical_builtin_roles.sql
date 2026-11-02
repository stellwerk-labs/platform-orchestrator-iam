-- +goose Up
ALTER TABLE roles ADD COLUMN builtin_key TEXT CHECK (builtin_key IN ('admin','deployer','viewer')),
ADD CONSTRAINT roles_builtin_system CHECK (builtin_key IS NULL OR is_system);
CREATE UNIQUE INDEX roles_builtin_key ON roles(org_id,builtin_key) WHERE builtin_key IS NOT NULL;
-- Historical seeds used these exact immutable system identities and permission
-- sets. Ambiguous/custom roles remain unclassified and cannot grant Admin status.
UPDATE roles SET builtin_key = CASE display_name WHEN 'Admin' THEN 'admin' WHEN 'Deployer' THEN 'deployer' WHEN 'Viewer' THEN 'viewer' END
WHERE is_system AND created_by='ffffffff-ffff-ffff-ffff-ffffffffffff'
AND ((display_name='Admin' AND permissions=ARRAY['manage_all']::text[])
 OR (display_name='Deployer' AND permissions=ARRAY['write_all']::text[])
 OR (display_name='Viewer' AND permissions=ARRAY['read_all']::text[]));
-- +goose StatementBegin
CREATE FUNCTION preserve_builtin_role_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF OLD.builtin_key IS NOT NULL AND (NEW.builtin_key IS DISTINCT FROM OLD.builtin_key OR NOT NEW.is_system) THEN
        RAISE EXCEPTION 'canonical built-in role identity is immutable';
    END IF;
    RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER preserve_builtin_role_identity BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION preserve_builtin_role_identity();
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM roles WHERE builtin_key IS NOT NULL) THEN
        RAISE EXCEPTION 'cannot downgrade while canonical built-in role identities exist';
    END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER preserve_builtin_role_identity ON roles;
DROP FUNCTION preserve_builtin_role_identity();
DROP INDEX roles_builtin_key;
ALTER TABLE roles DROP CONSTRAINT roles_builtin_system, DROP COLUMN builtin_key;
