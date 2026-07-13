-- +goose Up

-- add a new role for every org_id in the table role with the name 'Deployer' and permissions 'write_all'
INSERT INTO roles (id, org_id, display_name, permissions, created_at, created_by)
SELECT
    gen_random_uuid() as id,
    org_id,
    'Deployer' as display_name,
    ARRAY['write_all'] as permissions,
    now() as created_at,
    'ffffffff-ffff-ffff-ffff-ffffffffffff' as created_by
FROM (
    SELECT DISTINCT org_id
    FROM roles
) distinct_orgs;

-- +goose Down

DELETE FROM roles
WHERE display_name = 'Deployer';


