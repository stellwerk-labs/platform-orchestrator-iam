-- +goose Up
-- A platform principal is a service user that belongs to no organization. A
-- plugin workload principal holds no static token and authenticates only
-- through its workload binding; a static-token principal (the Data Plane
-- admission checker) holds one. Organization service users keep their org,
-- expiry and token hash.
ALTER TABLE service_user_tokens
    ADD COLUMN scope TEXT NOT NULL DEFAULT 'organization',
    ALTER COLUMN org_id DROP NOT NULL,
    ALTER COLUMN current_token_expires_at DROP NOT NULL,
    ALTER COLUMN current_token_sha256_hash DROP NOT NULL,
    ADD CONSTRAINT service_user_tokens_scope CHECK (
        (scope = 'organization' AND org_id IS NOT NULL
            AND current_token_expires_at IS NOT NULL AND current_token_sha256_hash IS NOT NULL)
        OR (scope = 'platform' AND org_id IS NULL
            AND (current_token_expires_at IS NULL) = (current_token_sha256_hash IS NULL))
    ),
    ADD CONSTRAINT service_user_tokens_id_org UNIQUE (id, org_id);

CREATE INDEX service_user_tokens_platform ON service_user_tokens (id) WHERE scope = 'platform';

-- A role row names the service user together with its organization, so a
-- platform principal (no organization) can never hold a role, and no service
-- user can hold a role outside its own organization. This replaces the
-- single-column reference with the same cascade.
ALTER TABLE service_user_roles
    ADD CONSTRAINT service_user_roles_service_user_org FOREIGN KEY (service_user_id, org_id)
        REFERENCES service_user_tokens (id, org_id) ON DELETE CASCADE,
    DROP CONSTRAINT service_user_roles_service_user_id_fkey;

-- +goose Down
-- Platform principals cannot be represented below this version; deleting them
-- also deletes their workload bindings and issued workload tokens.
DELETE FROM service_user_tokens WHERE scope = 'platform';

ALTER TABLE service_user_roles
    ADD CONSTRAINT service_user_roles_service_user_id_fkey FOREIGN KEY (service_user_id)
        REFERENCES service_user_tokens (id) ON DELETE CASCADE,
    DROP CONSTRAINT service_user_roles_service_user_org;

DROP INDEX IF EXISTS service_user_tokens_platform;

ALTER TABLE service_user_tokens
    DROP CONSTRAINT service_user_tokens_id_org,
    DROP CONSTRAINT service_user_tokens_scope,
    ALTER COLUMN current_token_sha256_hash SET NOT NULL,
    ALTER COLUMN current_token_expires_at SET NOT NULL,
    ALTER COLUMN org_id SET NOT NULL,
    DROP COLUMN scope;
