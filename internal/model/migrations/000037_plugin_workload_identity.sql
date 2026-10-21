-- +goose Up
CREATE TABLE plugin_workload_bindings (
    id UUID PRIMARY KEY,
    issuer TEXT NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    namespace TEXT NOT NULL CHECK (char_length(namespace) <= 63 AND namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'),
    service_account TEXT NOT NULL CHECK (
        char_length(service_account) <= 253
        AND service_account ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$'
    ),
    audience TEXT NOT NULL CHECK (char_length(audience) BETWEEN 1 AND 255 AND audience ~ '^[!-~]+$'),
    service_user_id UUID NOT NULL,
    plugin_id TEXT NOT NULL CHECK (char_length(plugin_id) <= 200 AND plugin_id ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])$'),
    installation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID NOT NULL,
    CONSTRAINT plugin_workload_bindings_service_account UNIQUE (issuer, namespace, service_account),
    CONSTRAINT plugin_workload_bindings_service_user UNIQUE (service_user_id),
    CONSTRAINT plugin_workload_bindings_service_user_fk FOREIGN KEY (service_user_id)
        REFERENCES service_user_tokens (id) ON DELETE CASCADE
);

CREATE TABLE plugin_workload_tokens (
    token_sha256_hash BYTEA PRIMARY KEY CHECK (octet_length(token_sha256_hash) = 32),
    binding_id UUID NOT NULL REFERENCES plugin_workload_bindings (id) ON DELETE CASCADE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > issued_at AND expires_at <= issued_at + INTERVAL '15 minutes')
);

CREATE INDEX plugin_workload_tokens_binding ON plugin_workload_tokens (binding_id);
CREATE INDEX plugin_workload_tokens_expires_at ON plugin_workload_tokens (expires_at);

-- +goose Down
DROP TABLE IF EXISTS plugin_workload_tokens;
DROP TABLE IF EXISTS plugin_workload_bindings;
