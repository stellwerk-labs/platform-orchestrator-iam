-- +goose Up
CREATE TABLE plugin_capabilities (
    org_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    level TEXT NOT NULL CHECK (level IN ('read', 'write', 'manage')),
    scopes TEXT[] NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, plugin_id, id),
    UNIQUE (org_id, id),
    CHECK (id LIKE 'plugin.' || plugin_id || '.%'),
    CHECK (substring(id FROM char_length('plugin.' || plugin_id || '.') + 1) ~ '^[a-z]([a-z0-9-]*[a-z0-9])?$'),
    CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY['organization', 'project', 'environment']::TEXT[])
);

CREATE INDEX plugin_capabilities_org ON plugin_capabilities (org_id);

-- +goose Down
DROP TABLE IF EXISTS plugin_capabilities;
