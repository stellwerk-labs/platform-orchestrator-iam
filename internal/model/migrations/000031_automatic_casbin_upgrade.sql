-- +goose Up

CREATE TABLE authorization_migration_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    policy_sha256 text NULL CHECK (policy_sha256 IS NULL OR policy_sha256 ~ '^[0-9a-f]{64}$'),
    reconciled boolean NOT NULL DEFAULT false,
    reconciled_at timestamp with time zone NULL
);

INSERT INTO authorization_migration_state (singleton) VALUES (true);

-- +goose Down

DROP TABLE authorization_migration_state;
