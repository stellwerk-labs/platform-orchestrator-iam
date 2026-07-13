-- +goose Up

DROP TABLE sso_configuration;
CREATE TABLE sso_configuration (
    org_id text NOT NULL,
    provider_org_id text NOT NULL,
    CONSTRAINT sso_configuration_pk PRIMARY KEY (org_id),
    CONSTRAINT unique_provider_org_id UNIQUE (provider_org_id)
);

-- +goose Down

DROP TABLE sso_configuration IF EXISTS;
CREATE TABLE sso_configuration (
    org_id text NOT NULL,
    connection_id text NOT NULL,
    CONSTRAINT sso_configuration_pk PRIMARY KEY (org_id)
);
