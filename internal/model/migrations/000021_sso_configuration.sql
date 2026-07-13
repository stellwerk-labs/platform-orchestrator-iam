-- +goose Up

CREATE TABLE sso_configuration (
	org_id text NOT NULL,
    connection_id text NOT NULL,
    CONSTRAINT sso_configuration_pk PRIMARY KEY (org_id)
);

-- +goose Down

DROP TABLE sso_configuration IF EXISTS;
