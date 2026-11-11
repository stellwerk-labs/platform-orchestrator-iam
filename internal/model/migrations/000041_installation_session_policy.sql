-- +goose Up
CREATE TABLE installation_session_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    browser_idle_timeout_ns BIGINT CHECK(browser_idle_timeout_ns >= 1000000000),
    cli_token_ttl_ns BIGINT CHECK(cli_token_ttl_ns >= 1000000000),
    CHECK ((browser_idle_timeout_ns IS NULL) = (cli_token_ttl_ns IS NULL)),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    updated_by UUID,
    source TEXT NOT NULL DEFAULT 'bootstrap' CHECK(source IN ('bootstrap','api'))
);
INSERT INTO installation_session_policy(singleton) VALUES(true);
CREATE TABLE installation_session_policy_events (
    revision BIGINT PRIMARY KEY,
    browser_idle_timeout_ns BIGINT NOT NULL,
    cli_token_ttl_ns BIGINT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT statement_timestamp(),
    changed_by UUID,
    source TEXT NOT NULL
);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM installation_session_policy WHERE source='api') THEN
        RAISE EXCEPTION 'retain runtime session policy until explicitly migrated back to installation configuration';
    END IF;
END $$;
-- +goose StatementEnd
DROP TABLE installation_session_policy_events;
DROP TABLE installation_session_policy;
