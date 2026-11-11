-- +goose Up
ALTER TABLE session_tokens ADD COLUMN last_active_at TIMESTAMP WITH TIME ZONE;
-- Legacy sessions have no reliable activity history. Do not grant idle sessions
-- another window during an upgrade; users can sign in again.
UPDATE session_tokens SET last_active_at = created_at AT TIME ZONE 'UTC';
ALTER TABLE session_tokens ALTER COLUMN last_active_at SET NOT NULL;
ALTER TABLE session_tokens ALTER COLUMN last_active_at SET DEFAULT statement_timestamp();

-- +goose Down
ALTER TABLE session_tokens DROP COLUMN last_active_at;
