-- +goose Up

CREATE TABLE invitations (
    id uuid primary key not null,
    org_id text not null,
    created_at timestamp without time zone not null,
    expires_at timestamp without time zone not null,
    created_by uuid not null,
    redemption_token_hash bytea not null,
    email_address text not null,
    membership_subject_type membership_subject_type not null,
    membership_subject text not null
);

CREATE INDEX ON invitations(created_at);
CREATE INDEX ON invitations(org_id);

-- +goose Down

DROP TABLE IF EXISTS invitations;
