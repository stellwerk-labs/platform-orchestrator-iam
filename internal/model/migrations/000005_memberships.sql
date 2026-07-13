-- +goose Up

CREATE TYPE membership_subject_type AS ENUM ('virtual-group');

CREATE TABLE memberships (
    -- use an id for the primary key
    id UUID PRIMARY KEY NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    -- each membership is for a user id
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- in an org
    org_id TEXT NOT NULL,
    -- with a particular subject type (eg: virtual-group, group, etc)
    subject_type membership_subject_type NOT NULL,
    -- and subject identifier
    subject TEXT NOT NULL,

    -- this membership is unique
    CONSTRAINT unique_membership UNIQUE (user_id, org_id, subject_type, subject)
);

-- sortable
CREATE INDEX ON memberships (created_at);

-- need to be able lookup memberships by org and type efficiently for things like authorization
CREATE INDEX ON memberships (org_id, subject_type, subject);

-- need to be able to look up memberships by user efficiently for listing memberships on current-user
CREATE INDEX ON memberships (user_id);

-- +goose Down

DROP TABLE IF EXISTS memberships;
