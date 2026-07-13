-- +goose Up

CREATE TABLE scoped_roles (
    id uuid not null primary key,
    org_id text not null,
    scope text not null,
    org_role_id uuid not null,
    constraint unique_scope_per_org unique (org_id, org_role_id, scope),
    constraint fk_scoped_roles_org_role_org_id foreign key(org_role_id, org_id) REFERENCES roles(id, org_id) on delete cascade
);

CREATE INDEX idx_scoped_roles_org_id ON scoped_roles (org_id);

-- +goose Down

DROP TABLE scoped_roles IF EXISTS;
