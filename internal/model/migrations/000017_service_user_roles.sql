-- +goose Up

CREATE TABLE service_user_roles (
    service_user_id uuid not null references service_user_tokens(id) on delete cascade,
    org_id text not null,
    role_id uuid not null,
    created_at timestamp without time zone not null,
    primary key (org_id, service_user_id, role_id),
    constraint fk_service_user_roles_role_org_id foreign key (role_id, org_id) references roles(id, org_id)
);

INSERT into service_user_roles (service_user_id, org_id, role_id, created_at)
SELECT sut.id, sut.org_id, r.id, now()
FROM service_user_tokens sut
JOIN roles r ON r.org_id = sut.org_id
WHERE r.display_name = 'Admin';

-- +goose Down

DROP TABLE service_user_roles IF EXISTS;
