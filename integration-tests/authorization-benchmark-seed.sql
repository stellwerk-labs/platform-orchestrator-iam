\if :{?developer_count}
\else
\set developer_count 5000
\endif

\if :{?developers_per_org}
\else
\set developers_per_org 50
\endif

\if :{?projects_per_developer}
\else
\set projects_per_developer 5
\endif

BEGIN;

DELETE FROM users WHERE display_name LIKE 'Authorization Benchmark Developer %';
DELETE FROM roles WHERE org_id LIKE 'authorization-benchmark-org-%';
DELETE FROM authorization_resources WHERE org_id LIKE 'authorization-benchmark-org-%';

INSERT INTO users (id, display_name, created_at)
SELECT ('10000000-0000-4000-8000-' || lpad(developer::text, 12, '0'))::uuid,
       'Authorization Benchmark Developer ' || developer,
       now()
FROM generate_series(1, :developer_count) AS developer;

INSERT INTO roles (id, org_id, display_name, created_at, permissions)
SELECT ('20000000-0000-4000-8000-' || lpad(org_number::text, 12, '0'))::uuid,
       'authorization-benchmark-org-' || lpad(org_number::text, 4, '0'),
       'Benchmark developer',
       now(),
       ARRAY['read_all', 'deployment_cancel']
FROM generate_series(1, ceil(:developer_count::numeric / :developers_per_org)::integer) AS org_number;

INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role, scope)
SELECT ('30000000-0000-4000-8000-' || lpad(developer::text, 12, '0'))::uuid,
       now(),
       ('10000000-0000-4000-8000-' || lpad(developer::text, 12, '0'))::uuid,
       'authorization-benchmark-org-' || lpad((((developer - 1) / :developers_per_org) + 1)::text, 4, '0'),
       'role',
       ('20000000-0000-4000-8000-' || lpad((((developer - 1) / :developers_per_org) + 1)::text, 12, '0')),
       ('20000000-0000-4000-8000-' || lpad((((developer - 1) / :developers_per_org) + 1)::text, 12, '0'))::uuid,
       ''
FROM generate_series(1, :developer_count) AS developer;

INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
SELECT 'organization:authorization-benchmark-org-' || lpad(org_number::text, 4, '0'),
       'organization',
       'authorization-benchmark-org-' || lpad(org_number::text, 4, '0'),
       'authorization-benchmark-org-' || lpad(org_number::text, 4, '0'),
       NULL
FROM generate_series(1, ceil(:developer_count::numeric / :developers_per_org)::integer) AS org_number;

INSERT INTO authorization_resources (resource, resource_type, resource_id, org_id, parent_resource)
SELECT 'project:authorization-benchmark-project-' || lpad(developer::text, 6, '0') || '-' || project_number,
       'project',
       'authorization-benchmark-project-' || lpad(developer::text, 6, '0') || '-' || project_number,
       'authorization-benchmark-org-' || lpad((((developer - 1) / :developers_per_org) + 1)::text, 4, '0'),
       'organization:authorization-benchmark-org-' || lpad((((developer - 1) / :developers_per_org) + 1)::text, 4, '0')
FROM generate_series(1, :developer_count) AS developer
CROSS JOIN generate_series(1, :projects_per_developer) AS project_number;

COMMIT;

SELECT :developer_count AS developers,
       ceil(:developer_count::numeric / :developers_per_org)::integer AS organizations,
       :developer_count * 2 AS casbin_policies,
       :developer_count * :projects_per_developer AS project_relations;
