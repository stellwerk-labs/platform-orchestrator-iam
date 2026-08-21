#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
legacy_ref=${LEGACY_REF:-v2.0.1}
run_id="stellwerk-authz-upgrade-$$"
network_name="$run_id"
postgres_name="$run_id-postgres"
nats_name="$run_id-nats"
spicedb_name="$run_id-spicedb"
cp_name="$run_id-cp"
legacy_iam_name="$run_id-legacy-iam"
casbin_iam_name="$run_id-casbin-iam"
casbin_iam_second_name="$run_id-casbin-iam-second"
legacy_image="$run_id-legacy"
casbin_image="$run_id-casbin"
temp_dir=$(mktemp -d)

cleanup() {
  docker rm -f "$legacy_iam_name" "$casbin_iam_name" "$casbin_iam_second_name" "$cp_name" "$spicedb_name" "$nats_name" "$postgres_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
  docker image rm "$legacy_image" "$casbin_image" >/dev/null 2>&1 || true
  rm -rf "$temp_dir"
}
trap cleanup EXIT INT TERM

wait_for_command() {
  container=$1
  shift
  attempts=0
  until docker exec "$container" "$@" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 60 ]; then
      echo "timed out waiting for $container" >&2
      docker logs "$container" >&2 || true
      return 1
    fi
    sleep 1
  done
}

wait_for_http() {
  container=$1
  attempts=0
  until docker run --rm --network "$network_name" curlimages/curl:8.16.0 -fsS "http://$container:8080/health" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 90 ]; then
      echo "timed out waiting for HTTP health on $container" >&2
      docker logs "$container" >&2 || true
      return 1
    fi
    sleep 1
  done
}

run_migration_tool() {
  docker run --rm --network "$network_name" \
    --entrypoint /opt/server/authorization-migrate \
    -e DATABASE_URL="postgres://iam:secret@$postgres_name:5432/iam?sslmode=disable" \
    "$casbin_image" "$@"
}

start_casbin_iam() {
  container_name=$1
  docker run -d --name "$container_name" --network "$network_name" \
    -e PORT=8080 \
    -e DATABASE_NAME=iam -e DATABASE_USER=iam -e DATABASE_PASSWORD=secret \
    -e DATABASE_HOST="$postgres_name" -e DATABASE_PORT=5432 \
    -e CONTROL_PLANE_URL="http://$cp_name" \
    -e SESSION_TOKEN_COOKIE_DOMAIN=localhost -e UI_HOST_URL=http://localhost \
    -e NATS_URL="nats://$nats_name:4222" -e NATS_BOOTSTRAP_STREAMS=true \
    -e SHUTDOWN_DELAY=0s \
    "$casbin_image" >/dev/null
}

authorize_on() {
  container=$1
  expected_status=$2
  user_id=$3
  resource=$4
  permission=$5
  actual_status=$(docker run --rm --network "$network_name" curlimages/curl:8.16.0 -sS -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -d "{\"user_id\":\"$user_id\",\"checks\":[{\"resource\":\"$resource\",\"permission\":\"$permission\"}]}" \
    "http://$container:8080/internal/authorize")
  test "$actual_status" = "$expected_status"
}

git -C "$repo_dir" archive "$legacy_ref" | tar -x -C "$temp_dir"
docker build -q -t "$legacy_image" "$temp_dir" >/dev/null
docker build -q -t "$casbin_image" "$repo_dir" >/dev/null

docker network create "$network_name" >/dev/null
docker run -d --name "$postgres_name" --network "$network_name" \
  -e POSTGRES_DB=iam -e POSTGRES_USER=iam -e POSTGRES_PASSWORD=secret \
  postgres:17-alpine >/dev/null
docker run -d --name "$nats_name" --network "$network_name" nats:2.12.0-alpine --jetstream >/dev/null
docker run -d --name "$spicedb_name" --network "$network_name" \
  -e SPICEDB_GRPC_PRESHARED_KEY=t0k3n authzed/spicedb:v1.45.4 serve-testing >/dev/null
docker run -d --name "$cp_name" --network "$network_name" \
  -v "$repo_dir/integration-tests/authorization-upgrade-nginx.conf:/etc/nginx/nginx.conf:ro" nginx:1.29-alpine >/dev/null

wait_for_command "$postgres_name" pg_isready -U iam -d iam

docker run -d --name "$legacy_iam_name" --network "$network_name" \
  -e PORT=8080 \
  -e DATABASE_NAME=iam -e DATABASE_USER=iam -e DATABASE_PASSWORD=secret \
  -e DATABASE_HOST="$postgres_name" -e DATABASE_PORT=5432 \
  -e CONTROL_PLANE_URL="http://$cp_name" \
  -e SESSION_TOKEN_COOKIE_DOMAIN=localhost -e UI_HOST_URL=http://localhost \
  -e SPICEDB_URL="$spicedb_name:50051" -e SPICEDB_PRE_SHARED_KEY=t0k3n \
  -e NATS_URL="nats://$nats_name:4222" -e NATS_BOOTSTRAP_STREAMS=true \
  -e SHUTDOWN_DELAY=0s \
  "$legacy_image" >/dev/null
wait_for_http "$legacy_iam_name"

docker exec -i "$postgres_name" psql -v ON_ERROR_STOP=1 -U iam -d iam >/dev/null <<'SQL'
INSERT INTO users (id, display_name, created_at) VALUES
  ('10000000-0000-4000-8000-000000000001', 'Project admin', now()),
  ('10000000-0000-4000-8000-000000000002', 'Organization viewer', now()),
  ('10000000-0000-4000-8000-000000000003', 'Custom auditor', now());

INSERT INTO roles (id, org_id, display_name, created_at, permissions) VALUES
  ('20000000-0000-4000-8000-000000000001', 'acme', 'Admin', now(), ARRAY['manage_all']),
  ('20000000-0000-4000-8000-000000000002', 'acme', 'Deployer', now(), ARRAY['write_all']),
  ('20000000-0000-4000-8000-000000000003', 'acme', 'Viewer', now(), ARRAY['read_all']),
  ('20000000-0000-4000-8000-000000000004', 'acme', 'Auditor', now(), ARRAY['audit_logs']);

INSERT INTO memberships (id, created_at, user_id, org_id, subject_type, subject, role, scope) VALUES
  ('50000000-0000-4000-8000-000000000001', now(), '10000000-0000-4000-8000-000000000001', 'acme', 'role', '20000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001', 'project:30000000-0000-4000-8000-000000000001'),
  ('50000000-0000-4000-8000-000000000002', now(), '10000000-0000-4000-8000-000000000002', 'acme', 'role', '20000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000003', ''),
  ('50000000-0000-4000-8000-000000000003', now(), '10000000-0000-4000-8000-000000000003', 'acme', 'role', '20000000-0000-4000-8000-000000000004', '20000000-0000-4000-8000-000000000004', 'project:30000000-0000-4000-8000-000000000001');

INSERT INTO service_user_tokens (id, org_id, display_name, generated_at, current_token_expires_at, current_token_sha256_hash) VALUES
  ('60000000-0000-4000-8000-000000000001', 'acme', 'Environment deployer', now(), now() + interval '1 day', decode(repeat('11', 32), 'hex'));
INSERT INTO service_user_roles (service_user_id, org_id, role_id, created_at, scope) VALUES
  ('60000000-0000-4000-8000-000000000001', 'acme', '20000000-0000-4000-8000-000000000002', now(), 'env:40000000-0000-4000-8000-000000000001');

INSERT INTO scoped_roles (id, org_id, scope, org_role_id)
SELECT gen_random_uuid(), 'acme', scope, role_id
FROM (VALUES
  ('project:30000000-0000-4000-8000-000000000001'),
  ('env:40000000-0000-4000-8000-000000000001')
) AS scopes(scope)
CROSS JOIN (VALUES
  ('20000000-0000-4000-8000-000000000001'::uuid),
  ('20000000-0000-4000-8000-000000000002'::uuid),
  ('20000000-0000-4000-8000-000000000003'::uuid),
  ('20000000-0000-4000-8000-000000000004'::uuid)
) AS roles(role_id);
SQL

docker run --rm --network "$network_name" curlimages/curl:8.16.0 -fsS -X POST \
  "http://$legacy_iam_name:8080/internal/orgs/acme/actions/sync-scopes" >/dev/null
docker run --rm --network "$network_name" curlimages/curl:8.16.0 -fsS -X POST \
  "http://$legacy_iam_name:8080/internal/orgs/acme/actions/sync-spicedb" >/dev/null
authorize_on "$legacy_iam_name" 204 10000000-0000-4000-8000-000000000001 env:40000000-0000-4000-8000-000000000001 manage
authorize_on "$legacy_iam_name" 204 10000000-0000-4000-8000-000000000002 env:40000000-0000-4000-8000-000000000001 read
authorize_on "$legacy_iam_name" 204 60000000-0000-4000-8000-000000000001 env:40000000-0000-4000-8000-000000000001 write

run_migration_tool preflight >"$temp_dir/preflight.json"
policy_sha256=$(sed -n 's/.*"policy_sha256": "\([0-9a-f]*\)".*/\1/p' "$temp_dir/preflight.json")
test "${#policy_sha256}" -eq 64

docker stop "$legacy_iam_name" >/dev/null
docker stop "$spicedb_name" >/dev/null
docker stop "$cp_name" >/dev/null

# The first automatic attempt migrates the schema but cannot reconcile while
# the control plane is unavailable. It must fail closed and leave retry state.
start_casbin_iam "$casbin_iam_name"
failed_status=$(docker wait "$casbin_iam_name")
test "$failed_status" != "0"

# A restarted replica and a second replica may start concurrently. The advisory
# lock serializes reconciliation and both must become healthy without SpiceDB.
docker start "$cp_name" >/dev/null
docker start "$casbin_iam_name" >/dev/null
start_casbin_iam "$casbin_iam_second_name"
wait_for_http "$casbin_iam_name"
wait_for_http "$casbin_iam_second_name"

run_migration_tool verify --policy-sha256 "$policy_sha256" >"$temp_dir/verify.json"
grep -q '"ready": true' "$temp_dir/verify.json"
grep -q '"environments": 1' "$temp_dir/verify.json"
docker exec "$postgres_name" psql -U iam -d iam -Atc \
  "SELECT reconciled FROM authorization_migration_state WHERE singleton" | grep -qx t

authorize_on "$casbin_iam_name" 204 10000000-0000-4000-8000-000000000001 env:40000000-0000-4000-8000-000000000001 manage
authorize_on "$casbin_iam_name" 204 10000000-0000-4000-8000-000000000002 env:40000000-0000-4000-8000-000000000001 read
authorize_on "$casbin_iam_name" 204 10000000-0000-4000-8000-000000000003 project:30000000-0000-4000-8000-000000000001 audit_logs
authorize_on "$casbin_iam_name" 403 10000000-0000-4000-8000-000000000003 project:30000000-0000-4000-8000-000000000001 write
authorize_on "$casbin_iam_name" 204 60000000-0000-4000-8000-000000000001 env:40000000-0000-4000-8000-000000000001 write
authorize_on "$casbin_iam_name" 403 60000000-0000-4000-8000-000000000001 project:30000000-0000-4000-8000-000000000001 write

docker stop "$casbin_iam_name" >/dev/null
docker stop "$casbin_iam_second_name" >/dev/null

docker exec "$postgres_name" psql -v ON_ERROR_STOP=1 -U iam -d iam -c \
  "UPDATE roles SET permissions = ARRAY['audit_logs', 'temporary_change'] WHERE id = '20000000-0000-4000-8000-000000000004'" >/dev/null
if run_migration_tool rollback --confirm-no-rbac-writes --policy-sha256 "$policy_sha256" >/dev/null 2>&1; then
  echo "rollback unexpectedly accepted changed RBAC data" >&2
  exit 1
fi
docker exec "$postgres_name" psql -v ON_ERROR_STOP=1 -U iam -d iam -c \
  "UPDATE roles SET permissions = ARRAY['audit_logs'] WHERE id = '20000000-0000-4000-8000-000000000004'" >/dev/null

run_migration_tool rollback --confirm-no-rbac-writes --policy-sha256 "$policy_sha256" >"$temp_dir/rollback.json"
grep -q '"schema_version": 29' "$temp_dir/rollback.json"
grep -q '"ready": true' "$temp_dir/rollback.json"

echo "SpiceDB-to-Casbin upgrade, authorization, verification, and guarded rollback passed."
