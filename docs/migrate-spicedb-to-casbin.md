# Migrate authorization from SpiceDB to Casbin

This is the supported upgrade path from IAM `v2.0.1` (database schema 29) to
the first Casbin-based IAM release (database schema 31).

PostgreSQL is the source of truth for roles, memberships, service-user role
bindings, and scopes in the SpiceDB release. SpiceDB contains a projection of
that data, so no SpiceDB export is required. Project and environment ancestry
is reconstructed from the control plane before IAM serves authorization
traffic.

## Automatic startup upgrade

Starting the Casbin IAM image against schema 29 performs the complete upgrade:

1. IAM obtains a PostgreSQL advisory lock. One replica performs the upgrade;
   concurrent replicas wait and then inspect the verified result.
2. A read-only preflight validates legacy role references, scope syntax, and
   projection coverage and fingerprints all RBAC records.
3. Database migrations create the Casbin resource hierarchy and durable,
   resumable migration state.
4. IAM reads every organization, project, and environment from the control
   plane and reconciles the hierarchy.
5. IAM verifies schema 31, RBAC data identity, resource coverage, and parentage,
   records completion, and only then starts its HTTP server and becomes ready.

If PostgreSQL or the control plane is unavailable, or any validation fails, IAM
exits before serving traffic. Kubernetes can restart it safely: schema changes
and reconciliation are idempotent, and the recorded state resumes an
interrupted attempt. Once the upgrade is complete, later legitimate RBAC
changes do not have to match the original migration fingerprint.

The Platform Orchestrator Helm chart `0.4.0` sets the IAM Deployment strategy
to `Recreate`. This creates a short maintenance window and prevents old
SpiceDB-based pods from writing schema 29 while a Casbin pod upgrades it. For
Helm installations, follow the chart's
`docs/migrations/spicedb-to-casbin.md` procedure; no one-off migration Job is
needed.

## Preconditions

1. Upgrade IAM to `v2.0.1` first. Earlier database versions are deliberately
   rejected instead of being treated as an untested direct-upgrade path.
2. Confirm the new IAM process can reach its PostgreSQL database and the
   control-plane HTTP service.
3. Retain the old IAM image, the SpiceDB deployment configuration, its
   PostgreSQL database, and its credentials for the rollback window.
4. Prepare and test a PostgreSQL backup and restore procedure. The guarded
   schema rollback is convenient, but the backup is the recovery path after
   RBAC data changes or an unexpected failure.
5. Outside Helm, stop every old IAM replica before starting the new image. Do
   not use a rolling update across this database compatibility boundary.

## Verification and recovery utility

The image includes `/opt/server/authorization-migrate` for diagnostics, custom
orchestrators, and rollback. Its commands emit JSON to standard output and
return a non-zero status when a check fails:

- `preflight` validates schema 29 and records a SHA-256 fingerprint of RBAC
  data without changing the database.
- `apply` runs the same serialized and resumable path as normal IAM startup and
  requires the saved preflight fingerprint.
- `verify` checks schema 31, data identity, resource coverage, and parentage. A
  preflight fingerprint is optional and adds an unchanged-RBAC check.
- `rollback` refuses to downgrade unless the supplied RBAC fingerprint is
  unchanged.

The examples below use Docker syntax. `iam-database.env` must expose either
`DATABASE_URL` or the normal IAM `DATABASE_*` variables.

```bash
export IAM_CASBIN_IMAGE=ghcr.io/stellwerk-labs/platform-orchestrator-iam:v2.1.0
export IAM_NETWORK=<deployment-network>

docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  "$IAM_CASBIN_IMAGE" verify > iam-casbin-verify.json

jq -e '.ready == true and .schema_version == 31' iam-casbin-verify.json
```

For a custom platform that cannot run the normal server entrypoint, stop every
legacy IAM replica, run `preflight`, take a consistent database backup, and run
`apply` with the saved fingerprint:

```bash
docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  "$IAM_CASBIN_IMAGE" preflight > iam-casbin-preflight.json

jq -e '.ready == true and .schema_version == 29' iam-casbin-preflight.json
export IAM_POLICY_SHA256="$(jq -r .policy_sha256 iam-casbin-preflight.json)"

pg_dump --format=custom --file=iam-before-casbin.dump "$DATABASE_URL"
pg_restore --list iam-before-casbin.dump >/dev/null

docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  -e CONTROL_PLANE_URL=http://platform-orchestrator-control-plane:8080 \
  "$IAM_CASBIN_IMAGE" apply \
  --policy-sha256 "$IAM_POLICY_SHA256" > iam-casbin-apply.json

jq -e '.ready == true and .schema_version == 31' iam-casbin-apply.json
```

Do not start IAM if `apply` fails. Fix database or control-plane connectivity
and rerun the same command. A failed hierarchy check is fail-closed and cannot
silently grant access.

## Rollback

Keep SpiceDB and its database intact but stopped for the chosen rollback
window. Stop every Casbin IAM replica before either rollback path.

If no role, membership, or service-user role data changed after cutover, use
the guarded schema downgrade with the fingerprint saved by `preflight`:

```bash
docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  "$IAM_CASBIN_IMAGE" rollback \
  --confirm-no-rbac-writes \
  --policy-sha256 "$IAM_POLICY_SHA256" > iam-spicedb-rollback.json

jq -e '.ready == true and .schema_version == 29' iam-spicedb-rollback.json
```

Then start the retained SpiceDB deployment and IAM `v2.0.1`. Before reopening
traffic, call both legacy reconciliation endpoints for every organization:

```text
POST /internal/orgs/{orgId}/actions/sync-scopes
POST /internal/orgs/{orgId}/actions/sync-spicedb
```

If `rollback` reports a changed fingerprint, do not force a schema downgrade.
Restore `iam-before-casbin.dump`, start the retained SpiceDB deployment and IAM
`v2.0.1`, run both legacy reconciliation endpoints for every organization, and
then verify authorization. Restoring the backup also reverts authentication and
session changes made after the cutover.

## Qualification

`make test-authorization-upgrade` runs the supported path entirely in Docker.
It boots the tagged `v2.0.1` server with PostgreSQL, NATS, and SpiceDB; seeds
organization-, project-, and environment-scoped human and service-user roles;
and records legacy authorization results. It then proves automatic startup
fails closed during a control-plane outage, starts two replacement replicas
concurrently, verifies the serialized and resumed migration, stops SpiceDB,
repeats the authorization checks, and exercises guarded rollback to schema 29.
