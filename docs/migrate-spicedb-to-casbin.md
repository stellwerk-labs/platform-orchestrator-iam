# Migrate authorization from SpiceDB to Casbin

This is the supported upgrade path from IAM `v2.0.1` (database schema 29) to
the first Casbin-based IAM release (database schema 30).

PostgreSQL is the source of truth for roles, memberships, service-user role
bindings, and scopes in the SpiceDB release. SpiceDB contains a projection of
that data, so no SpiceDB export is required. The cutover does require a short
IAM maintenance window because the environment-to-project hierarchy must be
rebuilt from the control plane before authorization traffic resumes.

The new IAM image contains `/opt/server/authorization-migrate`. Its four
commands emit JSON to standard output and return a non-zero status when a check
fails:

- `preflight` validates schema 29, legacy role references, scope syntax, and
  projection coverage. It records a SHA-256 fingerprint of all RBAC data.
- `apply` verifies that fingerprint, migrates to schema 30, and reconciles the
  full organization/project/environment hierarchy from the control plane.
- `verify` checks schema 30, data identity, resource coverage, and parentage.
- `rollback` refuses to downgrade unless the RBAC fingerprint is unchanged.

## Preconditions

1. Upgrade IAM to `v2.0.1` first. Earlier database versions are deliberately
   rejected instead of being treated as an untested direct-upgrade path.
2. Make the new IAM image available without deploying it.
3. Confirm the migration container can reach the IAM PostgreSQL database and
   the control-plane HTTP service.
4. Retain the old IAM image, the SpiceDB deployment configuration, its
   PostgreSQL database, and its credentials for the rollback window.
5. Prepare a tested PostgreSQL backup and restore procedure. The guarded schema
   rollback is convenient, but the backup is the recovery path after RBAC data
   changes or an unexpected failure.

## Cutover

The examples use Docker syntax to make the required process explicit. Use the
equivalent one-off Pod or Job in Kubernetes. `iam-database.env` must expose
either `DATABASE_URL` or the usual IAM `DATABASE_*` variables.

Set the image and network for the deployment:

```bash
export IAM_CASBIN_IMAGE=ghcr.io/stellwerk-labs/platform-orchestrator-iam:<casbin-version>
export IAM_NETWORK=<deployment-network>
```

1. Stop every IAM replica and keep it stopped. Do not allow membership,
   service-user role, or role writes during the remaining steps.

2. Run the read-only preflight and retain its report outside the container:

```bash
docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  "$IAM_CASBIN_IMAGE" preflight > iam-casbin-preflight.json

jq -e '.ready == true and .schema_version == 29' iam-casbin-preflight.json
export IAM_POLICY_SHA256="$(jq -r .policy_sha256 iam-casbin-preflight.json)"
```

3. Take a consistent backup after IAM is stopped. Keep the backup together
   with the preflight report and verify that the archive is readable:

```bash
pg_dump --format=custom --file=iam-before-casbin.dump "$DATABASE_URL"
pg_restore --list iam-before-casbin.dump >/dev/null
```

4. Apply the migration. This command is idempotent after schema 30, so rerun it
   if control-plane reconciliation was interrupted:

```bash
docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  -e CONTROL_PLANE_URL=http://platform-orchestrator-control-plane:8080 \
  "$IAM_CASBIN_IMAGE" apply \
  --policy-sha256 "$IAM_POLICY_SHA256" > iam-casbin-apply.json

jq -e '.ready == true and .schema_version == 30' iam-casbin-apply.json
```

Do not start IAM if `apply` fails. Fix database or control-plane connectivity
and rerun the same command. A failed hierarchy check is fail-closed; it cannot
silently grant access.

5. Deploy the Casbin IAM image with its normal PostgreSQL and NATS settings.
   Remove `SPICEDB_URL` and `SPICEDB_PRE_SHARED_KEY`; no SpiceDB endpoint is
   used by the new service.

6. Run an independent verification against the live database:

```bash
docker run --rm --network "$IAM_NETWORK" \
  --entrypoint /opt/server/authorization-migrate \
  --env-file iam-database.env \
  "$IAM_CASBIN_IMAGE" verify \
  --policy-sha256 "$IAM_POLICY_SHA256" > iam-casbin-verify.json

jq -e '.ready == true and .schema_version == 30' iam-casbin-verify.json
```

7. Smoke-test at least one organization-level role, one project-scoped role,
   one environment-scoped role, and one service user before reopening traffic.

Keep SpiceDB and its database intact but stopped for the chosen rollback
window. It can be permanently removed after the new release has been stable
and a fresh IAM backup has been taken.

## Rollback

Stop every Casbin IAM replica before either rollback path.

If no role, membership, or service-user role data changed after cutover, use
the guarded schema downgrade:

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
`v2.0.1`, run both reconciliation endpoints for every organization, and then
verify authorization. Restoring the backup also reverts authentication and
session changes made after the cutover, which is why the guarded downgrade is
preferable when its fingerprint check passes.

## Qualification

`make test-authorization-upgrade` runs the supported path entirely in Docker.
It boots the tagged `v2.0.1` server with PostgreSQL, NATS, and SpiceDB; seeds
organization-, project-, and environment-scoped human and service-user roles;
runs preflight and apply; stops SpiceDB; verifies Casbin decisions through the
HTTP API; and exercises the guarded rollback to schema 29.
