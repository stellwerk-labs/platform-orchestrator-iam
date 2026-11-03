# Canonical organization Admin verification, release candidate

This candidate adds the optional identity interface used by generic plugin
policies to verify organization Admin membership. Publication and the coordinated
release versions are still pending.

## Changes

- Add a separate generated `shared/adminapi` package for canonical organization
  Admin verification while preserving the existing shared SDK interfaces.
- Distinguish actual organization Admin membership from a custom role carrying
  granular permissions. A role with every plugin permission still does not
  confer the Admin identity required by an Admin-only operation.
- Allow the Control Plane to enforce the declared policy for both plugin reads
  and writes using current authoritative membership.

## Upgrade

Publish the additive IAM shared module before building the matching Control Plane
consumer. Use the qualified coordinated release set and back up the affected
databases before upgrading. Final versions will be added after qualification.

Existing authentication methods and the policies of unrelated endpoints remain
unchanged. This interface verifies membership; it does not grant a plugin licence
or registry download access.
