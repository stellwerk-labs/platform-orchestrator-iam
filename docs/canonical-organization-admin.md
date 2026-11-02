# Canonical organization Admin predicate

The optional `GET /internal/orgs/{orgId}/administrators/{userId}` endpoint returns
`allowed` from live IAM identity and membership tables. It belongs to the existing
trusted internal service boundary, like internal authorization; it is not a new
public actor-header or bearer-token shortcut.

Only an active human's organization-wide membership in the canonical seeded
Admin role qualifies. Project/Environment scopes, role display names, arbitrary
`manage_all` roles, plugin capabilities, platform privileges, service principals
and the internal-system bypass do not qualify. The CP calls this optional
predicate for `require_org_admin` plugin policy; older IAM returns no supported
predicate and CP fails closed for that policy.

Migration39 adds immutable per-organization `roles.builtin_key`. Historical
backfill accepts only existing system-role seed evidence: the internal-system
creator, exact built-in name and exact original permission set. A custom or
ambiguous historical role stays unclassified and does not acquire Admin authority.
New seeding writes explicit keys. Once classified, the key survives display-name
changes and cannot be reassigned or made non-system. Downgrade refuses to erase
existing canonical identities; use forward recovery with preserved evidence.

The public main shared client/server interfaces are unchanged. The separately
generated optional client lives in `shared/adminapi`, its server in
`internal/adminapi`, and source schema in `openapi/admin.yaml`. No extra shared
module dependency is introduced.

Candidate tests use real PostgreSQL schemas for canonical scope/org membership,
role-name independence, custom-manage_all denial, immediate membership revocation,
historical backfill, downgrade refusal/forward recovery, and the generated client
against the actual validated HTTP handler. This is source-level evidence; the
combined packaged Core/plugin deployment is qualified separately.

## Candidate release impact

Apply migration39 before enabling CP/plugin policy that requires this canonical
predicate. Ordinary authorization and old manifests keep their existing policy;
requiring consumers fail closed against an older/unavailable IAM. Preserve a
private backup and use tested restore/forward recovery, since downgrade cannot
erase classified canonical identities. Ambiguous historical roles remain denied.

The optional `shared/adminapi` package is additive to the existing shared module
and requires coordinated SDK publication plus a CP consumer dependency update.
No public SDK/server version is assigned by this candidate. Its mandatory main
interfaces remain unchanged. The private QA workspace provides the unpublished
package for candidate tests; CP's workspace-off canonical tidy/security gate is
still blocked until the package is available. Local signed source commits do not
establish published SDK availability or complete deployed recovery qualification.
