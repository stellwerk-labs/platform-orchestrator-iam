# Plugin workload identity and platform principals

Contract level `v1alpha`. This page describes how IAM identifies native plugin
workloads and the Data Plane admission checker, and what Core receives.

## Platform principals

A service user has a scope:

| Scope | Belongs to | Roles | Credential | Managed by |
|---|---|---|---|---|
| `organization` | exactly one organization | only in that organization | static `SU-` token | the organization (`/orgs/{orgId}/service-users`) |
| `platform` | no organization | none, ever | a plugin workload principal: exchanged `PWT-` tokens only; a static-token principal: one `SU-` token | platform operators (`/platform-principals`, `/plugin-workload-bindings`) |

The database enforces the platform rules: a platform principal has no
organization, a role row must name its service user's own organization, and a
plugin workload principal never holds a static token. A platform principal
keeps the service user identity variant, so `userid.IsServiceUser` is true for
it.

Because it belongs to no organization, no organization route reaches a
platform principal: an organization's service user list never contains it, and
regenerate, delete and role replacement answer 404. Removing an organization's
access (`/internal/orgs/{orgId}/actions/remove-access`) expires only that
organization's service users. Every organization, project or environment
authorization check for a platform principal is denied, and it has no
organization memberships.

## Who manages them

Every `/platform-principals` and `/plugin-workload-bindings` route requires the
platform permission `plugin_workload_binding_write`, held only by the principals
in `PLUGIN_WORKLOAD_BINDING_WRITERS` and by IAM's internal system identity.
Organization roles never grant it. Creating a static-token principal and
regenerating its token additionally require a user or the internal system
identity: like service user creation, a service user may not mint a long-lived
credential. A plugin workload never holds a platform permission.

IAM logs every change with the operator: `created plugin workload binding`,
`revoked plugin workload binding`, `created static-token platform principal`,
`regenerated platform principal token` and `deleted platform principal`. The
principal itself records who created it or last regenerated its token
(`generated_by`, `generated_at`).

## Plugin workloads

A plugin installation serves every organization it is enabled for through one
platform principal. Core confines each call to the organization of its path.

1. Bind the plugin's Kubernetes ServiceAccount and create its principal in one
   request:

   ```bash
   curl -X POST "${PO_API_URL}/plugin-workload-bindings" \
     -H "Authorization: Bearer ${PLATFORM_ORCHESTRATOR_TOKEN}" \
     -H "Content-Type: application/json" \
     -d '{
       "issuer": "https://kubernetes.default.svc.cluster.local",
       "namespace": "stellwerk-plugins",
       "service_account": "example-plugin-native-plugin-runtime",
       "audience": "platform-orchestrator-plugin-workload",
       "platform_principal": {"display_name": "example-plugin"},
       "plugin_id": "dev.stellwerk.example",
       "installation_id": "44444444-4444-4444-4444-444444444444"
     }'
   ```

   The answer names the new principal as `service_user_id` with
   `"service_user_scope": "platform"`. Record that UUID as the installation's
   `service_user_id` in the Core Plugin Manager.

2. The runtime's token sidecar exchanges the projected ServiceAccount token at
   `POST /auth/plugin-workload-token` and authenticates as the principal.

Exactly one of `platform_principal` and `service_user_id` is required.
`service_user_id` names an existing plugin workload principal without a
binding. Use it after a revocation or to move the plugin to another
ServiceAccount: the principal, and therefore the identity Core records, stays
the same. An organization service user or a static-token principal cannot be
bound. A ServiceAccount and a principal each have at most one binding.

Revoking the binding (`DELETE /plugin-workload-bindings/{bindingId}`) deletes
every token issued for it; the next request with such a token fails. The
principal stays without any credential until a new binding names it. Deleting
the principal (`DELETE /platform-principals/{principalId}`) also deletes its
binding and tokens.

A plugin workload principal holds no role, so it cannot register its plugin's
capabilities. Core registers them for every organization the installation is
enabled for, through `PUT /orgs/{orgId}/plugins/{pluginId}/capabilities` as
IAM's internal system identity.

### Bindings of organization service users

Bindings created before platform principals existed may name an organization
service user (`"service_user_scope": "organization"`). They keep working, with
these limits:

- While the service user holds any role, the exchange refuses it, its issued
  workload tokens stop authenticating at the next request, and the transitional
  static-token adapter (`PLUGIN_WORKLOAD_STATIC_TOKEN_ADAPTER`) does not keep
  its static token. A service user created without a `roles` field holds the
  organization's Admin role, so such a binding stops serving.
- No role can be assigned to a bound service user (409).
- Removing the organization's access expires the service user and stops the
  plugin for every organization.

Replace such a binding with a platform principal: revoke it, create a new
binding with `platform_principal`, and record the new principal in the
installation.

## The Data Plane admission checker

The Data Plane holds one admission checker token for the plugin dispatches of
every installation and organization. Make it a static-token platform principal:

```bash
curl -X POST "${PO_API_URL}/platform-principals" \
  -H "Authorization: Bearer ${PLATFORM_OPERATOR_USER_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Data Plane admission checker", "expiry_in_days": 365}'
```

The answer contains the token once. Store it in the Secret behind the Data
Plane's `EXTERNAL_DEPLOYMENT_CORE_BEARER_TOKEN_FILE` and record the principal's
`id` as `admission_checker_id` of every installation in the Core Plugin
Manager.

- `POST /platform-principals/{principalId}/actions/regenerate` with
  `{"expiry_in_days": N}` issues a new token. The previous one stops
  authenticating; because of the authentication cache this can take up to a
  minute. Update the Secret and restart the Data Plane, which reads the file at
  startup.
- `DELETE /platform-principals/{principalId}` revokes it, again within the
  authentication cache TTL.
- The token expires like any service user token. Regenerate it in time.
- A plugin workload principal has no static token; regenerating it answers 409.

## What Core receives

Authentication (`/internal/authenticate`) returns only `From` (the principal's
UUID) and `X-Token-Hash`. There is no organization claim for any principal. Core
recognizes the plugin and the checker by identity: the request's `From` must
equal the installation's `service_user_id` or `admission_checker_id`.

To verify an identity before recording it, Core reads:

- `GET /internal/plugin-workload-bindings?plugin_id=&installation_id=`: the
  installation's bindings with `service_user_id` and `service_user_scope`. The
  plugin's principal must appear there with scope `platform`.
- `GET /platform-principals/{principalId}` (as IAM's internal system identity):
  the checker must be a platform principal with `"credential": "static_token"`
  and no `workload_binding_id`.

## Gateway routes

Route `/auth/plugin-workload-token`, `/plugin-workload-bindings`,
`/plugin-workload-bindings/{bindingId}`, `/platform-principals`,
`/platform-principals/{principalId}` and
`/platform-principals/{principalId}/actions/regenerate` to IAM. Never route
`/internal/` paths through the gateway.
