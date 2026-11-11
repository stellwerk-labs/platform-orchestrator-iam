# IAM security maintenance

Unreleased. These notes describe the local maintenance branch, not an available
artifact or a completed deployment.

## Security changes

Official builds use Go 1.26.11, including the net/http MaxBytesReader race fix
for [GO-2026-6859](https://pkg.go.dev/vuln/GO-2026-6859).

Echo 4.16.3 fixes forwarded-header trust and proxy handling. Untrusted forwarding
headers no longer select the SCIM fallback URL scheme; TLS-terminating deployments
should configure `API_HOST_URL` for their public HTTPS origin. The security checker
reuses CP and DP's exact module/checksum and stale advisory-record verification;
other application findings remain blocking.

The existing compression dependency is updated to 1.20.2 for
[GO-2026-6865](https://pkg.go.dev/vuln/GO-2026-6865). Other HTTP, cryptography,
OpenAPI and telemetry dependencies retain their maintenance updates. Membership
reference descriptions use valid OpenAPI 3.0 composition. Identity and permission
semantics are unchanged.

Normal CI now checks source dependencies with pinned govulncheck 1.9.0 and fails
on reachable known vulnerabilities. A passing source scan is not a guarantee
against unknown vulnerabilities or a substitute for deployment qualification.

The image build also scans both the server and authorization migration tool
before packaging them. Builds keep linker symbols so the scanner can distinguish
included functions from unused module dependencies. DWARF debug information
remains omitted. Stripped binaries are rejected by the binary check rather than
treated as a successful scan.

Docker context filtering also excludes `.envrc` variants and direnv state. A
network-disabled Docker COPY test checks these exclusions with public sentinel
files and verifies that application source remains in the context.

## Compatibility and release checks

The disposable self-hosted SSO integration fixture uses the reviewed Keycloak
26.8.1 release, pinned to its multi-platform image digest. Normal integration
tests exercise SSO, SCIM deprovisioning and authorization against this fixture.
An empty test realm does not qualify a live Keycloak database migration: back up
the existing database and follow the vendor upgrade guide before a live change.

Existing published versions and artifacts remain immutable. Use a new patch
version after the normal integration and artifact checks pass. Source builds
following the supported release tooling require Go 1.26.11. Clients using the
corrected vendored API documents must verify their exact published server source
pins before release.
