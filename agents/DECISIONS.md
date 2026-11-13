# Decisions

- Upgrade qualification may supply a verified isolated current-image context;
  ordinary use retains its repository default. Legacy released source remains
  a separate exact historical baseline. Fixture services use immutable digests.

- Preserve the complete pinned Distroless base and BuildKit SBOM/provenance.
- Reproducibility compares actual platform payload manifests/configurations/layers/binaries/notices. Attestation and full index variance is recorded, not suppressed.
- Collect production notice graphs separately for each Linux architecture and all shipped executables. Restrict SDK classifier exceptions to exact declared module identities and verified legal bytes/source provenance.
- The application's classifier prefix may cover only its own root module and exact shared SDK from the same source checkout. Other similarly prefixed module identities fail; the own SDK receives the actual source root LICENSE explicitly.
- The sole binary false-positive policy is bound to an exact reviewed finding, adjacent source literal hashes, ELF architecture, dependency version/checksum, no replacement and Go toolchain metadata. Ordinary-file scanning has no such exception, and artifact-owned ignore controls are rejected.

## Installation settings and Provider retirement

- Session policy changes serialize with user authentication and renewal; persist explicit human settings grants, revision checks and audit records. Environment durations seed policy once, while saved installation policy survives restart.


## 2026-11-12: IAM database TLS

- Preserve existing permissions, confirmation and default behavior. PostgreSQL TLS is opt-in through `DATABASE_SSLMODE`; use existing driver and certificate mechanisms.
- Catalogue filters use complete optional summaries, omit version data for core-only readers, and keep unavailable distinct from false. Verification remains unimplemented; its filter is intentionally present with an explicit limitation.

## 2026-11-13: Plaintext deployment log privilege

`deployment_logs_read` requires an exact configurable-role grant or `manage_all`; ordinary `deployment_read`, Viewer (`read_all`), Deployer (`write_all`), and generic level grants do not grant plaintext logs. Canonical Admin receives access through existing `manage_all`. Organization, project, and environment assignments follow existing resource-tree inheritance, so administrators can delegate narrowly through existing role and membership management. No stored-role or schema migration is needed because core permission definitions ship in code. Deploy IAM with the new catalog before CP begins checking the permission.


## 2026-11-13: Public IAM 2.8.0 dependency closure

Pin IAM shared v1.4.0 as a real published dependency before public PR qualification. Preserve the reviewed TLS and managed-log source commits, use Go 1.26.11 and the existing CI/release mechanisms, and document the access change and IAM-first rollout. Hosted required CI remains mandatory before merge and stable publication.


## 2026-11-13: Signed source successor

Preserve unsigned 2.8.0 tag and empty draft after cancelled run43507431186. Recover forward as 2.8.1 from actual main3e033, with protected GitHub SQUASH landing and exact-source signature verification. No workflow, behavior, dependency or signature gate change.
