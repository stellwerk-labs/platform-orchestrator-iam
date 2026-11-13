# Learnings

- Upgrade helpers must expose their current-image build context explicitly, or
  they bypass otherwise verified disposable-source preparation and its receipt.

- go-licenses v2.0.1 does not recognize the SDK root EUPL text. Exact declared SDK provenance must be handled explicitly; external unknown licenses remain fatal.
- gitleaks directory scans skip binary files. Stream printable binary strings through the same pinned scanner, without saving extracted secrets.
- Standard-library packages have no Go module record. Dependency notice collection must not treat their package paths as external modules.
- Published golib and graph modules use the same EUPL text. Explicit declarations must enumerate actual module identities, never use an owner-wide exception. Prefix-based classifier exclusions need collision guards.
- A content-only private-reference scan misses sensitive names. Scan relative artifact paths and rescan the complete generated evidence staging tree before publication.
- BuildKit local OCI exports need an explicit image name/tag to populate attestation subjects. An untagged export is not qualified evidence and is not a valid substitute in a tagged reproducibility pair.
- Go's adjacent string pool can create a secret-rule match across benign source literals. Require exact per-file evidence and source/build-metadata binding, never suppress a whole rule or binary class.
- Gitleaks8.30.1 always loads the scan target's .gitleaksignore even with --gitleaks-ignore-path /dev/null. Reject artifact ignore files explicitly, disable inline allow comments and isolate stdin scanner working directories.
- ORAS local-layout digest-only resolution can return application/octet-stream and omit image dependencies. Resolve a descriptor-verified root tag, select the platform and verify its destination manifest and blobs. Unprivileged Syft needs a writable mode1777 temporary filesystem and explicit cache location.
- Parsed tar entries omit arbitrary PAX fields and trailing bytes; gzip decompression also discards optional wrapper fields. Scan retained non-body tar bytes and every validated gzip member's wrapper separately from executable bodies.

## Installation settings and Provider retirement

- Background polling is not physical input. Browser activity, absolute lifetime and device-login expiry require separate rules; a policy transition must prune expired credentials before any extension.


## 2026-11-12: qualification boundaries

- A paginated first page cannot prove version absence. Complete catalogue summaries require version-read permission, not just catalogue read access.
- `require` prevents plaintext fallback but does not generally authenticate server identity. CA verification uses existing driver settings; a private-key mount needs its own restrictive permissions.

## 2026-11-13

New sensitive read permissions must be excluded from level wildcards, otherwise Viewer and Deployer inherit them. IAM root tests resolve the published shared module by default. Temporary workspaces can qualify coordinated changes before SDK publication, but release closure requires the real public SDK pin with `GOWORK=off`, no local replacements, and public checksum resolution.
