# PhilCore Desktop Trusted-Tester Policy

Status: O.9 artifact revoked during O.11.1; no tester distribution has occurred.

## Release boundary

The revoked identifier is `philcore-desktop-o9-trusted-tester-rc1` and its
SHA-256 is `eb3ae7e67ecad33128477269dd2e8de98003671fdaa5156f3854d4744c045a9c`.
It must never be distributed or used as a rollback artifact. Its Finder and
independent-user Gatekeeper validations are failed.

The replacement identifier is
`philcore-desktop-o11-1-trusted-tester-rc2`. A bundle
may be produced only after Developer ID verification, Apple notarization
acceptance, stapling, and Gatekeeper acceptance all succeed on both the working
application and clean final extractions. Direct ZIP-entry contamination scans
and genuine second-user Finder extraction and double-click launch are mandatory.
Preparation, fixture output, command-line executable launch, or testing under
the repository user cannot satisfy the Finder gate.

The initial cohort is limited to ten named, directly invited testers. Each tester
must acknowledge release-candidate status, macOS 13+ on Apple silicon, local-only
operation, no production use, and no high-value assets. Public-network mutation,
public UserOperations, account deployment, and paymasters remain prohibited.

## Installation and verification

The operator supplies the ZIP, published SHA-256, Developer ID common name, and
Team ID. Before installation, run:

```bash
./verify-trusted-tester-artifact.sh \
  "/path/to/philcore-desktop-o9-trusted-tester-rc1-macos-arm64.zip" \
  "EXPECTED_SHA256" \
  "Developer ID Application: ORGANIZATION (TEAMID)" \
  "TEAMID"
```

The verifier fails independently for checksum, Apple signature, authority, Team
ID, staple, Gatekeeper, manifest, or internal component hash errors. PhilCore
hashes supplement Apple platform trust and never override it.

## Privacy and feedback

PhilCore performs no automatic telemetry or silent diagnostic upload. Testers
initiate local sanitized diagnostic export and review it before sharing. Reports
must exclude private keys, vault or recovery material, `phil_secret`, witnesses,
authentication secrets, biometric data, and private system logs.

Testers report defects and security incidents through the invitation's explicit
feedback channel. A suspected integrity, signing, update, or secret-exposure
incident requires immediate use cessation, package quarantine, and operator
notification. No feedback channel is embedded until a cohort is actually named.

## Rollback, revocation, and expiration

Rollback removes the application and its tester-only local data only after the
tester has exported any explicitly desired sanitized diagnostics. Operators
revoke a release by withdrawing its checksum and identifier, notifying the
entire named cohort, and requiring deletion of the ZIP and installed application.

The RC expires 30 days after actual distribution or immediately when replaced,
revoked, or found to have a signature/integrity defect. Replacement requires a
new release identifier and the full Apple trust pipeline; in-place mutation is
not allowed.

## O.10 Operations Rehearsal

Phase O.10 adds a no-send trusted-tester operations rehearsal. It revalidates the
existing notarized O.9 ZIP, rehearses clean extraction, isolated installation,
launch, native user-presence diagnostics, packaged proof execution, clean
environment execution, sanitized diagnostics, app removal, and residual-data
documentation.

Fixture records may exercise acknowledgement, defect intake, update rejection,
rollback, and revocation behavior. Fixture records do not count as real tester
acceptance, real distribution, external audit evidence, or Beta approval.

The current bundle identifier `com.philcore.desktop.localalpha` may be retained
only for the first controlled trusted-tester release-candidate cohort. A stable
identifier decision and migration plan are required before broader Beta or any
public-network-enabled build.

## O.11 First Tester Cycle

Phase O.11 records the operator as `tester-001-operator` for the first real
trusted-tester cycle. The cycle binds acknowledgement, verification,
installation, native user-presence, proof execution, diagnostics, removal,
defects, and feedback to the exact O.9 artifact SHA-256.

The external tester slot remains `tester-002-external-pending` until a separate
distribution-specific operator approval exists. Apple notarization approval is
not distribution approval. The default external gate is blocked, and
`distributedToTesters` remains `false`.

## Current Artifact

The revoked historical artifact is recorded under
`apps/philcore-desktop/release/local-alpha/philcore-desktop-o9-trusted-tester-rc1/`.
Its Apple trust and stage-specific hash evidence are recorded in
`config/release/philcore-desktop-o9-release-evidence.json`.

`distributedToTesters` remains `false`. Distribution cannot be considered until
RC2 completes fresh notarization and the independent Finder gate passes.
