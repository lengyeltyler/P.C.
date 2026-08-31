# PhilCore Evidence Provenance Specification V2

Status: Package 6A mechanics plus Package 6B’s first schema-v2 physical-ceremony
record and fail-closed registry verification.

## Purpose

This specification defines append-only schema-v2 evidence provenance records and
the permanent freeze of historical schema-v1 evidence artifacts. It separates
deterministic computation from sanitized observation and operator attestation,
and it keeps CI verification offline and fail-closed.

## Layers

| Layer | Meaning | CI role |
| --- | --- | --- |
| Deterministic computed values | Digests and facts derived from Git blobs at a bound source baseline | Verified in `deterministic_evidence` |
| Sanitized observations | Allowlisted, non-secret runtime observations inlined after staging | Payload digest verified; never treated as authority alone |
| Operator attestations | Allowlisted role statements; digests are **not signatures** and provide **no non-repudiation** | Payload digest verified only |
| Frozen historical schema-v1 records | O.41 / O.42 / O.42.1 / O.43 committed evidence JSON under `config/solidity/` | Byte-locked every deterministic-evidence run; historical `--check` identities retained |
| Schema-v2 append-only records | New files only under `config/provenance/v2/` (directory created on demand) | Package 6A mechanics; Package 6B registers and verifies committed records |
| Provenance v2 registry | `config/provenance/v2-registry.json` maps record paths to dedicated container commits | Verified offline by Package 6B; bijection with `config/provenance/v2/` |
| Deterministic CI verification | Offline hash, schema, baseline, and registry checks | Required automated lane |
| Manual / physical ceremony | Device, biometric, signing, or Apple-service work | Remains `physical_ceremony_manual` / excluded; CI verifies committed provenance, not the ceremony |

## Permanent legacy freeze

The lock manifest `config/provenance/legacy-evidence-lock.json` and the
implementation constants bind the four schema-v1 evidence paths to the
owner-locked baseline:

- commit `d1d85696fbb6800de68eec4b6bc20177e8b14e42`
- tree `5293c0aa38055771424acf52ca47489ef406b307`

Verification does **not** trust a hash that lives only beside the artifact in
the candidate tree. `verifyLegacyLockedArtifacts`:

1. Resolves that exact commit and tree through Git;
2. Reads each locked path from that baseline’s Git objects;
3. Independently hashes the baseline blob;
4. Requires the manifest hash, current working-tree artifact hash, and
   baseline-blob hash to agree;
5. Fails distinctly (`LEGACY_BASELINE_UNAVAILABLE`) if the locked baseline is
   missing from the Git repository used for resolution.

**Residual control:** code review and branch protection remain the ultimate
control against a coordinated change that edits the implementation, tests,
manifest, and locked constants together.

Policy:

- There is **no** environment variable, CLI flag, break-glass mode, or other
  path that permits overwriting those artifacts.
- Legacy generators without `--check` throw `LEGACY_EVIDENCE_FROZEN` **before**
  computing or writing output.
- `--check` remains read-only and preserves historical stale-failure identities.
- CI never regenerates these artifacts to make `--check` green.
- Every `deterministic_evidence` lane run executes the provenance schema unit
  suite, which re-checks the four locked artifact byte identities against the
  owner baseline.

Locked artifacts:

1. `config/solidity/O41_RECOVERY_ENROLLMENT_ENVIRONMENT_EVIDENCE.json`
2. `config/solidity/O42_RECOVERY_ENROLLMENT_CEREMONY_EVIDENCE.json`
3. `config/solidity/O42_1_PLATFORM_WEBAUTHN_COMPATIBILITY_EVIDENCE.json`
4. `config/solidity/O43_NATIVE_IPHONE_IMPLEMENTATION_EVIDENCE.json`

## Schema-v2 record shape

A schema-v2 record binds:

- `sourceBaselineCommit` / `sourceBaselineTree` — never the future container
  commit of the evidence record itself;
- `computed` — canonicalized inputs plus domain-separated `computed.digest`;
- `observed` — sanitized inlined payload plus domain-separated `payloadDigest`,
  or null;
- `operatorAttested` — sanitized inlined payload plus domain-separated
  `payloadDigest`, or null;
- `recordDigest` — domain-separated digest of the entire record with
  `recordDigest` null.

**“Bound to a baseline”** means the implementation **actively verifies** the
commit and tree against Git history (object resolution, tree match, and—for
committed records—dedicated-child container binding). It is not a passive label.

### Container binding

Committed-record verification requires `containerCommit` and checks that the
evidence commit has **exactly one** immediate parent equal to
`sourceBaselineCommit`. Merge commits are rejected even when one parent is the
baseline.

APIs are deliberately distinct:

- `verifyAssembledProvenanceRecordPreCommit` — pre-commit digest/baseline checks;
  rejects a `containerCommit` argument (`PRECOMMIT_API_MISUSE`);
- `verifyCommittedProvenanceRecordV2` — requires `containerCommit` and full
  dedicated-child binding; never silently skips container checks.

### Digest domain separation

Digests use immutable framing:

`PHILCORE_EVIDENCE_PROVENANCE_V2\0<DOMAIN>\0<canonical-json-bytes>`

Domains: `COMPUTED`, `OBSERVED`, `OPERATOR_ATTESTED`, `RECORD`. Callers cannot
supply an arbitrary domain string. Identical payload bytes therefore produce
different hashes in different domains.

### Git identity safety

`sourceBaselineCommit` and `containerCommit` must be canonical lowercase full
40-character hexadecimal SHAs before any Git subprocess. Option-like,
abbreviated, uppercase, malformed, whitespace-containing, and symbolic revisions
are rejected.

Source inputs are read from Git blob content at `sourceBaselineCommit`, not from
a dirty or later working tree. Assembly requires a clean source tree via a
provenance-specific read-only check (it deletes nothing and does not use
`scripts/ci/verify-clean-tree.cjs`).

## Staging and filesystem safety

- Observation and attestation inputs are external temporary JSON documents under
  `os.tmpdir()`, outside any Git worktree.
- Symlink staging inputs are rejected. Only validated owned temps are unlinked;
  invalid paths are rejected without deletion.
- Temporary inputs are removed on success and every post-validation failure.
- Output must be a **new** relative POSIX path under `config/provenance/v2/`.
- Missing real directories are created on demand and revalidated; symlink
  components from the repository root through `config/provenance/v2` are
  rejected.
- Evidence files are created exclusively (`O_CREAT|O_EXCL`, plus `O_NOFOLLOW`
  where supported). Existing targets are never truncated.
- Symlink components and symlink leaves—including **dangling** symlinks—are
  rejected via `lstat` (not `existsSync`). Genuinely missing components may be
  created as real directories and then revalidated.
- If an ordinary write error occurs after exclusive creation, only the file
  created by that invocation is removed. Pre-existing bystander files and
  colliding targets that blocked exclusive creation are never removed.
- **Residual (accepted local-workflow, not zero risk):** a same-user concurrent
  mutation that replaces a parent directory between validation and create can
  cause a new file to be created outside the intended repository path. Exclusive
  creation still prevents truncating an existing target.

## Canonicalization, JSON, and resource bounds

- Object keys are sorted recursively; array order is significant.
- Strings are NFC-normalized; CRLF is normalized to LF at the input boundary.
  Raw string length is checked **before** NFC and again after normalization.
- Non-finite numbers and non-safe integers are rejected; negative zero is
  canonicalized to positive zero.
- `__proto__`, `constructor`, and `prototype` keys are rejected at every depth.
- Raw JSON input rejects duplicate object keys before ordinary `JSON.parse`
  can discard them.
- Cycles in programmatically supplied objects raise `PROVENANCE_CYCLE`.
- Conservative resource limits (exported as `RESOURCE_LIMITS`):
  - **Raw external inputs** (staged observation/attestation JSON and the legacy
    lock file) are size- and type-inspected, then read through a bounded
    file-descriptor loop of at most `MAX_RAW_STAGED_BYTES + 1` bytes—never an
    unbounded `readFileSync`. Oversized inputs are rejected without fully
    materializing the file.
  - **Parser traversal** bounds nesting depth, total nodes, object keys, array
    length (rejecting the next element before parsing it when already at the
    limit), and string length.
  - **Programmatic values** are bounded before expensive canonicalization work
    where feasible (early-stop key enumeration before sorting; string length
    before NFC). If a caller has already constructed an oversized in-memory
    object, that prior allocation is outside the helper’s control; the helper
    bounds traversal and subsequent allocation only—it does not claim to prevent
    the caller’s prior allocation.

## Sanitization

Unknown observation and attestation keys are rejected. Secret-shaped keys and
values are rejected, including usernames, absolute paths (including paths
**embedded** inside free-text, not only at offset zero), home paths, Windows
drive/UNC paths, NULs and unsafe control characters, environment dumps, tokens,
API keys, private keys, mnemonics, seeds, offline recovery factors,
`phil_secret`, identity roots, commitments, nullifiers, proof witnesses/inputs,
credential IDs, biometric output, device serial numbers, UDIDs, and other unique
device identifiers. Operator roles are constrained to documented non-personal
enums (`RELEASE_OPERATOR`, `SECURITY_REVIEWER`, `EVIDENCE_WITNESS`,
`CI_AUTOMATION`).

Package 6A uses a provenance-specific allowlist/deny check rather than the
Sepolia secret scanner, to avoid side effects and scope expansion outside
evidence provenance.

## Implementation entry points

- Mechanics: `scripts/cryptography/evidence-provenance-v2.cjs`
- Legacy lock: `config/provenance/legacy-evidence-lock.json`
- Package 6A tests: `test/unit/evidence-provenance-schema.test.cjs` (lane
  `deterministic_evidence`; executed by `scripts/ci/run-lane.cjs`)
- Package 6B registry: `config/provenance/v2-registry.json`
- Package 6B verifier: `scripts/ci/verify-provenance-v2-registry.cjs`
- Package 6B tests: `test/unit/evidence-provenance-v2-registry.test.cjs`
  (same lane)

## Package 6B — first schema-v2 physical-ceremony record

Package 6B adds the first committed schema-v2 physical-ceremony observation
record and a fail-closed registry verifier.

### Dedicated-child Commit A topology

The Phase 5B record lives in a **dedicated child** of the source baseline:

- Commit A has exactly one parent: the source baseline commit
  `45c38dec9ba0e3f13db83bcbc943f1e72c64b894` (tree
  `eb6f0463882c1c5ac47c7d56900bc7ffb5ec762b`);
- Commit A is **not** a merge commit;
- Commit A adds **only** the record file under `config/provenance/v2/`;
- Registry, verifier, tests, classification, and documentation land in a
  subsequent Commit B.

**Merge policy:** integrating Package 6B into the mainline must use a normal
merge that preserves Commit A’s dedicated-child topology. **Squash merge is
prohibited** for this package: squashing would destroy the container commit
identity the registry binds and that Package 6B independently re-checks.

### Record and registry behavior

- Observation and attestation digests are **not signatures** and provide **no
  non-repudiation**.
- Raw build logs and result bundles were **not retained** for this Phase 5B
  record; only the sanitized observation/attestation payloads and computed
  source-blob hashes are committed.
- Package 6B independently **recomputes** every `computed.sourceBlobSha256`
  entry from Git blob bytes at `sourceBaselineCommit` and requires a strict
  bijection with `computed.sourcePaths`.
- The registry requires a bijection with regular files under
  `config/provenance/v2/`: every registered path exists; every regular file is
  registered; unexpected directories and symlinks fail closed.
- Working-tree record bytes, `git show <containerCommit>:<recordPath>` bytes,
  and `recordFileSha256` must all agree.
- Shallow history that cannot resolve the container’s parent fails closed.

### What CI verifies

CI verifies **committed provenance** (registry, digests, baseline binding,
source-blob recomputation, dedicated-child topology). CI does **not** re-run
the physical ceremony, contact a device, create credentials, or claim the
ceremony occurred beyond what the sanitized record asserts.

**Residual control:** coordinated verifier/registry/record tampering remains
controlled by code review and branch protection—the same residual accepted for
Package 6A’s legacy freeze.

## Out of scope for Package 6A

- Assembling a real schema-v2 ceremony record (addressed by Package 6B’s
  dedicated Commit A; further ceremonies remain later packages)
- Signing systems, personal operator identity, network calls, hardware,
  biometrics, credential creation, or new dependencies
- Regenerating or greening historical schema-v1 `--check` failures
- Modifying `scripts/ci/verify-clean-tree.cjs`
- Claiming perfect elimination of same-user parent-directory races
