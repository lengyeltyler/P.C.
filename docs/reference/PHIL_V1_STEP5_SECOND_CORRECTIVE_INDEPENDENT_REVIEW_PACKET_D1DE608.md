# Phil V1 Step 5 Second Corrective Independent Review Packet: `d1de608`

Status: Awaiting review by a separate reviewer

Date: 2026-08-22

## Exact review target

```text
candidate commit: d1de6082f01756d68f7c732d0c3e8fe3d47d6c96
candidate tree:   6987606552bf75b9116f618d87157857659bc387
candidate parent: d1c94c629ba8152799d6a994a45d28b7af3ad9a2
review range:     d1c94c629ba8152799d6a994a45d28b7af3ad9a2..d1de6082f01756d68f7c732d0c3e8fe3d47d6c96
```

Verify these identities first. Review the committed candidate, not this later
packet commit or a mutable working tree.

The parent preserves the independent rejection of corrective candidate
`fb5fb7bdf1ada9e142079086ee829a9e96af081d`. The second correction must close
all three findings without reopening any earlier finding or weakening an
accepted Step 2-4 boundary.

## Review boundary

This is an independent, read-only architecture and source review. Do not edit,
commit, install, publish, connect a device, use a secret, invoke an external
prover, contact an RPC endpoint, sign, deploy, submit a transaction, select a
production proof backend, or start Step 6.

Read-only use of current official Apple, NIST, dependency, and network
documentation is permitted and required for claims that may have changed.
Existing dependencies may be used for local checks; do not install
replacements.

## Required source scope

```text
apps/phil-device-sdk/src/postQuantumMigrationV1.ts
apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts
apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts
apps/philcore-ios-companion/PhilCoreCompanion/PhilDeviceApprovalKeyManager.swift
package-lock.json
config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json
scripts/security/generate-phil-v1-step5-artifacts.cjs
test/unit/phil-v1-step5-post-quantum-migration.test.cjs
docs/reference/PHIL_V1_STEP5_ARTIFACT_MANIFEST.json
docs/reference/PHIL_V1_STEP5_IMPLEMENTATION_REPORT.md
docs/reference/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md
docs/security/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_THREAT_MODEL.md
docs/security/PHIL_V1_STEP5_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md
docs/reference/PHIL_V1_STEP5_CORRECTIVE_INDEPENDENT_REVIEW_FB5FB7B.md
docs/reference/PQ_MIGRATION_READINESS.md
docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md
docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
README.md
```

Consult accepted Step 2-4 reports and candidates wherever the correction
relies on their P-256, recovery, proof, verifier, account, or authority
evidence. Independently inspect every bound Git blob and dependency identity;
an existing hash is insufficient unless the artifact actually implements the
named operation.

## Mandatory corrective questions

### Finding 1: semantic implementation binding

1. Does the secp256k1 record bind an exact source blob that both constructs the
   stated Keccak digest and executes canonical low-S secp256k1 public recovery?
   Does the locked Ethers version actually provide the called implementation?
2. Does the SHA-256 record bind exact concrete SHA-256 calls rather than a
   Keccak-only, abstract, fixture-only, or descriptive artifact?
3. Does the P-256 local-key-wrap record now name the exact implemented Apple
   `eciesEncryptionCofactorX963SHA256AESGCM` behavior, including X9.63 rather
   than HKDF? Verify the bound accepted Step 2 blob and current Apple API
   semantics.
4. Are the three source blobs, dependency-lock hash, Ethers version, accepted
   Step 2 commit, and function names exact? Is evidence level no stronger than
   the actual prior implementation/review evidence?
5. Search every active registry entry for another algorithm/artifact mismatch.
   Treat a syntactically valid Git identity with incorrect semantics as a
   finding.
6. Does replacing the old P-256 scheme label/ID propagate through registry,
   capabilities, policies, trusted states, fixture, manifest, ceremonies, and
   current documentation without leaving a Step 5 alias/substitution path?

### Finding 2: exact policy trust

7. Does trusted state bind both an exact current policy epoch and exact
   expected policy hash, with both fields included in its domain-separated
   hash?
8. Independently recreate the prior exploit: trusted policy epoch 1 with a
   candidate policy at epoch 999. Confirm policy creation, validation, and
   claim assessment all reject it.
9. Construct a different but otherwise valid policy at the same trusted epoch
   by changing only recovery independence or another admitted field. Confirm
   it is rejected by exact policy identity rather than accepted as
   self-consistent.
10. Can the deliberately named untrusted policy-hash derivation function grant
    authority, reach claim assessment, bypass exact trusted state, or create a
    circular/self-authorizing trust anchor?
11. Do migrations require the old exact policy under old trusted state and the
    new exact policy under new trusted state while retaining policy,
    capability, authority, registry, and freshness rollback protections?

### Finding 3: trusted-state format tampering

12. Independently recreate the prior exploit by changing only
    `formatVersionHash` while retaining every other field and the prior trusted
    hash. Confirm every validation/claim path rejects before reconstruction.
13. Confirm missing, malformed, alternate-case/length, future, zero, and
    unknown format values cannot normalize into the V1 trusted-state domain.

## Regression and authority questions

14. Are original findings 1, 2, and 4 still closed: accurate Apple ML-DSA
    classification, same-network higher-capability migration, and exact
    proof/verifier compatibility?
15. Do all 17 registry records retain accurate labels, kinds, postures,
    lifecycles, evidence, standards, implementation bindings, compatibility,
    and retirement state? Does STWO remain forbidden and unreachable?
16. Do policy constructors still reject unknown, duplicate, wrong-kind,
    candidate-only, retired, forbidden, incompatible, OR-combined, stale,
    future, and untrusted schemes or policies?
17. Are recovery still exact encrypted 2-of-3 key unwrapping, all current
    network records classical-only, the epoch-2 capability explicitly
    synthetic, and `wholeSystemPostQuantum: false` honest?
18. Is the candidate wholly unreachable from runtime, renderer, preload,
    device, signer, secret, prover, adapter execution, RPC, deployment,
    transaction, publication, production backend selection, and Step 6?

Report any missing closure, new regression, ambiguity, semantic binding error,
trust-anchor circularity, downgrade path, stale external claim, or authority
expansion as a finding rather than silently repairing it.

## Required local checks

```text
git status --short
git diff --check d1c94c629ba8152799d6a994a45d28b7af3ad9a2..d1de6082f01756d68f7c732d0c3e8fe3d47d6c96
npm run typecheck
npm run test:phil-v1-step5-pq-migration
npm run verify:phil-v1-step5-artifacts
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step4-composed-account
```

Independently recompute all 17 label IDs, record hashes, registry hash, source
SHA-256, fixture SHA-256, three capability hashes, three trusted-state hashes,
current/target policy hashes, and ceremony hash. Confirm the manifest and
fixture are exact and mutually consistent.

## Required response

Report findings first in severity order with exact file/line evidence. Separate
verified source facts, reproduced local evidence, inference, and unverified
claims. Explicitly adjudicate each of the three corrective findings and confirm
whether earlier findings remain closed. Then return exactly one verdict:

```text
ACCEPT_SECOND_CORRECTIVE_STEP_5_EXACT_CANDIDATE
```

or

```text
REJECT_SECOND_CORRECTIVE_STEP_5_EXACT_CANDIDATE
```

Acceptance requires all three findings to be closed, all earlier closures to
remain intact, and no new unresolved security, correctness, standards,
classification, semantic-binding, compatibility, freshness, provenance,
downgrade, recovery, network-evidence, artifact, or authority-boundary finding.
Even if accepted:

```text
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```
