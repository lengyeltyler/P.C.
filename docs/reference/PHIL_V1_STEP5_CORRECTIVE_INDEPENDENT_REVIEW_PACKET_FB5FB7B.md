# Phil V1 Step 5 Corrective Independent Review Packet: `fb5fb7b`

Status: Awaiting review by a separate reviewer

Date: 2026-08-22

## Exact review target

```text
candidate commit: fb5fb7bdf1ada9e142079086ee829a9e96af081d
candidate tree:   bec2fff0d3415dbebc0a8ee255be179c7c1b2875
candidate parent: 18b3cef30d9a27a3a3f80a3d849a17fac231b9df
review range:     18b3cef30d9a27a3a3f80a3d849a17fac231b9df..fb5fb7bdf1ada9e142079086ee829a9e96af081d
```

Verify these identities first. Review the committed candidate, not this later
packet commit or a mutable working tree.

The parent records the independent rejection of original candidate
`fc6514394f5f1ff540c10ac87704a3c24e5f3a4b`. The corrective candidate must
close all five findings without weakening any previously passing boundary.

## Review boundary

This is an independent, read-only architecture and source review. Do not edit,
commit, install, publish, connect a device, use a secret, invoke an external
prover, contact an RPC endpoint, sign, deploy, submit a transaction, select a
production proof backend, or start Step 6.

Read-only use of current official Apple, NIST, and network documentation is
permitted and required for claims that may have changed. Existing dependencies
may be used for local checks; do not install replacements.

## Required source scope

```text
apps/phil-device-sdk/src/postQuantumMigrationV1.ts
config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json
scripts/security/generate-phil-v1-step5-artifacts.cjs
test/unit/phil-v1-step5-post-quantum-migration.test.cjs
docs/reference/PHIL_V1_STEP5_ARTIFACT_MANIFEST.json
docs/reference/PHIL_V1_STEP5_IMPLEMENTATION_REPORT.md
docs/reference/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md
docs/security/PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_THREAT_MODEL.md
docs/security/PHIL_V1_STEP5_CORRECTIVE_IMPLEMENTATION_REPORT.md
docs/reference/PQ_MIGRATION_READINESS.md
docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md
docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
docs/reference/PHIL_V1_STEP5_INDEPENDENT_REVIEW_FC65143.md
README.md
```

Consult accepted Step 2-4 reports and exact candidates wherever the corrective
candidate relies on their P-256, recovery, proof, verifier, account, or
authority evidence. Do not inherit the implementer's verdict or bindings
without checking them.

## Mandatory corrective questions

### Finding 1: Apple ML-DSA classification

1. Do current Apple primary sources document Secure Enclave ML-DSA-65 signing,
   hybrid ML-DSA-65/P-256 signing, and ML-KEM-768/1024 key establishment on the
   stated supported platforms?
2. Is ML-DSA-65 classified as `PLATFORM_DOCUMENTED` and
   `SPECIFIED_CANDIDATE`, while both Phil device-integration flags and PQ device
   authorization remain false?
3. Is there any new unsupported claim that the documented API was built,
   physically tested, integrated into Phil, or admitted for authorization?

### Finding 2: same-network capability migration

4. Does a migration validate the old bundle against the old capability and
   trusted state, and the new bundle against the new capability and trusted
   state?
5. Can a policy migrate to a distinct later capability record on the same
   network and under the same capability authority?
6. Are cross-network migration, capability-authority substitution, changed
   records without a higher capability epoch, capability rollback, and trusted
   freshness-floor rollback rejected?
7. Are both capability hashes and both trusted-state hashes included in the
   ceremony hash?

### Finding 3: complete-registry binding

8. Do network capabilities and policy bundles bind both registry epoch and the
   complete deterministic registry hash?
9. Does every registry record hash include scheme kind, posture, lifecycle,
   evidence, standard, implementation binding, proof compatibility, and
   retirement epochs?
10. Are active implementation bindings exact accepted commits, Git blobs, or
    dependency-lock identities rather than free-form product labels? Verify
    every asserted identity against repository history and the accepted Step
    2-4 evidence.
11. Does any classification, implementation-binding, retirement, or
    compatibility change propagate into the registry, capability, and policy
    identities?

### Finding 4: proof/verifier compatibility

12. Does each verifier bind the exact compatible proof scheme ID, and do both
    network construction and policy construction reject incompatible pairs?
13. Are the Step 3 Noir/UltraHonk proof and Garaga verifier still classical,
    exact, mutually compatible, and bound to the accepted Step 3 evidence?
14. Was the category-confused ML-DSA signature-verifier record removed from
    the proof-verifier registry, leaving exactly 17 unique schemes?
15. Does STWO remain structurally forbidden from every registry, network,
    policy, claim, and execution path?

### Finding 5: trusted freshness and provenance

16. Is a trusted-state input mandatory for every capability, policy, ceremony,
    and claim validation path?
17. Does the trusted state bind exact registry identity, network ID,
    capability-authority identity, greatest accepted capability epoch, exact
    expected capability hash, and greatest accepted policy epoch?
18. Are self-consistent but stale, unknown, substituted, or tampered records
    rejected with no caller-relative fallback?
19. Is the distinction explicit that this pure module validates a trusted-state
    record but does not itself provide protected persistence, signed updates,
    network discovery, or production authority?

## Regression and authority questions

20. Do all policy constructors still reject unknown, duplicate, wrong-kind,
    candidate-only, retired, forbidden, incompatible, and OR-combined schemes?
21. Are recovery still exact encrypted 2-of-3 key unwrapping, all current
    network records classical-only, and `wholeSystemPostQuantum: false` honest
    for every currently constructible path?
22. Is the synthetic Starknet capability epoch 2 plainly test-only and free of
    a live Starknet or PQ-support claim?
23. Is the candidate wholly unreachable from runtime, renderer, preload,
    device, signer, secret, prover, adapter execution, RPC, deployment,
    transaction, publication, and Step 6 authority?

Report any missing closure, new regression, ambiguity, stale external claim,
weak implementation binding, trust-anchor circularity, downgrade path, or
authority expansion as a finding rather than silently repairing it.

## Required local checks

```text
git status --short
git diff --check 18b3cef30d9a27a3a3f80a3d849a17fac231b9df..fb5fb7bdf1ada9e142079086ee829a9e96af081d
npm run typecheck
npm run test:phil-v1-step5-pq-migration
npm run verify:phil-v1-step5-artifacts
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step4-composed-account
```

Independently recompute the 17 scheme IDs, registry hash, source SHA-256,
fixture SHA-256, all three network capability hashes, trusted-state hashes,
current bundle hash, and synthetic rotation ceremony hash. Confirm the
generated artifact manifest is exact.

## Required response

Report findings first in severity order with exact file/line evidence. Separate
verified source facts, reproduced local evidence, inference, and unverified
claims. Explicitly adjudicate each of the five original findings as closed or
open. Then return exactly one verdict:

```text
ACCEPT_CORRECTIVE_STEP_5_EXACT_CANDIDATE
```

or

```text
REJECT_CORRECTIVE_STEP_5_EXACT_CANDIDATE
```

Acceptance requires all five findings to be closed and no new unresolved
security, correctness, standards, classification, binding, compatibility,
freshness, provenance, downgrade, recovery, network-evidence, artifact, or
authority-boundary finding. Even if accepted:

```text
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```
