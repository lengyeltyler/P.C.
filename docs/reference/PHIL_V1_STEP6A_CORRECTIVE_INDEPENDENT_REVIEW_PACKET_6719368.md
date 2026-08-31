# Phil V1 Step 6A Corrective Independent Review Packet: `6719368`

Status: Awaiting review by a separate reviewer

Date: 2026-08-22

## Exact Review Target

```text
candidate commit: 671936805d511cca0aa4f5754cc8a00693adf71d
candidate tree:   96147ed1d7ad076d4e5a5de576056915be8d6014
candidate parent: 60b79117da1a0c373239a427091c926f48eed1e4
review range:     60b79117da1a0c373239a427091c926f48eed1e4..671936805d511cca0aa4f5754cc8a00693adf71d
```

Verify these identities first. Review the committed candidate, not this later
packet commit or a mutable working tree. The parent records the independent
rejection of first candidate `33570bb`.

## Review Boundary

This is an independent, read-only corrective architecture, test-evidence, and
documentation review. Do not edit, commit, install, publish, connect a device,
use a secret, invoke an external prover, contact an RPC or bundler, simulate,
sign, construct or submit a UserOperation or transaction, deploy, select a
production proof backend, or begin Step 6B.

Current official EIP and Base documentation may be read to reconfirm external
facts. Existing dependencies may be used for the exact local checks below; do
not install replacements or run network-capable, device, signing, deployment,
submission, broad historical, or clean-tree lanes.

## Corrective Scope

The candidate claims only two corrections:

1. add every missing deterministic rejection test identified by the independent
   review; and
2. reconcile current Step 6 status documentation.

The adapter source, generator, fixture, artifact manifest, package scripts,
domain IDs, and semantic hashes must remain byte-identical to first candidate
`33570bb`. Any source change, authority expansion, regenerated artifact, new
operational path, or unrelated correction is a finding.

## Required Source Scope

Changed corrective files:

```text
test/unit/phil-v1-step6a-base-network-adapter.test.cjs
docs/security/PHIL_V1_STEP6A_CORRECTIVE_IMPLEMENTATION_REPORT.md
docs/reference/PHIL_V1_STEP6A_BASE_NETWORK_ADAPTER_GATE.md
docs/reference/PHIL_V1_STEP6A_IMPLEMENTATION_REPORT.md
docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md
docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
README.md
docs/CANONICAL_DOCS.md
```

Unchanged evidence and production-candidate comparison scope:

```text
apps/phil-device-sdk/src/networkAdapterV1.ts
apps/phil-device-sdk/src/authorizationEnvelopeV1.ts
apps/phil-device-sdk/src/deviceApprovalV1.ts
apps/phil-device-sdk/src/postQuantumMigrationV1.ts
scripts/security/generate-phil-v1-step6a-artifacts.cjs
config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json
docs/reference/PHIL_V1_STEP6A_ARTIFACT_MANIFEST.json
docs/reference/PHIL_V1_STEP6A_INDEPENDENT_REVIEW_33570BB.md
```

Inspect existing EVM/runtime compatibility code only as needed to reconfirm
unchanged isolation and absence of candidate reachability.

## Mandatory Corrective Questions

### Finding 1: committed rejection coverage

1. Does the focused suite execute an incorrect separately pinned manifest hash
   and a tampered stored manifest hash?
2. Does it rebuild and reject each fixed Base profile substitution: adapter ID,
   adapter version, adapter type, network, account model, scope canonicalizer,
   action codec, replay model, fee model, device-signature suite, proof suite,
   and PQ classification?
3. Does it independently exercise implementation-hash and audit-status-hash
   substitution under the pinned trust anchor?
4. Does it cover empty and duplicate device-suite sets plus zero implementation
   and audit identities through the actual manifest constructor?
5. Does it construct changed chain and EntryPoint actions and reach their exact
   Base-profile rejection branches?
6. Does it construct changed account, target, target-calldata, nonce-key, and
   nonce-sequence actions and prove the original accepted envelope cannot be
   reused with them?
7. Does it independently mutate envelope adapter, network, account binding,
   action type, action hash, intent, nonce domain, nonce, validity, value limit,
   fee limit, and device-signature suite and reach the intended branch?
8. Does it reject both exceptional/root-proof and recovery operation classes?
9. Does it reject initCode, paymaster data, account-self target, EntryPoint
   target, priority fee above maximum fee, and uint256 fee-ceiling overflow?
10. Does it execute malformed/noncanonical decimal, negative, unsafe-number,
    uint192, uint64, zero-gas, uint128, malformed-address, malformed-bytes32,
    zero-expiry, and reversed-validity cases?
11. Does it tamper the stored action format, action hash, account-call
    commitment, UserOperation nonce, and maximum-fee value and reach the
    canonical validator rather than a duplicate test-only check?
12. Does it reject device-epoch mismatch, approval outside the action window,
    zero device/key/approval-nonce identities, zero approval time, and reversed
    approval timestamps?
13. Are the tests deterministic and built from the actual constructors and
    validators without mocks, copied rejection logic, RPC state, wall-clock
    dependence, or regenerating evidence?
14. Do the newly committed assertions close every exact omission listed in the
    first independent review? Identify any documented or packet-required branch
    that remains unexecuted.

### Finding 2: canonical current status

15. Do README, canonical index, secure-identity architecture, roadmap header,
    ordered table, current-status section, Step 6A gate, implementation report,
    rejection record, and corrective report consistently state that Step 6 was
    authorized and started, first candidate `33570bb` was rejected, this
    corrective candidate is unaccepted, Step 6 is incomplete, and Step 6B is
    unauthorized?
16. Does a stale-status scan find any active current document that still says
    Step 6 is unstarted, lacks authorization, or says the first candidate is
    awaiting review? Historical immutable review packets and reviews must remain
    accurate records rather than being rewritten.

### Regression and authority boundary

17. Are the adapter source, generator, fixture, artifact manifest, and package
    scripts byte-identical to candidate `33570bb`? Are source and fixture hashes
    and every semantic hash unchanged?
18. Does the corrective diff contain only the eight declared test/documentation
    files and no unrelated, generated, runtime, contract, proof, device, secret,
    signer, network, or publication change?
19. Do the original 8 focused tests still pass with the new branches actually
    executed, and do the Step 3-5 regressions and artifact verification remain
    green?
20. Does the candidate still grant no device-signature verification, protected
    manifest persistence, raw calldata/UserOperation construction, smart-
    account compatibility, nonce consumption, simulation, RPC, signing,
    deployment, transaction, network authorization, PQ capability, production
    authority, or Step 6B authority?

Report any missing branch, assertion that does not reach production source,
wrong expected failure, stale status, semantic drift, source/artifact change,
new overclaim, or authority expansion as a finding rather than repairing it.

## Required Local Checks

```text
git status --short
git rev-parse 671936805d511cca0aa4f5754cc8a00693adf71d
git rev-parse 671936805d511cca0aa4f5754cc8a00693adf71d^{tree}
git diff --check 60b79117da1a0c373239a427091c926f48eed1e4..671936805d511cca0aa4f5754cc8a00693adf71d
git diff --name-status 60b79117da1a0c373239a427091c926f48eed1e4..671936805d511cca0aa4f5754cc8a00693adf71d
git diff --exit-code 33570bb39a334c0ef079fd82c714912ab94b18f4 671936805d511cca0aa4f5754cc8a00693adf71d -- apps/phil-device-sdk/src/networkAdapterV1.ts scripts/security/generate-phil-v1-step6a-artifacts.cjs config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json docs/reference/PHIL_V1_STEP6A_ARTIFACT_MANIFEST.json package.json
npm run typecheck
npm run verify:phil-v1-step6a-artifacts
npm run test:phil-v1-step6a-base-adapter
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step4-composed-account
npm run test:phil-v1-step5-pq-migration
```

Do not run the Step 6A generator in write mode during review.

## Required Response

Report findings first in severity order with exact file/line evidence. Separate
verified source facts, reproduced evidence, inference, and unverified claims.
Explicitly adjudicate all 20 corrective questions and both original findings.
Then return exactly one verdict:

```text
ACCEPT_STEP_6A_CORRECTIVE_EXACT_CANDIDATE
```

or

```text
REJECT_STEP_6A_CORRECTIVE_EXACT_CANDIDATE
```

Acceptance requires both findings to be closed, every original source/security
conclusion to remain intact, and no new unresolved coverage, documentation,
artifact, compatibility, correctness, or authority-boundary finding. Even if
accepted:

```text
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
STEP 6A LOCAL BINDING ACCEPTED: YES
STEP 6 COMPLETE: NO
DEVICE SIGNATURE VERIFIED BY STEP 6A: NO
BASE NETWORK AUTHORIZATION PATH AVAILABLE: NO
POST-QUANTUM CAPABILITY: NONE
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6B: NO
```
