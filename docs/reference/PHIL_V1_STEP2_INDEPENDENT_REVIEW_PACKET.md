# Phil V1 Step 2 Independent Review Packet

Status: Ready to give to an independent reviewer

Date: 2026-08-21

## Reviewer Independence

The reviewer must not be the author of this candidate and must not treat the
implementer's threat model or prior Codex statements as an acceptance verdict.
The review is read-only unless a separate correction task is authorized.

Review the exact Git commit supplied with this packet. First record:

```text
repository absolute path
branch
HEAD commit
git status --short
```

Stop if the working tree is dirty, the commit differs from the supplied
candidate, or any reviewed file is silently replaced during review.

## Required Source Scope

```text
apps/phil-device-sdk/src/secureIdentityV1.ts
apps/phil-device-sdk/src/identityDataRecoveryV1.ts
apps/phil-device-sdk/src/deviceApprovalV1.ts
apps/phil-device-sdk/src/step2DeviceAdmissionV1.ts
apps/philcore-ios-companion/PhilCoreCompanion/PhilDeviceApprovalKeyManager.swift
apps/philcore-ios-companion/PhilCoreCompanionTests/PhilDeviceApprovalPhysicalCeremonyTests.swift
test/unit/phil-v1-step2-device-recovery.test.cjs
scripts/security/benchmark-phil-v1-step2-recovery.cjs
```

Required contracts and evidence:

```text
docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md
docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
docs/security/PHIL_V1_STEP2_DEVICE_RECOVERY_THREAT_MODEL.md
docs/security/PHIL_V1_STEP2_PHYSICAL_IPHONE_CEREMONY_PLAN.md
docs/reference/PHIL_V1_STEP2_DEVICE_RECOVERY_IMPLEMENTATION_REPORT.md
docs/reference/PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md
docs/reference/PHIL_V1_STEP2_FINALIZATION_GATE.md
```

The legacy STWO path, a proof-backend choice, Step 3 adapter implementation,
deployment, RPC, public networks, real secrets, and production custody are out
of scope except where they reveal accidental reachability or authority.

## Mandatory Review Questions

1. Does the pairwise HKDF-SHA-256/AES-256-GCM access structure give any one
   holder enough information to recover or test `K_backup`, and are pair,
   set, epoch, salt, info, IV, AAD, and wrapper bindings unambiguous?
2. Are canonical JSON, Base64URL, bytes32, uint64, sorting, and ABI encodings
   deterministic and cross-platform, with no alternate accepted encoding?
3. Can public envelope, bundle, summary, error, or test artifacts disclose
   `phil_secret`, `K_data_root`, recovery material, account keys, credential
   identifiers, or personal data?
4. Do corruption, mixed-set, rollback-floor, delay, expiry, cancellation,
   notification evidence, destructive approval, replacement, and audit
   transitions fail closed with correct error precedence?
5. After completed recovery, are prior devices and credentials revoked,
   capabilities invalidated, accounts pending reconciliation, and only the
   required device/recovery/capability epochs incremented?
6. Is device approval inseparably bound to the authorization envelope,
   human presentation, device/key/suite, current epoch, nonce, and time window,
   without App Attest or proof validity becoming authority?
7. Are Secure Enclave creation, query, access control, signature, ECIES,
   cancellation mapping, persistence, non-exportability, metadata, rotation,
   and exact deletion semantics correct? Specifically assess partial failure
   between private-key creation and public-metadata storage.
8. Is any recovery secret or recovery operation reachable from renderer,
   preload, dapp, adapter, plugin, or agent surfaces?
9. Does the restricted device-admission policy reject every unmeasured profile
   or condition and avoid converting physical-candidate evidence into
   production authority?
10. Which production integrations remain necessary, and are they correctly
    excluded from rather than falsely claimed by this foundation gate?

## Required Local Checks

Use the repository's pinned Node/npm environment and run:

```text
npm run test:phil-v1-step2-device-recovery
npx tsc --noEmit
npm run benchmark:phil-v1-step2-recovery
git diff --check
```

The physical ceremony must not be repeated and an iPhone must not be connected
without a new explicit physical-device authorization. Review the committed
sanitized evidence instead.

## Required Verdict Format

Return findings first, ordered by severity, with exact file and line evidence.
Then provide one verdict:

```text
ACCEPT_STEP_2_EXACT_CANDIDATE
REJECT_STEP_2_BLOCKING_FINDINGS
UNABLE_TO_REVIEW_EXACT_CANDIDATE
```

Also state:

```text
reviewed commit
working-tree status
commands run and exact outcomes
cryptographic composition verdict
iOS/Secure Enclave verdict
recovery lifecycle verdict
protected-runtime verdict
device-admission verdict
residual risks that do not block this foundation gate
whether any correction requires renewed physical-device evidence
```

An acceptance verdict authorizes only Step 2 adjudication. It does not select
a proof backend, start Step 3, connect a device, publish, deploy, call an RPC,
or use real authority.
