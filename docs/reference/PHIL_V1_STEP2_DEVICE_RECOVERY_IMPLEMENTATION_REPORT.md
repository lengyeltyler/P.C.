# Phil V1 Step 2 Device And Recovery Implementation Report

Status: Step 2 exact source candidate independently accepted; implementation
gate complete

Date: 2026-08-21

## Outcome

The repository now contains a locally working Step 2 foundation for private
scoped identity, authenticated encrypted user data, encrypted identity/data
continuity, exact `2-of-3` recovery-key unwrapping, recovery lifecycle
controls, device-approval binding, and an iOS Secure Enclave source boundary.

This is not production approval. A bounded physical-iPhone ceremony passed,
including corrective cancellation handling and exact disposable-key deletion.
An exact fail-closed device-admission boundary now admits only the observed
physical environment and explicitly grants no production authority.
The first two exact candidates were independently rejected and corrected. The
final exact source candidate `fe583b6aef84a8636736b2041db2a56046a5972e`
atomically updates an existing active metadata record, adds only when absent,
resolves a duplicate-add race with one atomic retry, and never deletes the prior
record before persistence succeeds. It received
`ACCEPT_STEP_2_EXACT_CANDIDATE`. Step 2 is complete; Step 3 has not started.

## Implemented Source

- `apps/phil-device-sdk/src/secureIdentityV1.ts`
  - exact scoped identity domains and encodings;
  - random relationship instances and scoped commitments; and
  - AES-256-GCM user-data records with the accepted AAD hash.
- `apps/phil-device-sdk/src/identityDataRecoveryV1.ts`
  - canonical encrypted continuity package;
  - public recovery envelope with no root/account/credential/PII fields;
  - pairwise HKDF/AES-GCM exact `2-of-3` `K_backup` wrappers;
  - share/set/epoch validation, corruption rejection, and anti-rollback floor;
  - notification evidence, delay, expiry, cancellation, and destructive
    approval binding;
  - operation-bound requests that prevent identity recovery and recovery-set
    replacement from being substituted for one another;
  - completed-recovery device/recovery/capability epoch rotation;
  - old-device revocation, capability invalidation, and account reconciliation
    state; and
  - complete recovery-set replacement after loss or revocation.
- `apps/phil-device-sdk/src/deviceApprovalV1.ts`
  - versioned enrollment record;
  - exact accepted device-approval digest;
  - envelope, human-presentation, device, key, suite, epoch, nonce, and time
    verification; and
  - injected signature verification so platform algorithms remain explicit.
- `apps/philcore-ios-companion/PhilCoreCompanion/PhilDeviceApprovalKeyManager.swift`
  - separate Secure Enclave P-256 key generation;
  - ThisDeviceOnly/non-synchronizable/user-presence controls;
  - approval-digest signing;
  - local-vault-key wrapping/unwrapping; and
  - atomic active-metadata update/add with no delete/add gap and exact rollback
    of the just-created key on persistence failure; and
  - fail-closed Simulator behavior.

## Exact Recovery Mechanism

The suite is:

```text
phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1
```

Three holders each receive only their two pair contributions. The public
bundle contains three authenticated wrappers of one random `K_backup`. Any
two holders derive their pair wrapper key; one holder cannot. `phil_secret`,
`K_data_root`, device keys, account keys, and recovery-factor material never
appear in the public bundle.

The implementation does not claim that this new composition has been
independently audited. That is an explicit remaining gate.

## Acceptance Matrix

| Step 2 requirement | Current evidence | Status |
| --- | --- | --- |
| Physical-iPhone proving if local proving remains required | No backend/local proving requirement selected in Step 2 | Not applicable unless Step 3 selects local proving |
| Supported-device, memory, battery, thermal, interruption limits | Executable policy admits only the observed iPhone 17/iOS 26.6 build, physical/Secure Enclave/authenticated/protected-data state, at least 7,671 MiB total memory, 100% battery, Low Power Mode off, and nominal thermal; every unmeasured condition fails closed | Passed for bounded candidate; no broader device or production claim |
| Secure Enclave-generated approval/wrapping key with user presence | Physical creation, cancellation, signing, wrapping/unwrapping, non-exportability, persistence, and deletion pass; metadata failure rolls back the exact just-created key; active metadata uses atomic update/add semantics for later generations | Accepted for the bounded Step 2 candidate; induced metadata-failure cleanup remains disclosed and unadmitted |
| Protected runtime isolation | New recovery module absent from renderer/preload; source lock enforces absence; safe public bundle/summary | Passed as local foundation boundary; production IPC composition remains later work |
| App Attest limited to support evidence | Not used | Passed |
| Authenticated encrypted identity/data package | AES-256-GCM package plus exact public envelope/AAD | Passed locally |
| User-controlled exact `2-of-3` key unwrapping | Every pair succeeds; one/duplicate/mixed factors fail | Passed locally |
| Corruption and rollback | Share, wrapper, ciphertext, set/epoch, and rollback rejection tests | Passed locally |
| Replacement, revocation, lost device/share | Operation-bound request, notification/delay/expiry/cancel gate, full set rotation, old-share rejection, epoch changes, any-pair restore | Accepted in the second independent review |
| Notifications, delay, audit, destructive approval | Request/evidence hashes, delay/expiry/cancel, audit head update | Passed as local foundation primitive; operational delivery remains later integration |
| Independent device/recovery threat review | `fe583b6aef84a8636736b2041db2a56046a5972e` independently accepted after two preserved rejection/correction rounds | Passed |

## Validation Evidence

Passed locally:

```text
TypeScript no-emit check
11 targeted Step 2 adversarial tests
iOS Simulator unsigned build
generic arm64 iOS unsigned build
classification validation
bounded physical-iPhone ceremony with sanitized evidence
```

Synthetic Node 26.0.0 benchmark:

```text
200 package creations: mean 1.103 ms
600 pair restorations: mean 0.574 ms
RSS before: 117.953 MiB
observed process peak: 130.078 MiB
```

These Node measurements are not physical-device, battery, thermal, or
production evidence. The separate
[physical-iPhone evidence report](./PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md)
records the bounded device results without treating total device memory or one
nominal run as an app resource limit.

## Step 2 Closure

The authorized physical phase is complete under the
[ceremony plan](../security/PHIL_V1_STEP2_PHYSICAL_IPHONE_CEREMONY_PLAN.md),
with sanitized results in the
[physical-iPhone evidence report](./PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md).

No required Step 2 foundation work remains. Product integration items listed
in the finalization gate retain their own later composition gates.

Broader devices and conditions remain unadmitted rather than silently pending.
They can be added later only with new evidence. The exact ledger and review
instructions are in the
[Step 2 finalization gate](./PHIL_V1_STEP2_FINALIZATION_GATE.md) and
[independent review packet](./PHIL_V1_STEP2_INDEPENDENT_REVIEW_PACKET.md).

Do not connect an iPhone or perform this ceremony without a separate explicit
physical-device authorization and disposable-evidence plan.

## Verdict

`STEP 2 EXACT SOURCE CANDIDATE: fe583b6aef84a8636736b2041db2a56046a5972e`

`STEP 2 INDEPENDENT REVIEW: ACCEPT_STEP_2_EXACT_CANDIDATE`

`STEP 2 COMPLETE: YES`

`STEP 3 STATUS: READY FOR SEPARATE USER DIRECTION; NOT STARTED`
