# Phil V1 Step 2 Device And Identity/Data Recovery Threat Model

Status: Step 2 exact source candidate independently accepted; threat gate
complete for the bounded foundation

Gate classification: Local foundation candidate, not production approved

## 1. Scope

This review covers the Step 2 implementation candidate for:

- pairwise scoped Phil identities;
- authenticated encrypted user-data records;
- the encrypted Phil identity/data continuity package;
- exact `2-of-3` recovery-key unwrapping;
- recovery delay, notification evidence, destructive approval, cancellation,
  rollback, replacement, revocation, and post-recovery epoch changes;
- the chain-independent device-approval digest and evidence verifier; and
- the iOS Secure Enclave approval/local-vault-wrapping source boundary.

It does not review a proof backend, circuit, verifier, Starknet adapter,
Ethereum/Base integration, public deployment, remote service, production UI,
or real recovery-factor custody operation.

A bounded disposable physical-iPhone ceremony was completed with synthetic
material only. No real Phil secret, recovery factor, account key, wallet,
RPC, deployment, or public-network mutation was used. The exact disposable
key and its public metadata were deleted and proven absent afterward.

## 2. Root-Proving Decision

Step 2 does not select or require a local root-proof backend. Root proofs are
reserved for exceptional operations, and backend/device admission belongs to
Step 3. The conditional physical-iPhone proving benchmark is therefore not a
Step 2 requirement for this candidate.

If Step 3 selects local-device proving, physical-device time, memory, battery,
thermal, interruption, and failure evidence becomes mandatory before that
backend can be admitted. Simulator or Mac results cannot satisfy that gate.

## 3. Protected Assets And Key Separation

| Asset | Purpose | Must not be derived from or replaced by |
| --- | --- | --- |
| `phil_secret` | Stable private Phil identity witness | Device, account, recovery, data, or proof key |
| `K_data_root` | User-data encryption continuity | Phil root, device signature, account validator, or recovery share |
| `K_backup` | Encrypt one continuity package | Any single recovery holder |
| Recovery contribution | One holder's input to two pair-specific wrappers | Phil root or data key |
| Device approval key | Replaceable hardware-backed approval | Phil identity or recovery quorum |
| Local vault wrapping key | Device-local protected-state unlock | Identity/data recovery continuity |
| Account validator key | Network-account execution | Phil identity or identity/data recovery |

The public recovery bundle contains only an envelope, authenticated
ciphertext, and three encrypted `K_backup` wrappers. Recovery shares are
separate secret-bearing artifacts and are never returned by the public summary
function.

## 4. Exact 2-Of-3 Construction

Suite ID:

```text
keccak256(utf8("phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1"))
```

Each of three holders receives two independent random 32-byte contributions,
one for each pair containing that holder. For pair `i-j`, Phil derives a
32-byte key-encryption key with HKDF-SHA-256 over the ordered pair
contributions, salted by `recoverySetId` and bound to the pair and
`recoveryEpoch`. That key encrypts the same random `K_backup` under
AES-256-GCM. The bundle stores wrappers for `1-2`, `1-3`, and `2-3`.

Consequences:

- one holder has no complete pair key and cannot unwrap `K_backup`;
- any exact pair can unwrap exactly one wrapper;
- mixed recovery sets/epochs fail before decryption;
- modifying a contribution, wrapper, envelope, or ciphertext fails closed;
- replacing or revoking one factor rotates the complete set and epoch; and
- compromise of any two holders is sufficient to recover the package, which
  is the intentional threshold failure condition.

This is a custom access-structure composition of HKDF-SHA-256 and AES-256-GCM,
not an independently audited threshold-sharing library. Independent
cryptographic review is required before Step 2 acceptance.

## 5. Threat Matrix

| Threat | Current control | Residual risk/status |
| --- | --- | --- |
| One lost or malicious factor | Exact two-share API; no complete pair key in one factor | Holder storage/custody UI not implemented |
| Two compromised factors | None by design; two are the offline decryption threshold | Immediate confidentiality loss is possible; lifecycle delay cannot cryptographically stop an attacker already holding the bundle and two factors |
| Mixed share sets | Suite, set ID, epoch, holder, pair, and authenticated wrapper binding | Passes synthetic negative tests |
| Share corruption | Canonical codec/checksum plus authenticated unwrap | Checksum is diagnostic, not a MAC; AEAD is authoritative |
| Bundle tampering | Ciphertext hash plus AES-GCM package authentication | Passes synthetic negative tests |
| Rollback | Caller-supplied greatest accepted epoch/counter floor | Production needs durable multi-device/reconciled floor storage |
| Lost device | Recovery does not require a device private key | New-device enrollment ceremony remains physically unverified |
| Lost share | Either remaining pair can recover; operation-bound replacement requires notification evidence, delay, expiry, cancellation state, destructive-approval binding, and rotates all shares | Operational factor replacement UI/runbook pending |
| Old device after recovery | Device epoch increments; prior credentials become revoked | Network/device reconciliation integration pending |
| Old app/agent capability | Capability epoch increments; restored capability state is invalidated | Durable capability implementation is later work |
| Old network account state | Account bindings become `pending_reconciliation` | No network authority resumes automatically |
| Recovery race | Official full-recovery and set-replacement transitions require operation-bound delay, expiry, cancellation, notification evidence, destructive approval, and exact bundle binding | These controls govern Phil's transition; they cannot prevent offline decryption after two-factor compromise; production transport pending |
| Fake notification | Every configured target requires an evidence hash | Evidence issuer/delivery trust must be specified operationally |
| Approval substitution | Request binds destructive approval digest and bundle | Full production recovery UI/evidence composition pending |
| Renderer/dapp/agent access | Recovery module is absent from renderer/preload surfaces | Full protected-process integration and IPC audit pending |
| Device replay | Envelope, presentation, device, key, epoch, nonce, and time binding; verifier requires a consumed-nonce store | Durable/atomic store implementation pending composed runtime work |
| Device-key export | Secure Enclave, ThisDeviceOnly, private-key usage, user presence; metadata failure rolls back the exact created key | Non-exportability passed on one iPhone 17/iOS 26.6; corrective cleanup is source-verified but its induced failure path is not physically exercised; re-review pending |
| Device loss | Device key is replaceable and absent from recovery package | Correct re-enrollment UX pending |
| App Attest overreach | App Attest is not used by this boundary | If added, it remains supporting server evidence only |
| PQ overclaim | Current P-256, HKDF, and AES composition is labeled classical | Step 5 remains required |
| Plaintext after recovery | Returned only to the protected recovery caller; buffers cleared where practical | JavaScript cannot guarantee complete memory zeroization |

## 6. Device Boundary

`PhilDeviceApprovalKeyManager.swift` defines a separate P-256 Secure Enclave
key with:

- `kSecAttrTokenIDSecureEnclave`;
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`;
- non-synchronizable permanent private-key storage;
- `.privateKeyUsage` and `.userPresence` access control;
- exact 32-byte approval-digest signing; and
- ECIES X9.63/SHA-256/AES-GCM wrapping of a random local vault key.

The local vault wrapping method is explicitly prohibited from making the
identity/data recovery package device-dependent. The Swift source contains no
Phil root, data-root, or recovery-share input.

The simulator fails closed for production Secure Enclave creation. Both the
iOS Simulator and generic unsigned iOS targets compile. The bounded physical
ceremony then exercised real Secure Enclave generation, cancellation, signing,
wrapping/unwrapping, non-exportability, lock/reboot persistence, and deletion.
Its corrective cancellation history and sanitized observations are recorded
in the
[physical-iPhone evidence report](../reference/PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md).

## 7. Supported Device And Operational Limits

| Environment | Evidence | Decision |
| --- | --- | --- |
| Node 26.0.0 arm64 macOS | Recovery/data tests and synthetic benchmark | Local implementation evidence only |
| iOS Simulator SDK 26.5, deployment target iOS 17 | Unsigned app build passes; production key creation refuses Simulator | Compile/negative evidence only |
| Generic arm64 iOS SDK 26.5 | Unsigned production-source build passes | Compile evidence only |
| Physical iPhone 17, iOS 26.6 | Bounded synthetic ceremony passed; exact candidate deleted | Restricted candidate admitted only inside the exact observed envelope; corrective successor re-review pending |
| Android/other hardware | No provider implementation | Unsupported |

App termination, a 60-second lock/unlock cycle, reboot/unlock, nominal thermal
state, battery state, and exact key deletion were observed. The executable
admission policy accepts only that exact profile and observed resource state,
grants no production authority, and rejects all unmeasured conditions. App
peak memory, energy, low-battery, Low Power Mode, thermal stress, biometric
lockout, passcode/biometric change, OS update, additional models, and
population limits remain unverified and therefore unadmitted. The reported
7,671 MiB is total device memory, not app peak usage.

## 8. Local Performance Evidence

On arm64 macOS with Node 26.0.0, 200 synthetic package creations and all 600
pair restorations measured:

- mean package creation: approximately `1.103 ms`;
- mean pair restoration: approximately `0.574 ms`;
- RSS before: approximately `117.953 MiB`; and
- observed process peak RSS: approximately `130.078 MiB`.

This includes Node/TypeScript process overhead, is not a mobile benchmark, and
makes no battery or thermal claim.

## 9. Required Independent Review

An independent reviewer must assess at minimum:

- pairwise access-structure correctness and single-holder information;
- HKDF salt/info, pair ordering, set/epoch separation, and wrapper AAD;
- IV uniqueness and AES-GCM package/record authentication;
- canonical JSON and ABI encoding ambiguity;
- rollback-floor durability and multi-device reconciliation;
- notification, delay, cancellation, destructive approval, and audit binding;
- protected-runtime reachability and public-surface redaction;
- Secure Enclave query/access-control/key-usage behavior on a physical device;
- recovery completion epoch transitions and non-resumption of old authority;
  and
- failure-separated real-world custody assumptions.

## 10. Verdict

`LOCAL STEP 2 FOUNDATION: IMPLEMENTED AND TESTED`

`STEP 2 ACCEPTANCE: BLOCKED ON EXACT CORRECTIVE-CANDIDATE RE-REVIEW`

`STEP 3 AUTHORIZATION: NO`
