# Phil V1 Step 6C Exact Implementation Packet

Status: Exact Step 6C-1 synthetic candidate independently accepted; initial and first five corrective Step 6C-2 candidates rejected; exact sixth-corrective candidate 4a81b08/tree 188d7d0 independently accepted; Step 6C-2 complete as a local source gate

Date: 2026-08-22

## Objective And Authority

Implement, only after separate authorization, one local routine-authorization
vertical slice:

```text
typed local application intent
  -> protected Desktop canonical package
  -> independently reconstructed iPhone presentation
  -> user-present Secure Enclave P-256 signature
  -> protected response verification
  -> official normally deployed EntryPoint v0.7 simulation
  -> exact unchanged local handleOps execution
  -> harmless zero-value target state
  -> deterministic bound receipt
```

This packet is a definition candidate. It authorizes no implementation,
dependency change, device action, RPC, deployment, signing, publication, or
production authority. The first exact definition candidate `fdf3c2e` was
independently rejected. The first corrective exact candidate `a24873e` was
also independently rejected. Their findings are preserved in
[the first review record](./PHIL_V1_STEP6C_DEFINITION_INDEPENDENT_REVIEW_FDF3C2E.md)
and [the corrective review record](./PHIL_V1_STEP6C_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_A24873E.md).
Exact second corrective candidate `227bd48d92c84672c50f2d19f47b9a24e5b17786`,
tree `cd5a734c5ca1ce486d55024befa85424aefefb42`, was independently accepted
with no critical/high finding. See
[the acceptance record](./PHIL_V1_STEP6C_SECOND_CORRECTIVE_DEFINITION_INDEPENDENT_REVIEW_227BD48.md).
Separately authorized implementation then exposed a nonce/catalog and policy-
window contradiction before any source candidate was retained. The exact
mechanical evidence is preserved in
[the implementation-blocker record](./PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md).
This third corrective definition keeps every accepted security boundary but
separates stable profile admission from per-operation action and time fields.
Exact status-correction candidate `fcc0103a61c051ad8507de79536978928b0e3e3f`,
tree `209df24d5cd3567668b69548235cb2064d7ab710`, was independently accepted.
The user's separate continuation instruction authorizes Step 6C-1 synthetic
local implementation within this packet. That bounded work produced source
candidates `a158688`, `aea7359`, `591f6b6`, and `5ab4650`, which independent reviews rejected. Those
candidates are superseded. Corrective source commit `6f048eb`, tree `a9032b2`,
plus the deterministic fixture, artifact manifest, implementation report, and
37 focused passing cases is frozen. Exact candidate `22b5cf3`, tree `2b0ff7f`,
is independently accepted for Step 6C-1 disclosed-synthetic local composition.

## Local-Only Profile

Step 6C no longer impersonates Base mainnet. It composes the accepted data
model and account semantics under a distinct local execution identity:

```text
chainId:                       31337
networkIdName:                 phil-local:step6c:31337
executionEnvironmentName:      phil-execution-environment-step6c-local-hardhat-v1
adapterIdName:                 phil-adapter-step6c-local-erc4337-v07-v1
EntryPoint package:            @account-abstraction/contracts 0.7.0
EntryPoint address:            address produced by normal local deployment
environmentClass:              1  // local_in_process
externalNetwork:               false
productionAuthority:           false
meaningfulAssets:              false
```

Every `Name` becomes `keccak256(utf8(exact name))`. Chain ID `8453`,
`keccak256("eip155:8453")`, the canonical public v0.7 EntryPoint address, and
the accepted Step 6A Base manifest are forbidden in a Step 6C request. Step 6A
and Step 6B remain unchanged evidence that the Base-shaped binding and account
checks work synthetically; they are not the Step 6C local environment.

The normally deployed local EntryPoint address, runtime code hash,
`SenderCreator` address/code hash, constructor-initialized reentrancy storage,
and empty deposit/nonce state are captured after deployment and bound into the
signed environment record. Runtime-code copying and `hardhat_setCode` are
forbidden in Step 6C.

## Frozen Domain Labels

```text
PHIL_EXECUTION_ENVIRONMENT_V1
PHIL_ROUTINE_DEVICE_ENROLLMENT_V2
PHIL_ROUTINE_SIGNATURE_REGISTRY_V2
PHIL_ROUTINE_ACCOUNT_CONFIGURATION_V1
PHIL_ROUTINE_APPLICATION_PRINCIPAL_V1
PHIL_ROUTINE_SCOPE_INSTANCE_V1
PHIL_ROUTINE_CAPABILITY_V1
PHIL_ROUTINE_PARAMETER_SCHEMA_V1
PHIL_ROUTINE_CATALOG_ENTRY_V1
PHIL_ROUTINE_CATALOG_V1
PHIL_ROUTINE_CAPABILITY_POLICY_V1
PHIL_ROUTINE_HUMAN_PRESENTATION_V1
PHIL_ROUTINE_AUTHORIZATION_CORE_V1
PHIL_ROUTINE_APPROVAL_NONCE_V1
PHIL_ROUTINE_AUTHORIZATION_REQUEST_V1
PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2
PHIL_ROUTINE_AUTHORIZATION_RESPONSE_V1
PHIL_ROUTINE_AUTHORIZATION_RECEIPT_V1
PHIL_ROUTINE_JOURNAL_RECORD_V1
PHIL_ROUTINE_JOURNAL_FRAME_AAD_V1
PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1
PHIL_STEP6C_IMPLEMENTATION_SET_V1
PHIL_STEP6C_AUDIT_STATUS_V1
```

For each label `L`, `L_HASH = keccak256(utf8(L))`.

Cryptographic identities are:

```text
signatureSuiteName = phil-signature-p256-sha256-prehash-raw-rs-low-s-v2
providerProfileName = apple-secure-enclave-p256-x962-sha256-digest-der-v1
wireEncodingName = phil-p256-signature-rs-64-low-s-v1
```

Their IDs are `keccak256(utf8(exact lowercase name))`.

Additional frozen IDs are:

```text
entryPointVersionHash = keccak256(utf8("erc4337-entrypoint-v0.7.0"))
adapterVersionHash = keccak256(utf8("phil-step6c-local-erc4337-adapter-v1"))
adapterType = 1  // PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT
applicationId = keccak256(utf8("phil-application-step6c-local-harmless-v1"))
principalIdHash = keccak256(abi.encode(
  PHIL_ROUTINE_APPLICATION_PRINCIPAL_V1_HASH,
  applicationId
))
scopeId = keccak256(utf8("phil-scope-step6c-local-routine-v1"))
recordSelector = bytes4(keccak256(utf8("record(bytes32,bool)")))
recordedValue = keccak256(utf8("PHIL_STEP6C_HARMLESS_VALUE_V1"))
actionTypeHash = existing PHIL_EVM_SINGLE_CALL_V1_HASH
accountModelId = existing PHIL_EVM_ERC4337_ACCOUNT_MODEL_ID
scopeCanonicalizationId = existing PHIL_EVM_SCOPE_CANONICALIZATION_ID
actionCodecId = existing PHIL_EVM_SINGLE_CALL_CODEC_ID
replayModelId = existing PHIL_ERC4337_NONCE_MODEL_ID
feeModelId = existing PHIL_ERC4337_FEE_MODEL_ID
supportedDeviceSignatureSuiteIds = [signatureSuiteId]
supportedProofSuiteIds = []
postQuantumCapability = 0
```

The principal derivation ABI types are `[bytes32,bytes32]`; the scope-instance
types are `[bytes32,bytes32,bytes32,bytes32,address]`, in displayed order.

After the disposable account address is predicted, its exact scope instance is:

```text
scopeInstance = keccak256(abi.encode(
  PHIL_ROUTINE_SCOPE_INSTANCE_V1_HASH,
  scopeId,
  applicationId,
  executionEnvironmentHash,
  account
))
```

After the harmless target address and runtime code hash are known, the stable
parameter schema is:

```text
parameterSchemaId = keccak256(abi.encode(
  PHIL_ROUTINE_PARAMETER_SCHEMA_V1_HASH,
  approvedTarget,
  approvedTargetRuntimeCodeHash,
  recordSelector,
  recordedValue
))
```

Its ABI types are `[bytes32,address,bytes32,bytes4,bytes32]`. The schema admits
exactly the canonical target calldata for `record(recordedValue,shouldRevert)`,
where `shouldRevert` is either canonical ABI `false` or canonical ABI `true`.
It does not contain the EntryPoint nonce, request time, session, or the
per-operation action hash.

The stable capability identity is then:

```text
capabilityId = keccak256(abi.encode(
  PHIL_ROUTINE_CAPABILITY_V1_HASH,
  applicationId,
  scopeInstance,
  approvedTarget,
  approvedTargetRuntimeCodeHash,
  actionTypeHash,
  parameterSchemaId
))
```

Its ABI types are
`[bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32]`. Neither the
coordinator, renderer, requesting application, request, nor device selects a
capability ID or parameter schema.

Every fresh Step 6C local profile freezes `scopeEpoch`, `capabilityEpoch`,
`policyEpoch`, `deviceEpoch`, `recoveryEpoch`, and `validatorEpoch` to `1`.
They are distinct signed fields even though their initial values match. No
caller, renderer, request, or device may select or rewrite these identities.

## Canonical Scalar And String Rules

- `bytes32` is exactly 32 bytes.
- `address` is exactly 20 bytes; text form is lowercase `0x` plus 40 hex
  digits. The ABI value is the 20-byte address, not its text.
- byte strings are lowercase `0x` plus an even number of hex digits.
- unsigned integer transport values are canonical base-10 strings: `0` or a
  nonzero digit followed by digits, with no sign or leading zero.
- ABI integers use the stated width and reject overflow before hashing.
- all timestamps are unsigned Unix seconds UTC.
- Step 6C catalog strings are deliberately ASCII-only: code points U+0020
  through U+007E, length 1 through 96 bytes, no leading/trailing space, no
  consecutive spaces, and no backslash, quote, `<`, `>`, or control character.
- a catalog string hash is `keccak256(utf8(exact validated bytes))`.
- booleans are ABI `bool` and transport JSON `true`/`false`, never strings.
- canonical base64url uses only `A-Z a-z 0-9 - _`, no `=`, whitespace, `+`,
  or `/`, and the shortest RFC 4648 URL-safe encoding; decoders must re-encode
  and require byte-for-byte equality.
- unknown fields, duplicate JSON object keys, non-UTF-8, BOM, noncanonical
  scalars, and unsupported enum values are rejected before any hash comparison.

The transport is strict UTF-8 JSON with exact schema field names. JSON member
order is not security-relevant and raw JSON bytes are never used as a signed
hash. Both sides decode into typed records and recompute the ABI hashes below.
Arrays preserve order and may not contain duplicates.

At disposable-profile construction, the protected Desktop clock supplies
`profilePolicyValidAfter = floor(milliseconds / 1000)` and
`profilePolicyValidUntil = profilePolicyValidAfter + 86400`. Both must be
positive and at most `2^48 - 1`. These two values are frozen in the capability
policy and account constructor storage for the 24-hour life of this disposable
local profile.

For every request, including the fresh request after a failed execution, the
protected Desktop clock independently supplies
`issuedAt = floor(milliseconds / 1000)` and `expiresAt = issuedAt + 120`.
Both must be positive and at most `2^48 - 1`; conversion to the action,
envelope, presentation, approval, and EntryPoint `uint48`/`uint64` values is
exact and checked before hashing. Action, envelope, presentation, and approval
use `validAfter/approvedAt = issuedAt` and
`validUntil/approvalExpiresAt = expiresAt`. The request interval must be wholly
contained in the frozen policy interval:

```text
profilePolicyValidAfter <= issuedAt
expiresAt <= profilePolicyValidUntil
```

Expiry of the profile policy requires a new disposable profile; no request may
extend, replace, or reinterpret the constructor-frozen policy window.

Before display, the iPhone's wall clock must satisfy
`deviceNow >= issuedAt - min(issuedAt,5)` and `deviceNow <= expiresAt`. Before
response acceptance, simulation, submission commit, and `handleOps`, the
protected Desktop or local block time must independently satisfy
`issuedAt <= now <= expiresAt`. No side may extend or rewrite the signed
window. Clock-source failure or rollback is terminal before submission.

## Immutable Step 5 Boundary

`PHIL_CRYPTO_SCHEME_REGISTRY_V1`, its epoch-1 hash, and every accepted Step 5
record remain byte-identical. Step 6C must not edit
`postQuantumMigrationV1.ts`.

Step 6C introduces `PhilRoutineSignatureRegistryV2` in a new module. It binds:

```text
formatVersionHash = keccak256(utf8("PHIL_ROUTINE_SIGNATURE_REGISTRY_V2"))
registryEpoch = 2
inheritedRegistryEpoch = 1
inheritedRegistryHash = exact accepted PHIL_CRYPTO_SCHEME_REGISTRY_V1 hash
routineDeviceSignatureSuiteId = new V2 signature suite ID
providerProfileId = Apple Secure Enclave provider profile ID
wireEncodingId = raw low-S wire ID
status = 1  // admitted only for Step 6C local routine composition
externalNetwork = false
postQuantum = false
```

This is a new local profile, not an in-place migration of any accepted account,
capability, policy, network record, or real user authority. A fresh disposable
Step 6C identity/profile is created directly under this registry. Movement of
an existing profile from epoch 1 to epoch 2 remains an exceptional migration
ceremony and is outside Step 6C.

Registry hash ABI types:

```text
[bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes32,uint8,bool,bool]
```

in exactly the field order above, prefixed by no other value.

## Required Canonical Records

### Execution environment V1

```text
PhilExecutionEnvironmentV1 {
  bytes32 formatVersionHash;
  uint8   environmentClass;
  uint256 chainId;
  bytes32 networkIdHash;
  bytes32 executionEnvironmentId;
  bytes32 adapterId;
  bytes32 entryPointVersionHash;
  address entryPoint;
  bytes32 entryPointRuntimeCodeHash;
  address senderCreator;
  bytes32 senderCreatorRuntimeCodeHash;
  bool    externalNetwork;
  bool    productionAuthority;
  bool    meaningfulAssets;
}
```

Hash ABI types:

```text
[bytes32,uint8,uint256,bytes32,bytes32,bytes32,bytes32,address,bytes32,address,bytes32,bool,bool,bool]
```

The local profile requires class `1`, chain `31337`, the exact local IDs,
normally deployed official v0.7 code, and all three booleans false.

`senderCreator` is derived exactly as the first `CREATE` child of the normally
deployed EntryPoint:

```text
address(uint160(uint256(keccak256(0xd694 || entryPoint[20] || 0x01))))
```

The address must contain the pinned package's `SenderCreator` runtime code.

### Local adapter manifest and action hashes

Step 6C transports a complete existing `PhilAdapterManifestV1`, constructed
with the generic manifest constructor rather than the Base-mainnet validator.
It uses the local adapter/environment/network IDs, the existing narrow account,
scope, call-codec, keyed-nonce, and no-paymaster fee model IDs, the new V2
device suite as its sole device suite, no proof suite, PQ capability `0`, and
local definition-candidate implementation/audit hashes.

Manifest hash ABI types and values are exactly:

```text
[bytes32,bytes32,bytes32,uint8,bytes32,bytes32,bytes32,bytes32,bytes32,
 bytes32,bytes32[],bytes32[],uint8,bytes32,bytes32]

[PHIL_ADAPTER_MANIFEST_V1_HASH, adapterId, adapterVersionHash, adapterType,
 networkIdHash, accountModelId, scopeCanonicalizationId, actionCodecId,
 replayModelId, feeModelId, supportedDeviceSignatureSuiteIds,
 supportedProofSuiteIds, postQuantumCapability, implementationHash,
 auditStatusHash]
```

The complete `PhilEvmSingleCallV1` and its existing action hash are reused with
chain `31337` and the normally deployed EntryPoint. Its action-hash ABI types
are:

```text
[bytes32,uint256,address,address,address,bytes32,bytes32,uint256,uint192,
 uint64,uint256,uint128,uint128,uint256,uint128,uint128,uint256,bytes32,
 bytes32,uint48,uint48]
```

Values are, in order, the existing action format hash, chain ID, account,
EntryPoint, target, target-calldata hash, account-call commitment, value,
nonce key, nonce sequence, packed UserOperation nonce, call gas, verification
gas, pre-verification gas, maximum fee per gas, maximum priority fee per gas,
maximum total fee, zero init-code hash, zero paymaster-data hash, valid-after,
and valid-until. The account-call commitment retains its existing
`[bytes32,address,uint256,bytes32]` formula.

`userOpNonce = (uint256(nonceKey) << 64) | uint256(nonceSequence)` and
`maxTotalFeeWei = (uint256(callGasLimit) + uint256(verificationGasLimit) +
preVerificationGas) * uint256(maxFeePerGas)`, with checked `uint256`
arithmetic. For packed v0.7, `accountGasLimits` is the 16-byte big-endian
`verificationGasLimit` followed by the 16-byte big-endian `callGasLimit`, and
`gasFees` is the 16-byte big-endian `maxPriorityFeePerGas` followed by the
16-byte big-endian `maxFeePerGas`. Every layer must reconstruct exactly these
values rather than accepting the derived values independently.

Existing account-binding, nonce-domain, and intent formulas are also reused
exactly:

```text
account binding types:
[bytes32,bytes32,bytes32,bytes32,uint256,address,address]

nonce domain types:
[bytes32,bytes32,bytes32,address,address,uint192]

intent types:
[bytes32,bytes32,bytes32,bytes32,bytes32]
```

All are recomputed with the local manifest/action; the Base-specific validator
is never called.

Manifest implementation and audit identities are deterministic, not supplied
by a caller. `implementationHash` is computed from this exact ordered Step
6C-1 production-source set:

```text
apps/phil-device-sdk/src/p256SignatureWireV2.ts
apps/phil-device-sdk/src/routineAuthorizationV1.ts
apps/phil-device-sdk/src/routineSignatureRegistryV2.ts
apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts
contracts/base/erc4337/PhilV1Step6CAccount.sol
contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol
```

The list is already UTF-8 bytewise lexicographic and may not be extended,
shortened, or reordered. For each path, `pathHash = keccak256(utf8(exact
repo-relative path))`, `contentHash = sha256(exact committed file bytes)`, and
`entryHash = keccak256(abi.encode(pathHash,contentHash))`. Then:

```text
implementationHash = keccak256(abi.encode(
  PHIL_STEP6C_IMPLEMENTATION_SET_V1_HASH,
  bytes32[6] entryHashes
))
```

The implementation-set ABI types are `[bytes32,bytes32[6]]`; each entry's
types are `[bytes32,bytes32]`.

Generated artifacts, fixtures, manifests, reports, tests, configuration, and
documentation are excluded, so recording the result cannot create a source
hash cycle. Step 6C-2 product wiring does not change this local adapter
identity; any change to one of these six sources creates a new implementation
hash and invalidates the admitted profile.

The six source paths, the dependency lockfile identity, the pinned compiler,
the resulting account/target creation and runtime code hashes, and all
transitive imported-source hashes are also recorded in the deterministic
artifact manifest. The six-file `implementationHash` is the signed adapter
source identity; the broader artifact manifest is independent reproduction
evidence and may not be substituted into the signed graph.

The definition-candidate manifest uses:

```text
auditStatusHash = keccak256(abi.encode(
  PHIL_STEP6C_AUDIT_STATUS_V1_HASH,
  uint8(1),
  implementationHash,
  bytes32(0)
))
```

Audit-status ABI types are `[bytes32,uint8,bytes32,bytes32]`.

After an independent exact-source review, an accepted profile may instead use
status `2` and `reviewReportHash = sha256(exact committed independent review
report bytes)`. Its audit hash is the same four-field formula with status `2`
and that nonzero report hash. Acceptance therefore requires a fresh manifest,
account configuration, policy, deployment, fixture, and review; it never
mutates an admitted candidate under the old hash. No other status is valid.
The independent report reviews the earlier exact source commit/tree and must
not claim or embed the later accepted-profile commit/tree, its manifest hash,
or its own file hash; that keeps the accepted-profile derivation acyclic.

### Routine device enrollment V2

```text
PhilRoutineDeviceEnrollmentV2 {
  bytes32 formatVersionHash;
  bytes32 deviceId;
  bytes32 deviceKeyId;
  uint64  deviceEpoch;
  uint64  generation;
  bytes32 signatureRegistryHash;
  bytes32 signatureSuiteId;
  bytes32 providerProfileId;
  bytes32 wireEncodingId;
  bytes   publicKeyX963;
  bytes32 publicKeyFingerprint;
  bytes32 publicKeyX;
  bytes32 publicKeyY;
  bool    secureEnclaveBacked;
  bool    userPresenceRequired;
  uint8   status;
}
```

`publicKeyX963` is exactly `0x04 || X || Y`, 65 bytes. Fingerprint is
`sha256(publicKeyX963)`. Coordinates are unsigned big-endian and must form a
non-infinity P-256 curve point. Status `1` is active. Hash ABI types:

```text
[bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes32,bytes,bytes32,bytes32,bytes32,bool,bool,uint8]
```

The iPhone Keychain tag is local metadata and never enters this record.

### Account configuration V1

```text
PhilRoutineAccountConfigurationV1 {
  bytes32 formatVersionHash;
  bytes32 executionEnvironmentHash;
  bytes32 adapterManifestHash;
  bytes32 applicationId;
  bytes32 principalIdHash;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  uint64  recoveryEpoch;
  uint64  validatorEpoch;
  address account;
  bytes32 accountRuntimeCodeHash;
  bytes32 deviceEnrollmentHash;
  bytes32 scopedOwnerCommitment;
  address approvedTarget;
  bytes32 approvedTargetRuntimeCodeHash;
  bytes32 actionTypeHash;
  uint192 nonceKey;
  uint256 maximumValueWei;
  uint256 maximumTotalFeeWei;
}
```

Hash ABI types are the exact field types above in order. The account is a
normally deployed disposable Step 6C account; code hash is captured after
deployment. `approvedTargetRuntimeCodeHash` is nonzero and equals
`keccak256(eth_getCode(approvedTarget,"latest"))` immediately before account
configuration construction; the returned runtime bytes must be nonempty. This
record intentionally does not contain the capability/policy
hash, preventing a configuration-policy hash cycle. The policy projects and
binds this configuration in the next record.

The Step 6C account runtime contains no Solidity `immutable` values; all
constructor trust anchors are write-once storage with no setter. The target is
normally deployed first, has no constructor-dependent runtime bytes, and its
address plus runtime code hash are captured before configuration. The account's compiled
runtime code hash is therefore independent of constructor arguments. The local
deployer's next `CREATE` address is computed from the disclosed deployer and
nonce before construction. The implementation order is: deploy environment
and target, compile/freeze account runtime hash, predict account address,
construct account configuration, stable catalog, and capability-policy hash,
then deploy the
account with those exact stored anchors and require the predicted address,
runtime hash, and every storage value. This removes any address/code/policy
fixed-point cycle.

The constructor stores exactly: EntryPoint address; chain ID; execution-
environment, adapter-manifest, signature-registry, device-enrollment, account-
configuration, catalog, and capability-policy hashes; the six exact catalog
display-text hashes; parameter-schema ID; profile-policy valid-after and
valid-until; application ID,
principal ID, scoped-owner commitment, scope ID/instance/epoch; capability ID/
epoch; policy epoch; device ID/key ID/epoch, signature suite/provider/wire IDs,
P-256 X/Y coordinates; recovery and validator epochs; approved target and its
runtime code hash; action
type; nonce key; maximum value; and maximum total fee. The constructor
recomputes the stable capability ID and all six catalog entry hashes from
these inputs, requires the resulting catalog and capability-policy hashes to
equal the admitted records, and rejects any request-specific action, nonce,
session, or request time in those stable identities. Each equals the
corresponding canonical record before deployment. Solidity storage inspection
after deployment must reproduce every value. No request-calldata field can
replace a constructor value; it can only be compared with it.

### Catalog entry and catalog V1

```text
PhilRoutineCatalogEntryV1 {
  uint8   kind;        // 1=app,2=network,3=account,4=target,5=action,6=parameters
  bytes32 entryId;
  string  displayText;
  bytes32 displayTextHash;
  bytes32 boundValueHash;
}
```

Entry hash types:

```text
[bytes32,uint8,bytes32,bytes32,bytes32]
```

Values are `[PHIL_ROUTINE_CATALOG_ENTRY_V1_HASH, kind, entryId,
displayTextHash, boundValueHash]`. `displayTextHash` must equal the validated
text hash. `boundValueHash` is:

```text
app:        applicationId
network:    executionEnvironmentHash
account:    keccak256(abi.encode(address account))
target:     keccak256(abi.encode(address target,bytes32 targetRuntimeCodeHash))
action:     actionTypeHash
parameters: parameterSchemaId
```

The catalog contains exactly one entry of each kind in kind order. Catalog
hash types are `[bytes32,bytes32[6]]`, values are the format hash and ordered
entry hashes.

Entry IDs are exact: app=`applicationId`, network=`networkIdHash`, account=
`keccak256(abi.encode(account))`, target=
`keccak256(abi.encode(target,targetRuntimeCodeHash))`,
action=`actionTypeHash`, and parameters=`parameterSchemaId`. No caller-selected
alias or second identifier is admitted. The catalog is a stable admitted
profile record; it never contains `actionHash`, `nonceSequence`, packed nonce,
request time, session ID, or nonce seed.

The six exact catalog display strings are:

```text
1  Phil Step 6C Local Harmless App
2  Local Hardhat Chain 31337
3  Disposable Phil Routine Account
4  Harmless Local Record Target
5  Record Harmless Local Value
6  Harmless Record Parameters
```

Each `displayTextHash` is `keccak256(utf8(exact displayed line after the kind
number and two spaces))`. The account constructor receives these six hashes
and the stable `parameterSchemaId`, recomputes every catalog entry and the
catalog hash, and rejects any mismatch. The raw strings remain required request
inputs so the iPhone independently validates their ASCII bytes and hashes
before display.

### Capability and policy projection V1

```text
PhilRoutineCapabilityPolicyV1 {
  bytes32 formatVersionHash;
  bytes32 scopedOwnerCommitment;
  bytes32 applicationId;
  bytes32 principalIdHash;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  uint64  recoveryEpoch;
  uint64  validatorEpoch;
  bytes32 capabilityId;
  uint64  capabilityEpoch;
  uint64  policyEpoch;
  bytes32 executionEnvironmentHash;
  bytes32 adapterManifestHash;
  bytes32 accountConfigurationHash;
  bytes32 deviceEnrollmentHash;
  bytes32 catalogHash;
  address approvedTarget;
  bytes32 approvedTargetRuntimeCodeHash;
  bytes32 actionTypeHash;
  uint256 maximumValueWei;
  uint256 maximumTotalFeeWei;
  uint48  validAfter;
  uint48  validUntil;
  bool    active;
}
```

Hash ABI types are the exact field types above in order. The resulting
`capabilityPolicyHash` is the `policyHash` used by the envelope and
presentation; the record deliberately contains no copy of its own hash. Step
6C requires a fresh disclosed local policy, zero maximum value, one harmless
target/action/schema, nonzero fee ceiling, active true, and the exact 24-hour
disposable-profile validity interval defined above. Every 120-second request
interval must be contained within it; request times never replace the policy
times or change `capabilityPolicyHash`.
Its application, principal, scope, scope epoch, recovery epoch, and validator
epoch must equal the account configuration and envelope. Device epoch must
equal the V2 enrollment and envelope. Approved target address and runtime code
hash must equal the account configuration, catalog, presentation, and installed
code. The account stores these anchors at construction and exposes no setter.

### Human presentation V1

The presentation deliberately contains no `requestId`, request digest, or
value derived from itself.

```text
PhilRoutineHumanPresentationV1 {
  bytes32 formatVersionHash;
  bytes32 applicationId;
  bytes32 applicationNameHash;
  bytes32 principalIdHash;
  bytes32 scopeId;
  bytes32 scopeInstance;
  uint64  scopeEpoch;
  bytes32 executionEnvironmentHash;
  bytes32 networkLabelHash;
  address account;
  bytes32 accountLabelHash;
  address target;
  bytes32 targetRuntimeCodeHash;
  bytes32 targetLabelHash;
  bytes32 actionTypeHash;
  bytes32 actionLabelHash;
  bytes32 parametersHash;
  bytes32 parameterSummaryHash;
  uint256 valueWei;
  uint256 maximumTotalFeeWei;
  uint48  validAfter;
  uint48  validUntil;
  bytes32 capabilityId;
  uint64  capabilityEpoch;
  bytes32 policyHash;
  uint64  policyEpoch;
  bool    externalNetwork;
  bool    productionAuthority;
  bool    meaningfulAssets;
}
```

Hash ABI types are the exact field types above in order. Every stable label
hash must equal the matching catalog entry; the dynamic parameter-summary hash
must equal the exact decoded target-calldata summary. Every bound value must
equal the environment, account, target, action type, parameter schema,
envelope, and capability/policy record as mapped below. The three booleans
must equal the environment and must be displayed as `Local test only` and
`No production authority`, and `No meaningful assets`.

The exact equality map is:

```text
applicationId/nameHash       <- catalog kinds 1 entryId/displayTextHash
principal/scope/epoch         <- account configuration, policy and envelope
executionEnvironmentHash     <- environment hash and catalog kind 2 boundValueHash
networkLabelHash             <- catalog kind 2 displayTextHash
account/accountLabelHash     <- action.account and catalog kind 3
target/codeHash/labelHash    <- action.target, config/policy, installed code and catalog kind 4
actionType/actionLabelHash   <- envelope.actionTypeHash and catalog kind 5
parametersHash               <- envelope.parametersHash and recomputed actionHash
parameterSummaryHash         <- exact dynamic summary derived from decoded target calldata
valueWei                     <- action.valueWei
maximumTotalFeeWei           <- action.maxTotalFeeWei; must be <= policy ceiling
validAfter/validUntil        <- action, envelope and request window; contained by policy window
capabilityId/epoch           <- envelope and capability/policy projection
policyHash/epoch             <- capabilityPolicyHash and policy projection epoch
external/production/assets   <- environment false/false/false
```

The app catalog entry's `boundValueHash` equals `applicationId`. Network,
account, target, action, and parameter-schema bound hashes use the formulas
above. Catalog kind 6 has the exact stable `parameterSchemaId` as both its
`entryId` and `boundValueHash`; it is not the per-operation parameters hash.
The presentation's `parametersHash` remains the exact recomputed `actionHash`.
Its `parameterSummaryHash` is derived from the canonical decoded
`shouldRevert` value:

```text
shouldRevert=false -> keccak256(utf8("Record disclosed harmless value"))
shouldRevert=true  -> keccak256(utf8("Intentionally revert before recording"))
```

Both exact summary strings obey the catalog ASCII rules. Desktop, iPhone, and
Solidity independently decode the raw target calldata and derive the same
summary hash. A caller-supplied summary, schema, label, or alias is rejected.
The envelope must set `policyHash = capabilityPolicyHash`,
`parametersHash = actionHash`, `actionTypeHash = PHIL_EVM_SINGLE_CALL_V1_HASH`,
and `intentDigest`, account binding, nonce domain, nonce, validity, value/fee
limits, adapter/network and device suite to the exact locally recomputed values.
Its principal, scope ID, scope instance, scope epoch, recovery epoch, and
validator epoch must equal the frozen account configuration and policy; its
device epoch must equal the enrollment. Application identity is bound through
the signed principal and scope instance, and the iPhone must display the app
name only after proving the catalog application entry binds that same
`applicationId`.

### Raw action, envelope, and unsigned approval

The request transports:

- the complete off-chain `PhilEvmSingleCallV1`;
- exact raw `targetCalldata`;
- the complete `PhilAuthorizationEnvelopeV1`;
- the complete unsigned `PhilDeviceApprovalV1` metadata; and
- the structured records above, not only their hashes.

The narrower tuple carried inside account calldata is named
`PhilStep6CAccountActionV1`; it is not a second definition of
`PhilEvmSingleCallV1`:

```text
PhilStep6CAccountActionV1 {
  address target;
  bytes32 targetCalldataHash;
  uint256 valueWei;
  uint192 nonceKey;
  uint64  nonceSequence;
  uint128 callGasLimit;
  uint128 verificationGasLimit;
  uint256 preVerificationGas;
  uint128 maxFeePerGas;
  uint128 maxPriorityFeePerGas;
  uint48  validAfter;
  uint48  validUntil;
}

[address,bytes32,uint256,uint192,uint64,uint128,uint128,uint256,uint128,uint128,uint48,uint48]
```

in order: target, targetCalldataHash, valueWei, nonceKey, nonceSequence,
callGasLimit, verificationGasLimit, preVerificationGas, maxFeePerGas,
maxPriorityFeePerGas, validAfter, validUntil. `nonceSequence` must equal the low
64 bits of the official EntryPoint nonce for `nonceKey`; it is a signed
projection, not independently stored account state.

The harmless target ABI is exactly
`record(bytes32 recordedValue,bool shouldRevert)`. For the successful fixture:

```text
recordedValue = keccak256(utf8("PHIL_STEP6C_HARMLESS_VALUE_V1"))
shouldRevert = false
targetCalldata = abi.encodeWithSelector(
  bytes4(keccak256(utf8("record(bytes32,bool)"))),
  recordedValue,
  false
)
valueWei = 0
```

The target begins with zero value and sequence `0`, rejects nonzero
`msg.value`, reverts before mutation when `shouldRevert=true`, and otherwise
stores the supplied value and increments its `uint64` sequence exactly once.
The required failed-execution liveness test signs the same exact method with
`shouldRevert=true` at EntryPoint nonce `n`; the fresh request at `n+1` uses
the successful calldata above and ends at recorded sequence `1`.

Desktop, iPhone, and Solidity require the raw target calldata to be exactly 68
bytes: the frozen 4-byte selector followed by canonical ABI words for the
frozen `recordedValue` and a boolean encoded as exactly `uint256(0)` or
`uint256(1)`. They decode and re-encode these values and require byte-for-byte
equality. Any other selector, value, length, boolean word, offset, trailing
byte, alternate function, or fallback call is rejected before signature or
execution. The decoded boolean also selects the exact dynamic parameter
summary hash defined above.

The account calldata uses these complete Solidity declarations. These are
distinct Solidity wire structs; TypeScript transport records are mapped to
them field-by-field and never substituted as ABI type definitions.

```solidity
struct PhilStep6CAccountActionV1 {
    address target;
    bytes32 targetCalldataHash;
    uint256 valueWei;
    uint192 nonceKey;
    uint64 nonceSequence;
    uint128 callGasLimit;
    uint128 verificationGasLimit;
    uint256 preVerificationGas;
    uint128 maxFeePerGas;
    uint128 maxPriorityFeePerGas;
    uint48 validAfter;
    uint48 validUntil;
}

struct PhilStep6CEnvelopeV1 {
    bytes32 formatVersionHash;
    uint8 operationClass;
    bytes32 scopedOwnerCommitment;
    bytes32 scopeId;
    bytes32 scopeInstance;
    uint64 scopeEpoch;
    bytes32 principalIdHash;
    bytes32 capabilityId;
    uint64 capabilityEpoch;
    bytes32 networkIdHash;
    bytes32 accountBindingHash;
    bytes32 adapterId;
    bytes32 actionTypeHash;
    bytes32 parametersHash;
    bytes32 intentDigest;
    bytes32 policyHash;
    bytes32 nonceDomain;
    uint256 nonce;
    bytes32 rootProofNullifier;
    uint64 validAfter;
    uint64 validUntil;
    uint256 valueLimit;
    uint256 feeLimit;
    uint64 deviceEpoch;
    uint64 recoveryEpoch;
    uint64 validatorEpoch;
    bytes32 deviceSignatureSuiteId;
    bytes32 proofDescriptorHash;
    bytes32 humanPresentationHash;
}

struct PhilStep6CApprovalV1 {
    bytes32 formatVersionHash;
    bytes32 authorizationEnvelopeDigest;
    bytes32 deviceId;
    bytes32 deviceKeyId;
    uint64 deviceEpoch;
    bytes32 approvalNonce;
    uint64 approvedAt;
    uint64 approvalExpiresAt;
}

struct PhilStep6CPresentationV1 {
    bytes32 formatVersionHash;
    bytes32 applicationId;
    bytes32 applicationNameHash;
    bytes32 principalIdHash;
    bytes32 scopeId;
    bytes32 scopeInstance;
    uint64 scopeEpoch;
    bytes32 executionEnvironmentHash;
    bytes32 networkLabelHash;
    address account;
    bytes32 accountLabelHash;
    address target;
    bytes32 targetRuntimeCodeHash;
    bytes32 targetLabelHash;
    bytes32 actionTypeHash;
    bytes32 actionLabelHash;
    bytes32 parametersHash;
    bytes32 parameterSummaryHash;
    uint256 valueWei;
    uint256 maximumTotalFeeWei;
    uint48 validAfter;
    uint48 validUntil;
    bytes32 capabilityId;
    uint64 capabilityEpoch;
    bytes32 policyHash;
    uint64 policyEpoch;
    bool externalNetwork;
    bool productionAuthority;
    bool meaningfulAssets;
}

struct PhilStep6CCoreV1 {
    bytes32 formatVersionHash;
    bytes32 protocolContextHash;
    bytes32 sessionId;
    bytes32 nonceSeed;
    uint64 issuedAt;
    uint64 expiresAt;
    bytes32 executionEnvironmentHash;
    bytes32 adapterManifestHash;
    bytes32 signatureRegistryHash;
    bytes32 deviceEnrollmentHash;
    bytes32 accountConfigurationHash;
    bytes32 catalogHash;
    bytes32 capabilityPolicyHash;
    bytes32 actionHash;
    bytes32 targetCalldataHash;
    bytes32 authorizationEnvelopeDigest;
    bytes32 rootProofNullifier;
    bytes32 humanPresentationHash;
}

function executeAuthorized(
    PhilStep6CAccountActionV1 calldata action,
    PhilStep6CEnvelopeV1 calldata envelope,
    PhilStep6CApprovalV1 calldata approval,
    PhilStep6CPresentationV1 calldata presentation,
    PhilStep6CCoreV1 calldata core,
    bytes calldata targetCalldata
) external;
```

The canonical function signature is exactly:

```text
executeAuthorized((address,bytes32,uint256,uint192,uint64,uint128,uint128,uint256,uint128,uint128,uint48,uint48),(bytes32,uint8,bytes32,bytes32,bytes32,uint64,bytes32,bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,bytes32,uint64,uint64,uint256,uint256,uint64,uint64,uint64,bytes32,bytes32,bytes32),(bytes32,bytes32,bytes32,bytes32,uint64,bytes32,uint64,uint64),(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes32,bytes32,address,bytes32,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint48,uint48,bytes32,uint64,bytes32,uint64,bool,bool,bool),(bytes32,bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32),bytes)
```

Its selector is exactly `0x5a99466a`, the first four bytes of Keccak-256 of
that ASCII signature. The implementation and generator independently assert
the signature string, selector, and tuple field count/order.

The exact `PackedUserOperation.callData` is
`abi.encodeCall(PhilV1Step6CAccount.executeAuthorized,
(action,envelope,approval,presentation,core,targetCalldata))`. After decoding,
the account requires `keccak256(callData) == keccak256(abi.encodeWithSelector(
0x5a99466a,action,envelope,approval,presentation,core,targetCalldata))`; trailing,
aliased, omitted, or noncanonical ABI bytes fail. Every Solidity format field
must equal its frozen domain constant. The SDK envelope digest prepends the
same constant and consumes the remaining envelope fields in the literal order
published later in this packet; the approval, presentation, and core hashes do
the same with their respective constants. The operation's `signature` is exactly the 64-byte
low-S `r || s` wire value and contains no wrapper, mode byte, or ABI envelope.
Every request generator must round-trip decode and byte-for-byte re-encode this
calldata before presenting it.

`validateUserOp` accepts calls only from the stored normally deployed
EntryPoint and rejects every selector except `executeAuthorized`. From the
decoded tuple, stored account/environment/configuration anchors, the actual
`PackedUserOperation`, and exact `targetCalldata`, it reconstructs the full
off-chain `PhilEvmSingleCallV1`, including chain ID, this account, EntryPoint,
account-call commitment, packed nonce, gas/fee fields, zero init-code and
paymaster hashes, and validity. It then recomputes the action hash, account
binding, nonce domain, intent, presentation, envelope, authorization core,
approval nonce, approval digest, request ID, platform signing digest, and raw
P-256 signature result. It also requires the transported root-proof nullifier
to be zero and every stored application/principal/scope/epoch/device/policy
anchor to match.
It strictly decodes the one admitted target method, frozen recorded value, and
canonical boolean; derives the stable parameter schema and capability ID;
derives the dynamic success/failure parameter summary; reconstructs all six
catalog entries from constructor-stored label hashes; and proves that the
catalog and capability-policy hashes remain the constructor-frozen profile
identities while the signed action/core/request hashes change for each nonce,
session, and request window. It requires the request's 120-second interval to
be wholly contained in the constructor-stored 24-hour policy interval.
It requires `action.target.codehash == approvedTargetRuntimeCodeHash` during
every validation, and the hash must equal the signed configuration, policy,
presentation, and target catalog binding. It separately requires
`action.target.code.length > 0`, so the empty-code hash is never admitted.

Successful validation returns the packed ERC-4337 validation data for this
request's exact `validUntil` and `validAfter`, with aggregator address zero;
signature failure returns the standard signature-failed value without calling
the target. Structural, binding, policy, nonce, calldata, or configuration
failure reverts validation. The account never treats a simulation-only result
as execution authority.

During actual `handleOps` validation only, after every structural check and the
P-256 signature succeeds, the account writes
`validatedUserOperationHash[requestId] = userOpHash`. A pre-existing nonzero
entry is permitted only when it equals the same official hash; any different
hash for one request ID reverts. The preceding `eth_call` simulation may
exercise the same write, but its state is not persisted. `executeAuthorized`
requires the exact nonzero mapping entry, uses it in
`PhilV1Step6CAuthorizationConsumed`, performs the target call, and deletes the
entry only on success. If the target reverts, the deletion and execution call
revert while EntryPoint consumes its own nonce and emits `success=false`; the
stale request-ID audit entry neither authorizes execution outside EntryPoint
nor gates any later request or nonce. It is not a nonce, consumed-
authorization set, retry permission, or replay sequence.

Solidity verification imports exactly OpenZeppelin Contracts `5.6.1`
`utils/cryptography/P256.sol` and calls `P256.verify(platformSigningDigest,
r,s,publicKeyX,publicKeyY)`. That function's low-S/public-key checks and
RIP-7212-then-Solidity fallback are part of the pinned dependency identity. The
local chain must prove the no-precompile fallback with positive and negative
vectors; Step 6C may not install code at `0x100`, replace the library, or
interpret an empty precompile response itself.

`executeAuthorized` is also EntryPoint-only. It rechecks every non-signature
binding, time window, value/fee ceiling, target address, target runtime code
hash, and calldata hash against the
same decoded values, then performs exactly
`target.call{value: 0}(targetCalldata)`. It bubbles failure so EntryPoint emits
`success=false`; on success it records and emits the authorization commitment.
There is no owner bypass, generic execute method, batch, delegatecall, fallback
execution, setter, or second nonce.

The envelope uses the existing exact `PhilAuthorizationEnvelopeV1` ABI and
digest function without changing its format ID. Step 6C requires routine
operation class, local environment/network/account/adapter bindings, the new
device signature suite, zero root-proof nullifier, zero proof descriptor, and
the human presentation hash above.

The inherited envelope digest ABI types are literally:

```text
[bytes32,uint8,bytes32,bytes32,bytes32,uint64,bytes32,bytes32,uint64,
 bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,
 uint64,uint64,uint256,uint256,uint64,uint64,uint64,bytes32,bytes32,bytes32]
```

Values are the format hash followed by operation class, scoped owner, scope
ID, scope instance, scope epoch, principal, capability ID/epoch, network,
account binding, adapter, action type, parameters, intent, policy, nonce
domain, nonce, valid-after, valid-until, value limit, fee limit, device,
recovery and validator epochs, device signature suite, proof descriptor, and
human-presentation hash. The existing format intentionally omits
`rootProofNullifier` from this digest, so Step 6C separately requires that
transported field to be exactly zero at every validator and in the account.

The unsigned approval contains the existing V1 digest fields in their existing
order. `approvedAt = request issuedAt`; `approvalExpiresAt = request expiresAt`.
Those are validity bounds, not the biometric-completion instant.

Its digest types and values are exactly:

```text
[bytes32,bytes32,bytes32,bytes32,uint64,bytes32,uint64,uint64]

[PHIL_DEVICE_APPROVAL_V1_HASH, authorizationEnvelopeDigest, deviceId,
 deviceKeyId, deviceEpoch, approvalNonce, approvedAt, approvalExpiresAt]
```

### Authorization core V1

```text
PhilRoutineAuthorizationCoreV1 {
  bytes32 formatVersionHash;
  bytes32 protocolContextHash;
  bytes32 sessionId;
  bytes32 nonceSeed;
  uint64  issuedAt;
  uint64  expiresAt;
  bytes32 executionEnvironmentHash;
  bytes32 adapterManifestHash;
  bytes32 signatureRegistryHash;
  bytes32 deviceEnrollmentHash;
  bytes32 accountConfigurationHash;
  bytes32 catalogHash;
  bytes32 capabilityPolicyHash;
  bytes32 actionHash;
  bytes32 targetCalldataHash;
  bytes32 authorizationEnvelopeDigest;
  bytes32 rootProofNullifier;
  bytes32 humanPresentationHash;
}
```

Hash ABI types:

```text
[bytes32,bytes32,bytes32,bytes32,uint64,uint64,bytes32,bytes32,bytes32,
 bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32]
```

`sessionId` and `nonceSeed` are independent cryptographically random nonzero
32-byte values. Request lifetime is exactly 120 seconds. The protocol context
is `PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1_HASH`.

### Approval nonce, request ID, and signing digest

The construction is acyclic:

```text
approvalNonce = keccak256(abi.encode(
  PHIL_ROUTINE_APPROVAL_NONCE_V1_HASH,
  authorizationCoreDigest,
  sessionId,
  nonceSeed
))

deviceApprovalDigest = existing PhilDeviceApprovalV1 digest over
  authorizationEnvelopeDigest, device/key/epoch, approvalNonce,
  issuedAt, and expiresAt; humanPresentationHash and signatureSuiteId are
  transitively bound by authorizationEnvelopeDigest

requestId = keccak256(abi.encode(
  PHIL_ROUTINE_AUTHORIZATION_REQUEST_V1_HASH,
  authorizationCoreDigest,
  approvalNonce,
  deviceApprovalDigest
))

platformSigningDigest = sha256(
  PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH || requestId
)
```

Approval-nonce ABI types are `[bytes32,bytes32,bytes32,bytes32]`. Request-ID
types are `[bytes32,bytes32,bytes32,bytes32]`. SHA-256 receives exactly 64
bytes: the 32-byte prehash domain followed by the 32-byte request ID. No text,
JSON, length prefix, EIP-191 prefix, personal-sign prefix, or other hashing is
allowed.

The account receives the core fields needed to recompute this graph. It
recomputes environment/profile bindings, action, presentation, envelope,
approval nonce, device approval, request ID, and platform signing digest before
P-256 verification. The final signature therefore covers the session,
nonceSeed, local environment, complete admitted profile hashes, action,
envelope, presentation, approval metadata, and validity.

## Request And Response Transport Records

`PhilRoutineAuthorizationRequestV1` transports the full typed records and raw
bytes described above plus the derived digests. Derived fields are assertions,
never trusted inputs; the iPhone rebuilds all hashes and requires equality.

Its exact top-level fields are:

```text
PhilRoutineAuthorizationRequestV1 {
  bytes32 formatVersionHash;
  PhilExecutionEnvironmentV1 executionEnvironment;
  PhilAdapterManifestV1 adapterManifest;
  PhilRoutineSignatureRegistryV2 signatureRegistry;
  PhilRoutineDeviceEnrollmentV2 deviceEnrollment;
  PhilRoutineAccountConfigurationV1 accountConfiguration;
  PhilRoutineCatalogEntryV1[6] catalogEntries;
  PhilRoutineCapabilityPolicyV1 capabilityPolicy;
  PhilEvmSingleCallV1 action;
  bytes targetCalldata;
  PhilAuthorizationEnvelopeV1 authorizationEnvelope;
  PhilEvmAdapterDeviceApprovalV1 unsignedDeviceApproval;
  PhilRoutineHumanPresentationV1 humanPresentation;
  PhilRoutineAuthorizationCoreV1 authorizationCore;
  bytes32 executionEnvironmentHash;
  bytes32 adapterManifestHash;
  bytes32 signatureRegistryHash;
  bytes32 deviceEnrollmentHash;
  bytes32 accountConfigurationHash;
  bytes32 catalogHash;
  bytes32 capabilityPolicyHash;
  bytes32 actionHash;
  bytes32 authorizationEnvelopeDigest;
  bytes32 humanPresentationHash;
  bytes32 authorizationCoreDigest;
  bytes32 approvalNonce;
  bytes32 deviceApprovalDigest;
  bytes32 requestId;
  bytes32 platformSigningDigest;
}
```

Every named nested record has the exact schema and ABI hash in this packet or
in the explicitly inherited existing V1 formula. `targetCalldataHash` must
equal `keccak256(targetCalldata)`. Derived top-level hashes must equal the
recomputed nested records and are never hashed as a second independent value.
The strict transport decoder requires exactly this key set and the exact nested
key sets; omitted, null, duplicate, or additional keys fail.

The iPhone performs these checks in order:

1. strict schema/scalar parsing;
2. exact local execution-environment profile and false classifications;
3. local adapter manifest, admitted signature registry, V2 device enrollment,
   and account configuration;
4. catalog entry hashes and bound values;
5. capability/policy projection and validity;
6. raw target calldata, action, fee, nonce, and account/environment bindings;
7. human presentation rebuilt from raw records and catalog;
8. envelope and unsigned approval rebuilt from those values;
9. authorization core, approval nonce, device digest, request ID, and signing
   digest rebuilt in the acyclic order; and
10. active session, clock, lock/background, and user-presence rules.

Only then may it display the derived strings and request LocalAuthentication.
It signs only `platformSigningDigest`.

The response fields are:

```text
PhilRoutineAuthorizationResponseV1 {
  bytes32 formatVersionHash;
  bytes32 protocolContextHash;
  bytes32 sessionId;
  bytes32 requestId;
  bytes32 deviceId;
  bytes32 deviceKeyId;
  uint64  deviceEpoch;
  bytes32 humanPresentationHash;
  bytes32 deviceApprovalDigest;
  bytes32 platformSigningDigest;
  bytes32 signatureSuiteId;
  bytes32 providerProfileId;
  bytes32 wireEncodingId;
  bytes32 signatureR;
  bytes32 signatureS;
}
```

Response hash ABI types are the exact types above in order. The response is
strict-parsed and `responseHash` is computed only after successful AEAD
decryption. It is never an outer header or AAD input. Request and response AAD
are only the exact direction/session/request byte strings frozen in the next
section. Desktop accepts only the one active session, recomputes every request
hash again from protected state, then recomputes the response hash and verifies
the P-256 signature before journaling approval.

## Authenticated Routine-Device Enrollment V2

Step 6C-2 enrolls the separate routine key before any authorization request.
The protocol identities are exact:

```text
protocolVersion = 2
transcriptLabel = PHIL_ROUTINE_DEVICE_ENROLLMENT_PROOF_V2
acceptanceLabel = PHIL_ROUTINE_DEVICE_ENROLLMENT_ACCEPTANCE_V2
completePath = /philcore/routine-enrollment/v2/complete
qrPrefix = phil-step6c-routine-enrollment-v2:
bootstrapBytes = 192
maximumHttpBodyBytes = 4096
maximumGeneration = 64
```

The QR suffix is canonical unpadded base64url of this fixed binary bootstrap:

| Offset | Bytes | Value |
| ---: | ---: | --- |
| 0 | 8 | ASCII `PHIL6CE1` |
| 8 | 1 | protocol version `0x02` |
| 9 | 32 | nonzero session ID |
| 41 | 4 | RFC1918 IPv4 in network byte order |
| 45 | 2 | nonzero port, unsigned big-endian |
| 47 | 32 | `keccak256(utf8(completePath))` |
| 79 | 32 | nonzero random enrollment challenge |
| 111 | 8 | expiry as unsigned Unix seconds big-endian |
| 119 | 8 | exact expected routine-key generation as unsigned big-endian |
| 127 | 65 | Desktop ephemeral uncompressed P-256 acceptance key |

Both devices show the first 12 bytes of `SHA-256(bootstrapBytes)` as uppercase
hex in six four-character groups. The iPhone does not create or sign the
enrollment response until the person confirms that fingerprint.

The public record has exactly these fields:

```text
schemaVersion = 2
generation: canonical positive uint64 string
deviceId: nonzero bytes32
deviceKeyId: nonzero bytes32
publicKeyX963: canonical 65-byte uncompressed P-256 point
signatureSuiteId: admitted P-256 SHA-256 prehash suite ID
providerProfileId: admitted Secure Enclave provider-profile ID
wireEncodingId: admitted low-S raw wire-encoding ID
publicKeyFingerprint: SHA-256(publicKeyX963)
secureEnclaveBacked: boolean
userPresenceRequired: boolean
```

Normal product enrollment requires both booleans true. Only an explicitly
classified source test may admit false values. The proof digest is SHA-256 of
the exact concatenation below, with no ABI padding or alternate encoding:

```text
utf8(transcriptLabel) || 0x00 || bootstrapBytes ||
deviceId || deviceKeyId || uint64be(generation) ||
signatureSuiteId || providerProfileId || wireEncodingId ||
publicKeyX963 || uint8(secureEnclaveBacked) || uint8(userPresenceRequired)
```

The iPhone signs that 32-byte digest using the key being enrolled and sends
strict UTF-8 JSON with exactly `protocolVersion`, `sessionId`, `challenge`,
`record`, and `proofSignatureDER`. Desktop strict-parses minimal DER, converts
to canonical low-S raw P-256 form, verifies proof of possession against the
record key, and stores the complete canonical public record through the OS
protection adapter. The HTTP request is one exact HTTP/1.1 JSON POST to the
decoded RFC1918 origin/path with Host, Content-Length, `Cache-Control:
no-store`, and no content/transfer encoding, cookie, authorization, proxy, or
redirect.

Before persistence Desktop derives:

```text
acceptanceDigest = SHA-256(
  utf8(acceptanceLabel) || 0x00 || bootstrapBytes || enrollmentProofDigest
)
```

It prepares a low-S P-256 signature with the ephemeral acceptance key, durably
persists the canonical enrollment, and only then returns strict JSON containing
exactly `protocolVersion`, `sessionId`, `challenge`,
`enrollmentProofDigest`, and `acceptanceSignatureDER`. The iPhone accepts only
status `200`, the exact endpoint and response metadata, exact JSON bindings,
and a valid signature under the QR-bound Desktop key. Desktop idempotently
returns the same signed acceptance when a retry contains another valid proof
for the same canonical enrollment record. Malformed/authentication failure is 400; concurrent
replacement conflict is 409; expiry is 410; excess body size is 413.

Desktop signs the already-derived 32-byte digest directly and zeroes the
ephemeral private key immediately after preparing the cached acceptance; the
response is released only after protected persistence, cached replay needs only
the public acceptance body, and replay ends at the frozen expiry. Swift verifies that
same digest without another hash using Security framework
`ecdsaSignatureDigestX962SHA256`. Both sides require strict canonical low-S DER.
The exact TypeScript-generated acceptance JSON is a mandatory Swift Simulator
vector. After authenticated replacement the product model reloads the active
record before displaying the routine-key fingerprint.

The frozen expected generation is restricted to 1 through 64 and is included in both the fingerprint and signed
proof transcript. Replacement requires that frozen generation to equal
`previous + 1` without exceeding 64 and requires fresh device and key IDs. The
iPhone prepares a pending key, activates it with recoverable prior metadata,
and commits it only after authenticated Desktop acceptance. It rolls back only
if failure occurs before request publication. Transport loss, forged or
malformed acknowledgement, cancellation after publication, or any other
ambiguous delivery retains the activated-pending key so the same generation
can be safely retried or recovered after restart.
The listener accepts only its one active unexpired session. Enrollment storage
records `synthetic_source_test` separately from `physical_device_unverified`;
neither label establishes source acceptance, Secure Enclave attestation,
physical-device verification, or production admission.

## Authenticated Local Transport V1

Step 6C-2 uses a new protocol, not a recovery endpoint or recovery session:

```text
protocolVersion = 1
transcriptLabel = PHIL_ROUTINE_AUTHORIZATION_TRANSPORT_V1
hkdfInfo = PHIL_ROUTINE_AUTHORIZATION_AES256_GCM_V1
requestAAD = DESKTOP_TO_IPHONE_ROUTINE_AUTHORIZATION_V1
responseAAD = IPHONE_TO_DESKTOP_ROUTINE_AUTHORIZATION_V1
beginPath = /philcore/routine/v1/begin
completePath = /philcore/routine/v1/complete
maximumEncryptedPlaintextBytes = 65503
maximumHttpBodyBytes = 65536
```

The QR payload text is exactly ASCII prefix
`phil-step6c-routine-v1:` followed by canonical unpadded base64url of this
216-byte binary bootstrap:

| Offset | Bytes | Value |
| ---: | ---: | --- |
| 0 | 8 | ASCII `PHIL6C01` |
| 8 | 1 | protocol version `0x01` |
| 9 | 32 | raw session ID |
| 41 | 4 | RFC1918 IPv4 in network byte order |
| 45 | 2 | nonzero port, unsigned big-endian |
| 47 | 32 | `keccak256(utf8(beginPath))` |
| 79 | 32 | `keccak256(utf8(completePath))` |
| 111 | 65 | Desktop ephemeral uncompressed P-256 X9.63 key |
| 176 | 32 | raw request ID |
| 208 | 8 | expiry as unsigned Unix seconds big-endian |

No JSON, CBOR, ABI padding, delimiter, alternate prefix, base64 padding, IPv6,
hostname, or URL is admitted in the QR. The decoder requires exact total
length, magic/version/paths, valid curve point, active request/session, RFC1918
address, nonzero port, and canonical re-encoding equality.

The iPhone creates a fresh ephemeral P-256 ECDH key and sends its 65-byte
public key to `begin`. Both sides validate both curve points and derive the
32-byte ECDH shared secret. The final transcript hash is SHA-256 of ABI encoding
with types:

```text
[bytes32,uint8,bytes32,uint32,uint16,bytes32,bytes32,bytes,bytes,bytes32,uint64]
```

Values are transport domain, protocol version, session ID, IPv4, port, begin
path hash, complete path hash, Desktop public key, iPhone public key, request
ID, and expiry. Both devices display the first 12 transcript-hash bytes as
uppercase hex grouped into six four-character groups; the user confirms
equality before the request is decrypted or signing is enabled.

The traffic key is HKDF-SHA256 with input key material=the raw ECDH shared
secret, salt=the 32-byte transcript hash, info=UTF-8 exact `hkdfInfo`, output
length 32. Frames use AES-256-GCM with a fresh random 12-byte nonce and 16-byte
tag. AAD is the exact UTF-8 direction label, one `0x7c` byte, the raw 32-byte
session ID, one `0x7c`, and the raw 32-byte request ID. Nonce reuse is terminal.

The HTTP origin is exactly `http://<decoded dotted-decimal IPv4>:<decoded
port>`. Both endpoints require HTTP/1.1 `POST`, exact decoded path, exact Host,
`Content-Length`, `Cache-Control: no-store`, no content encoding, no transfer
encoding, no cookies/authentication header, no redirect, no proxy, and an
ephemeral URLSession. Connection reuse is disabled.

`POST beginPath` requires `Content-Type: application/json` and one strict UTF-8
JSON object with exactly:

```text
protocolVersion:  JSON number 1
sessionId:        lowercase 0x bytes32
requestId:        lowercase 0x bytes32
iphonePublicKey:  lowercase 0x plus exactly 65-byte uncompressed X9.63 key
```

Unknown/duplicate fields, alternate number/string forms, BOM, trailing bytes,
wrong key/session/request, or a second begin fail. Success is status `200`,
`Content-Type: application/octet-stream`, and one encrypted Desktop-to-iPhone
frame. The iPhone derives/displays the transcript fingerprint and does not
decrypt that frame or enable approval until the person confirms equality.

Every encrypted HTTP frame is exactly:

```text
offset 0:  uint8 version = 1
offset 1:  nonce[12]
offset 13: uint32 ciphertextLength, unsigned big-endian
offset 17: ciphertext[ciphertextLength]
final 16:  AES-GCM tag[16]
```

There are no fields or trailing bytes. Ciphertext length is `1..65503`; total
frame length is exactly `33 + ciphertextLength` and therefore at most `65536`.
Strict request/response JSON plaintext must be at most `65503` bytes before
encryption; every HTTP request body must be at most `65536` bytes. Request
ciphertext decrypts
to the exact strict request JSON; response ciphertext decrypts to the exact
strict response JSON. The direction/session/request AAD defined above is not
carried in the frame and must be reconstructed from protected state.

`POST completePath` requires `Content-Type: application/octet-stream` and one
encrypted iPhone-to-Desktop response frame. Success is status `204` with zero
body bytes and no content type. The only protocol error statuses are `400`
malformed/authentication failure, `404` wrong path or unknown session, `409`
duplicate/out-of-order state, `410` expired, `413` body too large, and `415`
wrong media/content/transfer encoding. Any unexpected status, body on 204,
redirect, interim response, connection switch, or response content type is
terminal. Error bodies are empty and reveal no validation detail.

Each endpoint is single-use, expires with the request, rejects a second phone
key/frame, and closes after completion or any failure. Transport keys, ECDH
private keys, plaintext, and QR bootstrap are destroyed at termination and
never enter the durable journal or renderer.

## Apple DER And Raw P-256 Contract

Apple calls
`SecKeyCreateSignature(... .ecdsaSignatureDigestX962SHA256,
platformSigningDigest ...)` and returns one DER X9.62 signature.

The strict parser accepts exactly one DER SEQUENCE containing exactly two
positive minimal INTEGERs `r` and `s`. It rejects indefinite/non-minimal
lengths, wrong tags, missing/extra integers, empty/negative/zero/over-33-byte
integers, unnecessary/missing sign padding, trailing bytes, `r >= n`, `s >= n`,
and malformed keys. If `s > n/2`, output `n-s`. The wire encoding is exactly
unsigned big-endian `r[32] || s[32]`; consumers reject every other length and
all high-S inputs.

The generator must include low-S, high-S normalization, 31/32/33-byte DER
integers, every malformed class, wrong domain/request/key, swapped values,
single-bit changes, and Swift/TypeScript/Solidity parity.

## One Authoritative Nonce Design

The official EntryPoint keyed nonce is the only account-operation sequence.
Step 6C removes Step 6B's independent `nextNonceSequence` storage and does not
gate validation/execution on a second sequence.

The signed action projects `(uint192 nonceKey,uint64 nonceSequence)` from the
exact EntryPoint nonce. The account requires `userOp.nonce` to match that
projection and relies on EntryPoint validation for consumption. It may record
an authorization hash for successful audit/execution, but that record is not a
second nonce and may not prevent the next EntryPoint-valid sequence after a
failed target call.

`packedUserOperationBytes` is exactly `abi.encode(...)` over nine separate
packed v0.7 field arguments with types
`[address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes]` in order:
sender, nonce, initCode, callData, accountGasLimits, preVerificationGas,
gasFees, paymasterAndData, signature. It is not `abi.encode(singleStruct)` and
contains no outer tuple offset. `initCode` and paymaster data are empty.
`serializedUserOperationHash = keccak256(packedUserOperationBytes)`. This local
hash is distinct from `officialUserOperationHash`, which equals
`EntryPoint.getUserOpHash(exactPackedUserOperation)`; both and the exact packed
bytes are durably committed before submission.

If execution fails after validation, EntryPoint nonce advancement is final for
that local bundle. The request is terminally failed and never retried. A fresh
request reads the new EntryPoint nonce, uses a new session/nonce seed/approval,
and must be able to succeed. The mandatory test is:

```text
valid operation n -> target execution fails -> EntryPoint nonce becomes n+1
fresh operation n+1 -> validates and succeeds -> no Phil sequence deadlock
```

## Normally Deployed Official EntryPoint Contract

The isolated Hardhat chain uses ID `31337`. The test must:

1. compile the pinned official v0.7 source;
2. deploy `EntryPoint` normally and retain its actual address;
3. derive `senderCreator` from the deployed EntryPoint;
4. record creation/runtime code hashes for EntryPoint and runtime code hash for
   SenderCreator;
5. read OpenZeppelin's exact reentrancy storage slot
   `0x9b779b17422d0df92223018b32b4d1fa46e071723d6817e2486d003becc55f00`
   and require the constructor value `1` before any call;
6. require empty account deposit and zero keyed nonce before setup;
7. create and validate the execution-environment record with those identities;
8. deploy the Step 6C account bound to that environment and EntryPoint;
9. fund only disclosed local test accounts and call `depositTo(account)`;
10. require sufficient deposit and `missingAccountFunds == 0`;
11. build the operation using `getNonce(account,key)`;
12. perform a non-mutating `eth_call`/static `handleOps` on the exact serialized
    operation and beneficiary;
13. compare a stored `serializedUserOperationHash` immediately before submit;
14. submit the exact unchanged bytes through local `handleOps`; and
15. verify nonce, deposit/beneficiary accounting, EntryPoint/account/target
    logs, target state, and the receipt below.

No `setCode`, impersonated Base address, factory, `initCode`, paymaster,
counterfactual deployment, public RPC, or external network is allowed.

## Durable Journal And Point Of No Return

The protected host persists an authenticated encrypted append-only journal:

```text
PhilRoutineJournalRecordV1 {
  bytes32 formatVersionHash;
  uint64  generation;
  bytes32 previousRecordHash;
  bytes32 requestId;
  bytes32 sessionId;
  uint8   state;
  address entryPoint;
  address sender;
  uint256 userOperationNonce;
  bytes32 serializedUserOperationHash;
  bytes32 officialUserOperationHash;
  bytes   packedUserOperationBytes;
  address target;
  bytes32 targetRecordedValueBefore;
  uint64  targetRecordedSequenceBefore;
  bytes32 targetPreStateHash;
  uint64  scanStartBlockNumber;
  bytes32 scanStartBlockHash;
  bytes32 localTransactionHash;
  bytes32 localBlockHash;
  bytes32 receiptHash;
  uint64  recordedAt;
  bytes32 reasonHash;
}
```

Hash ABI types are the exact field types above in order, including dynamic
`bytes` for the packed operation. Zero values and empty bytes are used only
before the corresponding artifact exists. Every transition is a durable CAS on
`(generation,previousRecordHash,state)` followed by file flush and full-volume
sync through the existing durable protected-host primitive before an external
effect.

At submission commit, `targetPreStateHash` is exactly:

```text
keccak256(abi.encode(
  address target,
  bytes32 approvedTargetRuntimeCodeHash,
  bytes32 recordedValueBefore,
  uint64 recordedSequenceBefore,
  uint64 scanStartBlockNumber,
  bytes32 scanStartBlockHash
))
```

The host reads all six values at the captured local head and re-reads them
immediately before the CAS. Any difference fails pre-submission.

Step 6C creates a random disposable 32-byte `K_step6c_journal` in the protected
Desktop host. Step 6C-1 injects a disclosed synthetic key; Step 6C-2 stores the
real disposable key in the new disposable V1 profile's separately versioned
OS-protected wrapping record, never in a legacy Alpha identity/validator file.
It is neither Phil root/data/recovery material nor an account/device signing
key. Journal frames use AES-256-GCM, fresh random 12-byte nonce, 16-byte tag,
and strict record JSON plaintext. AAD is exactly
`abi.encode(PHIL_ROUTINE_JOURNAL_FRAME_AAD_V1_HASH,disposableProfileId,
uint64(generation))` with ABI types `[bytes32,bytes32,uint64]`; it is 96 bytes.
The outer strict JSON frame has exactly `version`, `nonce`, `ciphertext`, and
`tag`; version is JSON number `1`, while the other three are canonical
unpadded base64url defined in the transport section. Decoders reject padding,
standard-base64 `+` or `/`, noncanonical re-encoding, unknown/duplicate fields,
wrong decoded lengths, nonce reuse, authentication failure, record-hash chain
failure, or generation gaps. The key and entire disposable journal are deleted
at final ceremony cleanup; deletion does not touch identity or recovery state.
One product lifecycle serializes initialization, begin, replacement, status,
cancellation, deletion, and shutdown. Before clearing enrollment, requests,
journals, or the wrapped journal key, Desktop durably writes an OS-protected
authenticated deletion command. Restart decrypts and exact-validates that
command before completing deletion; an unauthenticated marker fails closed and
cannot authorize deletion.

States are:

```text
1 request_created
2 transport_waiting
3 device_approved
4 response_verified
5 simulation_passed
6 submission_committed
7 submitted
8 receipt_verified
9 completed
20 cancelled
21 expired
22 failed_pre_submission
23 failed_execution
24 receipt_invalid
25 submission_outcome_unknown
```

The atomic point of no return is the durable CAS from `simulation_passed` to
`submission_committed`. In that one fully synced record it stores the exact
EntryPoint, sender, nonce, serialized hash, official hash, packed operation
bytes, target value/sequence/pre-state hash, and current local head number/hash.
The stored bytes must decode and re-encode exactly and reproduce both hashes
before the CAS can succeed.
Before that CAS, cancel may win and creates state `cancelled`. After it, cancel
returns `too_late_submission_committed` and does not change state or claim that
execution stopped.

The host serializes cancel and submit through one protected per-request mutex.
Precedence before the point of no return is: malformed/untrusted response,
trusted-state drift, Desktop/iPhone lock or session replacement, expiry, then
user cancellation. After the point of no return, authenticated local-chain
receipt/state evidence takes precedence; lock, expiry, or cancellation changes
the UI warning but cannot rewrite the outcome.

Restart reconciliation is exact:

- states 1-5 become terminal `failed_pre_submission`; no signature/request is
  reused;
- state 6 first authenticates the stored scan-start block hash, decodes and
  re-encodes the stored operation, reproduces both hashes, and scans official
  EntryPoint `UserOperationEvent` logs from `scanStartBlockNumber + 1` through
  one captured current head for the exact official hash, sender, nonce, and
  zero paymaster. Exactly one `success=false` event plus its successful
  `handleOps` transaction receipt, consumed EntryPoint nonce, and target
  code/value/sequence at that event block equal to the committed pre-state
  proves terminal state 23. Exactly one `success=true` event identifies its
  transaction for full receipt verification, which requires the target event
  and state sequence to equal `targetRecordedSequenceBefore + 1`. No event,
  multiple events, a reorged scan anchor, inaccessible chain, or inconsistent
  nonce/target state becomes durable state 25. The
  operation is never resubmitted;
- state 7 requires the stored transaction hash and reconciles its block/receipt;
- state 8 re-verifies the receipt then advances to 9;
- terminal states never advance, except 25 may move to 23 only when later exact
  evidence proves the stored operation produced the verified failed EntryPoint
  event, or to 8 only when later exact evidence proves successful execution
  and supplies the full receipt; no other transition from 25 is valid;
- if the in-process chain no longer exists, outcome remains unknown and a new
  disposable profile is required.

## Receipt V1

The host requires exactly these logs from one successful local transaction:

- official EntryPoint `UserOperationEvent` with exact `userOpHash`, sender,
  nonce, success `true`;
- Step 6C account `AuthorizationConsumed` with exact request/envelope/device
  digests and target; and
- harmless target `ValueRecorded(bytes32,uint64)` with exact value and sequence.

The exact new event ABIs are:

```text
PhilV1Step6CAuthorizationConsumed(
  bytes32 indexed requestId,
  bytes32 indexed authorizationEnvelopeDigest,
  bytes32 indexed deviceApprovalDigest,
  bytes32 platformSigningDigest,
  bytes32 userOperationHash,
  address target
)

ValueRecorded(bytes32 indexed value,uint64 sequence)
```

The EntryPoint event is the pinned v0.7
`UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)` with
the first bytes32, sender, and paymaster indexed exactly as in the official
interface. Event `topic0` is `keccak256(utf8(canonical event signature))`.

Each event commitment is:

```text
keccak256(abi.encode(
  address emitter,
  bytes32 topic0,
  bytes32 topic1,
  bytes32 topic2,
  bytes32 topic3,
  bytes32 dataHash,
  uint256 logIndex,
  bytes32 transactionHash,
  bytes32 blockHash
))
```

Unused topic positions are zero. `dataHash = keccak256(exact log data bytes)`.
The verifier rejects duplicate expected events, wrong emitters/topics/data,
unexpected second account/target events, wrong order, removed logs, or a failed
transaction status.

Final target state hash is:

```text
keccak256(abi.encode(
  address target,
  bytes32 recordedValue,
  uint64 recordedSequence,
  bytes32 transactionHash,
  bytes32 blockHash
))
```

`executedAt` is the timestamp of the exact receipt block and must fit `uint64`.
Code hashes are `keccak256(eth_getCode(address, receiptBlockNumber))`. The
receipt carries environment, EntryPoint, account, and target code hashes and is
rejected if they differ from admitted state. In particular,
`targetCodeHash == accountConfiguration.approvedTargetRuntimeCodeHash ==
capabilityPolicy.approvedTargetRuntimeCodeHash ==
humanPresentation.targetRuntimeCodeHash`; a receipt cannot introduce the
expected target hash after authorization.

```text
PhilRoutineAuthorizationReceiptV1 {
  bytes32 formatVersionHash;
  bytes32 requestId;
  bytes32 authorizationCoreDigest;
  bytes32 authorizationEnvelopeDigest;
  bytes32 deviceApprovalDigest;
  bytes32 platformSigningDigest;
  bytes32 serializedUserOperationHash;
  bytes32 userOperationHash;
  bytes32 executionEnvironmentHash;
  bytes32 entryPointEventCommitment;
  bytes32 accountEventCommitment;
  bytes32 targetEventCommitment;
  bytes32 targetPreStateHash;
  bytes32 finalTargetStateHash;
  bytes32 entryPointCodeHash;
  bytes32 senderCreatorCodeHash;
  bytes32 accountCodeHash;
  bytes32 targetCodeHash;
  bytes32 transactionHash;
  bytes32 blockHash;
  uint256 entryPointNonceBefore;
  uint256 entryPointNonceAfter;
  uint64  executedAt;
  bool    simulationPassed;
  bool    executionSucceeded;
  bool    externalNetwork;
  bool    productionAuthority;
}
```

Receipt hash uses the exact field types/order above. The last four values must
be `true,true,false,false`. Non-revert or one event alone is never success.
The serialized/official operation hashes and target pre-state hash must equal
the fully synced submission-commit journal record; the receipt verifier
re-decodes the stored operation and independently reproduces both operation
hashes before accepting them.

## Source Matrix

Step 6C-1 may add only:

| Path | Responsibility |
| --- | --- |
| `apps/phil-device-sdk/src/p256SignatureWireV2.ts` | prehash, DER, low-S, X9.63, raw signature |
| `apps/phil-device-sdk/src/routineSignatureRegistryV2.ts` | immutable Step 5 inheritance and local V2 profile |
| `apps/phil-device-sdk/src/routineAuthorizationV1.ts` | records, stable schema/capability/catalog/policy hashes, per-request validation, presentation, response, receipt |
| `apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts` | pure journal transition/CAS contract |
| `contracts/base/erc4337/PhilV1Step6CAccount.sol` | local environment/account enforcement and P-256 verification |
| `contracts/base/erc4337/PhilV1Step6CHarmlessTarget.sol` | one zero-value record action |
| `hardhat.phil-v1-step6c.config.cjs` | isolated official local EntryPoint compile/test |
| focused Step 6C tests and generator | literal matrix and deterministic artifacts |
| Step 6C fixture/manifest/report | disclosed inputs, hashes, counts, nonclaims |

Step 6C-2 may then add the dedicated iPhone routine key/request/transport UI,
protected Desktop routine host/listener, narrow preload IPC, renderer states,
and their focused tests. It must reuse only reviewed transport primitives, with
a new protocol context, endpoint, session keys, messages, and journal. Recovery
credentials/endpoints/transcripts and generic signers remain forbidden.

Production Step 6C source may not import Step 6B harnesses, disclosed keys,
ceremony helpers, STWO/root-proof modules, recovery signers, legacy Alpha
validator authority, public RPC/bundler clients, or deployment scripts.

## Required API

Pure SDK functions:

```text
create/validatePhilExecutionEnvironmentV1
create/validatePhilRoutineSignatureRegistryV2
create/validatePhilRoutineDeviceEnrollmentV2
derivePhilRoutineParameterSchemaIdV1
derivePhilRoutineCapabilityIdV1
derivePhilRoutineParameterSummaryHashV1
create/validatePhilRoutineCatalogV1
create/validatePhilRoutineCapabilityPolicyV1
createPhilRoutineHumanPresentationV1
create/validatePhilRoutineAuthorizationCoreV1
derivePhilRoutineApprovalNonceV1
create/validatePhilRoutineAuthorizationRequestV1
create/verifyPhilRoutineAuthorizationResponseV1
create/verifyPhilRoutineAuthorizationReceiptV1
```

Protected host methods:

```text
beginRoutineAuthorization(typedApplicationIntent)
getRoutineAuthorizationStatus(requestId)
cancelRoutineAuthorization(requestId)
acceptRoutineDeviceResponse(encryptedResponse)
simulateApprovedRoutineAuthorization(requestId)
commitAndExecuteSimulatedRoutineAuthorization(requestId)
reconcileRoutineAuthorization(requestId)
```

No renderer method accepts or selects trust anchors, environment, EntryPoint,
account, device, catalog, capability, policy, target, fee, code hash, nonce, or
assurance label.

## Minimum Test Matrix

The committed suite must cover:

1. cross-language domain and ABI vectors for every record;
2. proof that the derivation graph is acyclic and every core field changes the
   final signing digest;
3. strict scalar/JSON/ASCII/unknown/duplicate-field rejection;
4. all DER, low-S, public-key, suite/provider/wire cases;
5. all raw action/envelope/approval/environment/enrollment/catalog/policy
   substitutions independently;
6. independent iPhone presentation derivation, target runtime admission,
   stable parameter-schema/capability/catalog identities, dynamic parameter
   summary derivation, and all label/value/code-hash equalities;
7. rejection of Base chain/network/canonical EntryPoint and any true external/
   production classification;
8. accepted Step 5 epoch-1 byte identity and local V2 registry binding;
9. normal EntryPoint deployment, SenderCreator/code, reentrancy slot, empty
   state, deposit, nonce, simulation, fee, beneficiary, and events;
10. official EntryPoint nonce as the sole sequence;
11. failed execution followed by a fresh successful next nonce with a new
    session, nonce seed, approval nonce, request time, action hash,
    presentation hash, envelope/core/request digest, and device signature,
    while parameter-schema, capability, catalog, and policy hashes remain
    byte-identical, and proves the successful-validation request-ID/userOp-hash
    handoff is exact, a
    failed target cannot make it a second nonce or block `n+1`, and successful
    execution deletes its own handoff entry;
12. mutation between approval, simulation, commit, and submit;
13. every journal transition, invalid transition, CAS conflict, flush failure,
    crash point, exact packed/official operation evidence, failed EntryPoint
    event recovery, restart reconciliation, outcome unknown, and late evidence;
14. cancel-before-commit wins and cancel-after-commit returns too late;
15. lifecycle races among cancel, expiry, lock, policy drift, submission, and
    receipt under the frozen precedence;
16. target selector/value/length/boolean/trailing-byte substitution plus
    revert/no-event/wrong-event/duplicate/reentry and rollback;
17. exact log/state/code/transaction/block receipt substitutions;
18. sanitized logs/renderer/audit;
19. routine/root-proof/recovery/STWO/legacy/generic-signer reachability
    rejected; and
20. static absence of public RPC, deployment, real secret, or meaningful asset
    authority.

The Step 6C-2 suite adds literal QR/base64url/HTTP/frame/AAD vectors,
authenticated transport MITM/context/endpoint/order/timeout/replay tests,
iPhone UI/accessibility, no-signature-before-presentation,
Face ID/passcode cancel/deny, background/lock/termination/disconnect, durable
journal interruption, key persistence, and exact disposable deletion.

## Commands And Artifacts

The implementation adds stable scripts:

```text
compile:phil-v1-step6c-account
test:phil-v1-step6c-wire
test:phil-v1-step6c-records
test:phil-v1-step6c-entrypoint
test:phil-v1-step6c-journal
test:phil-v1-step6c-desktop
test:phil-v1-step6c-ios-synthetic
verify:phil-v1-step6c-artifacts
```

It also runs typecheck, accepted Step 3-through-6B suites and artifact
verifiers, changed-link validation, JSON validation, and `git diff --check`.
Never run a clean-tree verifier that deletes ignored artifacts in read-only
review.

The deterministic manifest records exact commit/tree, every source/test/doc/
fixture hash and byte count, accepted inherited identities, local V2 registry,
all domains/types, stable parameter schema and capability, six exact catalog
labels and hashes, 24-hour profile-policy bounds, per-request 120-second
windows, dependency lock identities, EntryPoint creation/runtime and
SenderCreator hashes, constructor storage assertion, account/target code,
literal tests, disclosed keys, journal evidence, and explicit booleans for
device/network/production/assets/backend selection.

## Stop Conditions

Reject immediately for any hash cycle, request/nonce/time-dependent catalog or
constructor-frozen policy identity, unsigned security field, ambiguous
encoding/time/log/selector/frame, unsigned target runtime code, V1 registry
mutation, Base/public identity in the local
profile, second account nonce, non-constructor-faithful EntryPoint, renderer
trust selection, generic signer, recovery/routine key reuse, display not
derived from raw signed records, cancellation claim after commit, resubmission
of outcome-unknown work, post-commit journal without exact local and official
operation evidence, receipt inferred from non-revert, missing committed
negative branch, device use before authorization, or readiness claim above the
evidence.

## Verdict Contract

The third corrective definition status-correction review returned exactly:

```text
ACCEPT_THIRD_CORRECTIVE_STEP_6C_DEFINITION_STATUS_CORRECTION_EXACT_CANDIDATE
```

The earlier accepted second corrective candidate is historical evidence and
does not satisfy this corrected contract. The accepted third correction plus
the user's separate continuation instruction authorize only Step 6C-1
synthetic local implementation. Step 6C-2, physical evidence, and final Step
6C remain separate gates; every exact source candidate requires independent
read-only review.
