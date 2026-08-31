# Phil V1 Step 6C Third Corrective Definition

Status: Exact definition candidate; independent review required

Date: 2026-08-22

## Purpose

This bounded correction resolves the implementation blocker recorded in
[the nonce/catalog blocker report](./PHIL_V1_STEP6C_IMPLEMENTATION_BLOCKER_NONCE_CATALOG.md).
It changes no accepted Step 1-through-6B source, Step 5 registry identity,
EntryPoint version, device-signature suite, execution selector, receipt,
journal, transport, recovery boundary, root-proof boundary, network boundary,
or production claim.

The complete corrected contract is the current
[Step 6C implementation packet](./PHIL_V1_STEP6C_IMPLEMENTATION_PACKET.md),
[product-composition gate](./PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_PRODUCT_COMPOSITION_GATE.md),
and [threat model](../security/PHIL_V1_STEP6C_ROUTINE_AUTHORIZATION_THREAT_MODEL.md).
This record explains the delta and publishes a mechanical witness; it is not
an informal addendum that may override those primary documents.

## Corrected Separation

Step 6C now has two non-interchangeable layers:

```text
stable disposable profile
  environment + account + target/code + parameter schema + capability
  + catalog + 24-hour capability policy

per-operation request
  raw calldata + EntryPoint nonce + gas/fee + 120-second window
  + action + dynamic summary + presentation + envelope + core
  + session + nonce seed + approval + request ID + device signature
```

Stable constructor identities contain no EntryPoint nonce, action hash,
request timestamp, session ID, nonce seed, approval nonce, request ID, or
signature. Per-operation records still sign all of those values.

## Stable Parameter Schema

The new frozen domain hashes are:

```text
PHIL_ROUTINE_PARAMETER_SCHEMA_V1_HASH = 0xcebf7aec2aa652e1132d57a130f2c5d92ad8f9ce0f17d87e9076a0dad87718ca
PHIL_ROUTINE_CAPABILITY_V1_HASH = 0x335a168faf7c4da5c89f7003ce61d04988d2bb61d74c62ff2eee137d41367774
```

The one admitted method and value are:

```text
recordSelector = bytes4(keccak256(utf8("record(bytes32,bool)")))
recordedValue = keccak256(utf8("PHIL_STEP6C_HARMLESS_VALUE_V1"))
```

After normal target deployment:

```text
parameterSchemaId = keccak256(abi.encode(
  PHIL_ROUTINE_PARAMETER_SCHEMA_V1_HASH,
  approvedTarget,
  approvedTargetRuntimeCodeHash,
  recordSelector,
  recordedValue
))
```

The types are `[bytes32,address,bytes32,bytes4,bytes32]`. The raw calldata is
exactly 68 bytes and must decode/re-encode to the frozen selector and value plus
canonical ABI boolean `false` or `true`.

## Stable Capability

After the account address and scope instance are predicted:

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

The types are
`[bytes32,bytes32,bytes32,address,bytes32,bytes32,bytes32]`. This removes the
previous unspecified capability identity and prevents caller selection.

## Stable Catalog And Dynamic Summary

Catalog kind 6 uses `parameterSchemaId` as both `entryId` and
`boundValueHash`. The catalog contains none of the nonce-bearing action hash.
All six catalog strings are exact and constructor-admitted.

The presentation still sets `parametersHash = actionHash`. Its dynamic summary
is independently derived from the strict decoded boolean:

```text
false -> keccak256(utf8("Record disclosed harmless value"))
true  -> keccak256(utf8("Intentionally revert before recording"))
```

The account stores the six stable label hashes and parameter schema, rebuilds
the catalog, derives the dynamic summary from calldata, and then recomputes the
presentation and complete request-signing graph. It neither trusts a caller-
selected label nor drops the action hash from the signature.

## Stable Policy And Per-Request Expiry

The capability policy freezes:

```text
profilePolicyValidAfter = profile creation Unix seconds
profilePolicyValidUntil = profilePolicyValidAfter + 86400
```

Every request independently freezes:

```text
issuedAt = request creation Unix seconds
expiresAt = issuedAt + 120
```

and must prove
`profilePolicyValidAfter <= issuedAt < expiresAt <= profilePolicyValidUntil`.
The account stores the policy bounds. A fresh next-nonce request can therefore
have a new protected-clock time without changing the constructor policy hash.

## Exact Validation-To-Execution Hash Handoff

The official `userOpHash` is an EntryPoint argument to `validateUserOp` but is
not a field of `executeAuthorized`. After exact structural and signature
success, actual validation therefore stores
`validatedUserOperationHash[requestId] = userOpHash`. Execution requires that
entry, emits that exact hash, and deletes the entry only after target success.
A failed target leaves request-specific audit evidence but cannot authorize a
direct call, prevent a later request, or act as a nonce. The official
EntryPoint keyed nonce remains the sole sequence.

## Mechanical Stability Witness

The following disclosed synthetic witness uses target
`0x3333333333333333333333333333333333333333`, account
`0x1111111111111111111111111111111111111111`, EntryPoint
`0x2222222222222222222222222222222222222222`, nonce key `7`, policy interval
`[1800000000,1800086400]`, failed request interval
`[1800000100,1800000220]`, and successful request interval
`[1800000105,1800000225]`. Both operations use maximum-total-fee value
`8550000000000000` under the stable policy ceiling `20000000000000000`.

All remaining witness inputs are exact:

```text
chainId = 31337
targetRuntimeCodeHash = keccak256(utf8("phil-step6c-synthetic-target-runtime-v1"))
applicationId = keccak256(utf8("phil-application-step6c-local-harmless-v1"))
scopeId = keccak256(utf8("phil-scope-step6c-local-routine-v1"))
executionEnvironmentHash = keccak256(utf8("synthetic-environment"))
networkIdHash = keccak256(utf8("phil-local:step6c:31337"))
adapterId = keccak256(utf8("phil-adapter-step6c-local-erc4337-v07-v1"))
actionTypeHash = keccak256(utf8("PHIL_EVM_SINGLE_CALL_V1"))
adapterManifestHash = keccak256(utf8("synthetic-adapter-manifest"))
accountConfigurationHash = keccak256(utf8("synthetic-account-configuration"))
deviceEnrollmentHash = keccak256(utf8("synthetic-device-enrollment"))
scopedOwnerCommitment = keccak256(utf8("synthetic-scoped-owner"))
scopeEpoch = recoveryEpoch = validatorEpoch = capabilityEpoch = policyEpoch = 1
valueWei = maximumValueWei = 0
callGasLimit = 500000
verificationGasLimit = 8000000
preVerificationGas = 50000
maxFeePerGas = 1000000000
maxPriorityFeePerGas = 100000000
initCodeHash = paymasterAndDataHash = bytes32(0)
```

`principalIdHash`, `scopeInstance`, target calldata, account-call commitment,
packed nonce, total fee, action hash, catalog entries, and policy hash use only
the literal derivations in the corrected implementation packet; no additional
input is implicit.

```text
recordSelector = 0x178ae0b6
recordedValue = 0x4d535b2f9725c2d7e0d0bcffac515328a047ab00833562afdda23178bdaf9461
parameterSchemaId = 0x890527a538c52e82188b2d3e7a543e04e5bd812846502a9940173afe96226630
capabilityId = 0xb81019e924172a5ebae7d2a77e6057261b6f1c5a6332230e9ba290c40f3c4964
catalogHash = 0xaa4f8a3ac27398520f8d9512d1d807b339f89601c66b42ee6efe3521ffdaf21a
capabilityPolicyHash = 0x6acb016e6be102fbb459e60a5ae9f9368684590d9457706cd9500c84343ffb3e

failedActionHash(n=0,true) = 0x84bf9d1e05db507b5217506292d623121c89013c36052ed0c51743552d51eeea
successfulActionHash(n=1,false) = 0x96b9447415ae618955fa59f648e4dc8a420c925d39a338d69754b5a2eb70b72e

failedSummaryHash = 0xcc71f9d8fbe88efb80b3d7c447284927ce1bec5b8529950e9a06c83f89b97b58
successSummaryHash = 0xed79b61f4c70bb78956629e732df0ffbc34001123ab24728646a54cfcf5e2d9a
```

The failed and successful action/summary hashes differ. The parameter schema,
capability, catalog, and policy hashes are byte-identical. This is the required
separation; an implementation test must additionally prove all downstream
presentation, envelope, core, request, and signature hashes differ.

The six catalog display-text hashes in kind order are:

```text
0x8751d0b967b8172dec0598a335857e0ac7051b4eba83e9122d1222ff7d9cdd8c
0x51fba215d9099c6f84664bd8e1df361fe9a5da80f0cceee7f2fd993254cd5996
0x7ef878ab1acf73b2e9bfb49349c846746eb497895abf2de18e9831be39c8751a
0x065a873dff30b4d359e16f9157f4157fe8022a584106e098cb5855bbbb23c83f
0xc428221b25f4b10e9729dc0dde29b694a0d7a4cad9a187b3d7b1a7f728438909
0xfa7b9e03c3493b61d2fdd02b128aa23178b31aeb7e3503a4d7907b4ee0a585cc
```

## Local Definition Evidence

The candidate preflight reproduced:

```text
TypeScript typecheck                                      PASS
Step 3 root-proof adapter                                  4 PASS
Step 4 composed authorization                              3 PASS
Step 5 post-quantum migration                             14 PASS
Step 6A Base adapter                                       8 PASS
Step 6B local account                                     14 PASS
Step 3/4/5/6A artifact verifiers                          PASS
Step 4 reference-manifest deterministic regeneration      PASS
corrective domain/selector/stability witness               PASS
changed-document local links                              403 PASS
git diff --check                                           PASS
CI classification validator                       BASELINE 17 FAIL
```

The classification result is the unchanged historical inventory: twelve
Step 3-through-6B package scripts and five corresponding unit-test files are
not registered. This documentation-only correction changes none of those
items, `package.json`, classification rules, or implementation/test source. It
is recorded as baseline debt and is not called a passing gate.

## Required Independent Review

The reviewer must independently reproduce:

- both new domain hashes and exact ABI formulas;
- selector, recorded value, strict 68-byte target calldata, and summaries;
- capability determinism and absence of caller-selected identity;
- all six label hashes, entry hashes, and catalog hash;
- policy-window and request-window containment;
- byte-identical stable hashes across failed `n` and successful `n+1`;
- changed per-operation and terminal signing hashes across that sequence;
- constructor ability to reconstruct the stable catalog/policy anchors from
  stored values without request-selected labels; and
- exact validation-to-execution official-hash handoff, failed-call behavior,
  successful deletion, and proof that the mapping is not replay authority; and
- absence of any second nonce, mutable policy, weakened action binding, device
  authority, external RPC, public network, or production claim.

The verdict is exactly one:

```text
ACCEPT_THIRD_CORRECTIVE_STEP_6C_DEFINITION_EXACT_CANDIDATE
REJECT_THIRD_CORRECTIVE_STEP_6C_DEFINITION_EXACT_CANDIDATE
```

## Authority

This definition candidate authorizes no implementation resumption, device use,
signing, external RPC, network activity, deployment, publication, transaction,
real identity/recovery material, meaningful asset, or production authority.
Step 6C-1 and Step 6 remain incomplete until later gates pass.
