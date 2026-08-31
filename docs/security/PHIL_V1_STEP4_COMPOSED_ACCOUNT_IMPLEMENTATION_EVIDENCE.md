# Phil V1 Step 4 Composed Account Implementation Evidence

Status: Historical implementation evidence for rejected candidate 895320f

Date: 2026-08-21

## Outcome

The isolated candidate composes the accepted Step 3 root proof, a separate
native Cairo P-256 device signature, exact action and policy bindings, current
epochs, time/value/fee limits, revocation state, and three independent replay
keys in one Cairo entrypoint. A valid call writes exactly one synthetic receipt.

Independent review rejected the frozen candidate. See
`docs/reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_895320F.md`. This report is
retained as the implementer evidence that was reviewed; the corrective results
are recorded separately.

## Exact dependency identity

- Accepted Step 3 candidate: `11234ea623a6b8883eed0036f3d95174cef90627`.
- Cairo and Starknet: `2.14.0`.
- Scarb: `2.14.0`, executable SHA-256
  `2e20da95b4cd51c030c54c0e5977a3a398ca18c8b68eefe6dc6e000d91467488`.
- Starknet Foundry: `0.53.0`, `snforge` SHA-256
  `fb2d19e2c4befbdf2ffd9937351b6a6d9363421c50aafe86d252a92d19442d72`.
- Universal Sierra Compiler: `2.10.0`, executable SHA-256
  `de6d1d4e03b8398cd895238ff2205d848b73488b0c2e8b8c7fec427a0281c4f1`.
- Garaga: `1.0.1`, source commit
  `aa91b6504c86995789edb4e78f9f9ba20571625c`.

The vendored Step 3 verifier compiles to the exact accepted identities:

- Sierra class hash:
  `0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd`.
- compiled class hash:
  `0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911`.

The Step 4 gate candidate compiles to:

- Sierra class hash:
  `0x19fa752ccc7674182c08d632ce30ff3b759fd552ea7a7cdb41daa841e112002`.
- compiled class hash:
  `0x2cd91b470d1cc23d0f95a26dc6034c9d2306e0276828d7ac18fdba13149429a`.
- Sierra JSON: 625,258 bytes.
- CASM JSON: 283,564 bytes.

## Deterministic parity

The generator derives the envelope, P-256 public key, device-approval digest,
canonical low-S signature, and receipt in TypeScript. It emits matching Cairo
constants and structures. Cairo tests independently recompute both digests,
verify the P-256 signature with the native `secp256r1` syscall, validate the
accepted proof, compare all 13 public inputs, and reproduce the exact receipt.

The inherited proof calldata SHA-256 is
`f57b9171f9553d544a132d139df31adb9541493463085a0fc716e5266a92143d`.
The generated Step 4 vector contains `productionAuthority: false`,
`networkActivity: false`, and `physicalDeviceUsed: false`.

## Local test evidence

The final isolated suite contains 48 Cairo tests and 3 TypeScript tests. It covers the valid composed call,
deterministic digest parity, exact state advancement, all replay flags,
repeated authorization, missing/corrupted proof, proof public-input mismatch,
missing/corrupt/wrong-key/high-S device signatures, every configured binding,
all five epochs, approval and envelope time windows, value and fee limits,
policy-ceiling invariants, revocations, emergency stop, and unchanged state after a
rejected composition.

The valid local call measured:

- approximate L2 gas: 314,210,874;
- Sierra gas: 314,128,954;
- L1 data gas: approximately 5,568;
- syscalls: Keccak 105, StorageRead 78, StorageWrite 65, CallContract 3,
  Secp256r1Mul 2, Secp256r1New 2, GetExecutionInfo 1, EmitEvent 1,
  Secp256r1GetXy 1, Secp256r1Add 1, Deploy 1, LibraryCall 1.

These are Starknet Foundry local measurements, not a deployment estimate or
network fee quote.

## Structural isolation

The only new TypeScript surface derives a non-authoritative receipt. The only
new Cairo action writes that receipt and replay state. Static tests reject any
new runtime import, RPC/network client, signer, deployment syscall, arbitrary
contract-call syscall, class replacement, or STWO reference. The Step 3
verifier is reached only as its exact compiled library class.

No physical device, real secret, external prover, RPC, network transaction,
deployment, funds, production source wiring, Step 5 work, or publication was
used.

## Gate verdict

```text
STEP 4 ACCEPTED: NO
EXACT CANDIDATE 895320F: REJECTED
CORRECTIVE CANDIDATE REQUIRED: YES
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 5: NO
```
