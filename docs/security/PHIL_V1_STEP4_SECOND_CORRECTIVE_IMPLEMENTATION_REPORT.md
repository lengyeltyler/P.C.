# Phil V1 Step 4 Second Corrective Implementation Report

Status: Exact candidate independently accepted

Date: 2026-08-22

Rejected predecessor: `eaaae447a01bf901fc4183338da88b7406981a4e`

Accepted exact candidate: `3377606d404312ef7f7dcfec37a11c046f2c907e`

Independent review:
[acceptance of 3377606](../reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_3377606.md)

## Narrow correction mapping

| Independent finding | Correction |
| --- | --- |
| Zero approval timestamp | Added format-stage nonzero assertions for both `approved_at` and `approval_expires_at`, matching the positive-`uint64` TypeScript approval format before revocation or replay reads. |
| Missing policy-ceiling execution tests | Moved the unchanged value/fee ceiling assertions into one pure validator that the constructor must call. Two isolated Cairo tests now execute and match the exact value and fee rejection branches. |

No authorization digest, proof public input, signature algorithm, verifier
identity, replay key, epoch, policy binding, state write, or action surface was
changed.

## Second corrective local evidence

- 60 Cairo tests passed offline, including both zero timestamp cases and both
  exact policy-ceiling rejection branches.
- 3 TypeScript parity and structural-isolation tests passed.
- Deterministic artifact verification and repository typecheck passed.
- The package built offline with Scarb `2.14.0`; Starknet Foundry remained
  `0.53.0` and Universal Sierra Compiler remained `2.10.0`.
- Valid composition measured approximately 314,221,414 L2 gas, 314,139,494
  Sierra gas, and 5,472 L1 data gas.
- The accepted Step 3 verifier remains unchanged at Sierra class hash
  `0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd`
  and compiled class hash
  `0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911`.
- The second corrective Step 4 gate compiles to Sierra class hash
  `0x0453ab1f858031f49d19dc3cb431af0d80e81d0bb958372dfe88666173360669`
  and compiled class hash
  `0x36a5bb9774da5922be5d06473ff0c0e5915ab6404c277619c635563718c1a90`.
- Step 4 Sierra/CASM JSON sizes are 629,434 and 279,456 bytes.

The valid composition used Keccak 105, StorageRead 77, StorageWrite 64,
CallContract 3, Secp256r1New 3, Secp256r1Mul 2, GetExecutionInfo 1, Deploy 1,
EmitEvent 1, LibraryCall 1, Secp256r1GetXy 1, and Secp256r1Add 1.

The canonical vector, Cairo fixture, and proof calldata remain byte-identical
to the rejected predecessor; only the gate, tests, structural assertions, and
their deterministic manifest bindings changed.

The measurements were implementer-run and independently reproduced. They are
not a network fee estimate.

## Authority boundary

No physical device, real secret, external prover, RPC, network transaction,
deployment, funds, production wiring, backend selection, Step 5 work, or
publication was used or authorized.

```text
STEP 4 ACCEPTED: YES
ACCEPTED EXACT CANDIDATE: 3377606d404312ef7f7dcfec37a11c046f2c907e
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
STEP 5 STARTED: NO
```
