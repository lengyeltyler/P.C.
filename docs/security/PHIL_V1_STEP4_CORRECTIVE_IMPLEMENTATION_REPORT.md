# Phil V1 Step 4 Corrective Implementation Report

Status: Historical first corrective candidate; independently rejected

Date: 2026-08-22

Rejected predecessor: `895320f4060ab809b9dab564fcedc1118dfb5780`

Reviewed corrective candidate: `eaaae447a01bf901fc4183338da88b7406981a4e`

The independent review verified all corrections below but found a remaining
zero-approval-timestamp parity defect and two missing executed policy-ceiling
branches. See
[the exact review](../reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_EAAAE44.md).

## Correction mapping

| Independent finding | Correction |
| --- | --- |
| Arbitrary verifier class | Removed the verifier class from configuration and storage. The contract now constructs the exact accepted Step 3 class hash from a compiled constant for every proof dispatch and exposes a read-only identity view. |
| Zero approval nonce | Added a format-stage nonzero approval-nonce assertion matching TypeScript semantics. |
| Wrong failure precedence | Moved approval format first, approval bindings before epochs, approval time checks before replay, and left signature/proof validation after replay. |
| Incomplete replay matrix | Added isolated test-state cases for consumed envelope digest, root nullifier, and approval nonce, plus a format-versus-replay precedence case. |
| Unusable immutable configuration | Constructor now validates P-256 coordinates on-curve and rejects `next_nonce == u64::MAX`; direct helper tests cover both boundaries. |

## Substitute-verifier regression

`PhilStep4AccountConfigurationV1` no longer contains a verifier-class field.
The contract has no verifier-class storage cell. The proof dispatcher receives
only `accepted_step3_verifier_class_hash()`, which returns
`0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd`.
The regression suite confirms the configuration surface is absent, the view
reports that exact identity, and an empty proof still fails against the pinned
verifier.

## Corrective local evidence

- 56 Cairo tests passed offline.
- 3 TypeScript parity and structural-isolation tests passed.
- Valid composition measured approximately 314,216,714 L2 gas, 314,134,794
  Sierra gas, and 5,472 L1 data gas.
- The accepted Step 3 verifier remains unchanged at Sierra class hash
  `0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd`
  and compiled class hash
  `0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911`.
- The corrective Step 4 gate compiles to Sierra class hash
  `0x6bdbb969add096f3ff6b770ea8a828513a228ad51ef09987fbba164138c48f2`
  and compiled class hash
  `0x10d1c31c47506edf7610adc66adf8cd5474e1724e496568ded281eac09f04ff`.
- Corrective Sierra/CASM JSON sizes are 625,455 and 277,809 bytes.

These are implementer-run local results, not independent acceptance or a
network fee estimate.

## Authority boundary

No physical device, real secret, external prover, RPC, network transaction,
deployment, funds, production wiring, backend selection, Step 5 work, or
publication was used or authorized.

```text
STEP 4 ACCEPTED: NO
FIRST CORRECTIVE CANDIDATE ACCEPTED: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 5: NO
```
