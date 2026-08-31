# Phil V1 Step 3 Independent Review: `11234ea`

Status: Accepted

Date: 2026-08-21

## Exact reviewed candidate

```text
candidate commit: 11234ea623a6b8883eed0036f3d95174cef90627
candidate tree:   9ff5177d11525df640cf103fdf982d73fb47a4f1
candidate parent: 841a79cbd5f28b15bfdc06a831319a7dd7efcc46
review range:     841a79cbd5f28b15bfdc06a831319a7dd7efcc46..11234ea623a6b8883eed0036f3d95174cef90627
```

The separate reviewer verified these identities and reviewed the immutable
candidate, not the later review-packet commit or a mutable working tree. The
review remained read-only and local. No candidate file was modified.

## Findings

No unresolved critical, high, medium, or low security or correctness finding
was identified.

The reviewer independently established from source that:

- the authorization digest omits only the derived `rootProofNullifier` and
  retains the required envelope binding;
- operation classes, capability/proof fields, and the separate device-suite
  requirement fail closed;
- the Noir circuit implements the ABI-compatible Keccak identity, scoped-
  commitment, and nullifier relation with a canonical non-zero 251-bit root;
- the descriptor and verifier-binding construction binds the intended circuit,
  key, generated verifier source, suite/version labels, schema, and codec
  without a circular dependency;
- all seven logical public values are compared and losslessly encoded as the
  exact 13-value `u128`/`u64` sequence;
- the generated verifier performs the Honk and KZG checks before returning
  public inputs; and
- no Phil runtime, renderer, preload, plugin, Device Vault, signer, account,
  RPC, deployment, submission, or STWO authority path reaches the candidate.

## Reproduced evidence

The reviewer reproduced or independently recomputed:

- all four exact-candidate adapter tests;
- artifact verification and the TypeScript typecheck;
- the identity root, scoped commitment, envelope digest, root nullifier,
  descriptor fields, verifier-binding hash, and descriptor hash;
- the exact 13 values in both the native public-input file and Garaga calldata;
- the offline Scarb `2.14.0` build;
- both Starknet Foundry verifier tests;
- the reported valid and rejected verifier-call L2-gas figures;
- the Sierra/CASM sizes, felt counts, and class hashes;
- equality between the committed VK hash and the hash embedded in the generated
  Cairo verifier; and
- absence of the disclosed private literals from the committed proof, native
  public inputs, and Garaga calldata.

The repository remained clean after review.

The artifact manifest committed inside `11234ea` intentionally retains its
pre-review status, `exact-candidate-pending-independent-review`. Rewriting that
generated candidate artifact after review would change the reviewed tree. This
later record is the authoritative acceptance status and does not alter any
candidate hash.

## Explicit limitations

The disposable Nargo and Barretenberg executables were no longer present, so
the reviewer did not rerun native verification, the ten witness/input negative
executions, or repeated-proof randomization. The reviewer inspected their
fail-closed harness and independently established consistency among the
committed circuit, VK, proof, public values, Garaga calldata, and successful
Cairo verification. Native timing/memory, release-archive hashes, and the
earlier two-proof randomization measurement remain recorded evidence rather
than independently remeasured evidence.

This is not a new formal cryptographic audit of Noir, Barretenberg, or Garaga.
Noir remains beta, Barretenberg remains a nightly compatibility pin, iPhone
proving remains unverified, and no network-fee measurement was made. These are
explicit production-selection limits, not hidden Step 3 claims.

## Independent verdict

```text
ACCEPT_STEP_3_EXACT_CANDIDATE
```

Acceptance means that Step 3 passed as bounded local Starknet reference-adapter
evidence. It does not select a production backend and does not authorize Step
4, deployment, RPC activity, signing, a physical device, or a real secret.

```text
STEP 3 ACCEPTED: YES - LOCAL REFERENCE EVIDENCE ONLY
PRODUCTION PROOF BACKEND SELECTED: NO
START STEP 4: NO
```
