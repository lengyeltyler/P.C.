# Phil V1 Step 5 Second Bounded Corrective Implementation Report

Status: Exact second corrective candidate independently accepted

Date: 2026-08-22

## Scope

This correction addresses only the three findings against exact corrective
candidate `fb5fb7bdf1ada9e142079086ee829a9e96af081d`:

1. three active registry records bound artifacts that did not implement the
   named schemes;
2. an unknown future policy epoch passed a lower freshness floor; and
3. a forged trusted-state format marker passed reconstruction.

The rejection is preserved in
[the independent review record](../reference/PHIL_V1_STEP5_CORRECTIVE_INDEPENDENT_REVIEW_FB5FB7B.md).
No PQ runtime, device ceremony, proof backend, contract, adapter expansion,
deployment, RPC, transaction, signing, external prover, publication, or Step 6
work is included.

## Corrections

### Semantically exact active bindings

- The secp256k1 signature record binds the exact Keccak ceremony-digest and
  `recoverCanonicalSecp256k1Signer` source blob plus locked Ethers 6.17.0
  dependency that execute digest construction and low-S public-key recovery.
- The SHA-256 record binds the exact `v2NativeIPhoneRecovery.ts` source blob
  containing concrete Ethers `sha256` calls and the locked Ethers dependency.
- The old P-256 ECDH/HKDF label is removed. The replacement record names the
  actual accepted Apple local-key-wrap primitive:
  `SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM`. Its label-derived
  ID, standard reference, and implementation binding all describe ECIES
  cofactor/X9.63-SHA-256/AES-GCM rather than HKDF.

These changes alter the complete registry hash and therefore every capability,
policy, trusted-state, and ceremony identity derived from it.

### Exact trusted policy identity

Trusted state now contains both the exact accepted policy epoch and exact
expected policy hash. A deliberately named untrusted hash-derivation function
supports two-phase initialization but grants no authority. Policy creation and
validation require both exact values to match. An older policy, unknown future
epoch, or different same-epoch policy fails closed.

### Trusted-state format validation

Validation now compares the caller-supplied `formatVersionHash` with the exact
V1 domain before rebuilding or hashing the record. A forged format marker is
rejected even when every other field and the old canonical hash are retained.

## Implementer-run evidence

```text
npm run typecheck
PASS

npm run test:phil-v1-step5-pq-migration
14 passing

npm run verify:phil-v1-step5-artifacts
PASS

npm run test:phil-v1-step3-root-proof-adapter
4 passing

npm run test:phil-v1-step4-composed-account
3 passing

git diff --check
PASS
```

Focused negatives reproduce and reject policy epoch `999`, a substituted
same-epoch policy hash, and a forged trusted-state format. Binding assertions
pin the exact concrete source/dependency descriptions for all three corrected
registry entries.

Independent review of exact candidate
`d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` reproduced the complete matrix,
closed all three findings, retained every earlier closure, and found no new
unresolved finding. See
[the acceptance record](../reference/PHIL_V1_STEP5_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D1DE608.md).

## Verdict boundary

```text
SECOND BOUNDED STEP 5 CORRECTIVE CANDIDATE IMPLEMENTED: YES
STEP 5 INDEPENDENTLY ACCEPTED: YES
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```
