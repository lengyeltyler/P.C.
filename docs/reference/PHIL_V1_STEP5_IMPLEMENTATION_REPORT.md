# Phil V1 Step 5 Implementation Report

Status: Complete; exact second corrective candidate independently accepted

Date: 2026-08-22

## Delivered

- a frozen registry covering signatures, key establishment, hashes, symmetric
  encryption, KDFs, proofs, and verifiers;
- explicit lifecycle, evidence, and quantum-posture classifications;
- classical, hybrid-AND, and PQ-only policy modes;
- candidate/retired/forbidden activation rejection;
- Starknet and Base capability records with honest classical-only ceilings;
- exact registry hashes bound into capabilities and policies;
- proof/verifier compatibility bindings;
- trusted capability authority plus exact capability and policy hash/epoch
  pins;
- same-network capability-record migration with rollback rejection;
- network/path overclaim rejection;
- deterministic policy bundles and migration ceremonies;
- registry, security-mode, policy, device, validator, and recovery epoch rules;
- AND-only hybrid semantics and independent recovery binding;
- deterministic fixture and artifact manifest; and
- 14 targeted tests plus TypeScript validation.

## Implementer-run evidence

```text
npm run typecheck
PASS

npm run test:phil-v1-step5-pq-migration
14 passing

npm run verify:phil-v1-step5-artifacts
PASS
```

The fixture is architecture-only disclosed synthetic material. It contains no
production key, secret, authority, proof generation, signing action, physical
device evidence, RPC, deployment, or transaction.

## Current result

The current bundle is deliberately `CLASSICAL_ONLY`. It depends on P-256,
Apple's P-256 ECIES cofactor/X9.63-SHA-256/AES-GCM local-key wrapping path, and
the classical Step 3 Noir/UltraHonk proof/verifier path. Its claim assessment
is `algorithm_agile_only`, and the network authorization path is not marked
available.

Apple Secure Enclave ML-DSA-65 signing and ML-KEM-768/1024 key establishment
are captured as platform-documented candidates on supported iOS 26+
platforms. Neither is a Phil-integrated or physically verified capability.
ML-DSA, ML-KEM, SLH-DSA, and transparent STARK therefore remain
candidate/reserved entries and cannot be activated.

## Corrective scope

Independent review rejected exact candidate `fc65143` because Apple ML-DSA
classification was stale, capability-record migration was impossible, the
complete registry was not policy-bound, proof/verifier compatibility was
implicit, and freshness/provenance was caller-relative. The corrective source:

1. classifies Apple Secure Enclave ML-DSA-65 as platform documented but not
   Phil verified;
2. accepts distinct old/new same-network capability records and requires a
   higher epoch when the record changes;
3. binds the complete registry hash into network capabilities and policies;
4. binds each proof verifier to exact compatible proof IDs; and
5. requires protected trusted state with registry, network, capability
   authority, exact capability hash, and capability/policy freshness controls.

Independent review of that first corrective candidate `fb5fb7b` closed items
1, 2, and 4 but rejected three residual defects: three semantically inaccurate
implementation bindings, acceptance of an unknown future policy epoch, and
acceptance of a forged trusted-state format. The second bounded correction:

1. binds secp256k1 recovery to its concrete low-S recovery implementation;
2. binds SHA-256 to concrete SHA-256 calls and renames the P-256 local-key-wrap
   scheme to the actual Apple ECIES cofactor/X9.63-SHA-256/AES-GCM algorithm;
3. pins the exact accepted policy hash as well as its exact epoch; and
4. validates the caller-supplied trusted-state format before reconstruction.

The rejected review is preserved in
[the independent review record](./PHIL_V1_STEP5_INDEPENDENT_REVIEW_FC65143.md).
The rejected first corrective review is preserved in
[the corrective independent review record](./PHIL_V1_STEP5_CORRECTIVE_INDEPENDENT_REVIEW_FB5FB7B.md).
The exact second corrective candidate
`d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` was independently accepted with no
unresolved finding. See
[the final independent acceptance](./PHIL_V1_STEP5_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D1DE608.md).

## Authority boundary

```text
STEP 5 IMPLEMENTER CANDIDATE COMPLETE: YES
STEP 5 INDEPENDENTLY ACCEPTED: YES
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```

Step 5 is complete as a local architecture and migration-control gate. This
acceptance does not select a backend, authorize production, establish PQ
security, or start Step 6. Any later source correction creates a new candidate
and requires review of that exact source and tree.
