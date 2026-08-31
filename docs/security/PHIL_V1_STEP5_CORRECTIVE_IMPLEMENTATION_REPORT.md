# Phil V1 Step 5 Bounded Corrective Implementation Report

Status: Rejected by independent review; superseded by a second bounded correction

Date: 2026-08-22

## Scope

This historical report describes rejected candidate `fb5fb7b`. Its independent
review is preserved in
[the corrective review record](../reference/PHIL_V1_STEP5_CORRECTIVE_INDEPENDENT_REVIEW_FB5FB7B.md).

This correction addresses only the five findings against exact candidate
`fc6514394f5f1ff540c10ac87704a3c24e5f3a4b`:

1. stale Apple ML-DSA classification;
2. inability to migrate to an updated same-network capability record;
3. missing complete-registry binding;
4. missing proof/verifier compatibility binding; and
5. caller-relative freshness and provenance.

No PQ runtime, device ceremony, proof backend, contract, adapter expansion,
deployment, RPC, transaction, signing, external prover, publication, or Step 6
work is included.

## Corrections

### Apple capability evidence

ML-DSA-65 is now `PLATFORM_DOCUMENTED` and remains
`SPECIFIED_CANDIDATE`. The fixture records current Apple Secure Enclave
ML-DSA-65 signing and ML-KEM-768/1024 key establishment as documented on
supported iOS 26+ platforms. Both Phil integration flags and the PQ device
authorization flag remain false.

### Complete registry and implementation binding

Network capabilities and policies bind the registry epoch and complete
registry hash. The registry record hash covers lifecycle, evidence, posture,
standard, exact accepted commit/blob or dependency-lock binding, retirement,
and verifier compatibility. A changed implementation/classification therefore
changes the registry, capability, and policy hashes.

### Proof/verifier compatibility

Proof verifiers carry exact compatible proof IDs. Network records require
mutually compatible nonempty proof/verifier sets, and policy bundles recheck
the exact chosen pair. The incorrect generic ML-DSA signature-verifier entry
was removed from the proof-verifier registry.

### Trusted freshness and provenance

Validation now requires a deterministic protected trusted-state record with:

- exact registry epoch/hash;
- network ID;
- capability-authority hash;
- greatest accepted capability epoch;
- exact expected capability hash; and
- greatest accepted policy epoch.

Stale epochs, unknown hashes, authority/network mismatch, registry mismatch,
or a tampered trusted state fail closed. This module defines and validates the
record; durable protected-runtime persistence remains a later separately
reviewed integration.

### Capability migration

A ceremony validates the old policy against its old capability/trusted state
and the new policy against its new capability/trusted state. Both capabilities
must refer to the same network and authority. A changed capability requires a
higher epoch. Capability and trusted-state rollback fail closed. Both
capability hashes and both trusted-state hashes are ceremony-bound.

## Implementer-run evidence

```text
npm run typecheck
PASS

npm run test:phil-v1-step5-pq-migration
14 passing

npm run verify:phil-v1-step5-artifacts
PASS

git diff --check
PASS
```

The deterministic fixture executes a synthetic classical rotation from
Starknet capability epoch 1 to a distinct same-network epoch 2 record. It does
not claim that epoch 2 exists on Starknet or supports PQ authorization.

## Verdict boundary

```text
BOUNDED STEP 5 CORRECTIVE CANDIDATE IMPLEMENTED: YES
STEP 5 INDEPENDENTLY ACCEPTED: NO
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```
