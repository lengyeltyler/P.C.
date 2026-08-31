# Local-Proof-Gated First UserOperation

Status: proposal only and cryptographically blocked; no accepted addresses,
funding, or submission. The current STWO artifact exposes witness openings, so
default desktop/Sepolia preparation fails closed before signing. Downstream
lifecycle tests use an explicitly hypothetical witness-hiding fixture, not a
production proof implementation.

The first public UserOperation is an atomic counterfactual account deployment
plus a zero-value confirmation. It is not a standalone account-creation action:

```text
EntryPoint v0.7
  -> PhilCore4337LocalProofAccountFactoryV1.createAccount(...)
  -> PhilCore4337LocalProofAccountV1
  .executeLocalProofAuthorization(actionId, runtimeAuthorizationDigest, expiry)
    -> PhilCoreLocalProofConfirmationTargetV1
       .confirmPhilCoreAction(actionId, runtimeAuthorizationDigest)
```

Required local evidence:

- one canonical action ID and digest;
- authoritative policy and exact approval;
- fresh user presence;
- future reviewed witness-hiding proof generation and local verification;
- matching proof artifact digest and `proofInputHash`;
- final Runtime authorization digest;
- exact account/factory/EntryPoint/nonce/call/gas/fee/expiry binding;
- one-time Device Vault signature.

Future public evidence must include UserOperation hash, transaction hash,
EntryPoint, account, target, block, receipt, and confirmation event. Activity
copy must say: "PhilCore verified the action locally before signing." It must
not say Ethereum verified the STARK proof.

No fact registry, verifier, relay, or paymaster is required for this Model A
experiment. That omission is its central limitation.

The retained O.21.2 lifecycle can produce a short-lived signed-but-unsubmitted
artifact only under an explicitly hypothetical test proof stack. The normal
path is disabled and produces no signing artifact. Any future O.21.3 requires a newly generated
artifact after accepted deployments, live bundler simulation, exact prefund,
fresh nonce and fees, and a separate public submission approval.
