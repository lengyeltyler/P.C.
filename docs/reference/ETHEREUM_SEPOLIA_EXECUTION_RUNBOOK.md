# Ethereum Sepolia Execution Runbook

Status: dry-run stages only in O.17.

For the current `local-proof-gated-v1` first-operation review, see
[O.21.3 Final Ethereum Submission Boundary Review](./O21_3_FINAL_ETHEREUM_SUBMISSION_BOUNDARY_REVIEW.md).

## O.17 Safe Commands

```bash
npm run ethereum-sepolia:inspect
npm run ethereum-sepolia:prepare-manifest
npm run ethereum-sepolia:verify-manifest
npm run ethereum-sepolia:preflight
```

They use local files and compilation artifacts. They do not contact an RPC,
sign, fund, deploy, or submit.

## Future Guarded Stages

1. inspect configuration;
2. validate chain and canonical EntryPoint read-only;
3. compile and test;
4. calculate CREATE2 addresses from approved fixtures;
5. estimate deployments read-only;
6. produce proposed manifest;
7. accept source, hashes, roles, addresses, gas, fees, and fact model;
8. deploy harmless target;
9. deploy only the components selected by the accepted architecture; the
   local-proof-gated experiment deploys its harmless confirmation target and
   does not deploy a fact verifier, ActionGate, or consumer;
10. deploy the selected account factory;
11. verify code and constructor bindings;
12. derive account and inspect disposable funding;
13. prepare and display exact first UserOperation;
14. generate/verify STWO proof;
15. simulate with accepted v0.7 bundler;
16. approve, fresh-authenticate, and Device Vault sign;
17. separately approve submission;
18. submit once;
19. reconcile receipt, account, EntryPoint, gate, nullifier, and target event.

Every mutation stage defaults to dry run and must print a sanitized exact
mutation before approval.

## Stop Conditions

Stop on:

- chain, EntryPoint, address, bytecode, constructor, salt, or manifest mismatch;
- proposed rather than accepted manifest;
- dirty repository where release policy requires clean state;
- missing fact/verifier evidence;
- missing allowlist or nonzero value;
- paymaster data;
- nonce, gas, fee, prefund, or expiry change;
- missing/mismatched proof, approval, presence, Runtime, or signing artifacts;
- missing separate deployment/submission approval;
- ambiguous bundler response or inconsistent receipt.

Never retry an ambiguous mutation blindly. Reconcile first.

## Activity Reconciliation

One user-facing event advances through:

`Prepared -> Approved -> Submitted -> Included -> Confirmed`

or:

`Failed | Replaced | Expired`.

Technical state retains action ID, authorization reference, UserOperation and
transaction hashes, block, EntryPoint, account, target, nonce, gas, fees, and
receipt. App restart resumes observation, not authority. Confirmation requires
an independently verified receipt and expected events/state.
