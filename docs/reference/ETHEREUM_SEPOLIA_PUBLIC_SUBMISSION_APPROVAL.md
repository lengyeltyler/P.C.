# Ethereum Sepolia Public Submission Approval

Status: review package template; no approval granted.

## Required Deployment Review

The human reviewer must approve:

- network `Ethereum Sepolia`, chain `11155111`;
- EntryPoint v0.7 at
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`;
- exact source commit and compiler settings;
- each bytecode hash, constructor argument, deterministic salt, and proposed
  address;
- deployer and funder roles;
- current fact model or an accepted replacement architecture;
- recovery authority and delay;
- maximum deployment gas and fees;
- immutable rollback limitations.

## Required First-Action Review

- local-proof-gated account, factory, and immutable confirmation target;
- atomic counterfactual account deployment plus one confirmation action;
- exact `executeLocalProofAuthorization(...)` action ID, Runtime authorization
  digest, expiry, and terminal target calldata;
- value `0`;
- token movement `none`;
- paymaster `disabled`;
- exact nonce, gas, fee, and total spend ceiling;
- expiry;
- STWO proof, approval, presence, and Runtime correlation;
- full v0.7 UserOperation hash;
- expected EntryPoint, account-creation, account-execution, and target-confirmation
  events.

This `local-proof-gated-v1` operation does not invoke ActionGate, an Ethereum
STARK verifier, UnlockConsumer, a fact registry, or an on-chain nullifier. Those
belong to the separate fact-enforced architecture and must not appear in the
approval presentation for this experiment.

## External Inputs

Required later, never committed:

- Sepolia RPC and bundler endpoint references;
- disposable deployer/funder signer references;
- Device Vault validator and recovery authority records;
- accepted deployment manifest;
- fee caps;
- independent deployment and UserOperation approvals.

## Approval Gates

Deployment:

```text
PHILCORE_PUBLIC_NETWORK_APPROVED=1
PHILCORE_ETHEREUM_SEPOLIA_APPROVED=1
PHILCORE_ETHEREUM_SEPOLIA_DEPLOYMENT_APPROVED=1
```

First UserOperation:

```text
PHILCORE_PUBLIC_NETWORK_APPROVED=1
PHILCORE_ETHEREUM_SEPOLIA_APPROVED=1
PHILCORE_USEROP_SUBMISSION_APPROVED=1
```

Environment flags are necessary but not sufficient. The manifest must be
`accepted`, addresses and code must be independently verified, exact
presentation approval must be fresh, and the mutation transport must belong to
the separately approved live phase.

## First Mutation Command

O.17 reserves:

```bash
npm run ethereum-sepolia:deploy-test-target -- --submit
```

The current O.17 command has no RPC transport and always stops. A following
phase may implement the guarded transport only after the review above. If
deployment order changes after architecture review, the approval package and
command must be regenerated; no command is approved by this document.
