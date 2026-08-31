# PhilCore Local Authorization Demo

Status: Historical O.5 local workflow; current STWO authorization is
structurally disabled and quarantined.

Phase: O.5

## Purpose

This document records the earlier O.5 product-shaped local flow. It is retained
for regression and migration context, not as an available or accepted V1
authorization route.

It demonstrates the Runtime story:

```text
intent
  -> trust
  -> policy
  -> approval
  -> capability
  -> authorization
  -> historical STWO proof generation (now prohibited outside synthetic research)
  -> historical local proof verification
  -> local verified-fact fixture
  -> ERC-4337 local EntryPoint execution
  -> audit
```

## User Flow

1. Launch PhilCore Desktop.
2. Create or open a local identity.
3. Unlock the durable local identity and Device Vault.
4. Open Developer / Local Demo.
5. Approve the exact local action presentation.
6. Review the exact ERC-4337 signing presentation.
7. Complete fresh authentication.
8. Review proof, local fact fixture, UserOperation, nullifier, and consumer evidence.
9. Inspect audit timeline.
10. Lock session.

## Proof Panel

The proof panel displays:

- proof type;
- shortened proofInputHash;
- shortened fact pair;
- generation state and duration;
- local verification state and duration;
- local fixture fact availability;
- witness exposure status.

It does not display witness material or raw proof bytes.

## Execution Semantics

The demo executes through the actual local EntryPoint fixture and verifies ActionGate nullifier consumption and consumer event evidence. It does not submit a public UserOperation, call a public bundler, invoke a paymaster, publish a Starknet fact, anchor on L1, relay to Base, or mutate public chain state.

## Approval Binding

O.5 keeps the O.4 Runtime-generated digest-bound approval for the requested action. After proof and UserOperation preparation, it creates a second exact signing presentation bound to the ERC-4337 userOp hash. Fresh authentication must match that signing presentation digest before the Device Vault validator signer is used.
