# World ID Onboarding Model

## Current Status

This is a supporting onboarding/reference document for existing World ID signal and receipt helper assumptions. The current human-uniqueness and canonical activation boundary is defined in [Phil Human Uniqueness and World ID Boundary](./PHIL_HUMAN_UNIQUENESS_AND_WORLD_ID_BOUNDARY.md).

## Purpose

World ID is an optional proof-of-human onboarding layer for Phil.

It is not the identity root.

It exists to help qualify a Phil identity for future eligibility logic without changing the canonical Phil identity derivation.

## Current Flow

1. The device generates `phil_secret`.
2. The device derives `ownerCommitment`.
3. The device builds a context-bound World ID signal from:
   - `ownerCommitment`
   - `appId`
   - `action`
4. A World verification receipt is obtained off-chain.
5. The receipt is bound back to the Phil identity context through a binding hash.

## Binding Rule

The signal is context-bound and separate from identity derivation.

Current helper formula:

```text
signal =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_WORLD_SIGNAL_V1"),
      ownerCommitment,
      appId,
      action
    )
  )
```

This means:
- the signal is specific to the Phil identity context
- different apps or actions produce different signals
- World ID does not become the identity root

## What Is Implemented Now

Implemented:
- signal generation helpers
- verification receipt types
- binding helpers from World receipts to Phil identity
- off-chain storage model assumptions

Current verification modes in code:
- `backend-verified`
- `offchain-verified`
- `contract-verified`

## What Is Not Implemented

Not implemented:
- mandatory World verification before unlock
- Base contract enforcement of World eligibility
- production backend verification plumbing in this repo

## Architectural Stance

World ID remains modular.

That means:
- Phil identity stays rooted in `phil_secret`
- World ID can be attached as an eligibility signal
- another human-verification provider could replace World ID later without redesigning Phil identity
