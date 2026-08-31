# Phil Human Uniqueness and World ID Boundary

## Purpose

PhilCore’s long-term production rule is:

```text
1 canonical Phil = 1 eligible unique human
```

World ID is a future human-uniqueness provider under Trust Manager. It is not the Phil identity root.

## Boundary

```text
World ID
  -> proves unique-human eligibility for Phil enrollment

Phil Identity
  -> phil_secret -> identityRoot -> ownerCommitment

Phil Uniqueness Registry
  -> prevents another canonical Phil activation using the same allowed uniqueness enrollment proof
```

World ID must not become `phil_secret`, `identityRoot`, `ownerCommitment`, a replacement for passkeys, a replacement for Device Vault, unrestricted wallet authority, or a permanent public Phil identity identifier.

## Local Creation vs Canonical Activation

A user may technically create local test or development Phil identity material without World ID. Production canonical activation is different: a canonical Phil identity should not become production-active until unique-human enrollment succeeds.

World ID uniqueness gating can prevent duplicate canonical activation. It cannot prevent arbitrary offline generation of unused local secrets.

## Future Production Flow

```text
Create local Phil identity candidate
  -> World ID unique-human enrollment request
  -> World ID proof verification
  -> bind verified enrollment to ownerCommitment
  -> uniqueness registry rejects duplicate registration
  -> activate canonical Phil identity
```

No part of this flow is implemented by the current milestone.

## Binding Requirements

- The World ID proof request must be specific to the Phil relying party/application.
- The enrollment action must be specific to canonical Phil activation.
- The proof signal must bind to the proposed Phil `ownerCommitment` or an unambiguous hash containing it.
- A verified enrollment must be recorded in a uniqueness registry.
- Replay or duplicate enrollment must be rejected.
- Raw World ID secrets or unnecessary personal data must not enter PhilCore.
- World ID identifiers must not be exposed publicly unless required by the verification design.
- Version-specific proof fields must remain behind a World ID adapter boundary.
- World ID protocol upgrades must not change the Phil identity root.

Uniqueness proof replay protection and returning-user continuity are separate concepts. Do not assume a legacy nullifier is a permanent cross-version user identifier.

## Trust Manager Placement

World ID is a Trust Manager human-uniqueness provider. It may be required for production canonical Phil enrollment and may later be required for sensitive recovery or rebinding depending on policy.

World ID is not required for every ordinary unlock or Ethereum transaction. It is not a device possession credential and it is not a wallet signer.

## Recovery And Rebinding

Recovery should restore or rebind the existing Phil identity. It should not create a second canonical Phil for the same enrolled human. Future recovery policy may require a World ID-backed uniqueness/rebinding step, but that remains future work.

## Privacy Boundary

PhilCore should store only the minimum references needed to prove enrollment, reject replay, and preserve continuity. Raw World ID proof secrets, unnecessary personal data, and provider-specific internals should remain outside PhilCore’s identity root.

## Versioning And Adapter Requirements

World ID protocol details belong behind a future World ID adapter/provider boundary. Protocol upgrades must not alter:

- `phil_secret -> identityRoot -> ownerCommitment`
- WebAuthn/passkey architecture
- Device Vault boundaries
- Ethereum/Base execution adapter boundaries

## Current Non-Goals

This milestone does not integrate IDKit, call World ID APIs, verify World ID proofs, add SDK dependencies, deploy or modify contracts, implement a uniqueness registry, implement canonical activation, or enforce production enrollment.
