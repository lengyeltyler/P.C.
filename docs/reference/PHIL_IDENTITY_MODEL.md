# Phil Identity Model

Status: Accepted V1 model; current implementation compatibility is identified
explicitly below.

## Canonical Rule

Phil identity is rooted in a device-generated private secret:

```text
phil_secret -> identityRoot -> rootOwnerCommitment
```

This derivation is canonical.

No alternative identity source is canonical.

## What `phil_secret` Is

`phil_secret` is:
- generated locally on the user device
- kept private
- never intended to leave the device boundary
- the only root witness for future proof systems

`phil_secret` is not:
- a wallet address
- a World ID credential
- a chain-specific account
- a value staged on-chain

`rootOwnerCommitment` is the accepted semantic name for the existing
`ownerCommitment` bytes. The derivation does not change.

## What Becomes Public

`phil_secret`, `identityRoot`, and `rootOwnerCommitment` are protected by
default. They are not a universal public Phil ID.

Each network account, application, credential relationship, agent, or persona
receives a pairwise `scopedOwnerCommitment` derived from the private
`identityRoot`, exact `scopeId`, random `scopeInstance`, and `scopeEpoch`.
Exact domains, encodings, recovery requirements, and deliberate-linking rules
are frozen in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).

The current contracts still consume `ownerCommitment` as a public compatibility
anchor. That is current implementation evidence, not the target public
identity boundary, and it cannot create new V1 product authority.

## Current Usage

Current compatibility implementation:
- the SDK derives `ownerCommitment` locally from `phil_secret`
- the Base authorization flow uses `ownerCommitment` in public inputs
- the Base contracts treat `ownerCommitment` as the identity anchor
- the current AIR constrains `phil_secret -> identityRoot -> ownerCommitment`
- the current proof artifact is not witness hiding because its queried trace
  openings reveal the direct secret-bit columns

So the identity relation is cryptographically constrained, but the current
proof does not qualify as a privacy-preserving proof of knowledge. The proving
layer remains blocked on a reviewed witness-hiding construction. The source is
publishable only because ordinary and Device Vault proof generation,
finalization, publication, and execution use are structurally disabled.

## Legacy Path

The old address-plus-salt owner-commitment helper still exists only behind an explicit:

```text
allowLegacyOwnerCommitment: true
```

That path is:
- legacy only
- test only
- not canonical

## Relationship To Base

Base does not generate identity.

The current Base compatibility path receives public identity data in the
authorization payload:
- `ownerCommitment`
- `actionHash`
- `policyHash`
- `nullifier`
- `consumerDataHash`
- `expiry`

The Base contracts enforce consistency around those public values. This tuple
is not the accepted chain-agnostic V1 authorization envelope. Current
local proof wiring must not be treated as a private identity-knowledge proof.
Experimental proof bytes must not be exported or published; publishing the
quarantined source code is a separate action and does not disclose a user
secret.

## Relationship To World ID

World ID is separate from the identity root.

World ID can be used to:
- verify that a human completed onboarding
- bind a human-verification receipt to a Phil identity context
- feed future eligibility logic

World ID cannot:
- create `phil_secret`
- replace `phil_secret`
- derive `ownerCommitment`

## Honest Current State

Implemented:
- device-local `phil_secret`
- canonical `identityRoot`
- canonical `ownerCommitment`
- Base-native use of `ownerCommitment`

Not implemented:
- privacy-preserving proof of knowledge of `phil_secret`
- on-chain proof verification
- World ID enforcement in the active Base gate
