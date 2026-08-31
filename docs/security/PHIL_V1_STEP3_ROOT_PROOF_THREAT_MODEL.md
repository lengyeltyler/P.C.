# Phil V1 Step 3 Root-Proof Reference Threat Model

Status: Exact candidate under review

Date: 2026-08-21

## Scope

This threat model covers only the local Phil V1 Step 3 reference circuit,
proof descriptor, public-input adapter, generated Garaga Cairo verifier, and
synthetic verification tests. It does not approve a production backend,
account composition, iPhone proving, deployment, signing, RPC, transactions,
or routine authorization.

## Protected assets

- `phil_secret`, which must remain witness-hidden;
- the private nullifier seed;
- pairwise scope separation and scoped owner commitments;
- the exact exceptional authorization envelope;
- account, chain, action, policy, replay, limit, presentation, and epoch
  bindings committed by the envelope digest;
- proof-system, circuit, verification-key, verifier-code, schema, and codec
  identity; and
- the separate device-signature requirement, which a root proof must never
  replace.

## Attacker goals

An attacker may try to:

- recover or distinguish private witness material from a proof;
- prove with a wrong root secret or nullifier seed;
- move a valid proof to another scope, account, network, action, policy,
  presentation, epoch, verifier, or codec;
- replace the public descriptor with an attacker-selected verifier;
- alter a proof or public input while preserving acceptance;
- reuse the current witness-leaking STWO path;
- reach the reference adapter from UI, plugin, agent, runtime authority,
  Device Vault, signing, or submission code; or
- misrepresent local compatibility evidence as production or iPhone evidence.

## Security controls

The circuit derives `identityRoot` from the private root secret, derives the
scoped commitment from the exact public scope fields, derives the public
nullifier from that scoped commitment, the exact authorization digest, and the
private seed, and rejects zero required values. Six `bytes32` logical public
values are split into high/low `u128` pairs and the epoch remains `u64`, so no
field reduction can alias two accepted byte strings.

The envelope digest commits every envelope field except the derived
`rootProofNullifier`. The proof binds that one omitted value. This avoids the
former infeasible hash cycle without leaving any execution field unsigned.

The proof descriptor binds the exact proof suite, compiler/backend identity,
circuit, public-input schema, verification key, generated Cairo code, and
calldata codec. The TypeScript adapter recomputes the verifier binding and
rejects any mismatch. Before composition, it also requires exact equality for
all seven logical public inputs, including the admitted descriptor hash.

STWO is not imported. New code is unreachable from the desktop, renderer,
preload, plugin, agent, Device Vault, runtime authority, signer, and submission
surfaces. Committed private values are explicitly synthetic and disclosed.

## Evidence

- correct TypeScript/Noir public values agree;
- ten circuit-level wrong-witness, noncanonical-secret, or wrong-public-input
  cases fail;
- action, account, network, policy, limits, presentation, nonce, device,
  recovery, validator, and descriptor changes alter or fail the envelope
  binding;
- repeated proofs differ;
- serialized proof and public-input files contain neither disclosed private
  literal;
- native verification accepts the canonical proof and rejects a mutated proof;
- local Cairo verification must accept the exact calldata and reject a changed
  public input before this candidate can pass; and
- reachability tests reject imports from authority and UI surfaces.

## Residual risk and non-claims

- Nargo is beta and the compatible Barretenberg release is a nightly.
- Garaga compatibility and its audit do not audit Phil's relation or account
  composition.
- Secure prover randomness is inherited from Barretenberg and still requires
  independent production review and fail-closed platform integration.
- No iPhone proof time, memory, battery, thermal, interruption, or secure-random
  evidence exists.
- No production account checks the descriptor, envelope, nullifier, device
  signature, policy, replay state, and epochs as one action yet.
- A disclosed synthetic proof is evidence, not a trusted setup ceremony or a
  production key.

## Verdict boundary

Passing this gate can establish only that the exact local reference relation is
witness-hiding in the selected mode and locally verifiable by Starknet Cairo.
It cannot select a production backend or start Step 4 without an independent
exact-candidate review and a separate user decision.
