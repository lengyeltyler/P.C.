# Phil V1 Step 4 Composed Account Authorization Threat Model

Status: Active implementation gate

Date: 2026-08-21

## Protected outcome

The protected outcome is the one-time local account receipt written only after
one exact exceptional action passes every independent authority and state
check. The contract holds no funds and exposes no arbitrary execution.

## Adversaries

The gate assumes an adversary may control calldata, ordering, timing, the
submitter, malformed proofs and signatures, stale but formerly valid evidence,
replayed evidence, mismatched action presentations, and any single proof,
device, or policy input. The adversary may observe all committed synthetic
fixtures and contract state.

## Required defenses

- Root-proof soundness and witness hiding come only from the exact admitted
  Step 3 verifier and proof artifacts.
- Device approval is a separate P-256 signature bound transitively to the
  complete authorization digest and human-presentation hash.
- The contract recomputes both digests; caller-supplied digest assertions are
  never trusted.
- Immutable account configuration supplies the exact admitted identities,
  public key, policy ceilings, action, and verifier class.
- Sequential nonce plus consumed envelope, root-nullifier, and approval-nonce
  state provide independent replay barriers.
- All checks precede all writes; Cairo transaction rollback is required for
  failures inside the proof verifier or later code.
- Every accepted receipt states `productionAuthority: false` outside the
  contract and cannot be consumed by Phil runtime or a network submitter.

## Explicit non-goals and residual risk

- This is not a production account, deployment, formal proof, or audit of the
  underlying proof and signature libraries.
- The P-256 key is synthetic; no physical device is used in Step 4.
- The root-proof backend remains beta/nightly reference technology and is not
  post-quantum.
- Local L2-gas is evidence, not a network fee quote.
- The receipt action has no external effect, so later production composition
  must separately review call encoding, native account validation, fee payment,
  sequencer behavior, upgrades, and reentrancy.
- A future network adapter must re-establish every guarantee rather than
  treating this local candidate as universal authority.
