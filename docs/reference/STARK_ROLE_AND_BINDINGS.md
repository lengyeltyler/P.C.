# Current STARK Role And Bindings

Status: Quarantined synthetic research and byte-stable compatibility evidence;
no V1 authorization role.

ACP-0003 Step 1 selected no proof backend. Any future exceptional root proof
must satisfy the admission and full-envelope binding rules in
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
This STWO proof is ineligible because it exposes the witness.

## Scope

PhilCore can generate and verify a `stwo-unlock-keccak-v1` STARK proof locally
only behind the exact synthetic-research gate. The proof historically
supported one bounded `ACTION_UNLOCK`
authorization. It does not unlock the Device Vault, authenticate a user,
activate a capability, sign a UserOperation, or execute a contract.

The implementation is in:

- `proving/src/unlock_statement.rs`
- `proving/src/prover.rs`
- `proving/src/verifier.rs`
- `apps/phil-device-sdk/src/runtime/actionUnlockProofGeneration.ts`
- the ACTION_UNLOCK proof verification/finalization Runtime boundary

The Rust statement uses the STWO M31 backend with a Blake2s channel and Merkle
commitments. The desktop invokes fixed prover and verifier binaries through
main-process-only boundaries.

## Witness And Public Inputs

Intended private witness material:

- `phil_secret`
- per-authorization `nullifierSeed`

Public tuple:

- schema version
- proof type
- `ownerCommitment`
- `actionHash`
- `policyHash`
- public `nullifier`
- `consumerDataHash`
- `expiry`

`proofInputHash` is the canonical commitment to this tuple. The AIR constrains
the canonical domain-separated Keccak path from `phil_secret` through
`identityRoot` to the stated `ownerCommitment`, constrains the nullifier from
the public action/policy context and `nullifierSeed`, and binds the full public
tuple. The verifier also pins the canonical preprocessed program commitment.

However, the current STWO trace stores each `phil_secret` bit directly in a
committed column, and the serialized proof contains queried values from those
columns. With this trace layout and the pinned STWO proof format, those
openings recover the secret. Therefore this implementation is a constrained
argument for the relation, but it is **not a privacy-preserving proof of
knowledge** and proof artifacts must not be transmitted or published. A
supported witness-hiding proving construction is required before Phil may
claim private `phil_secret` knowledge. The current implementation is labeled
experimental, accepts only synthetic fixture witnesses behind an exact research
gate, and is rejected by finalization, publication, and execution validators.
See `WITNESS_HIDING_PROVING_STACK_REQUIREMENTS.md` for the replacement gate.

## Binding Matrix

| Concern | Current binding |
| --- | --- |
| Phil identity | AIR-constrained through `ownerCommitment` derived from `phil_secret`; current proof serialization is not witness hiding. |
| Action | Directly through `actionHash`. |
| Chain | Included in `actionHash` and `policyHash`. |
| Smart account | Included in `actionHash`. |
| Target, value, calldata | Included in `actionHash`; raw consumer payload is also committed by `consumerDataHash`. |
| Consumer and policy | Included in `actionHash`, `policyHash`, and the authorization package. |
| Expiry | Direct public field and included in `policyHash`. |
| Replay | Public nullifier, consumed atomically by `PhilBaseActionGate`. |
| User approval | Correlated by Runtime artifacts; not a proof public input. |
| User presence | Required by the signing boundary; not a proof public input. |
| EntryPoint | Bound later by ERC-4337 preparation/signing; not a proof public input. |
| UserOperation nonce, gas, fees | Bound later by the exact v0.7 UserOperation hash; not proof public inputs. |

The proof by itself is not permission to sign an arbitrary operation. The
M.9/M.10 boundaries bind the verified authorization to one EntryPoint, account,
nonce, target, value, calldata, gas policy, fees, chain, and expiry before the
Device Vault signer can sign the exact UserOperation hash.

## Verification And Execution

Current verified paths:

- local Rust proof generation;
- local Rust proof verification;
- local fixture fact installation;
- local Base mirror, ActionGate, consumer, and ERC-4337 execution.

Current public paths not exercised:

- Starknet fact publication;
- L1 anchoring;
- L1-to-Base relay;
- Base Sepolia fact mirroring;
- Base Sepolia UserOperation submission.

`PhilCore4337Account` validates ECDSA ownership of the UserOperation and limits
execution to the configured ActionGate selector. It does not verify STWO proof
bytes. `PhilBaseActionGate` delegates the proof check to its configured
`IPhilUnlockProofVerifier`. The production-shaped cross-domain design uses a
mirrored verified fact; the desktop uses an explicitly labeled local fixture.

## Security Meaning

A successful local proof establishes computational integrity of the canonical
identity/nullifier/action relation for the committed trace under the pinned
program. It does **not** currently establish private knowledge without witness
disclosure. In particular, Phil must not summarize the current result as:

> The prover privately proved knowledge of the Phil identity secret.

It does not mean:

- the identity or vault is unlocked;
- the user approved the action;
- platform user presence succeeded;
- an account exists on a public chain;
- a transaction was signed or submitted;
- the fact was published cross-domain.
- the proof is zero knowledge or safe to disclose to a verifier.
