# Canonical Repository And Alpha Proof Route

Status: **current source of truth for repository ownership and the local Alpha proof decision**

## Decision

- Canonical engineering repository: `PhilCore`
- Canonical integration branch for this candidate: `codex/local-alpha-demo-ready`
- Local Alpha private-proof backend: **Noir / Barretenberg UltraKeccakZK Honk**
- Starknet reference verifier: **Garaga-compatible Cairo composition retained and tested locally**
- Production proof backend: **not selected**
- Public-network proof deployment or submission: **not authorized**; a bounded
  Sepolia composed-mint candidate is implemented only through the
  signed-but-unsubmitted state described in
  [Phil Sepolia Mint Composed Demo V1](./reference/PHIL_SEPOLIA_MINT_COMPOSED_DEMO_V1.md)
- RISC Zero: retained only as the fallback comparator
- The old secret-bearing STWO artifact: quarantined and forbidden from real-secret authorization

This resolves the earlier ambiguity. PhilCore now has a selected, executable
private-proof route for the local product Alpha without pretending the beta and
nightly tools are production-approved.

## One Repository Rule

All product engineering continues from `PhilCore`. The former public-product,
pre-MVP, and proof-feasibility repositories are preserved as history rather
than treated as separate active products.

The unified Git ancestry includes these frozen preservation refs:

| Preserved history | Ref | Preserved tip |
|---|---|---|
| Current public-product candidate | `archive-public/codex/phil-demo-visual-integration` | `b749152` |
| Accepted efficient-route documentation | `archive-public/codex/phil-v1-efficient-route` | `faca1dd` |
| Public hardening boundary | `archive-public/codex/pre-public-hardening` | `f637113` |
| Public main | `archive-public/main` | `1fb407c` |
| Pre-MVP synthesis | `archive-pre-mvp/codex/pre-mvp-synthesis` | `fb384a4` |
| Proof feasibility evidence | `archive-proof/codex/phil-proof-feasibility-v1` | `f8832d9` |
| Philenator identity artwork | `archive-philenator/main` | `f174ded` |

Verified recovery bundles were created before consolidation. Their SHA-256
digests are:

| Bundle | SHA-256 |
|---|---|
| PhilCore | `16bb0c744b3a55594a0deb84fcb8a21d8697be31448792753a084afa58da7332` |
| Public-product history | `711dcb0c82a9c5f2fec86fe0b97ab8f2338e42b36e0f0b3cf1cd62ae9acfc052` |
| Pre-MVP history | `da20a9fba2c072a3a6df1ae61675b91090327c479caad1a1dbac93f19586ac56` |
| Proof-feasibility history | `eb6f6a5060363afe44b25d79ef5a3c6b0454244a6c34951705a179f8c2c6de56` |

The old folders are recovery copies. Do not develop independently in them.
Any future public repository is a generated, allowlisted publication from a
reviewed PhilCore commit; it is not a second development trunk.

## Exact Local Alpha Proof Stack

The product uses the exact Garaga-compatible pin already accepted by the
Step 3 and Step 4 gates:

| Component | Exact pin | Role |
|---|---|---|
| Noir / Nargo | `1.0.0-beta.16` | compile and solve the Phil root-proof relation |
| Barretenberg | `3.0.0-nightly.20251104` | UltraKeccakZK proof generation and native verification |
| Proof type | `phil-noir-ultra-keccak-zk-honk-garaga-v1` | product proof-family identifier |
| Product classification | `PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_LOCAL_ALPHA_V1` | prevents a production claim |
| Cairo reference | accepted Step 4 Garaga composition | local Starknet-reference verification evidence |

Current upstream releases were rechecked before this decision. A newer Noir or
Barretenberg version is not substituted blindly because the accepted Garaga
route pins an exact mutually compatible pair. Upgrading is a separate migration
candidate requiring regenerated verifier artifacts, parity tests, and review.

## Product Authorization Flow

The Desktop local Alpha now performs this real sequence:

1. PhilCore evaluates the bounded local intent and policy.
2. The user approves proof generation for the displayed request.
3. The root secret is supplied from the protected main-process state.
4. Nargo input and the solved witness travel through named pipes; neither is
   persisted as a plaintext regular file.
5. Barretenberg creates a randomized UltraKeccakZK proof.
6. PhilCore verifies the proof with the accepted verification key and
   independently reruns native verification before continuing.
7. The user reviews a separate, digest-bound local signing request.
8. Fresh Mac user presence is required.
9. The protected local signing key signs the exact operation.
10. The existing local Ethereum/EntryPoint fixture executes once, consumes the
    operation nullifier, and verifies the local receipt.
11. The operation nullifier is reserved before signing and durably recorded in
    a fail-closed local ledger so an interrupted or restarted app cannot reuse
    the same authorization.

The proof binds the protected identity secret to the scoped owner commitment,
local Alpha scope, scope instance and epoch, authorization digest, one-time
root-proof nullifier, and accepted proof-descriptor hash.

The circuit treats the canonical authorization digest and action-derived scope
instance as public commitments; it does not duplicate the application-level
field encoder inside Noir. The product recomputes the canonical digest from
the exact owner, action, policy, nullifier, consumer-data, and expiry fields,
checks the emitted public-input bytes byte-for-byte, and then verifies the Noir
proof. This is an indirect in-circuit action binding suitable for the bounded
local Alpha, not a claim that every application field is independently parsed
inside the circuit.

Proof bytes and public inputs remain in private workflow state. The renderer
receives only sanitized proof metadata and digests. The root secret, nullifier
seed, prover input, and witness are never returned to the renderer.

## Honest Current Boundary

This is a functioning **local Alpha proof gate**, not a production deployment.

- Native Barretenberg verifies the actual Noir proof locally.
- The accepted Step 4 Cairo/Garaga composition verifies this proof family in
  isolated local reference tests.
- The Desktop does not currently invoke a deployed Starknet verifier.
- The local Ethereum contract fixture still enforces the legacy mirrored
  `proofInputHash` after the real Noir gate succeeds; Ethereum does not verify
  the Noir proof itself.
- No RPC, public transaction, account deployment, meaningful asset, external
  prover, or public-network mutation is used.
- The iPhone is a Secure Enclave device-approval and recovery companion. It is
  not the Noir prover in this Alpha.
- Noir remains beta and the matching Barretenberg build remains nightly.
- No production backend, production key ceremony, signed distribution,
  external audit, or post-quantum proof claim follows from this decision.

## UI Decision

The interface chrome, cards, typography, buttons, and navigation are black and
white. The Philenator-generated background and the approved 3D character
artwork retain full color. Background traits generated by the pinned local
Philenator revision are used as the actual identity-world background; they are
not converted to grayscale.

## Next Gate

Before any public-network proof path is enabled:

1. package and physically test the unified Desktop and iPhone builds;
2. independently review the exact unified candidate;
3. decide whether Starknet/Garaga is the first public verifier deployment;
4. define fees, liveness, upgrade authority, finality, and failure recovery;
5. run a separately authorized testnet-only deployment gate.

Until then, public network mutation remains disabled.

## Bounded Sepolia composed candidate

The next local candidate now composes the existing Noir proof and physical
iPhone P-256 approval against one exceptional Sepolia mint digest before Device
Vault signs. Ethereum verifies only the restricted ERC-4337 execution signature
and ActionGate; it does not verify Noir or P-256. Deployment, funding, and
submission remain separately gated and unexecuted. This candidate does not
select a production proof backend or change the STWO quarantine.
