# ACP-0001: Verified Fact Cross-Domain Route Clarification

## Problem Observed

Phase M.6 transaction preparation initially assumed there might be a single ordinary user-callable Base transaction for verified-fact publication.

Implementation evidence shows the current contracts do not expose that shape. Base fact availability is reached through a cross-domain route:

```text
Starknet proof/fact message
  -> Ethereum L1 anchor
  -> Ethereum L1-to-Base relay
  -> Base mirror
  -> Base verification and execution
```

`PhilBaseActionGate.verifyAndConsume(...)` is execution and nullifier consumption. It is not fact publication.

## Implementation Evidence

- `PhilL1ProofInputHashAnchor.consumeProofInputHashFactFromL2(uint256,uint256)` consumes a Starknet L2-to-L1 message from configured `sourceL2Verifier` and anchors the fact on Ethereum L1.
- `PhilL1ToBaseProofInputHashMessenger.relayProofInputHashFactToBase(address,uint256,uint256)` relays an already anchored L1 fact to Base through the configured cross-domain messenger.
- `PhilBaseProofInputHashMirror.mirrorProofInputHashFact(uint256,uint256)` can only be called by the configured Base cross-domain messenger and requires the remote sender to be the authorized L1 messenger.
- `PhilBaseMirroredFactUnlockProofVerifier.verifyUnlockProof(...)` reads mirrored fact state and expects the proof blob to be the ABI-encoded two-felt fact pair.
- `PhilBaseActionGate.verifyAndConsume(...)` checks the package, calls the verifier, consumes the nullifier, and calls the authorization consumer.
- `starknet_integration/src/lib.cairo` contains spike/integration methods that verify a proof-input-hash slice and can send the two-felt fact payload to L1.
- No accepted production Runtime boundary or deployed Starknet fact-publication path was found during this review.
- M.6A identified `phil_starknet_integration::phil_proof_input_hash_verifier.verify_proof_input_hash_slice_and_send_to_l1(l1_recipient, proof, claim)` as the production-candidate Starknet publication entrypoint.
- The Starknet candidate path accepts `StarkProofMirror` and `ProofInputHashSliceClaim`, not the raw local Rust bincode full unlock proof blob unchanged.
- The L2-to-L1 payload is exactly `[fact_high, fact_low]`, where those values are the high and low 128-bit halves of `proofInputHash`.
- The current repository has local fixture and prior harness evidence for the payload shape, but no accepted production deployment, account/caller model, or Runtime transaction-preparation boundary.
- The current local environment lacks Scarb/Cairo tooling and generated Starknet target artifacts, so M.6A could not rerun the Starknet syscall harness without installing tooling and regenerating ignored artifacts.
- M.6A.1 added a pinned, non-installing toolchain check and artifact reproducibility path. It pins Scarb/Cairo `2.15.0`, Rust `nightly-2025-07-14`, and Node `>=22.0.0`.
- M.6A.1 regenerated the non-secret proof-input-hash slice args under ignored `proving/out/` and recorded safe artifact hashes in `config/starknet-publication-readiness.json`.
- M.6A.1 did not complete Cairo package builds or harness execution in the current environment because `scarb` and `cairo-execute` were not installed and generated Sierra/CASM artifacts were absent.

## Affected Documents

- `docs/PHILCORE_CORE_BOUNDARY.md`
- `docs/PHILCORE_RUNTIME_LIFECYCLE.md`
- `docs/PHILCORE_FUNCTIONAL_SPEC_V1.md`
- `docs/PHILCORE_TECHNICAL_SPEC_V1.md`
- `docs/reference/ACTION_UNLOCK_PROOF_SPEC.md`
- `docs/reference/ACTION_UNLOCK_PROOF_GENERATION_BOUNDARY.md`
- `docs/reference/ACTION_UNLOCK_PROOF_VERIFICATION_AND_FINALIZATION_BOUNDARY.md`
- `docs/reference/VERIFIED_FACT_PUBLICATION_AND_EXECUTION_READINESS_BOUNDARY.md`
- `docs/reference/VERIFIED_FACT_CROSS_DOMAIN_ROUTE.md`
- `docs/reference/STARKNET_VERIFIED_FACT_PUBLICATION_BOUNDARY.md`
- `docs/reference/STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md`
- `docs/reference/L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md`
- `docs/reference/L1_TO_BASE_FACT_RELAY_PREPARATION_BOUNDARY.md`
- `docs/reference/L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md`
- `config/starknet-toolchain.json`
- `config/starknet-publication-readiness.json`

No accepted source-of-truth document is changed by this proposal until reviewed and accepted.

## Affected Modules

- `contracts/l1/PhilL1ProofInputHashAnchor.sol`
- `contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol`
- `contracts/l1/PhilBaseCrossDomainMessengerAdapter.sol`
- `contracts/l1/interfaces/IStarknetMessaging.sol`
- `contracts/base/PhilBaseProofInputHashMirror.sol`
- `contracts/base/PhilBaseMirroredFactUnlockProofVerifier.sol`
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilUnlockConsumer.sol`
- `starknet_integration/`
- `starknet_integration_runner/`
- `cairo_air_adapter_spike/`
- `starknet_spike/`
- `starknet_adapter_spike/`
- future Runtime, Ethereum Adapter, and Starknet Adapter boundaries

## Affected Invariants

This clarification preserves:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- `proofInputHash`
- proof public input tuple
- STARK/proof architecture
- WebAuthn/passkey architecture
- encrypted registry/key lifecycle
- ERC-4337 Smart Accounts as preferred Ethereum authority model
- EOAs as compatibility paths
- Ethereum/Base as first execution path
- no multi-chain implementation yet
- no full post-quantum security overclaim

It clarifies that the proof-fact transport route is cross-domain and that Base execution waits on mirrored fact availability.

## Security Impact

Positive impact:

- Prevents accidental preparation of fictional or unauthorized Base fact-publication calls.
- Prevents misclassifying `verifyAndConsume(...)` as publication.
- Preserves messenger-only Base mirror protections.
- Forces exact route validation before any future transaction preparation.

Risks requiring future work:

- Starknet publication deployment, caller policy, and proof payload shape are not yet accepted as production Runtime behavior.
- The current production-candidate path verifies the proof-input-hash slice on Starknet. It must not be overstated as raw full-proof submission until that boundary is explicitly implemented and tested.
- `l1_recipient` is an explicit Starknet entrypoint argument today, so production Runtime must bind it to the expected L1 anchor address before preparing any transaction.
- Generated artifact hashes are readiness metadata only. They are not deployment approval and do not create Runtime authority.
- M.6A.1 established that Scarb/Cairo `2.15.0` can build the production-candidate Starknet contract and that the Rust syscall/L1 relay harnesses emit the expected `[fact_high, fact_low]` payload. `starknet_integration_runner` is classified as an executable harness: `scarb build` is required, `scarb test` is not applicable under Scarb `2.15.0`, and syscall/L1 relay harness execution is mandatory.
- M.6A.2 adds non-executing Starknet publication configuration binding for exact artifacts, network profiles, L1 recipient policy, expected L2 sender status, account/caller model, fee/nonce policy, and receipt/finality policy.
- M.6A.3 adds a controlled unsigned Starknet transaction-preparation boundary for `verify_proof_input_hash_slice_and_send_to_l1`. It constructs calldata and an unsigned account-invoke draft only; it does not sign, submit, emit messages, anchor facts, relay to Base, or create application execution authority.
- M.6A.4 adds a controlled publisher authorization and signing boundary. It signs only the exact immutable Starknet `INVOKE` v3 transaction hash through an isolated publisher signer and produces a signed but unsubmitted artifact; it does not submit, emit messages, anchor facts, relay to Base, or grant applications Starknet signing authority.
- M.6A.5 adds a controlled Starknet submission and receipt-monitoring boundary. It can submit one exact approved signed transaction and verify accepted-on-L2 receipt evidence, the verification event, and the `[fact_high, fact_low]` L2-to-L1 message; it still does not consume the message on L1, anchor facts, relay to Base, consume nullifiers, or execute consumers.
- M.6B adds a read-only Ethereum L1 message-availability and unsigned fact-anchor preparation boundary. It derives the Starknet L2-to-L1 message identity, checks availability through an explicit reader, and encodes `consumeProofInputHashFactFromL2(factHigh,factLow)` calldata; it still does not consume the message, submit/sign L1 transactions, anchor facts, relay to Base, consume nullifiers, or execute consumers.
- M.6C adds a controlled Ethereum L1 fact-anchor signing, submission, and receipt-monitoring boundary. It can sign one exact immutable EIP-1559 anchor transaction and can submit/monitor it only under explicit live Sepolia prerequisites. Fixture diagnostics remain non-mutating. It still does not prepare the L1-to-Base relay, call Base, consume PhilCore nullifiers, or execute consumers.
- M.6D adds a controlled L1-to-Base relay preparation boundary. It verifies anchored-fact evidence, validates relay/messenger/mirror configuration, encodes the exact Base mirror payload, and prepares an unsigned `relayProofInputHashFactToBase(baseMirror,factHigh,factLow)` draft. It still does not sign, submit, send a cross-domain message, mirror the fact on Base, consume nullifiers, or execute consumers.
- M.6E adds a controlled L1-to-Base relay signing, submission, and monitoring boundary. It binds caller-supplied `baseMirror` to an approved Base mirror configuration, signs only the exact immutable relay transaction, optionally submits only with explicit live Sepolia/Base Sepolia prerequisites, monitors L1 receipt and cross-domain delivery, and verifies Base mirror state. It still does not call the Base mirror directly, call `verifyAndConsume(...)`, consume PhilCore nullifiers, execute consumers, or provide applications generic signing/submission authority.
- M.7 adds a controlled Base authorization execution preparation boundary. It uses the actual `PhilBaseActionGate.verifyAndConsume(...)` ABI and prepares only an unsigned, unsubmitted transaction draft after mirrored-fact, finalized-package, active-capability, session-lifecycle, consumer-data, configuration, and nullifier-state checks. It still does not sign, submit, create a UserOperation, consume nullifiers, execute consumers, or mutate Base state.
- M.8 adds a controlled Base authorization execution signing, submission, and monitoring boundary. It signs only the exact M.7 draft after fresh authority/state checks and final execution approval; local Hardhat tests execute the real ActionGate/verifier/mirror/consumer path and verify nullifier consumption plus consumer execution. Live Base Sepolia execution remains disabled without live mirrored-fact evidence, accepted deployments, protected custody, funding, RPC, and explicit approval.
- M.9A adds a proposed local ERC-4337 Smart Account foundation. It selects EntryPoint v0.7, adds a minimal unaudited PhilCore account/factory, proves local EntryPoint `handleOps(...)`, deterministic deployment, and ActionGate execution through the smart account. It still does not sign or submit UserOperations, invoke paymasters, deploy live accounts, mutate live Base state, or change proof/cross-domain semantics.
- L1 anchoring and relay can be called by any account once preconditions hold, so fee attribution and relayer policy must be explicit.
- Readiness checks are snapshots and must not be treated as durable execution authority.
- Cross-domain finality, replay, relay griefing, and monitoring policies remain to be implemented.

## Migration Impact

No code migration is required for this ACP.

Future milestone naming should split the old single "verified-fact publication transaction preparation" idea into separate boundaries:

- Starknet fact publication artifact reproducibility and deployment readiness
- Starknet publication configuration binding
- Starknet publication transaction preparation
- Starknet publication submission and receipt monitoring
- L1 message availability and fact-anchor preparation
- L1 fact-anchor signing, submission, and receipt monitoring
- L1-to-Base relay preparation
- L1-to-Base relay signing, submission, cross-domain monitoring, and Base mirror verification
- Base `verifyAndConsume(...)` execution preparation

Existing M.5 readiness artifacts should be interpreted as route readiness snapshots, not as proof that a direct Base publication call exists.

## Rejected Alternatives

1. Preserve Starknet -> L1 -> Base fact route.
   - Accepted as the nearest implementation-grounded path because it matches current contracts and spike evidence.
2. Add a direct Ethereum/L1 proof-verification route.
   - Rejected for this milestone because it requires new verifier/interface work and contract changes.
3. Add a direct Base proof-verification route.
   - Rejected for this milestone because current Base verifier reads mirrored facts rather than verifying full STWO proofs.
4. Add a trusted or permissioned fact publisher temporarily.
   - Rejected for production framing because it weakens the proof-backed route. It may remain fixture-only if explicitly labeled.
5. Treat Starknet as proof infrastructure while Base remains execution.
   - Recommended clarification. It preserves the accepted Ethereum/Base execution framing while acknowledging cross-domain fact availability.
6. Redesign the verifier/fact registry interface.
   - Rejected for this milestone because contracts, ABIs, proof schemas, and public inputs are frozen unless separately reviewed.

## Recommended Change

Clarify the accepted architecture language as:

```text
Ethereum/Base is PhilCore's first production authorization-execution environment.
The current verified-fact availability route depends on Starknet-to-L1-to-Base transport before Base execution can verify and consume an authorization.
```

Add the route reference document as the current implementation-grounded technical reference for future M.6/M.7 work.

Add the Starknet publication boundary reference as the implementation-grounded source for the M.6A series. Recommended wording after review:

```text
PhilCore's current verified-fact route uses Starknet proof-input-hash slice verification to emit a two-felt L2-to-L1 fact message, then anchors and mirrors that fact before Base authorization execution.
```

Do not change source-of-truth architecture documents until this ACP is reviewed and accepted.

## Review Status

Proposed.
