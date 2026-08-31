# Verified Fact Cross-Domain Route

> **Current security gate:** this is a future architecture and contract-capability
> map, not an executable product route. The current STWO unlock artifact exposes
> witness openings. Runtime therefore permits generation only for process-local
> synthetic research, rejects finalization, and rejects Starknet, L1, Base, or
> external-verifier publication. The sequence below can be restored only with an
> independently reviewed witness-hiding proof type.

## Purpose

Phase M.6 records implementation evidence from the existing contracts and spike code after transaction preparation was stopped.

There is no current product route that publishes a verified fact. The designed
cross-domain route, presently blocked at proof finalization, is:

```text
Local ACTION_UNLOCK proof generation
  -> local proof verification
  -> [fact_high, fact_low] preview
  -> Starknet proof-input-hash verification and L2-to-L1 message
  -> Ethereum L1 fact anchoring
  -> Ethereum L1-to-Base relay
  -> Base mirrored fact
  -> Base authorization verification
  -> Base nullifier consumption
  -> consumer execution
```

`verifyAndConsume(...)` is execution. It consumes the nullifier and calls the authorization consumer. It is not fact publication.

## Route Diagram

```text
Authorization Package Draft
  -> future reviewed witness-hiding proof artifact
  -> local verification
  -> finalized non-executing Authorization Package (currently unavailable)
  -> [fact_high, fact_low] local preview
  -> Starknet verifier/spike contract verifies proof-input-hash slice
  -> Starknet verifier sends [fact_high, fact_low] to L1
  -> PhilL1ProofInputHashAnchor.consumeProofInputHashFactFromL2(factHigh, factLow)
  -> PhilL1ToBaseProofInputHashMessenger.relayProofInputHashFactToBase(baseMirror, factHigh, factLow)
  -> Base cross-domain messenger
  -> PhilBaseProofInputHashMirror.mirrorProofInputHashFact(factHigh, factLow)
  -> PhilBaseMirroredFactUnlockProofVerifier.verifyUnlockProof(...)
  -> PhilBaseActionGate.verifyAndConsume(...)
  -> PhilUnlockConsumer.consumePhilAuthorization(...)
```

## Contract And Caller Matrix

| Contract or module | Chain | Method | Mutability | Required caller | Remote sender requirement | Inputs | State changed | Event | Payable | User-callable | PhilCore-callable | Infrastructure-only | Nullifier consumed | Consumer execution |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `phil_proof_input_hash_verifier` in `starknet_integration/src/lib.cairo` | Starknet | `verify_proof_input_hash_slice(proof, claim)` | external | Starknet account / test syscall caller | None in code | STWO mirror proof, proof-input-hash slice claim | `verified_facts[fact] = true` | `ProofInputHashFactVerified` | Starknet fee model | Candidate, not production-confirmed | Candidate via future Starknet Adapter | No | No | No |
| `phil_proof_input_hash_verifier` in `starknet_integration/src/lib.cairo` | Starknet | `verify_proof_input_hash_slice_and_send_to_l1(l1_recipient, proof, claim)` | external | Starknet account / test syscall caller | None in code | L1 recipient, STWO mirror proof, claim | `verified_facts[fact] = true`; L2-to-L1 message queued | `ProofInputHashFactVerified` | Starknet fee model | Candidate, not production-confirmed | Candidate via future Starknet Adapter | No | No | No |
| `PhilProofInputHashFactRegistry` in `starknet_spike/src/lib.cairo` | Starknet | `mark_verified_and_send(l1_recipient, public_inputs)` | external | Starknet account / test caller | None in code | L1 recipient, public inputs | `verified_proof_input_hash[hash] = true`; L2-to-L1 message queued | `ProofInputHashVerified` | Starknet fee model | Research/spike only | No current production boundary | No | No | No |
| `PhilL1ProofInputHashAnchor` | Ethereum L1 | `consumeProofInputHashFactFromL2(uint256,uint256)` | external, state-changing | Any caller, if Starknet message exists | `sourceL2Verifier` enforced through `consumeMessageFromL2` | `factHigh`, `factLow` | `anchoredProofInputHashFact[factHigh][factLow] = true`; latest fact fields | `ProofInputHashFactAnchored` | No | Technically yes after message availability | Candidate via Ethereum Adapter or infrastructure | No | No | No |
| `IStarknetMessaging` | Ethereum L1 | `consumeMessageFromL2(uint256,uint256[])` | external, state-changing | Called by L1 anchor | Starknet core verifies message source and payload | L2 sender, payload | Starknet message consumed | Starknet core behavior | No in interface | Not directly in PhilCore route | No, called by anchor | Protocol-controlled | No | No |
| `PhilL1ToBaseProofInputHashMessenger` | Ethereum L1 | `relayProofInputHashFactToBase(address,uint256,uint256)` | external, state-changing | Any caller, if L1 fact anchored | None directly; target mirror later validates remote sender | Base mirror, fact pair | Cross-domain message requested; no local fact mapping | `ProofInputHashFactRelayedToBase` | No | Technically yes after L1 anchor | Candidate via Ethereum Adapter or infrastructure | No | No | No |
| `PhilBaseCrossDomainMessengerAdapter` | Ethereum L1 | `sendMessage(address,bytes)` | external, state-changing | Called by configured L1 relay contract | Canonical Base messenger handles transport | Base target, encoded message | Canonical bridge message requested | Canonical messenger behavior | Not payable in adapter | No | No direct application call | Yes | No | No |
| `PhilBaseProofInputHashMirror` | Base | `mirrorProofInputHashFact(uint256,uint256)` | external, state-changing | `crossDomainMessenger` only | `xDomainMessageSender() == authorizedL1Messenger` | `factHigh`, `factLow` | `mirroredProofInputHashFact[factHigh][factLow] = true`; latest fact fields | `ProofInputHashFactMirrored` | No | No | No ordinary transaction preparation | Messenger-only | No | No |
| `PhilBaseMirroredFactUnlockProofVerifier` | Base | `verifyUnlockProof(bytes,UnlockProofPublicInputs)` | external view | Any caller | None | 64-byte ABI-encoded `(factHigh, factLow)`, public inputs | None | None | No | Read-only | Read-only verifier call by action gate | No | No | No |
| `PhilBaseActionGate` | Base | `verifyAndConsume(BaseActionAuthorization,UnlockProofPackage,bytes)` | external payable, state-changing | Any caller with valid package and consumer data | None | Authorization, proof package, consumer data | `consumedNullifier[nullifier] = true` if full execution succeeds | `AuthorizationConsumed` | Yes | Yes, as execution | Future Ethereum Adapter execution boundary | No | Yes | Yes |
| `PhilUnlockConsumer` | Base | `consumePhilAuthorization(BaseActionAuthorization,bytes)` | external payable, state-changing | `PhilBaseActionGate` only | None | Authorization and encoded unlock request | Downstream call to target | `UnlockForwarded` | Yes | No direct user call | Contract-internal through gate | Contract-internal | No additional nullifier | Yes |

## End-To-End Sequence

| Step | Initiating actor | Input artifact | Output artifact | Chain | Transaction required | Confirmation/finality | Retry/replay behavior | User approval / PhilCore authorization | Failure modes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Authorization Package Draft | PhilCore Runtime / Authorization Engine | Capability, Trust, Policy, User Approval, action fields | Draft public tuple and `proofInputHash` | Local | No | Local only | Rebuild if inputs change | Required before package draft | Mismatched fields, expired request |
| Current STWO research proof | Proof System | Synthetic draft and process-local synthetic witness behind the exact research acknowledgement | `EXPERIMENTAL_SECRET_BEARING_PROOF_ARTIFACT` | Local synthetic research only | No | Process local only | Regenerate synthetic fixtures only | No production authority | Any real-secret or external use is prohibited |
| Current local proof verification | Proof System | Secret-bearing research artifact and public tuple | Local research verification result | Local synthetic research only | No | Process local only | Re-run synthetic regression verification | No new authority | Proof mismatch, timeout |
| Finalized non-executing package | Runtime / Authorization Engine | Future witness-hiding proof and verification | Finalized package, `[fact_high, fact_low]` preview | Unavailable for current proof | No | No current output | Not applicable until replacement | No execution authority | Current secret-bearing artifact is quarantined |
| Starknet fact publication | Future Starknet Adapter or infrastructure | STWO mirror proof/claim, L1 recipient | Verified Starknet fact and L2-to-L1 message | Starknet | Yes | Starknet acceptance/finality | Retry depends on Starknet account nonce and contract behavior | Future policy decision required | Missing production deployment, proof/claim failure, wrong L1 recipient |
| L1 message availability | Runtime monitor / infrastructure | Starknet message | Availability evidence | Ethereum L1 | No for check; yes for consumption | L1 view of Starknet message state | Recheck until available or expired | No new approval if within workflow | Message absent, wrong source, wrong payload |
| L1 fact anchoring | Any caller, PhilCore, or relayer | Available message, fact pair | Anchored L1 fact | Ethereum L1 | Yes | L1 confirmation/finality | Message consumption is one-time; repeated anchor likely fails at Starknet messaging | Should be workflow-approved or infrastructure-triggered | Message missing, source mismatch, payload mismatch |
| L1-to-Base relay | Any caller, PhilCore, or relayer | Anchored L1 fact, Base mirror address | Cross-domain Base message | Ethereum L1 | Yes | L1 tx plus Base bridge finality | Repeated relay can resend same fact; mirror setting is idempotent but costs fees | Should be workflow-approved or infrastructure-triggered | Unanchored fact, invalid mirror, messenger failure |
| Base mirror update | Base messenger | Cross-domain message | Mirrored Base fact | Base | Executed by messenger | Base confirmation/finality | Repeated mirror calls set same mapping true | No user direct approval; protocol/infrastructure step | Wrong messenger, wrong remote sender, bridge failure |
| Base fact availability | Runtime monitor / Ethereum Adapter | Base mirror state | Read-only fact availability evidence | Base | No | Snapshot only | Recheck before execution | No authority by itself | Stale read, wrong chain, wrong mirror |
| Base execution preparation | Ethereum Adapter | Finalized package, mirrored fact evidence, unconsumed nullifier evidence | Future unsigned execution artifact | Base | No for preparation | Snapshot only | Must revalidate | Requires user-authorized execution workflow | Nullifier consumed, config mismatch, expired package |
| Base authorization execution | Ethereum Adapter / wallet account | Authorization, fact pair proof blob, consumer data | Execution tx result | Base | Yes | Base confirmation/finality | Nullifier prevents replay after successful execution | Requires runtime authorization; likely smart account path | Invalid proof, missing mirror, nullifier race, consumer revert |

## Local STWO Versus Starknet Fact Origin

1. The current `stwo-unlock-keccak-v1` proof is a secret-bearing synthetic-research artifact. Local verification can derive a `proofInputHash` / `[fact_high, fact_low]` preview, but Runtime will not finalize or publish it and it creates no production Starknet-verifiable fact.
2. The repository contains Starknet spike/integration contracts that can verify a proof-input-hash slice and send a two-felt payload to L1: `starknet_integration/src/lib.cairo` and `starknet_spike/src/lib.cairo`.
3. The concrete L2-to-L1 message consumed by `PhilL1ProofInputHashAnchor` must be sent by the configured `sourceL2Verifier` with payload `[factHigh, factLow]`.
4. The repository contains spike/test syscall paths for this publication shape, but the current production Runtime does not contain an implemented Starknet publication workflow.
5. No accepted production deployment evidence for the Starknet verifier route was found in the inspected files.
6. Local tests can exercise the L1/Base side using mock Starknet/Base messengers and Cairo syscall harnesses. A full deployed Starknet-to-L1-to-Base route is not established by the current repo.
7. The current local proof artifact is prohibited from Base execution. A future reviewed witness-hiding artifact would still require the separately authenticated fact route; the Base mirrored verifier receives a 64-byte ABI-encoded fact pair and trusts Base mirror state.
8. A production Starknet verifier publication boundary, wrapper, deployment, or service remains required before a real fact can originate from local proof output.
9. `[fact_high, fact_low]` is a local preview until accepted by the Starknet/L1/Base fact route. It must not be treated as trusted fact state before anchoring/mirroring.
10. There is no production path that anchors a locally verified proof without Starknet. Local fixtures can mock the message path for tests only.

## M.6A Starknet Publication Readiness Clarification

The production-candidate Starknet entrypoint is:

```text
phil_starknet_integration::phil_proof_input_hash_verifier
  .verify_proof_input_hash_slice_and_send_to_l1(l1_recipient, proof, claim)
```

It verifies the `proofInputHash` slice proof, registers the fact in Starknet storage, emits `ProofInputHashFactVerified`, and sends `[fact_high, fact_low]` to the supplied L1 recipient.

The raw local full unlock proof is not submitted unchanged. The Starknet candidate path uses a Rust-generated Cairo argument mirror for `StarkProofMirror` and `ProofInputHashSliceClaim`.

The route is not production-ready until Starknet deployment, account/caller policy, generated artifacts, fee/nonce/finality handling, and Runtime/Starknet Adapter transaction preparation are accepted.

See [Starknet Verified-Fact Publication Boundary](./STARKNET_VERIFIED_FACT_PUBLICATION_BOUNDARY.md).

The reproducible local build and artifact check path is documented in [Starknet Toolchain And Artifact Reproducibility](./STARKNET_TOOLCHAIN_AND_ARTIFACT_REPRODUCIBILITY.md).

## Authority And Responsibility Classification

| Step | Classification | Recommended owner |
| --- | --- | --- |
| Build Authorization Package Draft | PhilCore Runtime operation | PhilCore Runtime / Authorization Engine |
| Generate and locally verify current STWO proof | Synthetic research operation only; production unavailable | PhilCore Proof System research boundary |
| Publish proof/fact on Starknet | Starknet Adapter operation, currently missing production boundary | Future Starknet Adapter or infrastructure |
| Consume Starknet message on L1 | Ethereum Adapter operation or infrastructure/relayer operation | Decide by policy; either PhilCore-prepared or relayer-triggered |
| Relay L1 fact to Base | Ethereum Adapter operation or infrastructure/relayer operation | Decide by policy; either PhilCore-prepared or relayer-triggered |
| Mirror fact on Base | Cross-domain messenger operation | Base messenger and `PhilBaseProofInputHashMirror` only |
| Monitor mirrored fact | Ethereum Adapter read-only operation | PhilCore Runtime / Ethereum Adapter |
| Prepare `verifyAndConsume(...)` | Ethereum Adapter execution preparation | PhilCore Runtime / Ethereum Adapter |
| Submit execution | User-authorized action | Future smart account / Ethereum Adapter path |
| Consume nullifier and execute consumer | Contract-internal action | `PhilBaseActionGate` and consumer |

PhilCore should not assume it directly sends every cross-domain transaction. It may coordinate the workflow, prepare user-payable calls when appropriate, or delegate anchoring/relay work to infrastructure under explicit policy.

## Transaction Boundary Candidates

### A. Starknet/L2 Fact Publication

- Actual method: candidate spike methods are `verify_proof_input_hash_slice_and_send_to_l1(...)` and `mark_verified_and_send(...)`.
- Actual proof payload: STWO mirror proof and proof-input-hash slice claim in `starknet_integration`; public inputs only in `starknet_spike`.
- Actual caller: Starknet account/test syscall caller; production caller model is not accepted yet.
- Current local proof submission: supported by spike/harness artifacts, not wired as production Runtime behavior.
- Transaction preparation possible now: not safely as a production boundary. The production contract, deployment, account model, and payload source must be accepted first.

### B. Ethereum L1 Fact Anchoring

- Method: `consumeProofInputHashFactFromL2(uint256 factHigh, uint256 factLow)`.
- Caller: any caller can submit the transaction if the Starknet message from `sourceL2Verifier` exists.
- Required precondition: Starknet L2-to-L1 message with exact `[factHigh, factLow]` payload.
- Message availability: must be checked against Starknet messaging state before preparation/submission.
- PhilCore role: candidate future preparation boundary or infrastructure-monitored relay.
- Replay/idempotency: Starknet message consumption is one-time; the anchor mapping is idempotent after success, but duplicate message consumption should fail upstream.

### C. L1-To-Base Relay

- Method: `relayProofInputHashFactToBase(address baseMirror, uint256 factHigh, uint256 factLow)`.
- Caller: any caller after the L1 anchor mapping is true.
- Fee/value: the current wrapper is not payable and calls the configured cross-domain messenger adapter. Production fee handling must be rechecked against the actual messenger profile.
- Remote target: `baseMirror` receives encoded `mirrorProofInputHashFact(factHigh, factLow)`.
- PhilCore role: candidate future preparation boundary or infrastructure/relayer task.

### D. Base Mirror

- Method: `mirrorProofInputHashFact(uint256 factHigh, uint256 factLow)`.
- Caller: Base cross-domain messenger only.
- Remote sender: configured authorized L1 messenger only.
- PhilCore role: monitor completion through read-only mirror state. PhilCore must not prepare this as a normal user transaction.

### E. Base Authorization Execution

- Method: `verifyAndConsume(BaseActionAuthorization authorization, UnlockProofPackage proofPackage, bytes consumerData)`.
- Caller model: any Base caller can call the gate, but Runtime must treat this as controlled execution through Ethereum Adapter and the preferred smart-account authority path.
- Proof/fact input: for the mirrored verifier, `proofPackage.proofBlob` is ABI-encoded `(uint256 factHigh, uint256 factLow)`, not raw STWO proof bytes.
- Nullifier semantics: `consumedNullifier[authorization.nullifier]` is set before consumer call, but EVM revert rolls back the nullifier if consumer execution reverts.
- Consumer semantics: `PhilUnlockConsumer` accepts calls only from the gate and then calls the downstream target.
- Boundary: this is the future Base execution preparation/submission boundary, not fact publication.

## Verified-Fact Lifecycle State Machine

| State | Required evidence | Permissible next states | Chain | Mutation status | Retry / expiry concerns |
| --- | --- | --- | --- | --- | --- |
| `proof_generated` | Proof artifact and package draft reference | `proof_verified_locally`, `failed`, `expired` | Local | No chain mutation | Regenerate before package expiry |
| `proof_verified_locally` | Local verifier result | `l2_publication_not_prepared`, `failed`, `expired` | Local | No chain mutation | Reverify if artifact changes |
| `l2_publication_not_prepared` | Local fact preview and missing accepted L2 boundary | `l2_publication_prepared`, `failed`, `expired` | Starknet candidate | No mutation | Blocked until production L2 interface is accepted |
| `l2_publication_prepared` | Future Starknet transaction draft | `l2_publication_submitted`, `failed`, `expired` | Starknet | No mutation until submitted | Must revalidate payload and recipient |
| `l2_publication_submitted` | Starknet tx hash | `l2_fact_verified`, `failed`, `expired` | Starknet | Pending mutation | Retry depends on Starknet account nonce and tx status |
| `l2_fact_verified` | Starknet verified fact state/event | `l2_to_l1_message_pending`, `failed`, `expired` | Starknet | Starknet state mutated | Wait for message availability |
| `l2_to_l1_message_pending` | L2-to-L1 message event | `l1_message_available`, `failed`, `expired` | Starknet/L1 | Message pending | Recheck until available/finalized |
| `l1_message_available` | Exact source and payload availability | `l1_anchor_prepared`, `failed`, `expired` | Ethereum L1 | No mutation yet | Freshness and finality required |
| `l1_anchor_prepared` | Unsigned anchor call draft | `l1_anchor_submitted`, `failed`, `expired` | Ethereum L1 | No mutation yet | Recheck message availability |
| `l1_anchor_submitted` | L1 tx hash | `l1_fact_anchored`, `failed` | Ethereum L1 | Pending anchor mutation | Message may already be consumed by another caller |
| `l1_fact_anchored` | `anchoredProofInputHashFact == true` | `l1_relay_prepared`, `failed`, `expired` | Ethereum L1 | L1 anchor state true | Fact can be relayed by any caller |
| `l1_relay_prepared` | Unsigned relay call draft | `l1_relay_submitted`, `failed`, `expired` | Ethereum L1 | No mutation yet | Recheck anchor and messenger config |
| `l1_relay_submitted` | L1 relay tx hash | `base_message_pending`, `failed` | Ethereum L1/Base bridge | Cross-domain message requested | Bridge delay/finality applies |
| `base_message_pending` | L1 relay event and messenger state | `base_fact_mirrored`, `failed`, `expired` | Base | Pending mirror mutation | Recheck until mirrored |
| `base_fact_mirrored` | `mirroredProofInputHashFact == true` | `execution_ready`, `failed`, `expired` | Base | Base mirror state true | Revalidate before execution |
| `execution_ready` | Mirrored fact, package unexpired, nullifier available | `execution_prepared`, `failed`, `expired` | Base | No execution mutation yet | Read-only state is stale immediately |
| `execution_prepared` | Unsigned `verifyAndConsume` call or UserOperation draft | `execution_submitted`, `failed`, `expired` | Base | No mutation until submission | Revalidate fact/nullifier/package/config |
| `execution_submitted` | Base tx/UserOperation hash | `nullifier_consumed`, `failed` | Base | Pending execution mutation | One successful execution wins nullifier race |
| `nullifier_consumed` | Gate consumed-nullifier state / tx receipt | `consumer_executed`, `failed` | Base | Nullifier consumed if tx succeeds | Revert rolls back nullifier |
| `consumer_executed` | `AuthorizationConsumed` and consumer result | Terminal | Base | Consumer execution complete | No replay with same nullifier |
| `failed` | Failure reason | Context-dependent retry | Any | Depends on failed step | Retry only with fresh evidence |
| `expired` | Expired package/workflow | Terminal or restart | Any | No further execution | New authorization required |

States after `l2_publication_not_prepared` depend on accepting and implementing a production Starknet fact publication boundary.

## Security Analysis

- Unauthorized fact injection: L1 anchoring consumes a Starknet message from configured `sourceL2Verifier`; Base mirroring requires the configured Base messenger and authorized L1 messenger.
- Fake local fact claims: local `[fact_high, fact_low]` is only a preview until the fact is anchored/mirrored.
- Messenger spoofing: Base mirror checks both `msg.sender == crossDomainMessenger` and `xDomainMessageSender() == authorizedL1Messenger`.
- Wrong L1 remote sender: rejected by `PhilBaseProofInputHashMirror`.
- Wrong Base messenger: rejected by `PhilBaseProofInputHashMirror`.
- Fact replay and duplication: fact mappings are idempotent, but message consumption and relay attempts may still incur fees or fail after another caller acts first.
- Nullifier race: Base gate rejects already-consumed nullifiers; only one successful transaction can consume a nullifier.
- Execution before mirror finality: mirrored verifier reads Base mirror state, so execution fails until the fact is mirrored.
- Stale fact-state reads: readiness and preparation must revalidate immediately before execution.
- Cross-domain reorg/finality: Runtime must model finality per Starknet, L1, and Base rather than treating relay events as instantly final.
- Relay front-running: any caller can anchor or relay once preconditions are true. This improves liveness but may complicate attribution and fee policy.
- Relayer censorship: infrastructure relayers may delay; PhilCore may need user-preparable fallback boundaries.
- Griefing through repeated relay attempts: repeated relay attempts can emit duplicate bridge messages for already anchored facts; mirror state remains true/idempotent.
- Mismatched fact pairs: mirrored verifier recomposes `proofInputHash` from `(factHigh, factLow)` and compares it with public inputs.
- Mismatched `proofInputHash`: Base gate recomputes `proofInputHash` and rejects mismatches before verifier use.
- Wrong chain/profile: future adapters must bind chain IDs and contract addresses exactly.
- Consumer failure after nullifier handling: because the consumer call is in the same EVM transaction, a consumer revert reverts the nullifier write too.
- Atomicity of `verifyAndConsume(...)`: nullifier consumption and consumer execution are atomic within the Base transaction.

Implemented protections are strongest at L1 anchor source validation, Base messenger/remote-sender validation, Base proof-input-hash recomputation, and Base nullifier consumption. Missing protections include production Starknet verifier deployment, L2 publication account policy, cross-domain monitoring/finality policy, and Runtime transaction-preparation boundaries for L1 anchor, L1 relay, Base monitor, and Base execution.

## Ethereum/Base-First Clarification

The accepted phrase "Ethereum/Base as the first production execution path" remains accurate if it means:

```text
Ethereum/Base is PhilCore's first production authorization-execution environment.
```

Implementation evidence requires a precision note:

```text
The current proof-fact availability route depends on Starknet-to-L1-to-Base transport before Base execution can verify and consume an authorization.
```

This does not make Starknet the identity layer and does not introduce multi-chain wallet support. It does mean the proof-fact infrastructure path is cross-domain, while the execution chain remains Base.

## Recommended Implementation Sequence

### M.6A - Starknet Fact Publication Readiness

- Code boundary: Starknet publication readiness and artifact reproducibility before transaction preparation.
- Transaction type: Starknet account transaction.
- Chain: Starknet.
- Authority required: future policy/user approval or infrastructure policy.
- State mutation: Starknet verified fact and L2-to-L1 message only after submission.
- Tests required: Cairo verifier payload, L2-to-L1 message payload, wrong recipient/source, exact fact pair.
- Prohibited: L1/Base execution, nullifier consumption, Base transaction preparation.
- Current M.6A.1 status: complete under the executable-harness classification for `starknet_integration_runner`.
- Current M.6A.2 status: configuration-only artifact/address/account boundary. See [Starknet Publication Configuration Boundary](./STARKNET_PUBLICATION_CONFIGURATION_BOUNDARY.md).
- Current M.6A.3 status: unsigned Starknet transaction draft boundary. See [Starknet Fact Publication Transaction Preparation Boundary](./STARKNET_FACT_PUBLICATION_TRANSACTION_PREPARATION_BOUNDARY.md).
- Current M.6A.4 status: signed but unsubmitted Starknet publisher artifact boundary. See [Starknet Publisher Authorization And Signing Boundary](./STARKNET_PUBLISHER_AUTHORIZATION_AND_SIGNING_BOUNDARY.md).
- Current M.6A.5 status: controlled Starknet submission and receipt monitoring boundary. See [Starknet Fact Publication Submission And Monitoring Boundary](./STARKNET_FACT_PUBLICATION_SUBMISSION_AND_MONITORING_BOUNDARY.md). It can observe Starknet acceptance, event evidence, and the L2-to-L1 message, but it still does not consume the L1 message, relay to Base, or consume a nullifier.

### M.6B - L1 Message Availability And Anchor Preparation

- Code boundary: read message availability and prepare `consumeProofInputHashFactFromL2`.
- Transaction type: Ethereum L1 transaction draft.
- Chain: Ethereum L1.
- Authority required: user-paid or relayer/infrastructure policy.
- State mutation: L1 anchor only after future submission.
- Tests required: message absent/present, wrong source, wrong payload, already consumed.
- Prohibited: direct Base mirroring, Base execution, nullifier consumption.
- Current status: read-only message availability and unsigned L1 anchor transaction-preparation boundary added. See [L1 Message Availability And Fact-Anchor Preparation Boundary](./L1_MESSAGE_AVAILABILITY_AND_FACT_ANCHOR_PREPARATION_BOUNDARY.md).

### M.6C - L1 Fact-Anchor Signing, Submission, And Monitoring

- Code boundary: sign, submit, and monitor the exact `consumeProofInputHashFactFromL2` transaction.
- Transaction type: Ethereum L1 EIP-1559 transaction.
- Chain: Ethereum Sepolia for live submission; local fixture for tests.
- Authority required: explicit relayer authorization, protected signer, and submission approval.
- State mutation: L1 message consumption and fact anchoring only after live submission confirmation.
- Tests required: exact signer binding, nonce/gas/fee/message revalidation, receipt event/state validation, duplicate handling.
- Prohibited: L1-to-Base relay, Base execution, nullifier consumption, arbitrary wallet behavior.
- Current status: controlled fixture/local signing and submission boundary added; live Sepolia submission remains blocked without live message/deployment/relayer prerequisites. See [L1 Fact-Anchor Signing, Submission, And Monitoring Boundary](./L1_FACT_ANCHOR_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

### M.6D - L1-To-Base Relay Preparation

- Code boundary: prepare `relayProofInputHashFactToBase`.
- Transaction type: Ethereum L1 transaction draft invoking the L1 relay contract.
- Chain: Ethereum L1 with Base cross-domain effect.
- Authority required: user-paid or relayer/infrastructure policy.
- State mutation: cross-domain message request only after future submission.
- Tests required: unanchored fact, invalid mirror, messenger config mismatch, encoded mirror call.
- Prohibited: preparing `mirrorProofInputHashFact` as a user transaction.
- Current status: unsigned L1-to-Base relay preparation boundary added. It validates L1 anchoring, relay deployment, messenger pairing, Base mirror configuration, exact Base mirror payload, fee/value behavior, and exact relay calldata. See [L1-To-Base Fact Relay Preparation Boundary](./L1_TO_BASE_FACT_RELAY_PREPARATION_BOUNDARY.md).

### M.6E - L1-To-Base Relay Signing, Submission, And Monitoring

- Code boundary: sign, optionally submit, and monitor the exact `relayProofInputHashFactToBase(baseMirror, factHigh, factLow)` transaction after M.6D preparation.
- Transaction type: Ethereum L1 EIP-1559 relay transaction.
- Chain: Ethereum Sepolia for live submission, Base Sepolia for mirror verification, local fixture for tests.
- Authority required: approved mirror binding, restricted relayer authorization, protected signer, submission approval, and live L1 anchoring evidence for public-network submission.
- State mutation: L1 cross-domain message request only after live submission; Base mirror mutation only by the cross-domain messenger after bridge delivery.
- Tests required: mirror target binding, relayer authorization, nonce/gas/fee/value revalidation, receipt event validation, cross-domain message status, Base mirror authorization invariants.
- Prohibited: direct Base mirror calls, Base `verifyAndConsume(...)`, nullifier consumption, consumer execution, arbitrary app-facing signer/submission authority.
- Current status: controlled fixture/local signing, restricted submission, L1 receipt monitoring, cross-domain monitoring, and read-only Base mirror verification boundary added. Live relay submission remains blocked without live L1 anchoring evidence, accepted Sepolia/Base Sepolia deployments, protected custody, and explicit approval. See [L1-To-Base Relay Signing, Submission, And Monitoring Boundary](./L1_TO_BASE_RELAY_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

### M.7 - Base `verifyAndConsume(...)` Execution Preparation

- Code boundary: prepare the exact Base execution call for `PhilBaseActionGate.verifyAndConsume(...)`.
- Transaction type: unsigned, unsubmitted Base transaction draft.
- Chain: Base.
- Authority required: finalized Authorization Package, active authoritative Capability Grant, eligible User Session lifecycle state, exact consumer data, and future controlled signer/submission authority.
- State mutation: none during preparation; nullifier consumption and consumer execution remain deferred to future submission.
- Tests required: exact calldata parity, mirrored-fact/package/capability/session/nullifier checks, ActionGate/verifier/consumer atomicity and replay regressions.
- Prohibited: treating execution preparation as fact publication, signing, submission, UserOperation creation, bundler/paymaster calls, nullifier consumption, consumer execution, Base state mutation, or application-facing submission authority.
- Current status: controlled Base authorization execution preparation boundary added. It requires Base mirrored-fact evidence, finalized package, active authoritative capability grant, eligible session lifecycle state, exact consumer data, read-only nullifier state, configuration validation, and optional read-only simulation/gas references. See [Base Authorization Execution Preparation Boundary](./BASE_AUTHORIZATION_EXECUTION_PREPARATION_BOUNDARY.md).

### M.8 - Base `verifyAndConsume(...)` Signing, Submission, And Monitoring

- Code boundary: authorize, sign, optionally submit, and monitor one exact prepared Base execution transaction.
- Transaction type: EIP-1559 Base execution transaction for local/controlled testnet EOA compatibility; ERC-4337 Smart Account remains the preferred production direction.
- Chain: local Hardhat for tests; Base Sepolia only for future live submission; Base mainnet disabled.
- Authority required: valid M.7 draft, active capability, eligible session, mirrored fact, available nullifier, accepted deployments, protected signer, and exact final execution approval.
- State mutation: live submission may consume the nullifier and execute the consumer.
- Tests required: exact signing, submission revalidation, receipt monitoring, nullifier mapping verification, consumer event/evidence verification, replay and rollback regressions.
- Prohibited: general wallet behavior, application-facing signer/submitter, arbitrary calldata, fixture evidence for live execution, Base mainnet submission, automatic ambiguous retry.
- Current status: controlled local/fixture signing, restricted submission, and receipt verification boundary added. Local Hardhat tests execute the real ActionGate/verifier/mirror/consumer path. Live Base Sepolia execution remains blocked without live mirrored-fact evidence, accepted deployments, protected custody, funding, RPC, and explicit approval. See [Base Authorization Execution Signing, Submission, And Monitoring Boundary](./BASE_AUTHORIZATION_EXECUTION_SIGNING_SUBMISSION_AND_MONITORING_BOUNDARY.md).

### M.9A - ERC-4337 Smart Account Foundation

- Code boundary: select and locally prove the EntryPoint/account/factory stack for future UserOperation preparation.
- Transaction type: local `handleOps(...)` fixture only; no bundler submission.
- Chain: local Hardhat only.
- Authority required: proposed ECDSA owner validator and stored `ownerCommitment` identity binding metadata.
- State mutation: local fixture account deployment and local ActionGate integration tests only.
- Tests required: EntryPoint `getUserOpHash` parity, deterministic factory address, invalid signature rejection, direct execute bypass rejection, counterfactual deployment, and ActionGate execution through the smart account.
- Prohibited: live account deployment, UserOperation signing/submission, paymaster invocation, session keys, Base mainnet, proof/public-input changes, or production approval.
- Current status: proposed local foundation added. See [PhilCore ERC-4337 Smart Account Foundation](./PHILCORE_ERC4337_SMART_ACCOUNT_FOUNDATION.md) and [ACP-0002](../architecture-changes/ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md).

## Missing Components

- Accepted production Starknet verifier deployment and address binding.
- Runtime/Starknet Adapter boundary for preparing and submitting L2 proof publication.
- Starknet-to-L1 message availability reader.
- L1 anchor preparation boundary with exact message source/payload validation.
- L1-to-Base relay preparation boundary with production messenger fee handling.
- Base mirror monitoring and finality policy.
- Base execution preparation boundary for `verifyAndConsume`.
- Accepted production ERC-4337 Smart Account security review, deployment, validator custody, and bundler integration.
- Operational policy deciding whether users, PhilCore, or infrastructure pay for anchoring and relaying.

## Negative Guarantees

This document does not:

- modify contracts or ABIs
- modify proof schemas or public inputs
- modify `ACTION_UNLOCK`
- modify `proofInputHash`
- modify `proofType = "stwo-unlock-keccak-v1"`
- modify `[fact_high, fact_low]`
- create transaction-preparation behavior
- create fact publication
- consume nullifiers
- call adapters
- submit transactions
- mutate chain state
- introduce multi-chain wallet support
