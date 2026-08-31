# O.31 V2 Implementation Roadmap

Status: implementation plan only; Solidity requires a separate approved phase.

This roadmap orders a future V2 implementation so security assumptions are
tested before any deployable artifact or public funding decision. O.31 itself
performs none of these implementation or deployment steps.

## Entry Conditions For A Solidity Phase

A separately approved implementation phase may begin only when:

- O.30 and O.31 artifacts are accepted as its exact design baseline;
- the source HEAD and worktree are independently verified;
- the O.31 three-domain recovery model remains unchanged;
- a bounded chain-side P-256/WebAuthn verification approach has passed the
  feasibility gate, or an explicitly reviewed independent hardware
  secp256k1 signer is selected without downgrading domain independence;
- exact compiler, dependency, OpenZeppelin/EntryPoint, and test-tool versions
  are pinned;
- the phase grants no deployment, funding, UserOperation, proof, signing, or
  public-mutation authority.

If the hardware-factor verifier cannot be implemented safely, stop. Do not
substitute a same-device software key or remove the hardware role.

## Contract Implementation Order

### 0. Freeze vectors and dependency decisions

- freeze O.30 EIP-712 type strings, field order, action IDs, purposes, and
  golden hashes;
- freeze O.31 role IDs, factor descriptor schemas, commitment hashes, request
  IDs, states, errors, and event fields;
- prototype and benchmark the fixed P-256/WebAuthn verifier with adversarial
  parsing inputs;
- decide chain-native primitive versus fixed audited library;
- document dependency source, license, source hash, audit status, and gas
  bound;
- fail closed before account implementation if no acceptable verifier exists.

Exit: independent hash vectors and verifier decision are reviewed.

### 1. Types, hashing, and canonical decoding

- implement fixed enums/structs for intents, actions, validator/factor
  descriptors, and pending states;
- implement domain, header, action-specific, authorization, recovery, config,
  and request hashing;
- implement canonical selector/length/payload decoding;
- implement nonce-key, epoch, validity, and fee-bound helpers;
- add independent JavaScript/TypeScript vector parity.

No external calls or state transitions in this stage.

Exit: every positive and negative hash/decoder vector passes.

### 2. Fixed validator verification

- implement initial local/test secp256k1 execution-validator verifier;
- implement fixed P-256/WebAuthn or reviewed hardware-signer recovery verifier;
- implement role commitment reconstruction and exact 2-of-3 bitmap handling;
- reject duplicate keys, duplicate roles, malleable signatures, malformed
  assertions, wrong flags, wrong RP/origin policy, wrong commitments, and
  stale epochs;
- ensure verifier selection is fixed by role/configuration, never calldata
  chosen.

Exit: verifier unit, differential, malformed-input, and gas-bound suites pass.

### 3. Account state, views, and ERC-4337 validation

- implement the exact non-upgradeable storage order;
- publish compiler storage-layout output;
- implement immutable bindings and views;
- implement EntryPoint-only `validateUserOperation`;
- implement typed validation context and bounded missing prefund;
- implement keyed nonce/freeze/epoch checks;
- reject paymasters and every non-O.30 selector.

Exit: validation, caller, nonce, epoch, freeze, fee, and storage invariants
pass without typed asset execution.

### 4. Typed execution and receivers

Implement one handler at a time:

1. fixed confirmation;
2. native transfer with empty calldata;
3. EntryPoint-deposit withdrawal;
4. ERC-20 exact transfer and balance deltas;
5. ERC-721 safe transfer and receiver;
6. ERC-1155 single safe transfer and single/batch receivers.

After each handler, add reentrancy, malformed-return, revert-atomicity,
wrong-recipient/amount/token/data, and event-state tests. Never introduce a
generic target/value/data helper reachable from account calldata.

Exit: complete typed action matrix passes and prohibited capability search is
clean.

### 5. Recovery state machine

- implement the closed recovery-state discriminator;
- implement exact threshold request and immediate freeze;
- implement delay, cancellation combinations, expiry, and permissionless
  exact completion;
- implement validator/recovery epoch changes;
- implement delayed complete-configuration rotation;
- assert no external call or value movement from every recovery/config path;
- integrate local Device Vault/hardware-factor fixture adapters only after the
  contract state machine is stable.

Exit: all transition, replay, loss, compromise, cancellation, and epoch
invariants pass under fuzzing.

### 6. Factory and deterministic account creation

- create a new non-upgradeable V2 factory;
- require complete initial validator and three-role configuration;
- bind every constructor/security input into creation code and CREATE2
  derivation;
- test counterfactual deployment through EntryPoint;
- prove the factory has no post-deployment privilege;
- preserve frozen V1 source and addresses.

Exit: independent CREATE2 derivation, source/bytecode binding, and malformed
configuration tests pass.

## Testing Order

### Unit tests

1. canonical hashes and independent vectors;
2. canonical decoding and action/purpose shape;
3. execution-validator signature validation;
4. each factor verifier and role commitment;
5. exact 2-of-3 permutations and duplicate rejection;
6. keyed nonce, epochs, validity, fee, and freeze;
7. every recovery/config transition;
8. each typed execution handler and receiver;
9. factory inputs and CREATE2 address.

### Security and adversarial tests

Required attacker scenarios:

- stolen locked and unlocked primary device;
- compromised execution-validator key;
- stolen hardware security key;
- stolen offline/secondary recovery factor;
- each single recovery role compromised;
- each two-role compromise combination;
- malicious application or renderer;
- malicious bundler, relayer, or RPC response;
- replay, duplicated UserOperation, stale signature, stale WebAuthn assertion,
  cancelled/expired/completed request replay;
- wrong chain, EntryPoint, account, owner commitment, action, purpose, nonce,
  validator epoch, recovery epoch, factor role, factor bitmap, recipient,
  token, token ID, amount, or data hash;
- same credential in two roles and validator/factor key reuse;
- malformed DER/P-256/WebAuthn input, origin/RP mismatch, missing presence or
  verification flags, and counter warnings;
- direct EOA, account-self, `tx.origin`, hidden-admin, proxy, module,
  delegatecall, generic call, sweep, approval, and fallback attempts;
- malicious ERC-20 returns/balances and NFT callback reentrancy;
- recovery or config path attempting any value movement/external call;
- gas griefing, oversized input, revert atomicity, and storage corruption.

### Invariant and fuzz tests

At minimum:

1. exactly one nonzero active validator;
2. validator/recovery epochs never decrease;
3. no transition increments by more than one;
4. active recovery implies lanes `0` and `1` reject;
5. recovery/config states are mutually exclusive;
6. pending request fields are either complete or zero;
7. only exact 2-of-3 distinct roles authorize recovery;
8. validator cannot double-count as role 0;
9. recovery/config functions never reduce account/token/deposit balances;
10. completion installs only stored pending commitments;
11. cancellation/expiry never install proposed authority;
12. old epochs and consumed request IDs never become valid again;
13. unsupported selectors and fallback always revert;
14. no storage slot aliases immutable or security state;
15. every successful value movement has one exact intent event and expected
    balance effect.

### Full lifecycle tests

No future funding may occur until this exact lifecycle passes:

```text
Create Account
  -> Register Device
  -> Register Hardware Key
  -> Register Recovery Factor
  -> Fund Account
  -> Execute Operation
  -> Recover Authority
  -> Release Residual Funds
  -> Verify Final State
```

Test meaning:

- `Create Account` creates the local/counterfactual configuration draft;
- the three registration stages produce a complete role-bound constructor
  configuration before deployment/funding;
- `Fund Account` occurs only in a local fixture and target-chain fork until a
  later exact public phase;
- `Execute Operation` consumes fresh one-time authority;
- `Recover Authority` loses/revokes the old validator, uses two independent
  factor roles, waits the challenge interval, and installs a new epoch;
- `Release Residual Funds` uses a fresh ordinary typed intent, not recovery
  privilege;
- `Verify Final State` reconciles native balance, EntryPoint deposit, all
  tracked token/NFT balances, epochs, active factors, old-authority rejection,
  events, and exact public-mutation count.

Run the lifecycle for every factor-loss permutation and at least one
adversarial cancellation/expiry path. A fork test is required unless a
documented technical blocker is accepted; local-only success is insufficient
for funding approval.

## Runtime And Device Vault Implementation Order

After contract fixtures are stable:

1. define public-only factor descriptors and protected local records;
2. add primary-device recovery-purpose custody distinct from execution;
3. add external hardware registration and assertion adapters;
4. add offline/secondary recovery-factor ceremony;
5. add immutable trusted presentations for enrollment, request,
   cancellation, expiry, and completion;
6. add exact one-time factor-signing sessions;
7. add pending/active/revoked reconciliation after verified account state;
8. add recovery monitoring and sanitized audit events;
9. add lifecycle orchestration without public submission methods.

Applications receive only intent/request status. They never receive factor
signing, Device Vault, proof, or adapter authority.

## Audit Preparation

Before external review:

- freeze compiler settings, dependencies, source tree, generated ABI,
  bytecode, storage layout, EIP-712 vectors, and CREATE2 vectors;
- publish a requirements-to-code-to-test traceability matrix;
- publish capability and prohibited-surface matrices;
- run static analysis, unit/security tests, invariant/fuzz tests, coverage,
  gas bounds, and differential hash checks;
- classify every warning with evidence; do not blanket-suppress findings;
- produce a recovery state-transition table and attacker walkthroughs;
- document WebAuthn parser/P-256 trust, attestation limitations, counters, and
  privacy leakage;
- document all external calls, return-data bounds, and reentrancy posture;
- verify no private material, endpoints, signatures, proof witnesses, or
  reusable approvals exist in the audit package;
- commission independent contract and cryptography review.

Audit scope must include account, factory, fixed verifier code, Runtime
encoding/reconciliation, Device Vault/hardware adapters, and full fund
lifecycle. Auditing the account alone is insufficient.

## Deployment Preparation

Deployment is a later, separately approved sequence:

1. accept audit/remediation evidence;
2. rebuild from a clean, exact source commit;
3. independently reproduce ABI, bytecode, storage layout, and CREATE2 vectors;
4. create a versioned deployment manifest with no credentials;
5. verify target-chain EntryPoint and any required fixed cryptographic
   primitive;
6. reproduce a counterfactual address from complete three-role commitments;
7. run local and pinned-fork lifecycle with exact deployment artifacts;
8. prove release of native balance, EntryPoint deposit, ERC-20, ERC-721, and
   ERC-1155 holdings supported by the account;
9. calculate maximum funding and stranded exposure;
10. request separate exact approvals for deployment, funding, operation, and
    residual release.

No deployment approval may imply funding or UserOperation approval. No test
funding may precede the full lifecycle. Meaningful assets remain prohibited
until production validator composition and operational recovery are accepted.

## Required Stop/Fail-Closed Conditions

Stop implementation or deployment planning on:

- any single-factor recovery path;
- role/key reuse or unverifiable factor independence;
- unaccepted P-256/WebAuthn verifier;
- ambiguous parsing or unbounded verifier gas;
- generic execution primitive or externally chosen verifier;
- hidden administrator, upgrade, module, delegatecall, sweep, or approval path;
- recovery external call or value movement;
- storage-layout ambiguity;
- lifecycle failure or residual-fund uncertainty;
- source, dependency, bytecode, EntryPoint, chain, factory, address, epoch, or
  receipt mismatch.

## O.31 Stop Boundary

This roadmap does not start any listed implementation stage. No Solidity,
bytecode, deployment manifest, account, credential enrollment, proof,
authorization, signature, UserOperation, funding action, live call, or public
mutation is produced in O.31.
