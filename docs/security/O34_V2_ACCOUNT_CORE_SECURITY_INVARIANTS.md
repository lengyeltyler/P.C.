# O.34 V2 Account Core Security Invariants

Status: `LOCAL_ENFORCEMENT_INVARIANTS_TESTED`.

These invariants govern the local O.34 account core. An accepted validation
is not execution authority outside the process and does not create a
signature or UserOperation.

## State Invariants

1. Account version, security-model ID, recovery delay, and recovery expiry
   equal the O.31/O.32 constants.
2. Chain, EntryPoint, account, and owner commitment agree between immutable
   account state and O.33 validator state.
3. Active validator commitment equals the O.32 commitment of the active
   validator and key-ID binding.
4. Security-configuration hash equals both O.33 recovery state and the O.32
   hash of the ordered three role commitments.
5. Only nonce lanes `0`, `1`, and `2` exist.
6. Recovery-active state has exactly one pending recovery; all other
   lifecycle states have none.
7. Recovery completion installs only pending state and increments validator
   and recovery epochs by exactly one.
8. Recovery cancellation changes neither epoch.
9. Every normalized state has no administrator, upgrade key, arbitrary
   execution, delegatecall, module, session-key, or paymaster capability.

Malformed or incoherent state is rejected before authority verification.

## Authorization Invariants

- The account never authors or repairs an intent.
- O.33 remains the sole local authority-verification engine.
- The account checks O.33's accepted keyed nonce and transition class.
- Wrong validator, key binding, validator epoch, recovery epoch, recovery
  configuration, chain, account, EntryPoint, owner commitment, purpose, or
  validity fails closed.
- Changed recipient, amount, token, token ID, receiver-data hash, purpose,
  fee bound, lifecycle digest, or another intent field invalidates the O.32
  hash chain.
- Expired or not-yet-valid authorization fails before a draft can be used.
- A validation context carries no evidence bytes, private material, or
  signing capability.
- A validation context is issued and consumed by object identity, binds the
  exact normalized state, and cannot be copied, serialized, or reused for a
  local transition.

## Replay And Nonce Invariants

- The external keyed nonce must equal the intent lane and sequence.
- Sequence less than current is stale; sequence greater than current is a
  prohibited gap.
- Unsupported lanes fail.
- A local transition consumes the exact authority digest and keyed nonce
  before producing next state.
- Only the consumed lane increments.
- Old epochs remain invalid even if a modeled nonce would otherwise be
  unused.
- Permissionless recovery completion consumes exact active pending state and
  cannot be repeated.

## Recovery Invariants

- Recovery uses exactly two distinct roles from the canonical three-domain
  configuration.
- One role never suffices.
- The daily validator does not count as a recovery role.
- O.34 preserves O.32/O.33's exact bitmap rule and does not implement a
  weaker cancellation fallback.
- Active recovery freezes ordinary execution and validator maintenance.
- Only exact recovery cancellation remains authorized through lane `2`.
- Completion requires exact request ID, elapsed delay, unexpired request,
  and unchanged source epochs.
- Recovery changes authority only. Request, cancellation, and completion
  cannot transfer assets or call an external contract.
- Asset movement after recovery requires an entirely fresh ordinary
  authorization under the new epochs.

## Execution Invariants

- There is no generic `execute`.
- There is no delegatecall.
- There is no unrestricted external-call target or calldata.
- There is no token approval.
- There is no administrator withdrawal or sweep.
- There are no installable modules, plugins, session keys, or paymasters.
- Confirmation can target only the immutable confirmation contract.
- Native transfer calldata is empty.
- Token drafts expose only their fixed transfer selector and exact signed
  fields.
- EntryPoint deposit withdrawal remains unimplemented and rejected in O.34.
- The execution lock rejects validation while set.

O.34 drafts describe what a future Solidity handler would be allowed to do.
They perform no external call and move no value.

## Fund Lifecycle Invariants

For every value-moving draft:

1. an O.32 fund-lifecycle preimage is mandatory;
2. its digest equals the signed intent digest;
3. its account and asset/token ID match the action;
4. the authorized amount is within the maximum holding bound;
5. a nonzero residual recipient is bound;
6. expected final balance is within the exact maximum stranded bound;
7. release-path verification, residual handling, post-state verification,
   and separate release authorization are all required.

These local flags do not prove deployable recovery. Funding remains forbidden
until a future phase verifies an actual V2 release path and complete
fund/execution/release lifecycle.

## Attack Prevention Matrix

| Attempt | Rejection boundary |
| --- | --- |
| cross-chain/account replay | immutable and O.33 domain binding |
| substituted EntryPoint | caller plus intent/validator state binding |
| changed recipient or amount | O.32 intent hash mismatch |
| changed UserOperation binding | external/package hash comparison and authority digest |
| stale/reused nonce | exact lane sequence and consumed nonce |
| stale validator/recovery authority | exact epoch checks |
| wrong validator/key | commitment coherence and O.33 authority checks |
| single-factor recovery takeover | exact 2-of-3 bitmap |
| execution during recovery | lane freeze |
| premature/wrong recovery completion | time, request ID, and source epochs |
| arbitrary call/delegatecall | absent type plus explicit forbidden-field check |
| paymaster injection | explicit rejection |
| stranded-fund plan | mandatory exact lifecycle/release gate |
| admin or upgrade takeover | no storage or capability |

## Tested Claims

The O.34 suite covers:

- coherent state creation and negative capability flags;
- exact O.32/O.33 valid authorization;
- recipient and amount mutation;
- wrong chain, account, EntryPoint, purpose, validator, key binding, and
  epochs;
- stale, future, wrong-lane, unsupported, and replayed nonces;
- copied, reused, and state-substituted validation contexts;
- wrong caller and UserOperation hash binding;
- missing, unverified, and modified fund-lifecycle data;
- arbitrary target/calldata, delegatecall, module, session-key, and
  paymaster rejection;
- unsupported EntryPoint withdrawal;
- valid 2-of-3 recovery and single-factor rejection;
- recovery freeze, delay, exact request, completion, cancellation, and epoch
  effects;
- zero execution, funds moved, signatures, UserOperations, and public
  mutations.

## Limits

O.34 is not Solidity parity or a deployable security claim. It does not yet
cover compiler storage layout, ABI decoding, EVM reentrancy/gas behavior,
token balance deltas, receiver hooks, EntryPoint execution, production
signature verification, recovery-config rotation, fork simulation, or
deployment.

The O.31 validator-plus-one-non-primary cancellation option remains
unrepresented by O.32. O.34 therefore stays strictly at exact 2-of-3.
The complete system is not quantum-resistant.

## Absolute Phase Boundary

Public mutations are zero. No contract was deployed, no funds moved, no
credential enrolled, no proof or signature produced, and no UserOperation
created or submitted.
