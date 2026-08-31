# O.33 V2 Validator and Authorization Engine Prototype

Status: `VALIDATOR_AUTHORIZATION_ENGINE_PROTOTYPE_LOCAL_ONLY`.

O.37.1 compatibility: validator selection, authority-kind separation, epoch
checks, recovery freezes, and fixture evidence references remain unchanged.
A future production recovery verifier decodes O.37.1 evidence version `2`;
this fixture-only engine still receives no signature bytes.

O.36.1 resolution: recovery and recovery-configuration cancellation now
accept only exact 2-of-3 current recovery factors. The former
`combined_validator_recovery` prototype kind remains representable only so
negative conformance tests can reject it; it is not an accepted authority.

O.33 implements a local prototype that consumes the O.32 cryptographic
foundation and answers:

> Given an exact PhilCore intent and authorization package, is the requested
> action authorized under the current identity, validator, epochs,
> constraints, recovery state, and replay state?

An accepted result is a validation decision only. It cannot execute an
action, request a Device Vault signature, create a UserOperation, call a
contract, or mutate a public system. Public mutations are zero.

## Baseline

The verified phase-start baseline was repository HEAD
`5520d660b50e5db5be700061bd3e93ccff87a8a8` on
`codex/device-identity-v1`, with a clean tracked worktree.

O.20 through O.32 evidence and the deterministic O.32 vector package were
reviewed. The durable desktop identity record and ignored local Sepolia
binding remained coherent:

- identity: `identity_abab9766da60_24afd015`;
- display name: `My Phil`;
- canonical validator:
  `0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa`;
- validator key ID: `validator_key_3c5b2ebebc4f3f3b`;
- contract binding:
  `0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809`.

The known historical O.22 source-binding mismatch remains failed closed and
does not supply O.33 with deployment authority.

O.31 permits cancellation by the current validator plus one independent
non-primary recovery factor. The current O.32 combined-cancellation digest
accepts only O.32's exact two-role bitmaps. O.33 consumes that existing O.32
primitive unchanged, so the prototype is conservatively stricter and does
not claim the validator-plus-one-factor liveness path. This does not expand
authority, but the representation mismatch must be resolved in a separately
reviewed cryptographic-version phase before a V2 account implements that
O.31 cancellation option.

## Architecture

```text
untrusted application request
  -> O.32 canonical intent encoding
  -> O.32 intentCoreHash reproduction
  -> O.32 Runtime authorization reproduction
  -> O.32 authorizedIntentHash reproduction
  -> validator/recovery state checks
  -> O.32 validator or recovery digest reproduction
  -> purpose-bound authority verifier
  -> accepted non-executable decision OR exact rejection
```

The O.33 implementation is split into:

- `v2Validator.ts`: validator/recovery state, epoch transitions, replay
  snapshot, evidence-reference boundary, and verifier abstraction;
- `v2AuthorizationEngine.ts`: ordered verification pipeline and explicit
  rejection taxonomy.

Neither module duplicates an O.32 type string, domain separator, structure
hash, or digest formula. Every digest is obtained by calling the O.32
implementation.

## Validator Responsibilities

The validator:

- verifies the intent belongs to the configured chain, EntryPoint, account,
  and owner commitment;
- reproduces and compares every O.32 hash layer;
- checks exact current validator address and key-ID binding;
- checks validator and recovery epochs in both the intent and authority;
- applies validity, nonce, replay, revocation, and recovery-freeze state;
- selects only the authority kind fixed for the action;
- calls a purpose-bound authority verifier over the exact final digest;
- returns an accepted or exact rejected result.

The validator does not:

- choose an action;
- modify the intent;
- widen purpose, amount, recipient, token, fee, validity, or lifecycle limits;
- substitute policy, approval, presence, or proof evidence;
- sign;
- hold Device Vault material;
- act as a wallet or administrator;
- execute the authorized transition.

## Inputs

### State snapshot

The validator state contains:

- chain ID, EntryPoint, account, and owner commitment;
- active validator, validator key-ID binding, and validator epoch;
- validator local status: active or revoked;
- recovery configuration hash, recovery epoch, and recovery state;
- locally observed consumed authority digests and keyed nonces.

Validator and recovery epochs must each be at least one. Consumed digests and
nonces must be unique.

### Authorization package

The package contains:

- the exact O.32 intent;
- declared `intentCoreHash`;
- exact O.32 Runtime authorization input;
- declared Runtime authorization digest;
- declared `authorizedIntentHash`;
- a bytes32 UserOperation hash binding;
- one authority envelope with validator, key-ID, epochs, recovery
  configuration, optional fixed factor bitmap, evidence reference, and
  declared final authority digest.

The bytes32 UserOperation binding is a compatibility input only. O.33 does
not construct or serialize a UserOperation.

### Execution context

The trusted caller supplies the current time and validator state snapshot.
Future account code must obtain equivalent facts from immutable/stateful
onchain context rather than caller assertions.

## Output

Accepted output contains:

- all four reproduced hashes;
- keyed nonce;
- authority kind and verifier identifier;
- the exact state-transition class the action would request;
- explicit `false` values for execution, signature production, and
  UserOperation creation;
- public mutation count zero.

The transition class is descriptive, not execution authority. Rejected
output contains a stable failure code and stage without returning protected
evidence.

## Ordered Verification Boundaries

1. Normalize the validator state.
2. Check chain, EntryPoint, account, and owner commitment.
3. Canonically encode the intent using O.32.
4. Check validity and both intent epochs.
5. Enforce recovery-state lane/action restrictions.
6. Compare the reproduced `intentCoreHash`.
7. Verify Runtime intent binding and Runtime digest.
8. Reproduce and compare `authorizedIntentHash`.
9. Check keyed-nonce replay.
10. Require the action's exact authority kind.
11. Enforce exact recovery factor bitmap where applicable.
12. Check validator, key ID, both authority epochs, recovery configuration,
    and local revocation.
13. Reproduce the O.32 validator/recovery digest.
14. Check digest replay.
15. Invoke the purpose-bound authority verifier.
16. Return a non-executable decision.

The order provides specific failures for wrong chain/account or stale state
before any authority verifier is invoked.

## Signature Verification Boundary

O.33 defines the canonical validator signature format identifier as:

```text
secp256k1-rsv-65-low-s-v1
```

The authorization engine does not receive signature bytes. It receives a
nonzero evidence-reference hash and passes the exact O.32 digest and public
bindings to a `PhilCoreV2AuthorityVerifier`. This keeps Device Vault custody
and signing outside validator logic.

A future production verifier must:

- resolve the referenced evidence through a protected, purpose-bound channel;
- require exactly 65-byte canonical RSV secp256k1 data;
- require low `s` and canonical recovery byte;
- recover exactly the configured validator;
- reject generic messages and personal-sign ambiguity;
- bind evidence to the exact validator/recovery digest;
- return no private material.

O.33 provides only a deterministic allowlisted fixture verifier. It creates
no signature, receives no signature bytes, is marked fixture-only, cannot
accept generic messages, and is not a production validator.

Unsigned, missing, malformed, unrelated, or non-allowlisted authority is
rejected.

## Epoch And Revocation Model

- creation requires validator and recovery epochs of at least one;
- normal rotation installs only `currentValidatorEpoch + 1`;
- normal rotation is blocked during either recovery state;
- local revocation rejects validator authority but does not erase the
  configured validator;
- threshold recovery remains available after local validator revocation;
- recovery completion installs only the proposed validator, increments both
  validator and recovery epochs exactly once, and returns to normal state;
- old and future epochs are rejected in both intent and authority inputs.

Local revocation is a defensive Runtime state, not an onchain revocation
claim. A future account remains authoritative until verified state proves a
rotation or recovery completion.

## Recovery Interaction

Recovery states are:

- `normal`;
- `recovery_active`;
- `recovery_config_rotation_active`.

During active validator recovery:

- ordinary lane `0` is frozen;
- maintenance lane `1` is frozen;
- only the exact recovery-cancellation action is validator-verifiable;
- a second recovery request is rejected.

During recovery-configuration rotation:

- ordinary lane `0` remains available;
- maintenance lane `1` is frozen;
- only the exact configuration-rotation cancellation is allowed on lane `2`.

A recovery request requires exactly one of the O.32 2-of-3 bitmaps `011`,
`101`, or `110`. One role, duplicate/extra roles, wrong configuration, or
stale recovery epoch is rejected. Recovery authority cannot authorize an
ordinary action. Recovery validation describes authority rotation only and
cannot move assets.

## Device Vault Boundary

Device Vault remains responsible for:

- protected key custody;
- purpose-bound signing;
- protected authentication and fresh local user presence;
- refusing arbitrary signing;
- key lifecycle and local revocation.

The O.33 validator receives only public bindings and an evidence reference.
It never decrypts a vault, signs, exports a key, or decides that presence
occurred. Runtime approval/presence commitments remain in the O.32
authorization chain.

## Security Assumptions And Limits

- O.32 canonical encodings and hashes are assumed correct and are
  byte-for-byte rechecked.
- The state snapshot and current time must come from a trusted source.
- A production authority verifier is not implemented.
- Local replay state is a model; future EntryPoint/account nonce state is
  authoritative.
- Accepted fixture results are compatibility evidence, not reusable
  authorization or execution authority.
- No Solidity parity, calldata decoder, signature cryptography, recovery
  delay, or public state transition is claimed.
- The complete system is not quantum-resistant.

## Phase Boundary

O.33 creates no Solidity, bytecode, factory, wallet, production validator,
credential, proof, signature, UserOperation, transaction, live call, funding
action, or public mutation.
