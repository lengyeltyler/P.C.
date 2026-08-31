# O.32 V2 Cryptographic Security Analysis

Status: `LOCAL_CRYPTOGRAPHIC_FOUNDATION_REVIEWED`.

This analysis covers the local O.32 intent, Runtime authorization, validator,
nonce/epoch, and recovery-commitment implementation. It does not claim that a
V2 account, credential verifier, recovery state machine, or live system now
exists.

## Security Claims

O.32 supports these narrow claims:

1. one exact supported action has one deterministic typed intent hash;
2. changing an action parameter, security context, account, chain, nonce,
   validity range, or epoch changes that hash;
3. Runtime proof, policy, approval, and presence commitments are all required
   to derive an authorized-intent hash;
4. the validator digest is bound to the authorized intent, exact
   UserOperation hash, validator identity, validator key-ID binding, both
   epochs, chain, and account;
5. recovery factors are represented only by role-bound public commitments in
   an exact 2-of-3 configuration;
6. no signature, credential, proof, UserOperation, contract, or public
   mutation is produced.

These hashes do not by themselves prove that Runtime evidence is honest, a
signature is valid, a WebAuthn assertion is valid, a nonce has been consumed,
or a recovery delay elapsed. Later trusted and onchain components must verify
those facts.

## Threats And Mitigations

| Threat | O.32 mitigation | Remaining obligation |
| --- | --- | --- |
| Hash ambiguity or field reordering | Exact type strings, type hashes, fixed field order, and `abi.encode`; no packed or optional serialization. | Future Solidity must reproduce the vectors byte-for-byte. |
| Cross-chain replay | Chain is in the intent and EIP-712 domain. | Account must reject a mismatched deployment chain. |
| Cross-account replay | Account is in the intent and EIP-712 domain. | Factory and account must preserve the exact binding. |
| EntryPoint substitution | EntryPoint is in the intent core and therefore transitively in the validator digest. | Account must enforce its immutable EntryPoint. |
| Action or limit substitution | Action-specific schemas bind recipient, asset, token ID, amount, receiver-data hash, fee cap, lifecycle limits, and validity. | Canonical calldata decoding must reject every extra or malformed field. |
| Signature replay | Exact UserOperation hash, keyed nonce, account, chain, and both epochs are bound. | EntryPoint/account must consume nonces and reject stale epochs. |
| Validator compromise | Validator authority is constrained to a fully authorized intent and can be invalidated by epoch rotation. | Future recovery and rotation state machines must be correct; compromise remains dangerous until rotation completes. |
| Validator/key-reference substitution | Validator address and domain-separated validator key-ID binding are explicit fields. | Device Vault must map that binding to the intended protected key. |
| Malicious application | Application identity, origin, session, capability, and policy-decision IDs are committed; trusted Runtime creates the authorization layer. | Trusted presentation must show exact action data and Runtime must not accept application-authored evidence. |
| Forged or swapped proof | Proof type, public input, artifact digest, and nullifier are committed. | Runtime must verify the fresh proof before creating the digest; Ethereum does not verify STWO in the current model. |
| Reused approval or presence | Approval and presence have separate exact commitments. | Runtime must enforce freshness, one-time use, and purpose before hashing. |
| Compromised recovery factor | Exact 2-of-3 distinct roles, role-bound verifier policy, current recovery configuration, and epoch are committed. | Independent custody, enrollment, signature/assertion verification, delay, cancellation, and monitoring are not implemented yet. |
| Same factor counted twice | Configuration commitments must be distinct and only exact two-role bitmaps are accepted. | Enrollment must prove role independence and prohibit validator-key reuse. |
| Stale recovery configuration | Recovery epoch and configuration hash are in recovery authority digests. | Account must increment epochs exactly and reject stale/future values. |
| Arbitrary signing oracle | Public API exposes named digest computations, not generic personal-sign or arbitrary typed-data signing. | Device Vault signing API must remain purpose-bound and accept only validated envelopes. |
| Circular authorization | Intent excludes signature/UserOperation serialization; Runtime and validator layers are derived in one direction. | Future adapters must not feed derived signatures back into the intent core. |
| Mutable transport data invalidates intent | Bundler, RPC, receipt, block, and signature bytes are excluded from the core. | Exact fee and UserOperation fields still require later bounded approval and validator binding. |

## Replay Analysis

### Same nonce

The same fields and same lane/sequence intentionally produce the same
`intentCoreHash`. Hash uniqueness is not nonce consumption. Once consumed,
the exact keyed EntryPoint nonce must be rejected by the future account. The
vector package records this expected rejection explicitly.

### Wrong chain or account

Changing either value changes the intent core. It also changes the EIP-712
domain. This is defense in depth, not permission to omit either check.

### Old validator epoch

Every validator digest binds `validatorEpoch`. Rotation must increment the
account epoch exactly once and reject both stale and future supplied epochs.
An old validator signature cannot be reinterpreted at the new epoch.

### Old recovery epoch

Ordinary and recovery intents bind `recoveryEpoch`. Recovery factor digests
also bind the active configuration hash and recovery epoch. A completed
recovery or configuration rotation must therefore invalidate outstanding
authority under the old state.

### Different UserOperation

The final validator or recovery digest binds the exact ERC-4337
`userOpHash`. An authorization for one operation is not valid for another,
even when both refer to the same intent.

## Encoding Review

The implementation:

- range checks every unsigned integer at its declared width;
- normalizes and rejects invalid or zero security-critical addresses;
- requires exact nonzero `bytes32` values except fields whose schema
  explicitly permits zero;
- enforces action/payload, action/purpose, and action/nonce-lane mappings;
- bounds intent lifetimes;
- hashes variable data before typed inclusion;
- rejects unsupported versions, actions, verifier kinds, thresholds, role
  bitmaps, and epoch relationships.

The tests independently reconstruct a native-transfer header and action
encoding with `AbiCoder`, rather than validating the implementation only
against itself.

## Recovery Commitment Review

The three commitments represent:

- `PRIMARY_DEVICE`: a recovery-purpose credential separate from the daily
  validator;
- `HARDWARE_SECURITY_KEY`: an external hardware-controlled verifier;
- `RECOVERY_FACTOR`: an offline or secondary security domain.

O.32 fixture values are public hashes only. They are not enrollments and are
not usable credentials. The verifier-kind constants describe future
compatibility choices; they are not evidence that P-256/WebAuthn or
secp256k1 verification has been implemented onchain.

A compromised single factor is insufficient under the exact threshold.
Compromise of two independent factors can authorize recovery after the future
delay and cancellation rules, so factor independence and monitoring remain
critical. Recovery authority must rotate validator state only and must never
become an asset-transfer authority.

## Residual Risks And Required Gates

- Keccak-256 and the initial secp256k1 validator do not make the complete
  system quantum-resistant.
- TypeScript parity does not prove future Solidity parity.
- No canonical calldata decoder exists yet.
- No signature malleability, P-256/WebAuthn, counter, origin, RP, or user
  verification logic is implemented in this phase.
- No EntryPoint nonce or epoch state is implemented.
- No recovery delay, freeze, cancellation, expiry, or completion state exists.
- No external audit or formal verification has occurred.
- Existing V1 source and deployment evidence are unchanged.

Before V2 account implementation can be considered complete, later phases
must independently reproduce these vectors, implement canonical decoding and
fixed verifier behavior, exercise adversarial and fuzz tests, and pass the
O.31 audit/deployment gates. Deployment and funding require additional exact
public-mutation approval.

## Phase Boundary

O.32 performed zero public mutations. It deployed no contract, moved no
funds, enrolled no credential, generated no live proof, requested no Device
Vault signature, created no signature, created no UserOperation, and sent no
transaction.
