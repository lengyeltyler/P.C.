# O.37.4 Authority Transport Threat Analysis

Status: `COMPLETE_LOCAL_SECURITY_INTERFACE_REVIEW`.

Scope is the O.37.4 authority transport, ERC-4337 binding, recovery rotation,
nonce ownership, and constructor boundary. This analysis creates no live
authority or public mutation.

## Envelope Attacks

| Attack | Required rejection |
| --- | --- |
| truncation or malformed offsets | exact ABI decode and bounded length fail |
| appended or extension bytes | canonical re-encoding differs and fails |
| reordered outer fields | fixed ABI types/header or nested decode fails |
| swapped factor roles | bitmap, ascending role, and commitment parity fail |
| duplicate factors | distinct role/commitment/evidence checks fail |
| mixed envelope versions | exact outer and nested versions fail |
| missing validator or recovery side | action-selected combined decode fails |
| signature-format substitution | action-derived authority class fails |

There is no permissive fallback decoder. Unknown versions and actions fail
closed.

## Recovery Attacks

Single-factor takeover fails because only bitmaps `3`, `5`, and `6` are
accepted and both distinct signatures are verified. Validator-only recovery
fails because the validator never counts as a recovery factor. A validator
plus one factor also fails.

Replayed rotation, altered proposals, and stale evidence fail through the
authorized-intent hash, UserOperation hash, current/proposed configuration
hashes, request ID, exact epochs, EntryPoint nonce, and pending-state checks.
Expired requests cannot complete; completion before the delay and expiry
before the fixed window fail. Cancellation needs a fresh exact 2-of-3
recovery envelope over the stored request.

Descriptor substitution fails because the account recomputes public-material,
descriptor, role, and configuration commitments. Runtime remains responsible
for enrollment evidence and custody independence; the chain must not claim
that a submitted assertion proves those offchain facts independently.

## ERC-4337 Attacks

Signature substitution across actions fails because action type chooses the
only accepted format and is included in the authorized intent. Account,
chain, EntryPoint, sender, nonce, calldata, fee, epoch, and UserOperation-hash
substitution each changes a verified binding.

Nonce confusion is addressed by one owner: EntryPoint v0.7. PhilCore checks
lane/action/intent parity but stores no competing sequence. Recovery epochs
and request IDs cannot be interpreted as replacement nonce counters.

An alternate EntryPoint, aggregator, paymaster, registry, module, ERC-1271
path, or dynamic verifier is outside the accepted interface and must fail.

## Constructor And Privacy Attacks

The constructor accepts only the frozen three role commitments and
configuration hash, not full descriptors. It recomputes their relationship
and CREATE2 binds the exact initialization tuple. Runtime must reject invalid
or non-independent descriptors before account deployment. Publishing raw
credential IDs, private material, biometrics, or local approval records is
forbidden.

An existing CREATE2 address is reusable only when code and all frozen getters
match. Unexpected code or state fails; factory idempotence is not authority
to replace or reinitialize an account.

## Residual Risks

WebAuthn origin, attestation quality, hardware classification, and real-world
custody independence remain Runtime/enrollment facts represented onchain by
commitments. P-256 and secp256k1 remain classical cryptography. Solidity
implementation, dependency behavior, gas bounds, storage layout, and
bytecode have not been reviewed in O.37.4.

The residual risks do not authorize weakening exact 2-of-3 recovery,
validator separation, typed execution, canonical evidence, or the
local-proof-gated security model.

## Conformance Evidence

The versioned O.37.4 deterministic package covers valid validator-only,
combined rotation with two factor pairs, factor rotation, recovery-only
cancellation, and malformed/mutated cases. Tests cover encoding, canonical
decoding, authority dispatch, duplicate/missing/reordered evidence, altered
commitment, stale epoch, and account/chain replay substitution. O.37.2 is
retained byte-for-byte as historical evidence.
