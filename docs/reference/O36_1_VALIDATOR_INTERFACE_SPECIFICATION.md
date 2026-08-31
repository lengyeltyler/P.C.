# O.36.1 Production Validator Interface Specification

Status: `FROZEN_FOR_FUTURE_O37_SOLIDITY_IMPLEMENTATION`.

This specification freezes the contract-visible execution-validator boundary.
It does not sign a digest, implement Solidity, create a UserOperation, or
grant executable authority.

## Validator Identity And Commitment

The initial V2 account supports exactly:

```text
verifierKind = 1 = SECP256K1_ECDSA
```

The O.32 commitment remains:

```text
PhilCoreV2ValidatorCommitment(
  uint8 verifierKind,
  address validator,
  bytes32 validatorKeyIdBinding
)
```

```text
validatorCommitment = keccak256(
  abi.encode(
    VALIDATOR_COMMITMENT_TYPEHASH,
    1,
    validator,
    validatorKeyIdBinding
  )
)
```

The address, key-ID binding, commitment, verifier kind, and current validator
epoch are account state. The key-ID binding is public domain separation; it
is not a local Device Vault record, credential name, key handle, or private
key.

No calldata-selected validator, ERC-1271 validator, aggregator, registry,
module, plugin, session key, fallback verifier, or administrator is accepted
in V2.0.

## Authorization Digest

The O.32 typed structure and field order are frozen unchanged:

```text
PhilCoreV2Authorization(
  bytes32 authorizedIntentHash,
  bytes32 userOpHash,
  address validator,
  bytes32 validatorKeyIdBinding,
  uint64 validatorEpoch,
  uint64 recoveryEpoch
)
```

The EIP-712 domain is exactly:

```text
EIP712Domain(
  string name,
  string version,
  uint256 chainId,
  address verifyingContract
)
```

with:

- name: `PhilCore V2 Account`;
- version: `1`;
- chain ID: the account's immutable deployment chain;
- verifying contract: the account address.

The final validator digest is:

```text
keccak256(
  0x1901
  || domainSeparator
  || keccak256(
       abi.encode(
         VALIDATOR_AUTHORIZATION_TYPEHASH,
         authorizedIntentHash,
         userOpHash,
         validator,
         validatorKeyIdBinding,
         validatorEpoch,
         recoveryEpoch
       )
     )
)
```

`authorizedIntentHash` transitively binds the exact O.32 intent core and
Runtime authorization digest. The intent binds action, purpose, owner,
account, chain, EntryPoint, keyed nonce, epochs, application context, fund
lifecycle, fee ceiling, validity, and typed payload. `userOpHash` binds the
exact ERC-4337 operation.

No Ethereum signed-message prefix, personal-sign domain, raw transaction hash,
arbitrary application digest, or caller assertion is valid.

## Canonical Evidence Envelope

Execution and ordinary validator-maintenance evidence is exact static ABI
encoding of:

```text
ValidatorAuthorityEnvelopeV1 {
  uint8 envelopeVersion       // exactly 1
  uint8 authorityKind         // exactly 1: execution validator
  uint8 verifierKind          // exactly 1: secp256k1 ECDSA
  address validator
  bytes32 validatorKeyIdBinding
  uint64 validatorEpoch
  uint64 recoveryEpoch
  bytes32 r
  bytes32 s
  uint8 v
}
```

The canonical ABI encoding is exactly 320 bytes. O.37 must reject any shorter,
longer, packed, offset-based, appended, or noncanonically padded form.

`r` and `s` are nonzero, `s` is in the lower half of the secp256k1 order, and
`v` is exactly `27` or `28`. Recovery must equal the current validator
address. Every duplicated state field must exactly match account state and
the digest input; it cannot override state.

The envelope is transport evidence only. The signature bytes are neither
stored nor emitted.

## Solidity Verification Boundary

The future account directly verifies:

1. `msg.sender` is its immutable ERC-4337 v0.7 EntryPoint;
2. `block.chainid` equals its immutable deployment chain;
3. account, EntryPoint, chain, owner commitment, security model, action,
   purpose, calldata, nonce key/sequence, both epochs, fee ceiling, validity,
   and typed payload reconstruct the exact intent;
4. the supplied Runtime authorization digest is nonzero and reconstructs the
   exact `authorizedIntentHash`;
5. `userOpHash` is the hash supplied by the immutable EntryPoint validation
   call and is included in the validator digest;
6. the envelope is exact, kind/version/verifier are supported, and duplicated
   fields match state;
7. canonical low-s secp256k1 recovery equals the active validator;
8. the EntryPoint owns nonce uniqueness and the account enforces the fixed
   lane/action mapping;
9. both epochs equal current state and the recovery freeze permits the lane;
10. paymaster data is absent and missing prefund is bounded by the signed
    total-fee ceiling.

Signature failure returns ERC-4337 signature-failure validation data where
required for simulation compatibility. Malformed shape, unsupported
authority, wrong caller, wrong lane, stale state, and invariant failures use
specific reverts. O.37 must freeze that classification in tests.

## Runtime And Device Vault Boundary

Runtime verifies locally:

- the fresh STARK/STWO proof and exact public-input binding;
- policy, application/capability, approval, and fresh user-presence evidence;
- fund-lifecycle and human-readable presentation requirements;
- the correct active validator key reference and session;
- that the future signing request is purpose-bound to the exact final digest.

Device Vault alone may use private validator material. It must recompute the
digest from public fields before any future signing operation.

The account does not verify the STARK proof, policy decision, approval,
presence ceremony, local session, application UI, or Device Vault custody. It
verifies the nonzero hashes transitively bound by the validator signature.

The following must never reach chain calldata, storage, logs, or evidence:

- Phil identity secret material or passphrase;
- identity-root witness material;
- private Device Vault keys or handles;
- proof witness or complete protected proof artifact;
- raw local policy, approval, or user-presence records;
- recovery secrets or encrypted packages;
- credential labels, local device names, or credential IDs.

## Replay And Epoch Model

Replay is prevented by cumulative binding:

- EntryPoint v0.7 keyed nonce `(uint192 key << 64) | uint64 sequence`;
- unique action ID in the intent;
- complete UserOperation hash;
- account-and-chain EIP-712 domain;
- `validAfter` and `validUntil`;
- current validator epoch;
- current recovery epoch.

The account does not duplicate EntryPoint sequence storage. It rejects a nonce
lane that does not match the typed action. EntryPoint consumes the sequence.

Normal validator rotation increments only validator epoch by exactly one.
Recovery completion increments validator and recovery epochs by exactly one.
Recovery-configuration completion increments only recovery epoch by exactly
one. Cancellation and expiry increment neither. Old and future epochs fail.

## Failure Model

The frozen failure families are:

- `VALIDATOR_EVIDENCE_MALFORMED`;
- `VALIDATOR_EVIDENCE_LENGTH_INVALID`;
- `VALIDATOR_ENVELOPE_VERSION_UNSUPPORTED`;
- `AUTHORITY_KIND_MISMATCH`;
- `VALIDATOR_VERIFIER_UNSUPPORTED`;
- `VALIDATOR_ADDRESS_MISMATCH`;
- `VALIDATOR_KEY_BINDING_MISMATCH`;
- `VALIDATOR_COMMITMENT_MISMATCH`;
- `VALIDATOR_EPOCH_STALE`;
- `VALIDATOR_EPOCH_FUTURE`;
- `RECOVERY_EPOCH_STALE`;
- `RECOVERY_EPOCH_FUTURE`;
- `VALIDATOR_SIGNATURE_MALLEABLE`;
- `VALIDATOR_SIGNATURE_INVALID`;
- `VALIDATOR_REVOKED_OR_FROZEN`;
- `DOMAIN_MISMATCH`;
- `ACCOUNT_MISMATCH`;
- `CHAIN_MISMATCH`;
- `ENTRYPOINT_MISMATCH`;
- `USER_OPERATION_HASH_MISMATCH`;
- `INTENT_HASH_MISMATCH`;
- `NONCE_LANE_MISMATCH`;
- `NONCE_REPLAY`;
- `AUTHORIZATION_NOT_YET_VALID`;
- `AUTHORIZATION_EXPIRED`;
- `MAX_TOTAL_FEE_EXCEEDED`;
- `PAYMASTER_PROHIBITED`.

No failure may fall back to another validator, verifier kind, authority
envelope, or generic signature path.
