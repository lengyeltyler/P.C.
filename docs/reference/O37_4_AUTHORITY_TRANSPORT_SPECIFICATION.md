# O.37.4 V2 Authority Transport Specification

Status: `COMPLETE_LOCAL_SECURITY_INTERFACE_FREEZE`.

O.37.4 closes the authority-transport gap found by O.37.3. It does not create
Solidity, bytecode, credentials, production signatures, or UserOperations.
All examples and vectors are deterministic test-only material.

## Authority Dispatch

An action has exactly one authority class:

| O.32 action type | Authority class | `PackedUserOperation.signature` |
| --- | --- | --- |
| `0` through `7` | validator only | direct `ValidatorAuthorityEnvelopeV1` |
| `8`, `9`, `11` | recovery only | direct `RecoveryAuthorityEnvelopeV2` |
| `10` | validator and recovery | `CombinedAuthorityEnvelopeV1` |

No envelope tag may select a weaker class. The account derives the class from
the action type already bound by the authorized intent, then decodes exactly
that format. An unknown action fails.

## Preserved Direct Envelopes

Ordinary execution uses the exact O.36.1 validator envelope: canonical
standard-ABI encoding of its ten static fields, version `1`, authority kind
`1`, verifier kind `1`, and exactly `320` bytes.

Recovery request, recovery cancellation, and recovery-configuration
cancellation use the exact O.37.1 recovery envelope directly:

```text
RecoveryAuthorityEnvelopeV2 {
  RecoveryEvidenceContextV2 context
  bytes firstFactorEvidence
  bytes secondFactorEvidence
}
```

It has envelope version `2`, authority kind `2`, and action type equal to the
intent action. Its canonical length is between `2624` and `8896` bytes.
Only bitmaps `3`, `5`, and `6` are valid. Factor evidence is ordered by
increasing role ID and the two factors must be nonempty and distinct.

## Combined Authority Envelope

Recovery-configuration rotation, action type `10`, is the only combined
authority action:

```text
abi.encode(
  uint8 envelopeVersion,
  uint8 authorityKind,
  uint8 actionType,
  bytes validatorEvidence,
  bytes recoveryEvidence
)
```

The exact type string is:

```text
PhilCoreV2CombinedAuthorityEnvelopeV1(uint8 envelopeVersion,uint8 authorityKind,uint8 actionType,bytes validatorEvidence,bytes recoveryEvidence)
```

Its Keccak-256 type hash is:

```text
0xaa0158949e9a247ad5e5be5fb3824e05c1c2255f58632a47c2e3c7bed5a6a03b
```

Fields have this immutable meaning:

1. `envelopeVersion`: exactly `1`;
2. `authorityKind`: exactly `3`, validator and recovery;
3. `actionType`: exactly `10`;
4. `validatorEvidence`: exact canonical 320-byte O.36.1 envelope;
5. `recoveryEvidence`: exact canonical O.37.1 envelope for action `10`.

The canonical combined length is:

```text
544 + recoveryEvidence.length
```

and therefore between `3168` and `9440` bytes. The decoder must decode,
re-encode, and require byte-for-byte equality. Truncation, extension,
appended bytes, alternate offsets, reordered fields, mixed versions, wrong
headers, or nested noncanonical encodings fail.

## Recovery Factor Witnesses

The nested O.37.1 evidence remains authoritative.

- Primary device is role `0`, WebAuthn P-256, generation-bound, UV required,
  single-device/platform policy, and bound to credential, RP-ID, origin,
  attestation, and independence commitments.
- Hardware security key is role `1`, WebAuthn P-256, generation-bound, UV
  required, single-device/cross-platform policy, and bound to the external
  hardware and custody-domain commitments.
- Independent recovery factor is role `2`, purpose-bound secp256k1,
  generation-bound, with signer-material and independent custody-domain
  commitments. It is not transaction authority.

WebAuthn factor evidence is canonical standard-ABI encoding, `992` through
`3968` bytes. Secp256k1 factor evidence is exactly `672` bytes. Full
descriptors accompany public witness material so the account can recompute
the selected stored commitment. Raw credential identifiers, private keys,
biometrics, and protected local records never enter the envelope.

## Digest Separation

For action `10`:

- the validator signs the exact O.32 configuration-rotation authorization
  digest;
- both selected factors sign the exact O.32 recovery authorization digest.

Both digests independently bind the same account, chain, authorized-intent
hash, UserOperation hash, validator and recovery epochs, current and proposed
configuration hashes, proposed epoch, and factor bitmap. A signature valid
for one digest cannot satisfy the other. Validator authority never counts as
a recovery factor.

## Failure Taxonomy

Transport decoding rejects unsupported actions, wrong authority class,
wrong version or action header, wrong length, malformed ABI, noncanonical
re-encoding, missing nested evidence, duplicate evidence, and an invalid
bitmap. Subsequent verification rejects role reordering, descriptor or
commitment mismatch, stale epochs, invalid signatures, wrong account, chain,
EntryPoint, intent, UserOperation hash, request, timing, or pending state.

The deterministic package is
`config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json`.
O.37.2 remains byte-for-byte historical evidence.
