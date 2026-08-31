# Hash Spec

Status: Current compatibility hashes, implemented Step 2 local-candidate
domains, and accepted later target domains. Step 2 exact source candidate
`fe583b6aef84a8636736b2041db2a56046a5972e` was independently accepted after
two preserved rejection/correction rounds. Its bounded physical-iPhone ceremony
and restricted admission policy passed.

## Domain Labels

Current implemented compatibility domains:

- `PHIL_OWNER_COMMITMENT_V1`
- `PHIL_IDENTITY_ROOT_V1`
- `PHIL_OWNER_COMMITMENT_CANONICAL_V1`
- `PHIL_WORLD_SIGNAL_V1`
- `PHIL_ACTION_UNLOCK_V1`
- `PHIL_POLICY_V1`
- `PHIL_NULLIFIER_V1`
- `PHIL_BASE_AUTHORIZATION_V1`
- `PHIL_UNLOCK_PROOF_INPUTS_V1`
- `PHIL_WORLD_ID_BINDING_V1`

Accepted target domains defined by
[Phil V1 Secure Identity Architecture](../PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md):

- `PHIL_IDENTITY_SCOPE_V1`
- `PHIL_SCOPED_OWNER_COMMITMENT_V1`
- `PHIL_CAPABILITY_GRANT_V1`
- `PHIL_AUTHORIZATION_ENVELOPE_V1`
- `PHIL_DEVICE_APPROVAL_V1`
- `PHIL_DEVICE_ENROLLMENT_RECORD_V1`
- `PHIL_IDENTITY_CONTINUITY_PACKAGE_V1`
- `PHIL_RECOVERY_PACKAGE_AAD_V1`
- `PHIL_RECOVERY_KEY_WRAP_V1`
- `PHIL_RECOVERY_SHARE_V1`
- `PHIL_RECOVERY_REQUEST_V1`
- `PHIL_RECOVERY_COMPLETION_V1`
- `PHIL_DATA_RECORD_AAD_V1`
- `PHIL_DATA_RECORD_V1`
- `PHIL_ROOT_PROOF_NULLIFIER_V1`
- `PHIL_PROOF_DESCRIPTOR_V1`

Every target domain is `keccak256(utf8(exact label))`; fields are encoded in
the exact order and widths stated in the accepted architecture. Existing
domains and bytes must not be reinterpreted under the target meanings.

Named suite identifiers are separately computed as
`keccak256(utf8(exact suite name))`; they are not domain labels. The Step 2
recovery candidate uses
`phil-pairwise-hkdf-sha256-aes256gcm-2of3-v1`.

## Identity

```text
identityRoot =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_IDENTITY_ROOT_V1"),
      phil_secret
    )
  )
```

```text
ownerCommitment =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_OWNER_COMMITMENT_CANONICAL_V1"),
      identityRoot
    )
  )
```

Legacy helper, retained only for tests:

```text
legacyOwnerCommitment =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_OWNER_COMMITMENT_V1"),
      owner,
      salt
    )
  )
```

## Unlock Action

```text
actionHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_ACTION_UNLOCK_V1"),
      chainId,
      consumer,
      account,
      target,
      value,
      keccak256(callData)
    )
  )
```

## Policy

```text
policyHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_POLICY_V1"),
      chainId,
      consumer,
      target,
      expiry,
      keccak256(policyData)
    )
  )
```

## Nullifier

```text
nullifier =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_NULLIFIER_V1"),
      ownerCommitment,
      actionHash,
      policyHash,
      nullifierSeed
    )
  )
```

## Base Authorization

```text
authorizationDigest =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_BASE_AUTHORIZATION_V1"),
      consumer,
      ownerCommitment,
      actionHash,
      policyHash,
      nullifier,
      consumerDataHash,
      expiry
    )
  )
```

## Proof Inputs

```text
proofInputHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_UNLOCK_PROOF_INPUTS_V1"),
      version,
      proofType,
      ownerCommitment,
      actionHash,
      policyHash,
      nullifier,
      consumerDataHash,
      expiry
    )
  )
```

## World ID Binding

Signal:

```text
signal =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_WORLD_SIGNAL_V1"),
      ownerCommitment,
      appId,
      action
    )
  )
```

Binding:

```text
bindingHash =
  keccak256(
    abi.encode(
      DOMAIN("PHIL_WORLD_ID_BINDING_V1"),
      ownerCommitment,
      signal,
      nullifierHash,
      appId,
      action,
      verificationLevel
    )
  )
```

## Honest Status

All hashes above are implemented in the SDK and the active Base contract path where relevant.

The pinned local STWO AIR also constrains the canonical
`phil_secret -> identityRoot -> ownerCommitment` relation and binds it to the
authorization/nullifier public inputs. That is a real computational-integrity
constraint, but the current proof serialization exposes queried secret-bit
trace openings. What is still missing is a reviewed witness-hiding proving
construction that can establish this relation without disclosing the witness.
