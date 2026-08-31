# Device Vault ECDSA Custody Requirements

Status: requirements only. Not implemented in N.2.

## Boundary

`device_vault_beta_ecdsa` is the future custody boundary for the ERC-4337 validator key. It must never derive the ECDSA key directly from `phil_secret`, and it must never expose raw private keys to applications.

## Requirements

| Requirement | Local Alpha UI | Base Sepolia Beta | Production |
| --- | --- | --- | --- |
| Secure random key generation | required before UI | required | required |
| No derivation from `phil_secret` | required | required | required |
| Encrypted Device Vault storage | required before UI | required | required |
| Authenticated unlock before signing | required before UI | required | required |
| No raw private-key export | required | required | required |
| Bounded signing API | required | required | required |
| Owner address derivation from public key | required | required | required |
| Key reference metadata | required | required | required |
| Audit events for key lifecycle | recommended | required | required |
| Backup policy | optional | required decision | required |
| Rotation | optional | required decision | required |
| Deletion | recommended | required | required |
| Recovery | optional | disclosed limitation if absent | required |
| Memory zeroization limitations documented | recommended | required | required |
| Process isolation model | optional | required decision | required |
| macOS Keychain/Secure Enclave feasibility | recommended | required decision | required |

## Draft Boundary Terms

- `DeviceVaultEcdsaValidatorKeyReference`: non-secret key identifier, owner address, custody mode, lifecycle state.
- `DeviceVaultEcdsaKeyGenerationRequest`: request to generate a new validator key inside the Device Vault.
- `DeviceVaultEcdsaSigningSession`: bounded signing session for one exact UserOperation hash or signing presentation digest.
- `DeviceVaultEcdsaCustodyStatus`: unavailable, generated, locked, unlocked_for_bounded_signing, rotated, deleted, recovery_required.
- `DeviceVaultEcdsaRotationRequirement`: future requirement object for replacing the validator key without changing `ownerCommitment`.

These terms are requirements, not implemented Runtime behavior.

## Explicit Non-Claims

N.2 does not implement Device Vault ECDSA custody, production signer isolation, validator rotation, or recovery. Fixture/developer keys remain local-only.
