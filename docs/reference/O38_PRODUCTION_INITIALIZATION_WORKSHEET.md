# O.38 Production Initialization Worksheet

O.39 supersession status:
`SCHEMA_COMPLETE_CONSUMER_RECOVERY_V3_ENROLLMENT_REQUIRED`.

This 20-field ABI remains structurally current, but O.39 superseded the
account version and recovery-configuration semantics. O.38 deployment hashes
must not be reused.

The identity record reviewed for this worksheet is
`identity_abab9766da60_24afd015` (`My Phil`). The owner commitment is
`0xabab9766da60e39c0c69fc6ecd7e0f31d116c626c8ea36c6401e331d99f4a9b1`.
The canonical validator is
`0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa`; its public key identifier is
`validator_key_3c5b2ebebc4f3f3b`, and the contract binding used in the tuple
is `0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809`.
No private material is part of this worksheet.

## Exact 20-field tuple

| # | Field / type | Source and expected value or rule | Class | Validation / incorrect-value risk |
| ---: | --- | --- | --- | --- |
| 1 | `entryPoint address` | canonical Sepolia v0.7 EntryPoint | public, infrastructure | exact factory binding; wrong value breaks ERC-4337 authority |
| 2 | `deploymentChainId uint256` | `11155111` | public, infrastructure | must equal live chain; prevents cross-chain initialization |
| 3 | `ownerCommitment bytes32` | canonical value above | public, user-specific | durable identity source; wrong value binds another identity |
| 4 | `identityBindingCommitment bytes32` | `keccak256(typehash,1,owner,scheme)` = `0xdfe42e50f98d9ea25a188a26b1e5ed41acac3c16e4827d835ba1102f0d74b999` | public, derived | exact recomputation; wrong value breaks identity binding |
| 5 | `factoryBinding address` | future verified V2 factory | public, deployment-derived | must equal caller and have code; wrong value prevents or redirects construction |
| 6 | `accountVersionId bytes32` | O.39 V3 `0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f` | public, constant | exact factory check; historical O.38 version is rejected |
| 7 | `securityModelId bytes32` | `keccak256("philcore-v2-typed-intent-local-proof-gated-v1")` = `0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44` | public, constant | exact check; wrong model creates authority ambiguity |
| 8 | `confirmationTarget address` | selected and freshly verified target; currently unset | public, infrastructure | nonzero/exact factory binding; wrong target misroutes confirmation |
| 9 | `initialValidator address` | canonical validator above | public, user-specific | nonzero and commitment-bound; wrong signer controls execution |
| 10 | `validatorVerifierKind uint8` | `1` | public, constant | exact fixed verifier kind |
| 11 | `validatorKeyIdBinding bytes32` | public contract binding above | public, user-specific | nonzero and commitment-bound; wrong value invalidates signatures |
| 12 | `validatorCommitment bytes32` | derived = `0x3206c5e72ac57b685c5fa3d65df94aeb59dfb27b5024d3b05db96c2a52c83b68` | public, derived | exact recomputation; wrong value rejected |
| 13 | `validatorEpoch uint64` | `1` | public, constant | exact initial epoch; wrong value breaks replay boundary |
| 14 | `primaryDeviceRecoveryCommitment bytes32` | real role-0 enrollment; unavailable | public, user/enrollment-derived | nonzero, distinct, fixed descriptor membership |
| 15 | `hardwareSecurityKeyCommitment bytes32` | ABI name retained; semantically the real Role-1 Independent Secondary Authenticator commitment (secondary platform device or hardware key); unavailable | public, user/enrollment-derived | nonzero, distinct, separately attested custody domain |
| 16 | `independentRecoveryFactorCommitment bytes32` | real role-2 enrollment; unavailable | public, user/enrollment-derived | nonzero, distinct, offline/independent domain |
| 17 | `recoveryConfigurationHash bytes32` | derived from V3, threshold 2, and ordered Role 0–2 fields 14–16; unavailable | public, derived | exact recomputation; historical V2 or wrong value rejected |
| 18 | `recoveryEpoch uint64` | `1` | public, constant | exact initial recovery epoch |
| 19 | `recoveryDelaySeconds uint64` | `172800` | public, constant | exact two-day delay; wrong value rejected |
| 20 | `recoveryExpirySeconds uint64` | `604800` | public, constant | exact seven-day expiry; wrong value rejected |

All fields are public once deployed. No raw credential ID, biometric,
private key, recovery private material, or endpoint credential belongs in
the tuple.

The factory address, selected confirmation target, three recovery
commitments, recovery configuration hash, and external CREATE2 user salt are
not yet available. The user salt is outside the 20-field tuple but is also
deployment-binding. O.37.10 synthetic fixture fields are explicitly rejected
as production values.

Result: synthetic Standard and Enhanced tuples are locally dry-run
completable. A production tuple is not deployable until the real primary
recovery credential, independent secondary authenticator, and offline
factor are enrolled and drilled; the user salt is generated; and a renewed
post-O.39 infrastructure/readiness gate succeeds.
