# PhilCore ERC-4337 UserOperation Signing Boundary

Architecture status: Current Ethereum/Base compatibility boundary. Public
`ownerCommitment` metadata must not be reused as a universal V1 identity.
Future adapter signing must bind the accepted scoped authorization envelope
after the preceding ACP-0003 gates pass.

Phase: M.10

This document defines the controlled authorization and signing boundary for one exact unsigned M.9 EntryPoint v0.7 `PackedUserOperation` draft. It produces a signed but unsubmitted UserOperation artifact only.

ACP-0002 remains `Proposed`.

## Signature Semantics

`PhilCore4337Account` validates signatures by:

1. receiving the canonical EntryPoint v0.7 `userOpHash`;
2. applying the Ethereum signed-message prefix with `MessageHashUtils.toEthSignedMessageHash(userOpHash)`;
3. recovering the signer with OpenZeppelin `ECDSA.recover(...)`;
4. accepting only the account `owner` address;
5. returning `SIG_VALIDATION_SUCCESS` or `SIG_VALIDATION_FAILED`.

The signing format is therefore EIP-191 personal-sign over the exact EntryPoint `getUserOpHash(PackedUserOperation)` digest. It is not EIP-712.

The signature boundary validates:

- 65-byte ECDSA encoding;
- expected `v` value;
- low-`s` canonicality;
- recovered owner equals the smart-account owner;
- signature covers the exact UserOperation hash.

## Custody Model

Implemented local mode:

- `developer_fixture`

Recommended future production mode:

- `device_vault_beta_ecdsa`

The Beta ECDSA validator key must remain separate from `phil_secret`. It should eventually be generated or imported under Device Vault custody, encrypted locally, bound to PhilCore identity through public account metadata, rotated through an explicit account-authority migration process, and recoverable only through a reviewed recovery boundary.

`ownerCommitment` remains public metadata. It is not the signer, not a private key, and not sufficient to authorize UserOperations.

## Signing Flow

```text
Valid unsigned M.9 UserOperation draft
  -> Runtime authority revalidation
  -> account/EntryPoint/owner binding revalidation
  -> nonce/gas/fee/prefund revalidation
  -> immutable signing presentation
  -> one-time authenticated approval
  -> protected Beta validator signer
  -> canonical EIP-191 signature
  -> signed but unsubmitted UserOperation artifact
  -> audit draft
  -> stop
```

## Revalidation

Before signing, the boundary revalidates:

- active capability status;
- eligible User Session state;
- valid platform user approval;
- valid Base execution approval;
- valid finalized Authorization Package;
- mirrored fact presence;
- nullifier availability;
- account owner and `ownerCommitment`;
- EntryPoint and factory binding;
- exact inner ActionGate call;
- EntryPoint nonce;
- gas and fee summaries;
- prefund status;
- UserOperation hash.

Any mutation requires a new M.9 draft and a new signing presentation.

## Approval

Signing approval is one-time, expiring, and bound to the exact presentation digest. Fixture approval cannot authorize public-network submission. Approval does not grant generic account authority and does not submit the UserOperation.

## Signed Artifact

Every successful artifact states:

- `userOperationSigned: true`
- `userOperationSubmitted: false`
- `bundlerSubmissionPerformed: false`
- `paymasterInvoked: false`
- `smartAccountDeploymentPerformed: false`
- `nullifierConsumed: false`
- `consumerExecuted: false`
- `baseStateMutated: false`
- `applicationCanSubmitDirectly: false`

The artifact contains the signature but no private key, seed phrase, Device Vault material, witness material, or full consumer data.

## Counterfactual Accounts

Counterfactual signing includes the exact factory `initCode` in the UserOperation hash. Signing does not deploy the account. Deployment remains pending until a future EntryPoint/bundler execution boundary.

## Disabled Features

Still disabled:

- bundler submission;
- `eth_sendUserOperation`;
- paymasters and sponsorship;
- session keys;
- batch execution;
- live account deployment;
- live Base mutation.

## Diagnostics

```bash
npm run diagnose:philcore-user-operation-signing
npm run inspect:signed-philcore-user-operation
```

Diagnostics are local/fixture-only by default. They do not call a bundler, submit a UserOperation, invoke a paymaster, deploy a live account, consume a nullifier, execute a consumer, or mutate Base state.

## Next Boundary

M.11 defines controlled ERC-4337 bundler submission and receipt monitoring in [PhilCore ERC-4337 Bundler Submission And Monitoring Boundary](./PHILCORE_ERC4337_BUNDLER_SUBMISSION_AND_MONITORING_BOUNDARY.md).

The signed artifact remains immutable. M.11 may consume it only through explicit submission approval, last-moment revalidation, restricted bundler submission, returned-hash verification, and receipt monitoring.
