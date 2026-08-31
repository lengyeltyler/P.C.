# Ethereum Sepolia First UserOperation

Status: redacted definition only; no signature or submission.

This document describes the stronger `ethereum-fact-enforced-v1` route through
ActionGate. The separately proposed `local-proof-gated-v1` experiment is
specified in [Local-Proof-Gated First UserOperation](./LOCAL_PROOF_GATED_FIRST_USEROP.md).
Evidence from one model must not be represented as evidence from the other.

## Intended Action

The first action confirms one approved action ID through:

```text
PhilCore4337Account.execute(
  ActionGate,
  0,
  ActionGate.verifyAndConsume(
    authorization,
    proofPackage,
    PhilUnlockConsumer request(
      account,
      PhilCoreAuthorizationConfirmationTarget,
      0,
      abi.encode(actionId)
    )
  )
)
```

The terminal target records the action ID, nullifier, and account and emits
`PhilCoreAuthorizationConfirmed`. It moves no ETH or token.

## Redacted PackedUserOperation

```json
{
  "sender": "<counterfactual or verified PhilCore account>",
  "nonce": "<fresh EntryPoint nonce>",
  "initCode": "<factory plus createAccount calldata, only if undeployed>",
  "callData": "<exact account.execute calldata>",
  "accountGasLimits": "<approved verification/call gas>",
  "preVerificationGas": "<approved estimate>",
  "gasFees": "<approved priority/max fees>",
  "paymasterAndData": "0x",
  "signature": "<created only after exact approval and fresh user presence>"
}
```

Required:

- chain `11155111`;
- canonical EntryPoint v0.7;
- deployment through accepted factory if needed;
- short expiry;
- zero value and no token movement;
- accepted target allowlist;
- exact O.17 authorization envelope;
- local STWO generation and verification;
- fact availability according to the accepted on-chain architecture;
- Device Vault signature;
- restricted approved bundler;
- Activity record and independently reconciled receipt.

## Current Blocker

The current account/gate cannot turn local STWO verification alone into
on-chain execution. A real `stwo-unlock-keccak-v1` call needs verifier evidence
visible to ActionGate. The first UserOperation is therefore not live-ready
until verified-fact transport is accepted and available, or an explicit
architecture change replaces that enforcement path.
