# Ethereum Sepolia Account Model

Status: proposed; ACP-0002 remains `Proposed`.

The bounded composed-mint candidate is specified separately in
[Phil Sepolia Mint Composed Demo V1](./PHIL_SEPOLIA_MINT_COMPOSED_DEMO_V1.md).
It uses a narrower immutable demo account, does not replace this recovery-capable
account model, and is not a Beta or production architecture decision.

## Selected Model

- one PhilCore identity;
- one Ethereum Sepolia `PhilCore4337Account`;
- deterministic factory deployment;
- ERC-4337 v0.7 `PackedUserOperation`;
- Device Vault controlled secp256k1 execution owner;
- separate recovery authority;
- no seed phrase presented as the PhilCore identity;
- immutable EntryPoint, ActionGate, owner commitment, and recovery timing;
- zero-value first action;
- paymaster disabled;
- disposable Sepolia ETH only.

The account is a non-upgradeable constructor deployment, not a proxy. The
factory embeds the account creation code and constructor bindings in CREATE2
address derivation.

## Counterfactual Address

`PhilCore4337AccountFactory.getAddress(owner, ownerCommitment, salt)` computes:

```text
CREATE2(
  factory,
  salt,
  keccak256(account creation code || constructor bindings)
)
```

Constructor bindings include EntryPoint, execution owner, owner commitment,
approved ActionGate, recovery authority, recovery delay, and recovery expiry.
Changing any binding changes the account address.

The salt must be domain separated and contain no `phil_secret`. Phil artwork
and display name do not participate. The counterfactual address is public
metadata and may correlate operations for that account; it must not reveal the
identity root secret.

The first v0.7 operation may include factory address plus `createAccount(...)`
calldata in `initCode`. EntryPoint can create the account and execute its first
call atomically. Duplicate factory calls return the existing account. A failed
UserOperation leaves no successful execution claim; funding and nonce state
must be reconciled independently.

## Execution Restrictions

Normal execution:

```text
EntryPoint
  -> PhilCore4337Account.execute(...)
  -> immutable approved ActionGate
  -> verifyAndConsume(...)
  -> approved authorization consumer
  -> terminal target
```

The account rejects:

- direct owner calls to `execute`;
- a caller other than its immutable EntryPoint;
- any target other than its immutable ActionGate;
- any selector other than `verifyAndConsume(...)`;
- normal execution while recovery has frozen the account.

The EntryPoint nonce prevents replay of the same UserOperation. The UserOp hash
binds EntryPoint, chain, sender, nonce, factory data, call data, gas, fees,
paymaster data, and signature. ActionGate consumes the public nullifier exactly
once and reverts it atomically if the downstream consumer fails.

## Validator and Recovery

The execution validator is conventional ECDSA for local Alpha and the proposed
disposable Sepolia experiment. Its private key remains encrypted in Device
Vault and is not derived from `phil_secret`, `identityRoot`, or
`ownerCommitment`.

Recovery uses a distinct authority and delayed workflow. Recovery can freeze
the account and rotate the execution owner; it cannot execute ordinary
ActionGate actions. This is not production approval.

## Concrete Blocker

The preferred O.17 narrative says local STWO verification should gate one
exact Device Vault signature without requiring an on-chain fact. That is a
valid architecture option, but it is not what the current contracts enforce.

For `stwo-unlock-keccak-v1`, `PhilBaseActionGate` invokes its configured
verifier. On Ethereum Sepolia, the current compatible verifier is
`PhilL1FactUnlockProofVerifier`, which requires an anchored proof-input-hash
fact. The account cannot call the harmless target directly.

Therefore the current account/factory can deploy against the canonical v0.7
EntryPoint, but the first real protected action requires either:

1. accepted Ethereum-visible fact transport and the current ActionGate path; or
2. an explicitly approved account/gate/validator architecture change that
   makes a Runtime/Device-Vault authorization attestation enforceable on chain.

O.17 implements neither choice and fails closed.

## Future Desktop Integration

The accepted visual shell should add only honest public-account states:

- Not set up
- Ready to deploy
- Deployment pending
- Test account active
- Action pending
- Action confirmed
- Action failed

Setup, review, and submit controls remain disabled in O.17. Technical mode may
show chain, EntryPoint, factory, account, nonce, bundler, operation/transaction
hashes, receipt state, and STWO authorization reference. It must never display
a fake "Connected" state or expose low-level RPC, proof, signing, or arbitrary
call builders.
