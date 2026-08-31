# Local-Proof-Gated Deployment Plan

Status: proposed; no public mutation authorized.

## Actual Contract Model

`PhilCore4337LocalProofAccountFactoryV1` deploys each account directly with
CREATE2. The account is not a proxy implementation, and the factory has no
implementation-address constructor argument. A standalone account
implementation deployment would be redundant and is prohibited by the O.19
scripts.

The implementation-grounded order is:

1. Deploy `PhilCoreLocalProofConfirmationTargetV1`; stop and verify.
2. Deploy `PhilCore4337LocalProofAccountFactoryV1` with the canonical
   EntryPoint, accepted target, and chain ID `11155111`; stop and verify.
3. Fund only the exact proposed counterfactual account if separately approved.
4. Deploy `PhilCore4337LocalProofAccountV1` through the factory as part of an
   independently approved first UserOperation; stop and verify.

## Required Public Inputs

Exact proposed addresses cannot be calculated until the human supplies a
disposable deployer address and nonce, Device Vault validator public address,
owner commitment, validator key ID, and account salt. None is inferred.

For O.20, `.env.sepolia.local` holds the canonical public Device Vault key
reference. The contract's `bytes32 validatorKeyId` is derived from that exact
reference with the domain
`PHILCORE_DEVICE_VAULT_VALIDATOR_KEY_ID_BINDING_V1`. This is a public ABI
binding, not a substitute validator address and not signing material.

Target and factory use ordinary CREATE addresses from consecutive deployer
nonces. The first account uses CREATE2 and binds factory, EntryPoint, validator
address, owner commitment, target, validator key ID, chain ID, account bytecode,
and salt.

All calculated addresses remain `proposed`. Read-only code checks do not make
them deployed, verified, or accepted.

`npm run ethereum-sepolia:prepare-local-proof-evidence` loads only the exact
local environment file, requires mode `0600`, rejects placeholders, secret or
approval fields, and checks its public identity fields against the single
canonical desktop identity index record. File values take precedence for the
eight preparation fields. The RPC endpoint is always redacted in output.

## Roles

- Deployer: disposable Sepolia-only EOA; no account execution authority.
- Funder: disposable Sepolia source, separately approved.
- Validator: Device Vault key, never exposed to deployment tooling.
- Recovery: unsupported by this experimental account.

Validator loss may permanently strand disposable test ETH. No meaningful
assets are permitted.
