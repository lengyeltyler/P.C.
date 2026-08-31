# O.37.9 Verifier Binding Resolution

Status: `COMPLETE_FACTORY_OWNED_IMMUTABLE_BINDING`.

O.37.9 resolves the O.37.8 discrepancy in favor of the O.37.6 model: the
version-specific factory is the sole source of the verifier address and
accepted runtime code hash. The account has no independent verifier
authority.

## Exact Binding

The future `philcore-v2-minimal-factory-v2` constructor fixes:

- O.37.7 verifier address;
- O.37.7 verifier runtime code hash;
- EntryPoint;
- deployment chain;
- confirmation target;
- compressed account-version ID;
- unchanged security-model ID;
- exact compiled compressed account creation code.

The factory exposes one account-facing view:

```text
verifierBinding()
  view
  returns (address verifier, bytes32 verifierRuntimeCodeHash)
```

Selector:

```text
0xa7d16353
```

The two return words are exact. The address word must have zero high bits,
the address and hash must be nonzero, and extra, truncated, or malformed
return data fails.

The factory has no verifier setter, registry, owner, administrator,
implementation, proxy, module, fallback selection, or alternate getter.

## Account Validation Sequence

For every `validateUserOp` call, the future account must:

1. require the immutable canonical EntryPoint caller, deployment chain, and
   exact account sender;
2. derive the exact bound `factoryBinding` from its immutable constructor
   state;
3. perform one `STATICCALL` to
   `factoryBinding.verifierBinding()`;
4. require success and exactly 64 canonical return bytes;
5. require nonzero verifier address and runtime code hash;
6. require `EXTCODEHASH(verifier)` to equal the returned hash;
7. derive the complete O.37.7 request from immutable state, current storage,
   typed calldata, and the exact UserOperation;
8. perform one `STATICCALL` to the returned verifier;
9. accept only the exact O.37.7 success magic and exact return shape.

Factory absence, call failure, malformed data, code absence, hash mismatch,
verifier revert, malformed verifier return, or wrong magic fails validation.
There is no retry, alternate verifier, registry lookup, or Runtime Boolean.

The account does not cache the returned pair in mutable storage. It has no
verifier setter and accepts no verifier argument in constructor calldata,
action calldata, authority evidence, or UserOperation fields.

## Constructor And Factory Authority

The account keeps the canonical 20-field initialization tuple. No verifier
address or verifier hash is added.

The constructor requires:

```text
msg.sender == initialization.factoryBinding
```

It makes no external call. The future factory supplies its own address as the
factory binding and is the only contract that can produce an accepted
instance of this account bytecode.

Creation remains nonpayable. The factory accepts no caller-supplied creation
code, verifier, implementation, or deployment target.

## CREATE2 Determinism

The O.35/O.37.6 formulas remain:

```text
initCodeHash = keccak256(
  exactCompressedAccountCreationCode
  || abi.encode(canonical20FieldInitialization)
)

deploymentSalt = keccak256(abi.encode(
  PHILCORE_V2_CREATE2_SALT_V1,
  deploymentChainId,
  compressedAccountVersionId,
  securityModelId,
  ownerCommitment,
  identityBindingCommitment,
  userSalt
))

account = last20(keccak256(
  0xff || factoryAddress || deploymentSalt || initCodeHash
))
```

The verifier binding affects the account identity through the immutable
version-specific factory address. A different verifier address or code hash
requires a different factory deployment and therefore produces a different
account address. The compressed account-version ID and bytecode also produce
a new address.

No helper deployer, proxy, minimal proxy, alternate CREATE2 authority,
caller-supplied init code, or post-deployment initialization is allowed.

## Security Consequences

The factory identifies verifier code; it does not grant user authority.
O.37.7 still requires the calling account to equal `request.account`.
The account still derives all request fields and independently enforces
EntryPoint, nonce, fee, validity, lifecycle, proposal, and execution rules.

The verifier cannot mutate account storage because the call is static and
the verifier contains no state. The factory cannot rotate account authority,
execute actions, recover assets, or change the verifier after deployment.

## Stop Boundary

This document creates no factory or account source, bytecode, deployment
configuration, address, transaction, signature, UserOperation, RPC call, or
public mutation.
