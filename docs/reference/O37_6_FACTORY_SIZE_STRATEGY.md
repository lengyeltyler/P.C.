# O.37.6 V2 Factory Size Strategy

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION`.

The selected factory is one non-upgradeable factory for
`philcore-v2-minimal-account-v1`. Its version label is
`philcore-v2-minimal-factory-v1`, with ID:

```text
0x4dfb8d9ebeba6fe8e49286a474a67c1978962b3d28fb367c475bc9506b22cb9b
```

## Size Constraint

The rejected factory runtime was `43013` bytes. Its rejected native-P256
variant consisted of `34933` bytes of embedded account creation code plus a
`5777`-byte factory shell. Factory reduction therefore depends first on
account-kernel reduction.

The new hard budget is:

```text
minimal account creation code <= 18432
minimal factory shell         <=  4096
minimal factory runtime       <= 22528
EIP-170 reserve               >=  2048
```

## CREATE2 Boundary

The factory remains the actual CREATE2 deployer. It does not forward creation
through a helper, external deployer, proxy, or caller-supplied bytecode.

The O.35 formula remains:

```text
initCodeHash = keccak256(
  exactMinimalAccountCreationCode
  || abi.encode(canonical20FieldInitialization)
)

deploymentSalt = keccak256(abi.encode(
  PHILCORE_V2_CREATE2_SALT_V1,
  deploymentChainId,
  minimalAccountVersionId,
  securityModelId,
  ownerCommitment,
  identityBindingCommitment,
  userSalt
))

account = last20(keccak256(
  0xff || factoryAddress || deploymentSalt || initCodeHash
))
```

The minimal account has a new version ID and creation code, so it must derive
a new address. Identity and owner commitments preserve identity continuity;
they do not preserve an account address across versions.

## Factory Immutable Configuration

The future factory constructor fixes:

- canonical EntryPoint;
- deployment chain;
- immutable confirmation target;
- minimal account-version ID;
- unchanged security-model ID;
- static authority-verifier address;
- accepted verifier runtime code hash;
- exact minimal account creation code through the compiled factory artifact.

The verifier address and code hash are public immutable views. The account
uses its existing factory binding to read them with `STATICCALL`. The factory
has no setter, owner, administrator, implementation, verifier registry, or
upgrade path.

Adding the verifier binding changes the new factory constructor, not the
account's frozen 20-field initialization tuple. The factory address changes
and therefore remains bound into CREATE2.

## Minimal External Surface

The factory exposes only:

```text
createAccount(AccountInitializationV1,bytes32 userSalt) returns (address)
getAddress(AccountInitializationV1,bytes32 userSalt) view returns (address)
deploymentSalt(AccountInitializationV1,bytes32 userSalt) pure returns (bytes32)
accountCreationCodeHash(AccountInitializationV1) pure returns (bytes32)
authorityVerifier() view returns (address)
authorityVerifierCodeHash() view returns (bytes32)
```

Creation is nonpayable and permissionless for one exact tuple. Existing code
is returned only after runtime code and every initial security getter match.
Unexpected code or evolved/mismatched state fails.

The factory must not receive funds, execute account actions, verify user
authority, recover an account, rotate a validator, select a different
verifier, or deploy arbitrary creation code.

## Deployment Ordering For A Later Phase

1. reproduce and review the stateless verifier source and bytecode;
2. establish its final address and runtime code hash;
3. compile the factory with those immutable constructor inputs;
4. reproduce factory and minimal-account bytecode and CREATE2 vectors;
5. stop for separate deployment approval.

O.37.6 performs none of these deployments. No address in this architecture
document is deployment authority.
