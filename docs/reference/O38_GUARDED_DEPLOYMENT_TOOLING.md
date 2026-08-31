# O.38 Guarded Deployment Tooling

Status: `DETERMINISTIC_PREPARATION_ONLY`.

`scripts/ethereum-sepolia/prepare-o38-v2-deployment.cjs` is deliberately not
a deployment runner. It creates no provider or wallet, reads no endpoint,
signs nothing, and has no transaction or UserOperation send method.

Default invocation:

```sh
npm run ethereum-sepolia:prepare-o38-v2-deployment
```

The default mode is `DRY_RUN`. It checks:

1. phase and local-only classification;
2. exact chain ID `11155111`;
3. exact EntryPoint 0.7 address;
4. compiled verifier, account, and factory runtime/creation artifact hashes;
5. exact verifier runtime hash proposed for factory binding;
6. all 20 initialization fields and canonical identity derivations;
7. distinct nonzero recovery commitments and exact configuration hash;
8. future factory/target binding;
9. nonzero domain-bound user salt;
10. positive deployment gas ceiling;
11. account init-code hash, deployment salt, and predicted CREATE2 address
    when all inputs exist.

The canonical template intentionally reports `INITIALIZATION_BLOCKED`. It
does not contain fake production recovery commitments, a future verifier or
factory address, a selected target, a user salt, or a deployment gas
ceiling.

`--require-ready` turns any missing field into a failure. Wrong chain,
EntryPoint, artifact, verifier hash, canonical identity field, factory
binding, target, epoch, delay, expiry, recovery configuration, salt, or cost
ceiling fails closed.

`--broadcast` first requires the exact environment value
`PHILCORE_O38_PUBLIC_MUTATION_APPROVED=O38_EXACT_PUBLIC_MUTATION_APPROVED`.
Even with that value, it fails with `O38_BROADCAST_PATH_NOT_IMPLEMENTED`.
This preserves the approval-guard design without creating dormant broadcast
authority during O.38. A later phase must implement, review, test, and bind a
transaction-specific approval to any signer or send path.

The O.38 Hardhat configuration disables environment networks and does not
load dotenv. Tests prove the script contains no RPC provider, wallet,
signing, raw transaction, UserOperation submission, or `.env.sepolia.local`
access.

## Explorer input preparation

All sources use Solidity `0.8.27+commit.40a35a09`, Cancun, optimizer enabled
with 200 runs, `viaIR: true`, literal source content, IPFS bytecode metadata,
and appended CBOR. There are no linked libraries.

- verifier: source
  `contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol`;
  constructor arguments: none;
- factory: source
  `contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol`;
  constructor types:
  `(address,uint256,address,address,bytes32)` for exact EntryPoint, chain ID,
  confirmation target, verifier, and verifier runtime hash;
- account: source
  `contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol`; created by the
  factory with one ABI tuple containing the worksheet's 20 fields.

Factory and account deployed runtime hashes contain immutable values. A later
verification package must compare constructor-patched runtime bytecode or
normalize only the compiler-reported immutable references; it must not
compare their generic unpatched artifact runtime hashes directly. No explorer
request was submitted.
