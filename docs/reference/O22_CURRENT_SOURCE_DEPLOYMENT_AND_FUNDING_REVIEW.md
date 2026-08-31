# O.22 Current-Source Deployment And Funding Review

Status: `PROPOSED`; unaccepted and non-mutating.

## Starting Point

O.20 recorded deployment evidence at source commit
`13b28149f99c4fae261b96f56fb9ad2790b21e23`. O.21.1 and O.21.2 then added
the real Runtime authorization and Device Vault signed-artifact boundaries.
The Solidity contracts did not change, but the old proposal's source guard
correctly became stale because its guarded Runtime signing files changed.

O.22 rebuilt all Solidity artifacts and generated a new proposal at:

```text
52093e994d6cec438ae32de26971bd7f718221e0
```

The committed proposal also records a SHA-256 tree over every deployment,
authorization, and signing source. Later documentation or evidence commits do
not weaken that binding; any change to a guarded source changes the tree hash
and fails validation.

## Compiler And Artifacts

The forced rebuild compiled 47 Solidity files with:

* Solidity `0.8.24`;
* optimizer enabled;
* 200 optimizer runs;
* `viaIR: true`;
* EVM target `paris`.

| Contract | Creation bytecode hash | Runtime bytecode hash |
| --- | --- | --- |
| `PhilCoreLocalProofConfirmationTargetV1` | `0x2d6acc0d004e51fed77a473beaba524a60a0a617667be36f064fbe3c4aea2127` | `0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad` |
| `PhilCore4337LocalProofAccountFactoryV1` | `0x1bd6d5d0f49474af2dbc2630b25316cf0856c4ea4d1aee869efdce0fcd03e147` | `0x8a62bef9a075d1638a8ebed8030d39928f31adaf86cf11d850a16ed815dba5a0` |
| `PhilCore4337LocalProofAccountV1` | `0xdfe8c94b7fa228961f3048c068a171778672e94650c1404eb8c345c1e5926881` | `0xbec05380e8225faa3f15b4b7894c90bc9e591a555839057ab71ceed5922ab76c` |

These hashes are unchanged from O.20. Source, ABI, bytecode, constructor, and
CREATE2 preimage hashes are recorded in the machine-readable proposal.

## O.21 Change Impact

| Change | Classification | Deployment or address impact |
| --- | --- | --- |
| Runtime unsigned preparation and digest correlation | UserOperation-affecting and authorization-validation-affecting | none |
| Device Vault purpose-bound signing session | signing-boundary-affecting | none |
| signed-artifact creation and validation | signature-validation-affecting | none |
| O.21 documentation and tests | documentation-only or test-only | none |
| O.22 latest/pending nonce evidence | read-only preparation evidence | none |

No constructor, contract ABI, contract bytecode, account initialization rule,
signature envelope accepted by the Solidity account, or CREATE2 input changed.
The off-chain authorization and signing flow did change, so no O.21 proof,
approval, presence evidence, digest, or signature may be reused.

## Read-Only Sepolia Evidence

The repository's restricted client contacted only the configured read-only
Ethereum Sepolia RPC. Its URL is redacted in committed output.

| Observation | Result |
| --- | --- |
| Chain ID | `11155111` |
| EntryPoint | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| EntryPoint code | present |
| EntryPoint code hash | `0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58` |
| EntryPoint nonce call | supported |
| Deployer latest nonce | `37` |
| Deployer pending nonce | `37` |
| Previous nonce | `37` |
| Pending transaction divergence | none |
| Deployer balance | `192724712126032299` wei (`0.192724712126032299` ETH) |
| Validator code | absent |
| Validator balance | `0` |
| Bundler | `BUNDLER_ESTIMATE_NOT_CONFIGURED` |

The observations are snapshots with a 15-minute freshness window. They must be
regenerated immediately before any approval or mutation.

## Proposed Addresses

The live pending nonce remains `37`, so the deterministic addresses did not
change:

| Role | Nonce/model | Proposed address | Code | Balance | Tx count |
| --- | --- | --- | --- | --- | --- |
| Confirmation target | CREATE nonce `37` | `0x7e26405275C84c541e9f9aB68D1C6F7234a16345` | empty | `0` | `0` |
| Account factory | CREATE nonce `38` | `0x7096565D191e664390b7041cCf297F443793e266` | empty | `0` | `0` |
| Smart account | factory CREATE2 | `0x30283Bfd6D65472d9f3b0A173382675b947C69d1` | empty | `0` | `0` |

The account CREATE2 preimage binds the factory, account salt, account creation
bytecode, canonical EntryPoint, validator, owner commitment, immutable target,
validator key ID, and chain ID. There is no standalone implementation
deployment.

No unexpected address collision exists. A future nonzero balance, code, nonce,
or history at any proposed address requires a new review. O.22 never chooses a
replacement salt automatically.

## First Operation

The structural proposal is:

```text
EntryPoint v0.7
  -> factory.createAccount(
       Device Vault validator,
       ownerCommitment,
       validatorKeyId,
       accepted salt
     )
  -> account.executeLocalProofAuthorization(
       fresh actionId,
       fresh Runtime authorization digest,
       fresh expiry
     )
  -> immutable target.confirmPhilCoreAction(
       actionId,
       Runtime authorization digest
     )
```

It is an atomic counterfactual account deployment and one zero-value
confirmation. It cannot transfer tokens or ETH, approve spending, batch,
delegatecall, invoke arbitrary targets, use a paymaster, or perform recovery.
It does not cause Ethereum to verify the local STARK proof.

The proposal is `NOT_SUBMISSION_READY`. Action ID, authorization and proof
digests, nullifier, proof verification, preparation approval, signing approval,
fresh presence, expiry, nonce, gas, fees, UserOperation hash, and Device Vault
signature must all be created fresh after accepted deployments and final
simulation.

## Gas Evidence

Two independent, non-mutating sources were used.

Live Sepolia `eth_estimateGas`:

| Operation | Gas |
| --- | ---: |
| Confirmation-target deployment | `307816` |
| Factory deployment | `1050089` |

Isolated local Hardhat with the actual v0.7 EntryPoint:

| Operation | Gas |
| --- | ---: |
| Target deployment used | `304234` |
| Factory deployment used | `1040699` |
| Direct factory account creation used | `645542` |
| Deployed-account confirmation UserOperation actual gas | `318116` |
| Counterfactual first UserOperation actual gas | `1008886` |
| Counterfactual first `handleOps` transaction estimate | `1034740` |
| Approximate counterfactual deployment component | `690770` |

The local run used the real account, target, factory, EntryPoint v0.7, and exact
288-byte signature envelope. It is not a bundler estimate. Verification, call,
and pre-verification components remain unresolved until an approved bundler
simulates the final signed-shape operation.

No ceiling changed:

* verification gas: `1500000`;
* call gas: `300000`;
* pre-verification gas: `200000`;
* max fee: `100 gwei`;
* max priority fee: `5 gwei`;
* authorization lifetime: `600` seconds.

## Funding Readiness

The final read used gas price `1.007963318 gwei`. The provisional recommended
max fee is twice that observation, `2.015926636 gwei`, within the unchanged
ceilings.

### Disposable Deployer

This category covers only target and factory deployment.

| Level | Wei | ETH |
| --- | ---: | ---: |
| Estimated minimum | `1368718429328790` | `0.00136871842932879` |
| Recommended test amount | `3421795569340316` | `0.003421795569340316` |
| Configured hard-ceiling exposure | `169738100000000000` | `0.1697381` |

### Counterfactual Smart Account

This category covers only first-UserOperation prefund.

| Level | Wei | ETH |
| --- | ---: | ---: |
| Estimated minimum | `1016920080043748` | `0.001016920080043748` |
| Recommended test amount | `4031853272000000` | `0.004031853272` |
| Configured hard-ceiling exposure | `200000000000000000` | `0.2` |

The combined configured worst-case ceiling is `369738100000000000` wei
(`0.3697381` ETH). This is a rejection ceiling, not a funding recommendation.

The actual current contract path supports direct ETH transfer to the
counterfactual address. After CREATE2 deployment, `BaseAccount` pays
`missingAccountFunds` from that balance during EntryPoint validation. An
EntryPoint deposit is not required. The account has no withdrawal or recovery
method, so unused prefund may be stranded. No funding occurred.

All amounts are provisional until an approved bundler returns an exact v0.7
estimate and prefund requirement for the final operation.

## RPC And Bundler Trust

The RPC may lie about chain, code, nonce, balances, fees, estimates, and
receipts. PhilCore must pin chain and EntryPoint, record block references,
recheck code and constructor bindings, compare latest and pending nonce, and
independently verify future receipts and events.

No bundler URL is configured or approved, and no bundler was contacted. A
future bundler may estimate and submit only one exact operation. It cannot
change sender, nonce, initCode, factory data, target, calldata, gas, fees,
paymaster data, signature, Runtime digest, or expiry. Any change requires a new
proof, preparation, approval, presence event, and signature.

## Approval Sequence

Each step is independent:

1. Accept the current source tree, compiler settings, artifacts, constructors,
   identity binding, nonce sequence, addresses, and disposable-only model.
2. Approve one read-only RPC and one ERC-4337 v0.7 bundler.
3. Re-run fresh nonce, address collision, gas, fee, and balance checks.
4. Approve only the exact target deployment. Deploy and verify, then stop.
5. Recalculate the factory CREATE address from the new live nonce.
6. Approve only the exact factory deployment. Deploy and verify, then stop.
7. Verify factory `getAddress(...)` and the full account CREATE2 preimage.
8. Obtain the final bundler simulation and approve exact deployer and account
   funding limits.
9. Approve and perform only the exact disposable funding actions, then stop.
10. Create a fresh O.21.1 proof-backed unsigned operation.
11. Obtain separate signing approval, fresh presence, and an O.21.2 Device
    Vault signature.
12. Revalidate every field and obtain a separate exact submission approval.

O.22 stops before step 1 is accepted and before every mutation.

## Rollback And Stop Conditions

Before mutation, rollback means deleting local proposals and regenerating.
After deployment or funding, Ethereum state cannot be rolled back; mismatched
disposable addresses must be abandoned.

Stop on wrong chain, EntryPoint mismatch, canonical identity mismatch,
compiler or source ambiguity, unverifiable nonce, pending nonce divergence,
address collision, deployment-model ambiguity, unresolved funding mechanism,
missing bundler estimate, stale evidence, or any required public mutation.

## Evidence

* `config/ethereum-sepolia/O22_CURRENT_SOURCE_DEPLOYMENT_PROPOSAL.json`
* `config/ethereum-sepolia/O22_FIRST_SEPOLIA_FUNDING_READINESS.json`

The old O.20 manifest remains historical and proposed. Existing mutation
commands still reject its stale source binding, providing an additional
fail-closed guard.
