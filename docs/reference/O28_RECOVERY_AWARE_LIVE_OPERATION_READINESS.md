# O.28 Recovery-Aware Live-Operation Readiness

Status: `PREFUNDED_ADDRESS_INCOMPATIBLE_WITH_RECOVERY`.

O.28 is read-only and local-only. It establishes the canonical test-fund
release policy, inspects every native-value path in the exact V1 account
deployed by the live factory, simulates the funded lifecycle locally through
EntryPoint v0.7, and determines whether unused ETH can be securely released.

O.28 performs no public mutation and does not deploy the funded account.

## Decision

The current funded V1 address does not have a release route.

`PhilCore4337LocalProofAccountV1` can receive ETH and can pay missing prefund to
EntryPoint during validation. Its only validated execution selector is
`executeLocalProofAuthorization(bytes32,bytes32,uint64)`. That function is
EntryPoint-only and calls the immutable confirmation target with zero value.

The account has no:

* generic authenticated execution;
* native withdrawal or sweep;
* EntryPoint-deposit withdrawal;
* token transfer;
* upgrade, delegatecall, administrator, or self-destruct route.

Account 1, Account 2, the canonical validator EOA, and arbitrary callers cannot
directly withdraw. The validator can authorize only the fixed zero-value
confirmation call because account validation rejects every other selector.

## Local Lifecycle

The isolated Hardhat simulation uses the actual account, factory, target, and
EntryPoint v0.7 source with fixture-only keys.

It:

1. prefunds the counterfactual address with `5124486704000000` wei;
2. atomically deploys the account and executes the confirmation target;
3. observes the remaining native balance and EntryPoint deposit;
4. attempts an exact sweep to an explicit residual recipient;
5. proves the sweep is unavailable and leaves the residual unchanged.

The fixture confirmation used `608115332692340` wei of gas cost and left:

* account native balance: `124486704000000` wei;
* EntryPoint deposit: `4391884667307660` wei;
* total residual: `4516371371307660` wei.

The exact sweep, wrong-recipient, wrong-amount, modified-calldata, wrong-signer,
wrong-validator, wrong-chain, wrong-account, stale-nonce, replay, old-authority,
direct-call, Account 1, and Account 2 attempts all failed.

Gas consumption is not fund recovery. Deploying V1 can consume some funded ETH
for legitimate operations, but it cannot release the remainder to an approved
recipient.

## CREATE2 And Live-Factory Consequence

The live factory embeds
`type(PhilCore4337LocalProofAccountV1).creationCode`. It exposes no choice of
implementation and is not upgradeable.

Adding a secure release function changes account creation code and therefore
the CREATE2 init-code hash. The counterfactual address changes even if every
constructor argument and salt remains the same. The live factory also cannot
deploy the modified code, so recovery requires:

1. a reviewed recovery-capable account version;
2. a new factory deployment;
3. a new counterfactual address;
4. a changed infrastructure binding;
5. local and fork lifecycle validation before funding;
6. new exact deployment and funding approvals.

ETH already held by
`0xF7212776373B51c1514Dd9C4490048270056C150` does not move to the new address.

## Funds At Risk

The current live balance is `5124486704000000` wei (`0.005124486704 ETH`).
The full amount can remain stranded.

Deploying the original V1 is required even to spend some of the balance on
authorized operation gas, but deployment does not create a recovery path.
Creating an EntryPoint deposit also does not help because V1 cannot call
`withdrawTo`.

## Corrective Options

1. Leave the V1 address undeployed and accept the full balance as stranded.
2. Deploy V1 and run the intended confirmation only after a new phase and
   approval, accepting that the remaining native balance/deposit still cannot
   be recovered. This does not satisfy the recovery objective.
3. Design and review a recovery-capable V2 plus new factory for future tests.
   This is the recommended future-development route, but it cannot recover the
   current V1 prefund.

O.28 stops for a user decision before selecting or implementing V2.

O.29 subsequently selected a local-only V2 architecture direction. It leaves
V1 and the O.27 prefund untouched, requires a new versioned account/factory,
and does not make the current V1 balance recoverable.

## Evidence And Stop

Machine-readable evidence:

* `config/ethereum-sepolia/O28_RECOVERY_AWARE_READINESS.json`

Commands:

```bash
npm run ethereum-sepolia:simulate-o28-recovery-readiness
npm run ethereum-sepolia:generate-o28-recovery-readiness
```

No smart-account deployment, factory call, proof, Runtime authorization,
user-presence event, Device Vault signature, UserOperation submission,
EntryPoint deposit, paymaster action, token or native-value movement, Account 1
transaction, Account 2 transaction, or other public mutation occurred.
