# O.25 Counterfactual Account Prefund And Bundler Readiness

Status: `READ_ONLY_READINESS_REVIEW_COMPLETE_BUNDLER_NOT_CONFIGURED`.

O.25 is a read-only and local-fixture review. It did not transfer ETH, deploy
the account, create an EntryPoint deposit, generate a STARK proof, request a
Device Vault signature, contact a bundler, or submit a UserOperation.

## Live Infrastructure

At Ethereum Sepolia block `11366223`, the existing deployment remained
unchanged:

| Component | Address | Runtime hash | Result |
| --- | --- | --- | --- |
| confirmation target | `0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7` | `0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad` | exact |
| account factory | `0x6a9905Bc18620d9689e6a3214C43eC10B99b824e` | `0x8a356af155426d2de17da0762d29c4c0a7956e3bc4e4b6811d1b819da789722f` | exact |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | `0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58` | exact |

Read-only factory getters returned the canonical EntryPoint, confirmation
target, and chain ID `11155111`. Both configured wallet records matched their
public addresses without emitting key material.

Account 1 remained at nonce `3` with
`270073390298140959` wei. Account 2 remained at nonce `0` with
`92576112524973299` wei. Neither account signed during O.25.

## Counterfactual Account

Independent CREATE2 derivation and the deployed factory's explicit
`getAddress(address,bytes32,bytes32,uint256)` method both returned:

```text
0xF7212776373B51c1514Dd9C4490048270056C150
```

The preserved preimage binds the deployed factory, salt, account creation
bytecode, canonical validator, owner commitment, validator-key identifier,
EntryPoint, confirmation target, and Sepolia chain ID.

The address remained:

* code-free;
* balance `0`;
* EntryPoint deposit `0`;
* EntryPoint nonce `0`;
* latest and pending transaction count `0`.

## First Operation

EntryPoint v0.7 receives an operation whose counterfactual fields represent:

```text
factory:
  0x6a9905Bc18620d9689e6a3214C43eC10B99b824e

factoryData:
  createAccount(
    canonical validator,
    canonical owner commitment,
    bound validator key ID,
    preserved salt
  )

callData:
  executeLocalProofAuthorization(
    fresh action ID,
    fresh Runtime authorization digest,
    expiry
  )
```

The packed-contract form remains `initCode = factory || factoryData`. The v0.7
bundler RPC form uses separate `factory` and `factoryData` fields.

The factory deploys `PhilCore4337LocalProofAccountV1` directly with CREATE2.
There is no standalone implementation and no initializer. Constructor inputs
fix the EntryPoint, validator owner, owner commitment, confirmation target,
validator-key binding, and chain. No recovery authority exists in this account
version.

Deployment and the confirmation call are atomic inside the first
`handleOps(...)`. Validation or execution failure reverts account creation.

## Estimation-Only Template

`config/ethereum-sepolia/O25_ESTIMATION_ONLY_USER_OPERATION.json` contains a
non-authoritative v0.7 template. It uses fixed O.25-only marker values and a
288-byte all-zero placeholder signature. It explicitly records:

* `estimationOnly: true`;
* `submissionReady: false`;
* no proof, authorization, approval, presence event, or Device Vault signature;
* no paymaster, token movement, batch, delegatecall, or public mutation.

The template cannot be promoted to authority. Every actual field must be
rebuilt after a fresh proof, Runtime authorization, user approval, presence
event, and Device Vault signing cycle.

## Local EntryPoint Simulation

The isolated Hardhat fixture used the actual account, factory, target, and
EntryPoint v0.7 source. It created an ephemeral fixture signature only; it did
not use PhilCore identity material.

| Measurement | Gas |
| --- | ---: |
| direct factory account creation | `645542` |
| approximate counterfactual creation component | `690770` |
| isolated account validation estimate | `19880` |
| isolated account execution estimate | `50694` |
| declared pre-verification gas | `200000` |
| first counterfactual UserOperation actual gas | `1034770` |
| `handleOps` transaction estimate | `1059768` |
| `handleOps` transaction gas used | `869553` |

The isolated validation and execution estimates remove the `21000` transaction
intrinsic gas but do not apportion EntryPoint orchestration overhead. The
UserOperation event exposes aggregate actual gas, so the decomposition is
evidence for sizing rather than a bundler quote.

The fixture moved the account nonce from `0` to `1`, confirmed the target, and
validated rollback or rejection for insufficient prefund, altered factory
data, salt or sender mismatch, wrong validator/signature, wrong call, stale
expiry, paymaster introduction, and gas-ceiling violation.

## Bundler Boundary

`PHILCORE_SEPOLIA_BUNDLER_URL` was empty. No provider was selected or
contacted. Status is `BUNDLER_NOT_CONFIGURED`.

A future approved provider must support:

* Ethereum Sepolia and chain ID `11155111`;
* canonical EntryPoint v0.7;
* counterfactual deployment;
* `eth_estimateUserOperationGas`;
* `eth_sendUserOperation` only after separate future approval;
* UserOperation and receipt lookup;
* operation without a paymaster;
* the PhilCore signature-envelope size;
* transparent fees and rate limits.

The bundler may relay an exact signed operation but may not alter any covered
field. A requested change requires a new proof, authorization, approval,
presence event, and Device Vault signature.

## Fee And Prefund Evidence

The observation at block `11366223` recorded:

| Value | Wei | Gwei |
| --- | ---: | ---: |
| base fee | `1099327403` | `1.099327403` |
| gas price | `1100827403` | `1.100827403` |
| RPC max fee | `2200154806` | `2.200154806` |
| RPC priority fee | `1500000` | `0.0015` |
| recommended max fee, with 25% margin | `2750193507` | `2.750193507` |
| recommended priority fee, with 25% margin | `1875000` | `0.001875` |

No ceiling changed:

* verification gas: `1500000`;
* call gas: `300000`;
* pre-verification gas: `200000`;
* max fee: `100 gwei`;
* max priority fee: `5 gwei`;
* authorization lifetime: `600` seconds.

For EntryPoint v0.7 without a paymaster:

```text
requiredGas =
  verificationGasLimit
  + callGasLimit
  + paymasterVerificationGasLimit
  + paymasterPostOpGasLimit
  + preVerificationGas

requiredPrefund = requiredGas * maxFeePerGas
```

Both paymaster gas terms are zero. The selected bounded operation declares
`2000000` total gas units.

| Level | Wei | ETH |
| --- | ---: | ---: |
| empirical actual-cost estimate at observed gas price | `1139103171802310` | `0.00113910317180231` |
| exact required prefund at current RPC max fee | `4400309612000000` | `0.004400309612` |
| recommended disposable prefund | `5500387014000000` | `0.005500387014` |
| proposed maximum funding approval | `5500387014000000` | `0.005500387014` |
| absolute rejection-ceiling exposure | `200000000000000000` | `0.2` |

The `0.2 ETH` figure is a rejection ceiling, not a recommendation.

## Funding Mechanism

The current account supports direct ETH prefunding of the deterministic
address. Its balance survives CREATE2 deployment. During validation,
`BaseAccount._payPrefund` sends `missingAccountFunds` to EntryPoint, so a
pre-created EntryPoint deposit is not required.

Direct transfer does not alter the CREATE2 address. It does create transaction
history and value at an undeployed address.

Residual-fund limitations are important:

* if the account is never deployed, the address has no private key and the ETH
  is practically inaccessible until exact CREATE2 deployment;
* after deployment, residual ETH can fund later permitted UserOperations;
* the account has no generic transfer or withdrawal path, so unused ETH may be
  stranded;
* an EntryPoint deposit is not better for recovery because `withdrawTo`
  requires the account as caller and this account exposes no withdrawal call.

The proposed Account 2 transfer is in
`config/ethereum-sepolia/O25_ACCOUNT_PREFUND_PROPOSAL.json`. It is an unsigned,
unapproved, unbroadcast EIP-1559 transfer proposal:

* recipient: the exact counterfactual account;
* nonce: `0`, from the recorded snapshot;
* value: `5500387014000000` wei;
* gas limit: `21000`;
* calldata: empty;
* maximum total debit: `5558141077647000` wei.

The proposal expired fifteen minutes after its observation. It must be
regenerated and re-approved from fresh state before any future funding.

## Evidence And Stop

Machine-readable evidence:

* `config/ethereum-sepolia/O25_COUNTERFACTUAL_ACCOUNT_READINESS.json`
* `config/ethereum-sepolia/O25_ACCOUNT_PREFUND_PROPOSAL.json`
* `config/ethereum-sepolia/O25_ESTIMATION_ONLY_USER_OPERATION.json`

Regeneration command:

```bash
npm run ethereum-sepolia:refresh-o25-readiness
```

This command remains read-only on Sepolia and mutation-capable RPC methods are
absent. If a separately approved bundler URL is configured in the ignored
mode-`0600` environment, the command may use only capability, estimation, and
lookup methods.

O.25 stops before funding. It also stops before proof generation, Runtime
authorization, Device Vault access, signing, or UserOperation submission.
