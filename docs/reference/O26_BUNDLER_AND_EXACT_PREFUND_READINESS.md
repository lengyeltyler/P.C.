# O.26 Bundler And Exact Prefund Readiness

Status: `BUNDLER_CONFIGURATION_REQUIRED`.

O.26 is read-only, estimation-only, unsigned, unfunded, and unsubmitted. It
revalidates the deployed Sepolia infrastructure, prepares a non-authoritative
ERC-4337 v0.7 estimation object, compares current provider requirements, and
refreshes the fee and prefund model. It does not contact a bundler unless
`PHILCORE_SEPOLIA_BUNDLER_URL` is explicitly configured.

## Current Result

`PHILCORE_SEPOLIA_BUNDLER_URL` is not configured. No provider was selected,
contacted, or automatically substituted. The exact remote
`eth_estimateUserOperationGas` result therefore remains unavailable.

The recommended provider is **Pimlico**, with **Alchemy** as fallback:

| Provider | Sepolia / v0.7 | Test access | Required methods | Paymaster |
| --- | --- | --- | --- | --- |
| Pimlico | documented | public endpoint, 20 requests/minute/IP | standard estimate, send, lookup, receipt, supported EntryPoints | optional |
| Alchemy | documented | account/plan dependent | standard estimate, send, lookup, receipt, supported EntryPoints | optional |
| Candide | documented | public endpoint, IP rate limited | standard estimate, send, lookup, receipt, supported EntryPoints | optional |

This recommendation does not configure or approve a provider. It reflects
Pimlico's documented credential-free test endpoint, explicit standard method
coverage, EntryPoint v0.7 estimation guidance, and sender-balance override
during estimation. Official sources are recorded in
`O26_BUNDLER_COMPATIBILITY_REPORT.json`.

To continue, set `PHILCORE_SEPOLIA_BUNDLER_URL` in the ignored, mode-`0600`
`.env.sepolia.local` file to an explicitly approved Sepolia endpoint. Keep any
credential-bearing URL outside version control. Then run:

```bash
npm run ethereum-sepolia:refresh-o26-readiness
```

The command will use only chain discovery, supported-EntryPoint, estimation,
and lookup methods. The restricted client does not expose
`eth_sendUserOperation`.

## Live Bindings

The O.26 snapshot rechecked:

| Component | Expected binding |
| --- | --- |
| network | Ethereum Sepolia, chain ID `11155111` |
| confirmation target | `0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7` |
| factory | `0x6a9905Bc18620d9689e6a3214C43eC10B99b824e` |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| counterfactual account | `0xF7212776373B51c1514Dd9C4490048270056C150` |

The target, factory, and EntryPoint runtime hashes matched. The factory's
EntryPoint, target, and chain immutables matched. Independent CREATE2
derivation and the live factory getter agreed on the account address.

The account remained undeployed and unfunded:

* code: empty;
* balance: `0`;
* EntryPoint deposit: `0`;
* EntryPoint nonce: `0`;
* latest and pending transaction count: `0`.

Account 1 and Account 2 public key bindings were checked without printing key
material. Neither account signed.

## Estimation Object

The first operation remains:

```text
counterfactual factory deployment
  -> PhilCore restricted account
  -> zero-value confirmation-target call
```

It has no token movement, approval, batching, delegatecall, recovery action,
or paymaster.

The O.26 signature envelope is exactly 288 bytes and matches the account's ABI
decoder:

* signature scheme version `1`;
* `local-proof-gated-v1` model identifier;
* O.26-only action and authorization markers;
* matching expiry and validator-key binding;
* deliberately invalid `r`, `s`, and `v` authority.

It is structurally closer to a real envelope than O.25's 288 zero bytes, but
it is cryptographically invalid and cannot authorize submission. Whether a
specific provider accepts it has not been tested because no endpoint is
configured. A provider requiring a real signature for estimation must be
rejected; O.26 must not create one.

The artifact explicitly says:

* `estimationOnly: true`;
* `submissionReady: false`;
* no real proof, Runtime authorization, approval, presence event, or Device
  Vault signature;
* account unfunded;
* UserOperation unsigned and unsubmitted;
* no public mutation.

## Gas Reconciliation

The current sources are:

| Component | Local fixture | Bundler | Selected |
| --- | ---: | ---: | ---: |
| approximate deployment component | `690770` | unavailable | included within provisional verification ceiling |
| isolated validation | `19880` | unavailable | included within provisional verification ceiling |
| isolated call | `50694` | unavailable | provisional `300000` |
| pre-verification | locally declared `200000` | unavailable | provisional `200000` |
| total actual UserOperation gas | `1034770` | unavailable | evidence only |
| total declared gas | `2000000` | unavailable | provisional `2000000` |

Until a remote estimate is available, O.26 retains the reviewed hard ceilings:

* `verificationGasLimit = 1500000`;
* `callGasLimit = 300000`;
* `preVerificationGas = 200000`;
* paymaster gas limits `0`.

These are provisional bounds, not an exact bundler quote. O.26 will not
silently raise a ceiling. A provider response may advise gas values but cannot
replace sender, nonce, factory, factory data, call data, fees, authorization
markers, expiry, or signature.

## Fee And Prefund

The committed JSON records a fresh block-bound fee snapshot and expires after
15 minutes. The recommendation applies a 25% margin to the RPC fee
observation, while preserving:

| Block `11366502` observation | Wei | Gwei |
| --- | ---: | ---: |
| base fee | `1067626619` | `1.067626619` |
| gas price | `1069126619` | `1.069126619` |
| current max fee | `2136753238` | `2.136753238` |
| current priority fee | `1500000` | `0.0015` |
| recommended max fee | `2670941547` | `2.670941547` |
| recommended priority fee | `1875000` | `0.001875` |

* maximum fee ceiling: `100 gwei`;
* maximum priority fee ceiling: `5 gwei`;
* absolute exposure ceiling: `0.2 ETH`.

For EntryPoint v0.7 without a paymaster:

```text
requiredPrefund =
  (
    verificationGasLimit
    + callGasLimit
    + paymasterVerificationGasLimit
    + paymasterPostOpGasLimit
    + preVerificationGas
  )
  * maxFeePerGas
```

Both paymaster terms are zero. Current exact amounts are generated into
`O26_REFRESHED_PREFUND_PROPOSAL.json`:

| Level | Wei | ETH |
| --- | ---: | ---: |
| current provisional minimum | `4273506476000000` | `0.004273506476` |
| recommended disposable test prefund | `5341883094000000` | `0.005341883094` |
| proposed maximum funding approval | `5341883094000000` | `0.005341883094` |
| absolute rejection-ceiling exposure | `200000000000000000` | `0.2` |
| expected actual cost at observed gas price | `1106300151542630` | `0.00110630015154263` |
| expected residual after success | `4235582942457370` | `0.00423558294245737` |

These figures are block-bound and expire. They remain blocked from funding
until remote estimation and a separate exact funding approval are complete.
The absolute ceiling is never a recommendation.

## Residual-Fund Risk

Classification:

```text
RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT
```

Direct ETH at the deterministic address survives CREATE2 deployment.
`BaseAccount._payPrefund` transfers missing prefund from the account to
EntryPoint during validation.

However:

* before deployment, the address has no private key and funds require exact
  CREATE2 deployment to become usable;
* after deployment, residual account ETH can pay later permitted
  UserOperations but cannot be transferred through a general withdrawal
  method;
* unused EntryPoint deposit is not more recoverable because the account cannot
  invoke EntryPoint `withdrawTo`;
* an off-chain simulation failure consumes no prefund;
* a reverted validation transaction leaves chain state unchanged, while the
  bundler bears its transaction cost;
* an included UserOperation whose execution fails may still consume actual
  gas and may leave account deployment in place;
* a direct transfer made before any UserOperation remains at the deterministic
  address even if a later deployment attempt fails.

Disposable Sepolia ETH can still support a tightly bounded experiment, but
the recommendation must minimize residual value. A reviewed restricted
recovery or withdrawal capability is required before non-disposable use.

## Evidence

Machine-readable evidence:

* `config/ethereum-sepolia/O26_BUNDLER_COMPATIBILITY_REPORT.json`
* `config/ethereum-sepolia/O26_FIRST_USEROP_GAS_ESTIMATE.json`
* `config/ethereum-sepolia/O26_REFRESHED_PREFUND_PROPOSAL.json`

O.26 stops before ETH transfer, EntryPoint deposit, account deployment, proof
generation, Runtime authority, user approval, fresh presence, Device Vault
access, signing, bundler submission, and any public mutation.
