# O.26.1 Live Alchemy Bundler Estimation Review

Status: `BUNDLER_ESTIMATION_SUCCEEDED`.

O.26.1 contacted the explicitly configured Alchemy endpoint through a
restricted ERC-4337 read-only client. It authenticated, verified Ethereum
Sepolia and canonical EntryPoint v0.7, accepted PhilCore's deliberately
invalid estimation envelope, and returned gas estimates. No ETH was
transferred and no UserOperation was signed or submitted.

## Shared Endpoint Correction

Alchemy serves ordinary Ethereum JSON-RPC and ERC-4337 Bundler API methods
through the same network endpoint. O.26.1 therefore permits identical
`PHILCORE_SEPOLIA_RPC_URL` and `PHILCORE_SEPOLIA_BUNDLER_URL` values only when
the endpoint is explicitly classified as Alchemy.

The URL remains secret and is represented by a redacted host classification
and SHA-256 binding. This exception does not apply to an unclassified
provider.

URL sharing does not merge capabilities. O.26.1 constructs two independent
wrappers:

| Client | Audit classification | Exposed operations |
| --- | --- | --- |
| chain | `ethereum_sepolia_chain_read_only` | explicit chain ID, code, balance, and transaction-count reads |
| bundler | `alchemy_erc4337_bundler_read_only_estimation` | explicit EntryPoint discovery, estimation, and UserOperation lookup methods |

Neither wrapper exposes generic `request(method, params)`. The O.26.1
bundler wrapper has no `eth_sendUserOperation` method. The chain wrapper has
no bundler, signing, or transaction-submission method.

## Live Infrastructure

At Ethereum Sepolia block `11369620`:

* the confirmation target runtime hash matched;
* the factory runtime hash and immutable EntryPoint, target, and chain
  bindings matched;
* the canonical EntryPoint v0.7 runtime hash matched;
* independent CREATE2 derivation and the live factory getter both returned
  `0xF7212776373B51c1514Dd9C4490048270056C150`;
* the account still had no code, balance, EntryPoint deposit, or nonce;
* Account 1 remained at nonce `3`;
* Account 2 remained at nonce `0`;
* neither wallet signed.

## Provider Compatibility

Alchemy authentication passed. Both the chain client and bundler client
reported chain ID `11155111`.

`eth_supportedEntryPoints` returned:

* EntryPoint v0.9: `0x433709009B8330FDa32311DF1C2AFA402eD8D009`;
* EntryPoint v0.8: `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`;
* canonical EntryPoint v0.7:
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`;
* EntryPoint v0.6: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`.

Required method results:

| Method | Result |
| --- | --- |
| `eth_supportedEntryPoints` | supported |
| `eth_estimateUserOperationGas` | supported |
| `eth_getUserOperationByHash` | supported; nonexistent all-zero hash returned sanitized `-32602 Missing/invalid userOpHash` |
| `eth_getUserOperationReceipt` | supported; nonexistent all-zero hash returned sanitized `-32602 Missing/invalid userOpHash` |

No paymaster was supplied or required. `eth_sendUserOperation` was not
exposed or called.

## Estimation Envelope

The estimate used the existing 288-byte ABI envelope with:

* the correct version, security-model, action, authorization, expiry, and
  validator-key fields;
* deliberately invalid ECDSA values;
* no proof, witness, approval, presence event, or Device Vault signature.

The local fixture decoded the envelope and rejected its cryptographic
authority. Alchemy accepted it for estimation. The evidence stores only its
digest and structural classification.

## Exact Request And Response

The request represented:

```text
counterfactual factory creation
  -> restricted PhilCore account
  -> zero-value confirmation target call
```

It used sender nonce `0`, no paymaster, no batching, no delegatecall, no token
movement, and no recovery call. A canonical request digest and before/after
object digests prove that the client did not alter the request. The request
was sent once with no retry.

Alchemy returned:

| Component | Hex | Decimal |
| --- | ---: | ---: |
| verification gas | `0x16e360` | `1500000` |
| call gas | `0x493e0` | `300000` |
| pre-verification gas | `0x30d40` | `200000` |
| total declared gas |  | `2000000` |

No paymaster gas fields were returned. No AA error occurred.

## Reconciliation

| Component | Local basis | Alchemy | Difference | Difference % | Selected |
| --- | ---: | ---: | ---: | ---: | ---: |
| deployment plus isolated validation | `710620` | `1500000` | `789380` | `111.0832%` | `1500000` |
| isolated call | `50694` | `300000` | `249306` | `491.786%` | `300000` |
| pre-verification | `200000` | `200000` | `0` | `0%` | `200000` |

The local UserOperation used `1034770` gas and the local `handleOps` estimate
was `1059768`. Alchemy's total declared gas is `965230` above local actual
gas, or `93.2796%`.

Alchemy returned the existing reviewed ceilings exactly. This result does not
support tightening them, but it also does not require raising them.

## Fees And Prefund

Block `11369620` supplied:

| Fee | Wei | Gwei |
| --- | ---: | ---: |
| base fee | `994317649` | `0.994317649` |
| gas price | `995817649` | `0.995817649` |
| current max fee | `1990135298` | `1.990135298` |
| current priority fee | `1500000` | `0.0015` |
| recommended max fee | `2487669122` | `2.487669122` |
| recommended priority fee | `1875000` | `0.001875` |

The recommended fee values retain the project's 25% bounded margin and remain
far below the `100 gwei` max-fee and `5 gwei` priority-fee ceilings.

With no paymaster:

```text
requiredPrefund =
  (verificationGasLimit + callGasLimit + preVerificationGas)
  * maxFeePerGas
```

| Result | Wei | ETH |
| --- | ---: | ---: |
| estimated minimum | `3980270596000000` | `0.003980270596` |
| recommended disposable prefund | `4975338244000000` | `0.004975338244` |
| proposed maximum funding approval | `4975338244000000` | `0.004975338244` |
| expected actual cost | `1030442228655730` | `0.00103044222865573` |
| expected residual | `3944896015344270` | `0.00394489601534427` |
| hard-ceiling exposure | `200000000000000000` | `0.2` |

The residual classification remains:

```text
RESIDUAL_FUNDS_NONRECOVERABLE_BY_CURRENT_ACCOUNT
```

Residual ETH can pay later permitted UserOperations but cannot be generally
withdrawn through the current restricted account.

## Funding Readiness

O.26.1 classifies the exact snapshot as:

```text
FUNDING_READY_FOR_SEPARATE_APPROVAL
```

The Account 2 proposal is an unsigned, unbroadcast, short-lived direct
transfer proposal:

* sender: `0xaDef2F2fdA57e92b593943f367D37d8Ce6B2F598`;
* recipient: `0xF7212776373B51c1514Dd9C4490048270056C150`;
* nonce: `0`;
* value: `4975338244000000` wei;
* gas limit: `21000`;
* calldata: empty;
* approved, signed, and broadcast: false.

The proposal expired 15 minutes after its block timestamp. Funding requires a
fresh regeneration plus a separate exact approval. O.26.1 itself does not
authorize funding.

## Evidence And Stop

Evidence:

* `config/ethereum-sepolia/O26_1_LIVE_BUNDLER_COMPATIBILITY_REPORT.json`
* `config/ethereum-sepolia/O26_1_REMOTE_USEROP_GAS_ESTIMATE.json`
* `config/ethereum-sepolia/O26_1_REFRESHED_PREFUND_PROPOSAL.json`

Regenerate the read-only evidence with:

```bash
npm run ethereum-sepolia:refresh-o26-1-live-bundler
```

O.26.1 stops before funding, account deployment, proof generation, Runtime
authorization, approval, fresh presence, Device Vault access, signing,
`eth_sendUserOperation`, and all public mutation.
