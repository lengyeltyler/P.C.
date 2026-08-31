# Ethereum Sepolia Read-Only Preflight

Status: `READ_ONLY_RPC_NOT_CONFIGURED`

O.19 accepts only `PHILCORE_SEPOLIA_RPC_URL`. The URL is never written to
evidence; reports retain only a redacted endpoint classification. The client
must verify chain ID `11155111` before any other read and exposes only:

```text
eth_chainId
eth_blockNumber
eth_getCode
eth_getBalance
eth_getTransactionCount
eth_gasPrice
eth_feeHistory
eth_call
eth_estimateGas
```

It does not expose transaction, wallet, signing, or UserOperation submission
methods. There is no Base fallback and no automatically selected provider.

Safe future invocation:

```bash
PHILCORE_SEPOLIA_RPC_URL='<approved read-only Ethereum Sepolia RPC URL>' \
  npm run ethereum-sepolia:prepare-local-proof-evidence
```

The current machine-readable result is
`config/ethereum-sepolia/ETHEREUM_SEPOLIA_READ_ONLY_PREFLIGHT.json`. No live
chain, EntryPoint, balance, fee, gas, or collision claim is currently made.
