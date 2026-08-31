# Local-Proof-Gated Sepolia Preflight

The preflight is read-only and disabled until an explicit endpoint is approved.

```bash
npm run ethereum-sepolia:local-proof-preflight
```

Without both `PHILCORE_SEPOLIA_READ_ONLY_RPC_URL` and
`PHILCORE_SEPOLIA_READ_ONLY_RPC_APPROVED=1`, it returns:

```text
READ_ONLY_RPC_NOT_CONFIGURED
```

With an approved endpoint it may call only `eth_chainId` and `eth_getCode`.
It verifies Ethereum Sepolia chain ID `11155111`, canonical EntryPoint v0.7
code, and whether explicitly proposed addresses are empty or already contain
code. It exposes no mutation client and never substitutes Base Sepolia.

Deployment and UserOperation commands are dry-run blockers. Deployment requires
the public-network, Ethereum Sepolia, model, and deployment gates. Submission
requires a separate UserOperation gate. O.18 sets none of them.
