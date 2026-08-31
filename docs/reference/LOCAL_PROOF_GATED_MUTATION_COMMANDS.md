# Local-Proof-Gated Mutation Commands

Status: documented and blocked. No transport is implemented in O.19.

All mutation stages require the three common gates:

```text
PHILCORE_PUBLIC_NETWORK_APPROVED=1
PHILCORE_ETHEREUM_SEPOLIA_APPROVED=1
PHILCORE_LOCAL_PROOF_ACCOUNT_MODEL_APPROVED=1
```

They also require an accepted manifest, a clean source-bound repository, exact
bytecode, and one stage-specific gate.

| Classification | Command | Additional gate | Future effect |
| --- | --- | --- | --- |
| local-only | `npm run ethereum-sepolia:inspect-local-proof-account` | none | inspect proposal |
| read-only public | `npm run ethereum-sepolia:local-proof-preflight` | explicit RPC selector | reads Sepolia only |
| public deployment mutation | `npm run ethereum-sepolia:deploy-local-proof-target` | `PHILCORE_SEPOLIA_TARGET_DEPLOYMENT_APPROVED=1` | deploy target |
| public deployment mutation | `npm run ethereum-sepolia:deploy-local-proof-factory` | `PHILCORE_SEPOLIA_ACCOUNT_DEPLOYMENT_APPROVED=1` | deploy factory |
| public funding mutation | `npm run ethereum-sepolia:fund-local-proof-account` | `PHILCORE_SEPOLIA_FUNDING_APPROVED=1` | send disposable Sepolia ETH |
| public UserOperation mutation | `npm run ethereum-sepolia:submit-first-local-proof-userop` | `PHILCORE_SEPOLIA_USEROP_SUBMISSION_APPROVED=1` | submit one exact UserOperation |

The historical `deploy-local-proof-implementation` command is explicitly
blocked because this factory directly deploys accounts and has no standalone
implementation dependency.

O.19 provides no signing key, transaction transport, funding transport, or
bundler submission method. The maximum exposure remains unresolved until live
read-only estimates and a hard cap are approved. Confirmed public mutations
cannot be rolled back by PhilCore.
