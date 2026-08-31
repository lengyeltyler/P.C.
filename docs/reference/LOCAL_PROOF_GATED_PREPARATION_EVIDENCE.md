# Local-Proof-Gated Preparation Evidence

Phase O.20 records the canonical local identity binding and guarded live
read-only Sepolia observations. The deployment manifest remains proposed.

| Evidence | Result |
| --- | --- |
| Architecture | conditionally approved for disposable Sepolia preparation |
| Manifest | proposed, not accepted |
| RPC | exact local file, output redacted |
| EntryPoint live verification | required |
| Proposed addresses | calculated from canonical public inputs |
| Address collision checks | required to be empty |
| Bundler | `BUNDLER_ESTIMATE_NOT_CONFIGURED` |
| Gas and fee estimates | deployment estimates when supported; UserOperation estimates unresolved without a bundler |
| Funding | unresolved |
| First UserOperation | inputs required, unsigned |
| Mutation gates | absent |
| Public mutation | false |

Machine-readable files:

- `config/ethereum-sepolia/ETHEREUM_SEPOLIA_READ_ONLY_PREFLIGHT.json`
- `config/ethereum-sepolia/LOCAL_PROOF_GATED_FIRST_USEROP_FINAL_PROPOSED.json`
- `config/ethereum-sepolia/LOCAL_PROOF_GATED_PREPARATION_EVIDENCE.json`

The exact local environment file is ignored by Git and must have mode `0600`.
It contains public proposal inputs and the RPC selector only; it must contain
no private key, identity secret, passphrase, recovery material, or mutation
approval.

Regenerate with:

```bash
npm run compile
npm run ethereum-sepolia:prepare-local-proof-evidence
```

The generator records the source commit, repository cleanliness, manifest hash,
compiler settings, bytecode hashes, static-analysis result, preflight,
addresses, estimates, funding, first operation, and no-mutation state. Endpoint
credentials and secret values are never included.
