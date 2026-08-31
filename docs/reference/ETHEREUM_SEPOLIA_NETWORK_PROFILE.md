# Ethereum Sepolia Network Profile

Status: proposed for Phase O.17; public mutation disabled.

## Locked Profile

| Field | Value |
| --- | --- |
| Profile | `ethereum_sepolia` |
| Network | Ethereum Sepolia |
| Chain ID | `11155111` |
| ERC-4337 version | `0.7` |
| EntryPoint | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` |
| EntryPoint dependency | `@account-abstraction/contracts@0.7.0` |
| UserOperation | `PackedUserOperation` |
| Paymaster | disabled |
| First action value | `0` wei |
| Mainnet claim | none |
| Public mutation | disabled |

The dependency, local EntryPoint artifact, `BaseAccount`, `IEntryPoint`,
`PackedUserOperation`, account tests, and hash-parity tests are the repository
source of truth for v0.7 semantics. The public EntryPoint address remains a
proposed external deployment reference until a later guarded read-only
preflight verifies its code on chain.

## Environment References

These names hold endpoints or accepted public addresses. They must not contain
private keys:

- `PHILCORE_SEPOLIA_RPC_URL`
- `PHILCORE_SEPOLIA_BUNDLER_URL`
- `PHILCORE_SEPOLIA_EXPECTED_CHAIN_ID`
- `PHILCORE_SEPOLIA_ENTRYPOINT`
- `PHILCORE_SEPOLIA_FACTORY`
- `PHILCORE_SEPOLIA_ACCOUNT_IMPLEMENTATION`
- `PHILCORE_SEPOLIA_TEST_TARGET`

Mutation additionally requires independent external approvals:

- `PHILCORE_PUBLIC_NETWORK_APPROVED=1`
- `PHILCORE_ETHEREUM_SEPOLIA_APPROVED=1`
- `PHILCORE_ETHEREUM_SEPOLIA_DEPLOYMENT_APPROVED=1` for deployment
- `PHILCORE_USEROP_SUBMISSION_APPROVED=1` for UserOperation submission

No approval is enabled in O.17.

## Base Assumption Audit

| Component | Classification | O.17 disposition |
| --- | --- | --- |
| ERC-4337 v0.7 account/factory/hash logic | chain-independent | reused |
| Device Vault ECDSA validator and signing | chain-independent | reused with exact chain binding |
| ActionGate, nullifier, UnlockConsumer | chain-independent despite `Base` name | reusable on Ethereum after accepted verifier selection |
| `PhilL1FactUnlockProofVerifier` | Ethereum Sepolia compatible | current-compatible fact verifier |
| L1 Starknet message anchor | Ethereum Sepolia compatible in principle | requires accepted deployment/configuration |
| Base mirror and L1-to-Base relay | Base-specific and not needed on Ethereum Sepolia | excluded |
| `BaseAuthorizationExecutionTransactionDraft` naming | Base-specific but structurally reusable | adapter/naming debt; no silent semantic translation |
| `baseExecutionDraft`/`baseStateMutated` fields | Base-specific but reusable local evidence | preserved for compatibility; Sepolia envelope is explicit |
| Bundler profile union | incomplete | `ethereum_sepolia` added |
| Bundler limitation text | Base-specific and requiring replacement | Ethereum-specific limitation added |
| `hardhat.shared.cjs` `BASE_RPC_URL` | Base-specific | not used by O.17; future guarded Sepolia client is separate |
| `scripts/base` deployment/submission scripts | mixed historical/Base-specific | not reused as Sepolia mutation scripts |
| Base explorer, mirror receipt, relay parsing | Base-specific | excluded |
| Desktop Base Beta labels/gates | Base-specific historical policy | not relabeled as Ethereum readiness |
| Historical v0.6 scripts | obsolete | archive/reference only |

## RPC Classification

Read-only:

- chain, code, balance, nonce, fee, call, estimate, bundler capability, and
  receipt lookup methods.

Public mutation:

- `eth_sendRawTransaction`
- `eth_sendUserOperation`

The O.17 scripts contain no RPC transport and perform neither class of public
call. Later mutation must fail closed on chain, EntryPoint, manifest,
allowlist, zero value, paymaster, fee, expiry, repository, and approval checks.

## Current Readiness

The profile is structurally ready for local preparation and review. It is not
accepted deployment evidence and does not prove that the EntryPoint, bundler,
factory, account, gate, verifier, consumer, or target exists on Sepolia.

