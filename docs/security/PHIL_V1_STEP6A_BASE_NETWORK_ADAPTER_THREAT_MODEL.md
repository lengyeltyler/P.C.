# Phil V1 Step 6A Base Network Adapter Threat Model

Status: Candidate threat model; independent review required

Date: 2026-08-22

## Protected Objective

Bind a routine, scoped Phil authorization envelope to one exact Base/ERC-4337
action without exposing identity-root or recovery secrets and without granting
runtime, signing, or network authority.

## Trust Boundary

The adapter trusts no caller-supplied digest merely because it is well formed.
It reconstructs the manifest, action, account, nonce, intent, envelope, device
approval, and final binding hashes. It still does not authenticate a device
signature or inspect network state. A later consumer must do both before it can
claim an executable authorization path.

## Threats And Candidate Controls

| Threat | Step 6A control | Residual risk |
| --- | --- | --- |
| Root or cross-scope identity leakage | Receives only scoped envelope fields; source has no root secret, root commitment, vault, data-key, or recovery-handle input | A future caller must preserve the same minimization boundary |
| Cross-network replay | Exact Base chain ID and `eip155:8453` manifest binding | No on-chain nonce has been queried or consumed |
| EntryPoint/version substitution | Exact Base v0.7 EntryPoint address is required | Bytecode and deployment state are not checked locally |
| Account substitution | Manifest, chain, EntryPoint, and account are included in the account binding and intent | The account implementation is not inspected or deployed by Step 6A |
| Target or calldata substitution | Target, value, and target-calldata hash are action-bound; account and EntryPoint targets are forbidden | Raw calldata is not constructed or compared in this sub-gate |
| Nonce collision or replay | ERC-4337 key and sequence are combined and bound with account, EntryPoint, adapter, and network | No durable nonce store or on-chain sequence check exists here |
| Fee or value escalation | Envelope ceilings are compared to exact value and disclosed no-paymaster maximum-fee fields | No gas estimation or execution simulation occurs |
| Paymaster or deployment authority injection | Nonzero `initCode` or paymaster hashes fail closed | A later builder must preserve the ban in raw UserOperation bytes |
| Batch, self-call, or EntryPoint-call privilege expansion | Single target only; account and EntryPoint targets fail closed | Target contracts can themselves be complex and require later policy/simulation review |
| Approval substitution | Device-approval digest is recomputed from the exact envelope digest, device/key IDs, epoch, nonce, and time window | The adapter explicitly does not verify the signature or nonce consumption |
| Exceptional proof bypass | Only routine capability class is admitted; proof fields remain zero | Exceptional/root operations require a separate proven adapter path |
| PQ overclaim | Exact Base profile has PQ capability `none` and no proof suite | Current P-256 device approval and EVM path remain quantum-vulnerable |
| Manifest self-authorization | Authorization requires a separately supplied pinned manifest hash | Step 6A does not yet persist that trust anchor in a protected runtime |
| Compatibility-code relabeling | New versioned source and fixture are isolated; old EVM artifacts remain compatibility-only | Later integration must mechanically prove there is no legacy bypass |
| Hidden operational authority | Output fixes production, network, and signature-verification flags to false; isolation tests ban RPC/signing/submission APIs | TypeScript objects are not a production authorization boundary |

## Security Non-Claims

- No proof backend is selected.
- No device signature is verified.
- No UserOperation or transaction is created.
- No contract enforces the new envelope.
- No Base state or bytecode is inspected.
- No network replay protection is consumed.
- No PQ or hybrid protection exists.
- No production funds, assets, credentials, or secrets are safe to use.

## Required Follow-On Evidence

Before any network-enforced claim, a later exact candidate must bind raw
calldata and packed UserOperation bytes, verify an admitted device signature,
enforce the capability and policy in one inspected account path, prove nonce
consumption and failure precedence, simulate adversarial cases, and receive an
independent contract and integration review. Public-network use still requires
separate explicit authorization.
