# PhilCore External Audit Scope

Status: prepared for external-audit engagement, not an audit result.

Phase O.7 extends the external-review package with local macOS packaging, bundled proof binaries, native user-presence helper boundary, release profiles, release manifests, SBOM output, package-size audit evidence, and packaged-app verification. The package is reproducible locally but does not approve public deployment, meaningful assets, production use, Developer ID distribution, notarization, or ACP-0002 acceptance.

## Tier 1 - Asset And Authority Critical

In scope:

- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- owner rotation and delayed recovery logic
- recovery-authority rotation logic
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilBaseMirroredFactUnlockProofVerifier.sol`
- nullifier handling and authorization consumption
- `contracts/base/PhilUnlockConsumer.sol`
- `contracts/base/PhilMintPassConsumer.sol`
- Device Vault ECDSA custody runtime boundary
- recovery-authority custody runtime boundary
- desktop platform authentication and macOS Keychain/safeStorage protection boundary
- desktop digest-bound approval and fresh-authentication evidence boundary
- desktop real local authorization workflow, proof invocation, local fixture fact availability, ERC-4337 signing, and local EntryPoint execution boundary
- desktop packaging, release manifest, SBOM, bundled proof binary integrity, and packaged renderer/preload security boundary
- macOS LocalAuthentication helper boundary and fresh-authentication evidence binding
- ERC-4337 UserOperation preparation, signing, submission, and receipt monitoring boundaries

Key questions:

- Can owner or recovery authority bypass ActionGate restrictions?
- Can recovery authority execute ordinary actions or transfer assets?
- Can recovery-authority rotation be abused to entrench a stolen owner or recovery key?
- Can nullifiers be replayed, consumed incorrectly, or consumed without approved execution?
- Can consumers retain unauthorized ETH, execute arbitrary targets, or create unsafe reentrancy behavior?
- Are signing presentations exact and mutation-resistant?

## Tier 2 - Proof And Cross-Domain Critical

In scope:

- ACTION_UNLOCK proof package creation and local verification boundary
- `proofInputHash` and `[fact_high, fact_low]` parity
- Starknet verified-fact publication path and artifact reproducibility
- `contracts/l1/PhilL1ProofInputHashAnchor.sol`
- `contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol`
- `contracts/base/PhilBaseProofInputHashMirror.sol`
- L1 anchor, L1-to-Base relay, Base mirror, and message caller restrictions

Key questions:

- Does the route preserve exact proof/fact/message binding?
- Are messenger sender checks sufficient?
- Is Base execution blocked until fact mirroring is confirmed?
- Are race/freshness limitations represented honestly?

## Tier 3 - Runtime Authorization

In scope:

- Trust Manager authoritative decision boundary
- Security Policy Engine bounded decision boundary
- platform user approval decision boundary
- authoritative scoped capability grant boundary
- authorization decision candidate and ACTION_UNLOCK package draft/finalization
- audit event drafts and audit correlation
- user session lifecycle and partial unlock boundaries

Key questions:

- Is authority confused between trust, policy, user approval, capability grants, authorization packages, and execution?
- Are runtime artifacts presentation-bound and correlation-bound?
- Are secrets excluded from audit, diagnostics, and runtime metadata?

## Out Of Scope

- public desktop authorization execution not implemented
- production passkey desktop authentication not yet implemented
- Developer ID signed/notarized desktop release not completed
- paymaster support
- session keys
- batching
- upgradeability/proxy patterns
- generic wallet execution
- mainnet deployment
- production key custody beyond documented models
- external infrastructure operation not present in the repository

## Assumptions

- `phil_secret -> identityRoot -> ownerCommitment` remains unchanged.
- `ACTION_UNLOCK`, `proofInputHash`, the proof public input tuple, and `[fact_high, fact_low]` remain unchanged.
- ERC-4337 Smart Accounts remain the preferred Ethereum authority model.
- EOAs are compatibility paths only.
- Base is the first authorization-execution environment, with Starknet/L1/Base proof-fact transport as documented in ACP-0001.
- ACP-0002 remains Proposed until explicitly accepted.

## Known Findings And Open Risks

- N.7 remediates `N6-MED-008` by making `PhilMintPassConsumer` zero-value-only.
- Remaining high npm advisory groups are accepted only as development-tooling risk, not production-runtime risk.
- Recovery-authority rotation is locally implemented but unaudited and not Beta-approved.
- O.7 local Alpha package is unsigned unless ad-hoc signing is explicitly run; it is not Developer ID signed or notarized.
- Native macOS user-presence boundary exists, but real manual Touch ID/device-owner evidence remains required before Base Sepolia.
- External audit has not occurred.
- Base Sepolia deployment, bundler, relayer, custody-operation, and submission approvals remain incomplete.

## Reproduction Commands

```bash
npm ci
npm run compile
npm run typecheck
npm run security:setup-slither
npm run security:full
npm run security:audit-package-check
npm run verify:starknet-artifacts
npm run test:proving
```

Focused Hardhat suites are listed in `config/security/philcore-external-audit-manifest.json`.

## Expected Deliverables

- contract security findings with severity and exploitability
- runtime authority-boundary findings
- proof/cross-domain route findings
- dependency and supply-chain review comments
- recommended Beta-blocking fixes
- production-blocking findings
- explicit sign-off limitations
