# PhilCore Solidity Static Analysis N.6

> Historical N.6 evidence. Its dependency counts and dispositions describe
> that phase, not the current lockfile. See
> [Dependency Advisory Status](./DEPENDENCY_ADVISORY_STATUS.md).

Status: internal static-analysis evidence, not a formal external audit.

Phase N.6 establishes a reproducible local Slither environment and records triage for PhilCore Solidity contracts. It does not approve Base Sepolia Beta, production use, public deployments, paymasters, generic wallet execution, or meaningful assets.

## Tooling

Selected model: repository-local Python virtual environment.

Commands:

```bash
npm run security:setup-slither
npm run security:slither
npm run security:philcore-contract-invariants
npm run security:npm-audit
```

Pinned references:

- Slither: `0.10.4`
- Toolchain config: `config/security/slither-toolchain.json`
- Python dependency lock: `config/security/slither-requirements-lock.txt`
- Slither config: `slither.config.json`

The local macOS Python reports a LibreSSL-backed `ssl` module, which causes an `urllib3` warning during Slither startup. The warning did not block analysis.

## Scope

Primary production-relevant contracts:

- `contracts/base/erc4337/PhilCore4337Account.sol`
- `contracts/base/erc4337/PhilCore4337AccountFactory.sol`
- `contracts/base/PhilBaseActionGate.sol`
- `contracts/base/PhilBaseMirroredFactUnlockProofVerifier.sol`
- `contracts/base/PhilBaseProofInputHashMirror.sol`
- `contracts/base/PhilUnlockConsumer.sol`
- `contracts/l1/PhilL1ProofInputHashAnchor.sol`
- `contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol`

Mocks were included in the Slither run so fixture-only findings are visible, but they are not deployment candidates.

## Slither Result

Machine-readable report:

- `config/security/philcore-solidity-static-analysis.json`
- raw Slither output: `config/security/philcore-slither-results.raw.json`

Summary:

| Impact | Count |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 6 |
| Low | 26 |
| Informational | 8 |

No critical or high Solidity findings were detected.

One production-relevant medium finding remains open:

| Finding | Status | Beta Impact |
| --- | --- | --- |
| `N6-SLITHER-004` / `N6-MED-008`: `PhilMintPassConsumer` can lock forwarded ETH | open | not blocking current Base Sepolia account-gate scope if this consumer is not deployed or value-bearing |

N.7 update: `PhilMintPassConsumer` is now explicitly zero-value-only. It rejects nonzero `msg.value` before mint state changes. If Slither continues to report the payable-interface `locked-ether` heuristic, the N.7 triage classifies it as remediated/accepted zero-value-only rather than open. Any future value-bearing mint path requires Architecture Change Control and a reviewed forwarding/refund model.

Other findings were triaged as local mocks, intended time boundaries, intended bounded external calls, informational detector limitations, or items deferred to external audit without high/critical impact.

## Custom Invariant Checks

Command:

```bash
npm run security:philcore-contract-invariants
```

Report:

- `config/security/philcore-contract-invariants-report.json`

N.6 passed all 17 PhilCore-specific checks. N.7 adds an eighteenth check for `PhilMintPassConsumer` zero-value enforcement. Current checks include:

- `execute(...)` remains EntryPoint-only.
- `execute(...)` remains restricted to immutable `approvedActionGate`.
- `execute(...)` remains restricted to `verifyAndConsume(...)`.
- no `delegatecall`, generic batch execution, paymaster/session-key behavior, or upgrade path exists in the account/factory boundary.
- recovery authority cannot invoke ordinary execution.
- recovery functions do not change EntryPoint, ActionGate, or `ownerCommitment`.
- Base mirror remains messenger-only and validates authorized L1 remote sender.
- ActionGate nullifier marking remains before consumer execution.
- PhilMintPassConsumer rejects nonzero `msg.value` before mint state changes.

## npm Advisory Triage

Machine-readable report:

- `config/security/philcore-npm-audit-report.json`

N.6 applied a non-forced lockfile remediation. Advisory count changed from 20 to 16:

| Severity | Before N.6 | After N.6 |
| --- | ---: | ---: |
| Critical | 0 | 0 |
| High | 5 | 3 |
| Moderate | 5 | 3 |
| Low | 10 | 10 |

Original high advisory groups:

| Package | N.6 Status | Exposure |
| --- | --- | --- |
| `lodash` | remediated by non-forced lockfile update | Hardhat/local tooling |
| `ws` | remediated by non-forced lockfile update | Hardhat/local tooling |
| `serialize-javascript` | formally accepted as development-tooling risk in N.7 | Hardhat/Mocha local tooling |
| `tmp` | formally accepted as development-tooling risk in N.7 | Hardhat/Solc local tooling |
| `undici` | formally accepted as development-tooling risk in N.7 | Hardhat local tooling; remediation requires Hardhat major-version review |

No remaining high advisory is classified as PhilCore production runtime exposure. N.7 records temporary development-tooling risk acceptance in `config/security/philcore-dependency-exposure.json`; production packaging must exclude these dev dependencies.

## Gate Impact

Met by N.6:

- reproducible Slither environment;
- Slither run completed;
- Slither findings triaged;
- no critical/high contract findings;
- custom PhilCore invariant checks passing;
- npm high advisories individually classified;
- lockfile reviewed and narrowly remediated without `npm audit fix --force`.

Still blocked:

- ACP-0002 remains `Proposed`;
- recovery-authority rotation is locally implemented in N.8 but unaudited and not Beta-approved;
- remaining high npm tooling advisories are accepted only as development-tooling risk pending a reviewed Hardhat/toolchain migration;
- deployment and bundler evidence are missing;
- external audit is not complete;
- `PhilMintPassConsumer` is zero-value-only; a value-bearing mint path remains prohibited without Architecture Change Control.

## CI Recommendation

Add a future non-secret security job that runs:

```bash
npm ci
npm run compile
npm run security:setup-slither
npm run security:slither
npm run security:philcore-contract-invariants
npm run security:npm-audit
```

The CI job should upload the JSON reports from `config/security/` as artifacts, fail on tool setup failures, fail on custom invariant failures, and fail on new high/critical Solidity findings. Dependency advisories should remain a separate gate so Hardhat-major migration decisions are not hidden inside `npm audit fix --force`.
