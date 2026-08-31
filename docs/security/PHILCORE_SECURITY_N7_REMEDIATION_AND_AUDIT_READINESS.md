# PhilCore N.7 Security Remediation And Audit Readiness

> Historical N.7 evidence. Its dependency counts and dispositions describe
> that phase, not the current lockfile. See
> [Dependency Advisory Status](./DEPENDENCY_ADVISORY_STATUS.md).

Status: internal security evidence, not an external audit.

Phase N.7 performs targeted remediation for the remaining production-relevant N.6 Solidity finding, records dependency-risk disposition, and prepares external-audit package evidence. It does not approve Base Sepolia Beta or production use.

## PhilMintPassConsumer Value Decision

Selected model: zero-value-only consumer.

`PhilMintPassConsumer` does not need ETH to mint a bounded pass. It has no downstream payable target, no pricing model, no refund behavior, and no administrator withdrawal path. Adding withdrawal or refund machinery would create unnecessary trust and reentrancy review surface.

N.7 therefore rejects nonzero `msg.value` in `consumePhilAuthorization(...)` before mint state changes.

Evidence:

- `contracts/base/PhilMintPassConsumer.sol`
- `test/unit/mint-path.test.cjs`
- `config/security/philcore-contract-invariants-report.json`

Result:

- zero-value mint succeeds;
- nonzero ActionGate value reverts atomically;
- mint state is unchanged on nonzero value;
- consumer balance remains zero after the rejected flow;
- future value-bearing mint/pass purchase flows require Architecture Change Control and a reviewed forwarding/refund model.

## Other Production Consumer Review

`PhilUnlockConsumer` remains a value-forwarding consumer. It binds value to decoded `UnlockRequest.value`, rejects mismatched `msg.value`, forwards exactly that value to the approved target, and reverts atomically on downstream failure.

`PhilMintPassConsumer` is now zero-value-only.

Mocks and adversarial consumers remain local-test fixtures only.

## Dependency Disposition

Remaining high npm advisory groups:

- `serialize-javascript`
- `tmp`
- `undici`

N.7 classifies all three as development-tooling exposure through Hardhat/Mocha/Solc/Hardhat HTTP tooling. No remaining high advisory is classified as PhilCore production runtime exposure.

Decision: accepted development-tooling risk pending a reviewed Hardhat/toolchain migration.

Controls:

- do not run tooling on untrusted repositories or config files;
- do not run tooling as an elevated user;
- use trusted local/test RPC endpoints;
- keep `package-lock.json` pinned;
- exclude dev dependencies from production runtime bundles;
- require Architecture Change Control for Hardhat major-version migration.

Machine-readable inventory:

- `config/security/philcore-dependency-exposure.json`
- `config/security/philcore-npm-audit-report.json`

## Static Analysis Delta

N.7 reruns Slither and the PhilCore custom invariants after the MintPass remediation.

Expected N.7 deltas:

- critical Solidity findings: 0;
- high Solidity findings: 0;
- `N6-SLITHER-004 / N6-MED-008` status: remediated or accepted zero-value-only;
- custom invariants: 18/18 passing, including `N7-INV-018`.

Slither may still report a `locked-ether` heuristic because the shared authorization consumer interface is payable. The N.7 triage classifies that finding by checking the explicit zero-value guard in the implementation.

## Audit Readiness

N.7 adds:

- `docs/security/PHILCORE_EXTERNAL_AUDIT_SCOPE.md`
- `config/security/philcore-external-audit-manifest.json`
- `npm run security:audit-package-check`

The audit package checker verifies required files, parses manifests, runs the existing security command bundle, checks the package-lock hash, confirms ACP status is explicit, and confirms the Beta gate remains blocked. It does not zip, upload, deploy, sign, or submit anything.

## Gate Impact

Improved:

- MintPass value risk remediated by zero-value-only restriction;
- dependency highs individually classified and formally accepted as development-tooling risk;
- audit package is prepared for internal review.

Still blocked:

- ACP-0002 remains Proposed;
- recovery-authority rotation is locally implemented in N.8 but unaudited and not Beta-approved;
- external audit is not complete;
- Base Sepolia deployments, bundler, relayer, custody-operation, and public submission approvals remain incomplete;
- meaningful assets remain prohibited.
