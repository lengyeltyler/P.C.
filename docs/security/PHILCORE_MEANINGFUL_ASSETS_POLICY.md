# PhilCore Meaningful Assets Policy

Status: active security policy for Alpha/Beta readiness.

## Policy

Local Alpha is limited to local fixtures, deterministic test accounts, and disposable assets.

Base Sepolia Beta, when approved, is limited to disposable testnet accounts and testnet assets only.

Before an external audit and explicit Beta/production gate approval, PhilCore must not be used to custody meaningful assets, production funds, user assets, production NFTs, or operationally important accounts.

Production meaningful assets remain prohibited until:

- ACP-0002 is accepted for the production scope;
- external security audit is complete;
- critical/high findings are remediated or formally risk-accepted;
- recovery-authority model is production-approved;
- deployment, bundler, relayer, and key-custody operations are approved;
- the Base Sepolia Beta security gate or successor production gate is explicitly passed.

## Stage Limits

| Stage | Allowed Assets | Status |
| --- | --- | --- |
| Local Alpha | fixtures and disposable local assets | allowed |
| Base Sepolia Beta | testnet assets only, after gate approval | blocked |
| Pre-audit public deployment | no meaningful assets | prohibited |
| Production | meaningful assets only after external audit and gate approval | prohibited |

## Operational Notes

No public UserOperation, deployment, relay, Starknet publication, L1 anchor, L1-to-Base relay, Base execution, or recovery action should be treated as production-authorized unless the relevant gate explicitly permits it.

Documentation or local test success is not approval to use meaningful assets.

All test funding is additionally governed by the canonical
[PhilCore Test-Fund Release Policy](./PHILCORE_TEST_FUND_RELEASE_POLICY.md).
Disposable status alone does not satisfy the release requirement.
