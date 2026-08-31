# Local-Proof-Gated Architecture Approval Checklist

Status: architecture decision completed for preparation only.

The human architecture decision is whether to permit one disposable Ethereum
Sepolia experiment under `local-proof-gated-v1`, accepting that Ethereum checks
the account signature and operation restrictions but does not verify the STWO
proof.

- [x] Accept the local trusted-computing assumption for one disposable account.
- [x] Accept the separate account/factory/target contracts for preparation.
- [x] Confirm no meaningful assets and no production claim.
- [x] Confirm zero value, fixed target/function, no paymaster, and bounded fees.
- [x] Confirm tester copy discloses local, not Ethereum, STARK verification.
- [ ] Review source commit and proposed bytecode hashes.
- [ ] Configure and verify a read-only Ethereum Sepolia endpoint separately.
- [ ] Approve deployment separately from first UserOperation submission.
- [ ] Preserve `PhilCore4337Account` and `ethereum-fact-enforced-v1`.
- [ ] Keep ACP-0002 Proposed until the broader account architecture is reviewed.

This scoped approval does not accept a manifest, set an environment gate, or
authorize public mutation.
