# Local-Proof-Gated Human Approval Checklist

Status: preparation checklist; all mutation approvals remain open.

## Architecture

- [x] Local proof enforcement is approved only for disposable Sepolia preparation.
- [x] Ethereum is explicitly not described as verifying STWO.
- [x] No meaningful assets or paymaster are permitted.
- [x] The fact-enforced model remains separate and stronger.

## Contracts And Source

- [ ] Review the exact target, factory, and counterfactual account source commit.
- [ ] Review bytecode and deployed-bytecode hashes.
- [ ] Confirm factory constructor values and lack of recovery.
- [ ] Confirm the direct-CREATE2 model has no standalone implementation deployment.

## Network And Addresses

- [ ] Supply an approved read-only Ethereum Sepolia RPC.
- [ ] Confirm chain ID `11155111` and the canonical v0.7 EntryPoint.
- [ ] Supply disposable deployer/validator public inputs.
- [ ] Calculate exact target, factory, and account addresses.
- [ ] Confirm every proposed address is empty through read-only calls.

## Funding And First Action

- [ ] Review live gas and fee estimates.
- [ ] Approve one ERC-4337 v0.7 bundler and independently verify its EntryPoint support.
- [ ] Run final-operation bundler simulation with the exact signature-envelope size.
- [ ] Approve a disposable deployer and funder.
- [ ] Approve a hard maximum exposure.
- [ ] Review the exact unsigned, zero-value, token-free, paymaster-free UserOperation.
- [ ] Confirm its action, authorization digest, expiry, gas, and fee caps.
- [ ] Confirm factory `getAddress(...)`, `sender`, and decoded `initCode` are identical.
- [ ] Confirm sufficient counterfactual-account prefund.
- [ ] Reload and cryptographically verify the final signed envelope.

## Independent Mutation Approvals

- [ ] Accept the deployment manifest.
- [ ] Approve target deployment.
- [ ] Approve factory deployment.
- [ ] Approve account funding.
- [ ] Approve the atomic counterfactual account deployment and confirmation action.
- [ ] Approve first UserOperation submission.

No checked architecture item sets an environment variable or authorizes public
mutation.
