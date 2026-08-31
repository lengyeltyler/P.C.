# Local-Proof-Gated Scoped Architecture Approval

Status: Conditionally Approved for Disposable Sepolia Preparation

The human decision for Phase O.19 approves `local-proof-gated-v1` only for
guarded preparation and read-only inspection of one disposable Ethereum
Sepolia experiment.

The approval means:

- PhilCore may prepare the experimental target, factory, account, and first
  unsigned UserOperation;
- PhilCore verifies STWO locally before Device Vault signing;
- Ethereum verifies the account signature, exact UserOperation, EntryPoint,
  nonce, expiry, and fixed call restrictions;
- Ethereum does not independently verify the STWO proof;
- no meaningful assets, paymaster, token movement, mainnet claim, Beta
  approval, or production claim is allowed;
- `ethereum-fact-enforced-v1` remains the stronger intended architecture.

This approval does not accept a deployment manifest and does not authorize
deployment, funding, signing, transaction submission, or UserOperation
submission. Each future mutation requires its own stage approval.
