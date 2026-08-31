# Local-Proof-Gated Account Threat Model

Status: experimental, disposable-testnet only; not production-approved.

## Defenses

| Threat | Boundary |
| --- | --- |
| Renderer or preload bypass | No signing primitive is exposed; Runtime must produce all exact evidence |
| Direct Device Vault call | One-time session binds canonical UserOperation hash and purpose-bound account digest |
| Artifact substitution | Action, identity, owner commitment, approval, presence, proof, account, chain, and audit correlation must match |
| Proof-result forgery outside Runtime | Proof artifact digest and verifier result must match before the signer is invoked |
| Approval or presence replay | Both are exact-digest bound and expire; approval is one-time |
| RPC or bundler mutation | Signature binds the complete UserOperation; altered nonce, calldata, gas, fee, initCode, or paymaster fails |
| Chain, EntryPoint, account, factory, target substitution | Runtime validation and on-chain signature domain bind each value |
| Fee inflation | Runtime enforces explicit gas and fee ceilings before Device Vault signing |
| UserOperation replay | EntryPoint nonce and account expiry reject replay |
| False security claims | Model/evidence fields explicitly say local verification and no on-chain fact enforcement |

The account also rejects malformed/high-S signatures through OpenZeppelin
ECDSA, wrong signature version/model/key, wrong selector, appended calldata,
paymasters, and direct account execution.

## Residual Risks

A stolen validator private key can create valid account signatures without a
proof unless custody prevents extraction. A fully compromised Mac controlling
Runtime, approval UI, user-presence evidence, and Device Vault execution can
defeat Model A's local trusted-computing boundary. Ethereum has no STARK fact
with which to detect that failure.

A malicious RPC can censor, delay, or lie about reads. A malicious bundler can
censor or reorder a valid operation but cannot alter its signed contents.
Counterfactual deployment metadata is publicly linkable. The confirmation
target is intentionally harmless and can be imitated by unrelated contracts;
Activity evidence must correlate the accepted account and receipt.

## Security Layers

- Cryptographic on-chain enforcement: validator signature, UserOperation hash,
  EntryPoint domain, nonce, fixed calldata, expiry, and account restrictions.
- Local trusted-computing enforcement: proof generation/verification, policy,
  approval, fresh presence, fee bounds, and Device Vault release.
- Operating-system compromise: not solved by Model A.

These limitations must be shown to every tester. No meaningful assets are
permitted.
