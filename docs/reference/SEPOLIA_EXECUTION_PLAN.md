# Guarded Base Sepolia Execution Plan

> This remains a Base-specific historical plan. It must not be renamed or
> reused as Ethereum Sepolia configuration. The active O.17 preparation
> runbook is [Ethereum Sepolia Execution Runbook](./ETHEREUM_SEPOLIA_EXECUTION_RUNBOOK.md).

## Preconditions

This plan is for a later dedicated phase. It performs no deployment or public
submission now.

Required decisions and approvals:

- explicitly review ACP-0002 for the bounded Beta scope;
- keep the disposable/no-meaningful-assets policy;
- approve the Beta execution and recovery custody model;
- accept exact account, factory, ActionGate, verifier, mirror, and consumer
  source hashes;
- approve a Base Sepolia RPC and ERC-4337 v0.7 bundler;
- define a separate public-network submission approval;
- complete the required independent security review.

## Exact Sequence

1. Lock Base Sepolia (`chainId 84532`) and EntryPoint v0.7.
2. Freeze compiler, dependency, account, factory, ActionGate, verifier, mirror,
   and consumer artifacts.
3. Verify deterministic account/factory behavior and exact validator signature
   format.
4. Bind local proof authorization to the exact UserOperation through the
   existing M.9/M.10 checks.
5. Configure an allowlisted, read-only-by-default Base Sepolia RPC.
6. Configure and capability-check one approved v0.7 bundler.
7. Keep paymaster disabled; fund one disposable account with capped Sepolia ETH.
8. Deploy and independently verify the approved contracts.
9. Record code hashes, constructor bindings, owner commitment, EntryPoint,
   ActionGate, recovery authority, and deployment receipts.
10. Create or verify one disposable PhilCore account.
11. Prepare one zero-value, allowlisted test action.
12. Generate and verify the STARK proof locally.
13. If exercising ActionGate, require accepted live mirrored-fact evidence.
    Otherwise stop before claiming the full proof-backed public route.
14. Present the exact UserOperation, require fresh user presence and separate
    public submission approval, then sign once.
15. Submit through the restricted bundler boundary.
16. Independently verify UserOperation receipt, EntryPoint event, target,
    calldata, value, nullifier, and consumer outcome.
17. Test denial, timeout, replay, nonce mutation, target mutation, chain
    mutation, expiry, bundler mismatch, and receipt mismatch.
18. Disable the public profile after the bounded exercise and preserve
    sanitized evidence.

## Configuration Inputs

Use named external selectors or secret references rather than placing
credentials in files. The dedicated phase should define exact names for:

- Base Sepolia RPC endpoint reference;
- approved bundler endpoint reference;
- public submission approval flag/artifact;
- deployment operator signer reference, if deployment is approved;
- disposable validator/recovery signer references;
- fee and balance caps;
- deployment manifest path and expected code hashes.

No private key, mnemonic, RPC credential, bundler credential, or approval token
may be printed or committed. Paymaster credentials are not required because
paymaster use remains disabled.

External services:

- Base Sepolia RPC provider;
- ERC-4337 v0.7 bundler;
- Base Sepolia block explorer/source verification service, if approved;
- testnet faucet or approved disposable funding source;
- Starknet/L1/Base cross-domain infrastructure only if the live fact route is
  included.

Human actions:

- architecture and Beta-scope approval;
- artifact/code-hash review;
- custody enrollment;
- disposable testnet funding;
- deployment approval;
- exact UserOperation approval with fresh presence;
- separate public submission approval;
- receipt and audit review.

## Stop Conditions

Stop before mutation when any chain, address, code hash, EntryPoint, bundler,
nonce, fee, fact, nullifier, capability, session, presentation digest, signer,
expiry, or approval is missing or changed.

The first public exercise must not enable generic RPC, generic account calls,
arbitrary targets, a paymaster, meaningful assets, or automatic retries.
