# O.38 Post-Deployment Verification Plan

Status: `CHECKLIST_ONLY`.

This checklist is for a separately authorized Sepolia deployment phase. Each
step uses a restricted read-only client unless it is itself the one exactly
approved mutation. A mismatch stops the phase; no automatic retry or
replacement is allowed.

## Before each mutation

- recheck chain `11155111`, EntryPoint identity/code, selected confirmation
  target, deployer address/nonce/balance, live fees, artifacts, maximum gas,
  and explicit transaction envelope approval;
- prove prior transaction hash/receipt state so no duplicate deployment is
  attempted;
- keep verifier, factory, and account approvals separate.

## Verifier

- receipt success, sender, nonce, creation input, block, fee, and address;
- runtime hash exactly
  `0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be`;
- ABI hash exactly
  `0xc508c5fe01e267ec247080f3aae1daccb6d518a8eab63f6298160b40f8d4747e`;
- no constructor arguments, no mutable storage, correct version and success
  magic, and no creation/runtime drift.

## Factory

- receipt and exact constructor arguments;
- reconstruct immutable-patched runtime and compare its hash;
- call `verifierBinding()` and compare address and runtime hash;
- verify EntryPoint, chain, and confirmation-target immutable patches;
- verify exact account creation bytecode and sample creation-code hash;
- recompute deployment salt and CREATE2 prediction independently;
- verify no admin, upgrade, registry, or mutable verifier state.

## Account

- predeployment prediction has no code and `createAccount` emits the same
  address;
- reconstruct immutable-patched runtime and compare it byte-for-byte;
- verify EntryPoint, chain, factory, owner, identity, account version,
  security model, and confirmation target through aggregate views;
- verify validator address, key binding, commitment, kind, and epoch `1`;
- verify all three enrollment commitments, configuration hash, recovery epoch
  `1`, exact delay/expiry, idle lifecycle, and no pending request;
- verify EntryPoint lane 0/1/2 nonces are zero and deposit is zero before any
  separate deposit approval;
- verify native, token, and EntryPoint balances are zero and no unexpected
  event or second account exists.

## End to end

Only after deployment verification:

1. construct a fresh dry UserOperation with current state;
2. in a later approved read-only phase, obtain bundler estimation only;
3. obtain fresh Runtime proof and exact-action authorization;
4. obtain fresh user-presence approval and Device Vault signature;
5. execute one separately approved confirmation action;
6. test the bounded native release and EntryPoint deposit withdrawal paths;
7. reconcile sender, account, recipient, deposit, beneficiary, gas, and
   residuals exactly;
8. verify no token movement and repeat the token-stranding warning.

Historical proof, approval, signature, UserOperation, fixture authority, or
nonce may not be reused.
