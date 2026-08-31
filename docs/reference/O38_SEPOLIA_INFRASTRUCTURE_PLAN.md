# O.38 Sepolia Infrastructure Plan

Status: `PLAN_ONLY_NO_ADDRESS_DECLARED_DEPLOYED_BY_O38`.

## Proposed network binding

- chain: Ethereum Sepolia;
- chain ID: `11155111`;
- EntryPoint: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`;
- EntryPoint interface/package: Account Abstraction `0.7.0`;
- future verifier: `<O38_FUTURE_VERIFIER_ADDRESS>`;
- future factory: `<O38_FUTURE_FACTORY_ADDRESS>`;
- future account: derived only after the exact factory, 20-field tuple, and
  user salt are frozen.

The canonical EntryPoint is reusable infrastructure, subject to fresh
read-only chain ID, runtime code hash, interface, deposit, and keyed-nonce
checks in the later deployment phase.

The O.23R confirmation target at
`0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7` is only a reuse candidate.
Repository evidence binds its historical runtime hash to
`0x33dedb191e724449780bd2ef2abbd77a2692bb154525553fcdebf11a915327ad`
and its interface matches `confirmPhilCoreAction(bytes32,bytes32)`. A later
read-only gate must confirm the live code hash and behavior before selecting
it. The O.38 template leaves the target unset.

The O.24 V1 factory, V1 account, and the counterfactual V1 account are not V2
infrastructure and must remain isolated. Their layouts, initialization,
version identities, verifier binding, and creation code are incompatible.
The V2 verifier and factory are new version-specific deployments.

## Proposed order

1. Freshly verify chain, EntryPoint, selected confirmation target, fees,
   deployer address, balance, and nonce without mutation.
2. Reproduce the O.37.10 artifacts again and bind the approval package to
   their exact hashes.
3. Deploy the stateless verifier; verify runtime hash and empty storage.
4. Deploy the factory with exact constructor arguments:
   `(EntryPoint, 11155111, confirmationTarget, verifier, verifierCodeHash)`.
5. Verify factory runtime, immutables, account creation code, and prediction.
6. Only after three-domain enrollment is complete, freeze the exact 20-field
   tuple and user salt and request a separate account-deployment approval.
7. Deploy through `createAccount`; never deploy the account constructor from
   an EOA.
8. Verify state before considering any deposit, funding, or UserOperation.

No O.38 address is labeled canonical, deployed, or approved.

## Service requirements

The later phase needs a restricted Sepolia RPC client for chain, code,
receipt, fee, balance, nonce, and read-only contract calls. The bundler must
support EntryPoint 0.7 and estimation/read methods. Submission remains absent
until an independently approved live-operation phase. RPC and bundler
allowlists remain logically separate even if one credential-bearing service
hosts both.

Explorer verification must accept exact Solidity `0.8.27`, Cancun, optimizer
200, `viaIR`, literal source metadata, and the constructor arguments recorded
in the verification plan. No explorer request is made by O.38.

No private endpoint, `.env.sepolia.local`, bundler, explorer API, or live
chain was accessed.
