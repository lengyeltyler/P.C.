# Phil V1 Step 6A Base Network Adapter Gate

Status: Complete; exact corrective candidate independently accepted

Date: 2026-08-22

## Decision

Step 6 begins with one deliberately incomplete Base profile. It proves that a
routine Phil capability envelope can be bound to one exact ERC-4337 account,
EntryPoint, call commitment, nonce, validity window, value ceiling, and
disclosed maximum-fee model without changing or exposing the Phil identity.

```text
STEP 6A LOCAL ADAPTER CANDIDATE: IMPLEMENTED
STEP 6A INDEPENDENTLY ACCEPTED: YES - LOCAL BINDING GATE ONLY
STEP 6 COMPLETE: NO
BASE NETWORK AUTHORIZATION PATH AVAILABLE: NO
DEVICE SIGNATURE VERIFIED BY THIS ADAPTER: NO
USEROPERATION OR TRANSACTION CREATED: NO
POST-QUANTUM CAPABILITY: NONE
GUARANTEE: LOCAL POLICY ONLY
PRODUCTION AUTHORITY: NO
NETWORK ACTIVITY: NO
```

The executable boundary is
`apps/phil-device-sdk/src/networkAdapterV1.ts`. The disclosed synthetic fixture
and hashes are in
`config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json` and
`PHIL_V1_STEP6A_ARTIFACT_MANIFEST.json`.

## Exact Profile

The candidate freezes:

- Base mainnet chain ID `8453` and `networkIdHash = keccak256("eip155:8453")`;
- ERC-4337 EntryPoint v0.7 at
  `0x0000000071727de22e5e9d8baf0edac6f37da032`;
- adapter type `network_account`;
- one P-256/SHA-256 device-approval suite;
- no proof suite and no post-quantum capability;
- a single-target call commitment with no self-call, EntryPoint call,
  `initCode`, paymaster, batch, delegatecall, or upgrade authority;
- the ERC-4337 keyed nonce model `(uint192 key, uint64 sequence)`;
- explicit call, verification, and pre-verification gas fields plus
  `maxFeePerGas`, `maxPriorityFeePerGas`, and a disclosed no-paymaster maximum
  fee ceiling; and
- exact envelope binding to adapter, network, account, EntryPoint, target,
  target-calldata hash, value, nonce, fees, validity, policy, capability, and
  human presentation.

[Base documents](https://docs.base.org/base-chain/specs/protocol/execution/evm/preinstalls)
the v0.7 EntryPoint as a preinstall, and
[Base Account](https://docs.base.org/base-account/overview/what-is-base-account)
uses ERC-4337 smart wallets.
[ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) leaves account signature
validation to the account and requires signatures to depend on the chain ID
and EntryPoint. Those facts establish a feasible adapter boundary, not a
completed Phil validator or network authorization path.

## What The Candidate Produces

The adapter produces a deterministic local binding record. It recomputes:

1. the adapter-manifest hash;
2. the single-call action hash;
3. the account binding and nonce domain;
4. the Phil authorization-envelope digest;
5. the canonical device-approval digest from the envelope and approval
   metadata; and
6. one final adapter-authorization hash over all of those values.

Authorization construction also requires a separately supplied
`trustedManifestHash` and rejects any self-consistent manifest that does not
match it. Step 6A's disclosed fixture pins the generated candidate manifest;
a later protected runtime must persist the independently admitted value rather
than deriving trust from an untrusted manifest.

The record hard-codes `deviceSignatureVerified = false`,
`networkAuthorizationPathAvailable = false`, `productionAuthority = false`,
and `networkActivity = false`. The name “authorization” describes the object
being bound; the record is not itself permission to sign, submit, or execute.

## Deliberately Not Implemented

Step 6A does not:

- receive a Phil secret, root commitment, data key, recovery material, private
  key, unrestricted signer, or vault handle;
- verify a device signature;
- accept an exceptional root proof or recovery operation;
- construct raw account calldata, a packed UserOperation, or a transaction;
- query a node, bundler, paymaster, explorer, or contract;
- simulate, sign, submit, monitor, deploy, or mutate network state;
- prove that any existing PhilCore account contract consumes this new format;
  or
- relabel existing Ethereum/Base contracts and scripts as the new Phil V1
  scoped identity architecture.

The target-calldata hash commits to bytes supplied by a future caller. A later
UserOperation builder must independently prove that its exact raw calldata
matches that hash and that the selected account contract enforces the same
semantics.

## Exit Criteria

Step 6A may be accepted only after an independent read-only review reproduces:

```text
npm run typecheck
npm run test:phil-v1-step6a-base-adapter
npm run verify:phil-v1-step6a-artifacts
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step4-composed-account
npm run test:phil-v1-step5-pq-migration
git diff --check
```

The reviewer must verify the exact candidate commit and tree, hashes, fixed
Base profile, every substitution guard, local-only classifications, source
isolation, deterministic artifacts, and absence of new runtime or network
authority.

## Next Gate

Even an accepted Step 6A completes only the local binding sub-gate. The next
efficient move would be a separately authorized Step 6B candidate proving that
one exact local smart-account validator/capability surface consumes these
bindings without a bypass. Deployment, RPC, signing, transactions, publication,
production wiring, additional networks, credentials, applications, and agents
remain separate gates.

## Independent Review Result

Exact candidate `33570bb39a334c0ef079fd82c714912ab94b18f4` was independently
rejected because its committed negative-test matrix omitted documented
manifest/action substitutions and its canonical roadmap retained a stale Step
6 status. The omitted source branches independently failed closed; no source
bypass was reproduced. See [the review record](./PHIL_V1_STEP6A_INDEPENDENT_REVIEW_33570BB.md).

A bounded correction added the omitted deterministic manifest, action,
overflow, malformed-input, and stored-derived-field tests and reconciles the
current roadmap status without changing the adapter source. Before acceptance,
it remained an unaccepted candidate pending another independent review. See
[the corrective report](../security/PHIL_V1_STEP6A_CORRECTIVE_IMPLEMENTATION_REPORT.md).

Exact corrective candidate `671936805d511cca0aa4f5754cc8a00693adf71d`
received `ACCEPT_STEP_6A_CORRECTIVE_EXACT_CANDIDATE` with no unresolved
finding. See [the acceptance record](./PHIL_V1_STEP6A_CORRECTIVE_INDEPENDENT_REVIEW_6719368.md).
This completes only the Step 6A local binding gate; all non-claims and later
authorization boundaries remain in force.
