# O.35 V2 Factory And Account Lifecycle Test Plan

Status: `FUTURE_IMPLEMENTATION_TEST_PLAN`.

O.35 adds only design-conformance tests. The Solidity, bytecode, local-EVM,
fork, deployment, and fund-lifecycle tests below are acceptance requirements
for later approved implementation phases.

## Test Principles

- independently reproduce security-critical hashes and addresses;
- test failures before happy-path deployment;
- use public deterministic fixtures only;
- never use production credentials or protected witness material;
- keep local/fork tests separate from public-chain mutation;
- assert exact failure classes and unchanged state;
- test complete lifecycle, not isolated deployment success;
- retain V1 source-hash checks in every V2 factory phase.

## O.35 Design-Conformance Tests

The current O.35 unit test must verify:

- exact phase, baseline, identity, and public-mutation count;
- frozen V1 account/factory hashes;
- one immutable factory per version;
- no implementation registry, proxy, admin, initializer, fund custody,
  recovery, or execution authority;
- complete CREATE2 formula and initialization tuple;
- address-change and post-activation stability rules;
- atomic constructor-only initialization;
- exact initial validator/recovery epoch `1`;
- three roles and threshold `2`;
- lifecycle ordering and funding gate;
- migration has no V1 asset route or automatic movement;
- every security-boundary mutation/authority field is false;
- all five required documents are canonical-indexed;
- no Solidity V2 factory/account file, bytecode, credentials, signatures,
  UserOperations, or URLs were added.

## Future Creation Tests

### Deterministic address

1. factory `getAddress` equals independent CREATE2 reproduction;
2. a third build-artifact reproduction matches;
3. creation deploys exactly at the predicted address;
4. repeated exact creation returns/verifies the same address without state
   change;
5. different user salt changes the address;
6. zero/malformed salt fails;
7. factory address substitution changes the address;
8. chain and EntryPoint substitution changes or rejects derivation;
9. account/security-model version changes the address;
10. creation bytecode/compiler/link metadata changes the address.

### Identity and security fields

Mutate each field independently and require a different address or rejection:

- owner commitment;
- identity-binding commitment;
- initial validator;
- validator verifier kind;
- validator key-ID binding;
- validator commitment;
- each ordered recovery role commitment;
- recovery-configuration hash;
- confirmation target;
- recovery delay/expiry;
- initial epochs.

Post-activation validator/recovery transitions must not change the deployed
address.

### Collision and front-running

- exact existing account with matching code/state is idempotent;
- existing mismatched code fails;
- matching code with mismatched immutable/security state fails;
- factory cannot choose alternate salt automatically;
- exact permissionless front-run creates no caller authority;
- caller changes do not change address or account state;
- reverted creation leaves no code and emits no accepted creation evidence.

## Future Initialization Tests

Reject:

- missing or zero owner/identity commitment;
- missing/zero validator or key binding;
- unsupported validator verifier;
- validator commitment mismatch;
- validator epoch zero, two, or maximum-invalid value;
- missing recovery configuration;
- fewer/more than three roles;
- zero, duplicate, reordered, or role-incompatible commitments;
- wrong recovery-configuration hash;
- recovery epoch zero or two;
- wrong chain, EntryPoint, factory, version, security model, target, timing;
- nonzero value;
- pending recovery/config state;
- enabled execution lock, admin, module, session, or paymaster state.

Assert successful creation:

- makes no external call;
- leaves no partial initialization;
- cannot be initialized twice;
- sets all immutables exactly;
- sets validator/recovery epochs to `1`;
- sets recovery `NORMAL`;
- sets pending fields empty and lock false;
- leaves EntryPoint nonce lanes and deposit zero;
- grants no factory/deployer/caller privilege.

Fuzz the complete constructor tuple and assert any single-bit mutation either
changes the address or fails validation.

## Future Lifecycle Tests

For every lifecycle transition:

- exact prior state and evidence required;
- missing, stale, ambiguous, or conflicting evidence rejected;
- no transition skips a state;
- rejected transition leaves the prior record unchanged;
- lifecycle labels do not invoke contracts or create authority.

Specific cases:

- counterfactual address has unexpected code;
- unexpected predeployment balance;
- nonzero initial nonce or EntryPoint deposit;
- deployment receipt success but wrong event/address;
- correct receipt but wrong runtime code;
- correct code but wrong immutable/validator/recovery state;
- chain reorganization removes deployment;
- ambiguous submission cannot trigger automatic resubmission;
- activation cannot occur from factory/deployer attestation alone;
- funding blocked before `ACTIVE_UNFUNDED`;
- recovery pending blocks migration/retirement as specified;
- retirement blocked by pending receipt or unknown holdings.

## Future Migration Tests

Reject:

- wrong source or destination;
- wrong identity/owner/identity-binding commitment;
- wrong source/destination version, factory, code, chain, or EntryPoint;
- destination not active;
- stale source validator or recovery epoch;
- stale/replayed nonce or authority;
- ordinary purpose instead of migration purpose;
- changed asset, token ID, amount, recipient, data hash, fee, or expiry;
- migration during active recovery freeze;
- recovery authority used for asset movement;
- missing asset inventory;
- unexpected native/deposit/token/NFT balance;
- fee-on-transfer or malformed ERC-20 delta;
- unsafe receiver callback behavior;
- ambiguous/reverted receipt;
- adapter switch before reconciliation;
- retirement with unapproved residuals.

Positive future V2-to-new-version tests require fresh authorization for each:

- native asset;
- EntryPoint deposit;
- ERC-20;
- ERC-721;
- ERC-1155.

V1 tests must prove:

- V1 source and factory hashes remain unchanged;
- V1 has no typed migration release route;
- V2 cannot claim V1 or O.27-prefunded assets;
- identity continuity alone grants no V1 execution.

## Future Security Tests

### Factory compromise

- no owner/admin role or storage slot;
- no upgrade, implementation setter, delegatecall, fallback execution, sweep,
  recovery, pause, or arbitrary call;
- deployer key compromise changes no deployed account state;
- malicious factory caller receives no privilege;
- factory forced balance cannot be withdrawn through a hidden path;
- factory cannot deploy an alternate implementation under the same version.

### Malicious implementation/version

- source/build/runtime hash mismatch rejected;
- manifest rollback or version alias rejected;
- proxy bytecode or implementation slot rejected;
- linked-library substitution detected;
- account runtime has no factory-authorized entrypoint;
- exact version IDs match account views and creation inputs.

### Initialization/replay

- public initializer absent;
- reentrant constructor target absent;
- duplicate CREATE2 request cannot overwrite state;
- replayed creation evidence cannot activate a different account;
- event from wrong factory ignored;
- exact creation on another chain cannot satisfy current-chain acceptance.

### Recovery isolation

- factory cannot request/cancel/complete recovery;
- factory cannot rotate recovery config or validator;
- exact 2-of-3 remains required;
- daily validator does not count as recovery role;
- recovery moves no asset;
- post-recovery asset action requires fresh ordinary authorization.

## Future Fund-Safety Tests

The complete lifecycle test is mandatory:

```text
derive
  -> deploy atomically
  -> verify activation
  -> prove release paths
  -> fund exact bounded amount
  -> execute exact action
  -> separately authorize residual release
  -> reconcile zero or approved final state
```

Test native balance, EntryPoint deposit, ERC-20, ERC-721, and ERC-1155
individually. For each:

- maximum funding/holding and maximum stranded value are exact;
- residual recipient is explicit and not a factory/deployer admin;
- release selector/route is fixed and authorized;
- operation and release use different fresh approvals;
- balance and ownership deltas match;
- failed execution rolls back state;
- forced or unsolicited assets are detected;
- final balance is zero unless exact dust was pre-approved;
- local simulation passes;
- fork simulation passes or technical unavailability is recorded.

No public test funding may occur until all applicable gates pass.

## Tooling And Analysis Requirements

A future Solidity phase must add:

- compiler-pinned build and storage-layout artifacts;
- independent ABI/creation/runtime bytecode hashes;
- deterministic CREATE2 vector generator and checked-in public vectors;
- unit and integration tests against EntryPoint v0.7;
- property/fuzz tests for constructor, salt, role, epoch, and collision rules;
- invariant tests for no factory privilege and no partial initialization;
- static analysis and compiler warnings at zero unexplained findings;
- local complete lifecycle simulation;
- fork simulation with exact infrastructure bindings;
- source/bytecode verification scripts with no generic RPC passthrough;
- secret/artifact contamination scanning.

## Acceptance Gates

Factory implementation cannot proceed to deployment design until:

1. all creation and initialization tests pass;
2. independent CREATE2/address vectors match;
3. account/factory source and bytecode review passes;
4. V1 hashes remain unchanged;
5. no admin/proxy/upgrade/factory authority exists;
6. complete local fund lifecycle passes;
7. fork lifecycle passes or a reviewed technical reason exists;
8. recovery and migration invariants pass;
9. audit scope and residual risks are explicit;
10. a separate user-approved phase authorizes any live-chain step.

## O.35 Boundary

O.35 runs only design-conformance tests. It creates no Solidity, bytecode,
factory, account, wallet, credential, proof, signature, UserOperation,
transaction, live infrastructure, funding action, or public mutation.
