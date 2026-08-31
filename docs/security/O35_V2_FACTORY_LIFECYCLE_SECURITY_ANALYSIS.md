# O.35 V2 Factory And Lifecycle Security Analysis

Status: `LOCAL_FACTORY_LIFECYCLE_THREAT_ANALYSIS_COMPLETE`.

This analysis covers the O.35 factory, CREATE2, initialization, version,
migration, funding, and retirement design. There is no Solidity implementation
or deployed infrastructure to audit in this phase.

## Security Objectives

The design must ensure:

1. the factory can create only one reviewed account version;
2. every security input affects the predicted account address;
3. a deployed account is fully initialized or does not exist;
4. factory/deployer compromise creates no post-deployment account authority;
5. identity continuity cannot be used to seize old-account assets;
6. recovery remains exact 2-of-3 and account-local;
7. migration and funding require exact, fresh, typed authorization;
8. version change creates a new factory, code artifact, and address;
9. no lifecycle label is mistaken for onchain authority;
10. no secret or reusable authority enters factory inputs or evidence.

## Trust Boundaries

Trusted only after independent verification:

- canonical Phil identity and public commitments;
- reviewed O.32/O.33/O.34 behavior;
- pinned source, dependency, compiler, and build configuration;
- exact version-specific factory and account bytecode;
- canonical EntryPoint and chain;
- deterministic constructor and CREATE2 encodings;
- fresh chain receipts and state from restricted read-only clients;
- trusted human-readable approval presentation in later phases.

Untrusted for authorization:

- factory deployer and account deployment sender;
- factory caller;
- RPC, bundler, explorer, indexer, relayer, or block builder;
- deployment manifest without reproduction;
- front-end or application-supplied initialization fields;
- counterfactual address returned by one implementation;
- receipt status without event/code/state reconciliation;
- lifecycle labels not supported by current state.

The factory is not trusted with secrets, signing, recovery, execution,
funding, or migration authority.

## Threat Matrix

| Threat | Design response | Residual obligation |
| --- | --- | --- |
| malicious mutable implementation registry | one factory per immutable reviewed version; no registry or proxy | verify factory runtime has no hidden indirection |
| factory deployer compromise | deployer receives no role; caller does not affect authority | verify deployment constructor and ownership slots are absent |
| post-deployment factory compromise | account stores factory only as immutable provenance; no factory callback or privileged selector | test every account entrypoint against factory caller |
| malicious initializer | no public initializer; complete constructor-only state | audit creation code and storage initialization |
| partial initialization | constructor validates all fields and reverts atomically | assert no default validator/recovery state can deploy |
| duplicate initialization | no initializer and CREATE2 cannot overwrite code | test existing-code exact/mismatch branches |
| initial validator substitution | validator address, verifier, key binding, commitment, epoch enter creation code hash | independently derive address and inspect state |
| recovery factor substitution | all three ordered role commitments and config hash enter creation code hash | test role order, zero, duplicate, and mismatch cases |
| cross-chain replay | chain enters salt and constructor; account verifies runtime chain | test same inputs on another chain produce/reject as designed |
| EntryPoint substitution | EntryPoint enters constructor/code hash and immutable state | verify canonical code/interface separately |
| salt collision/reuse | domain-separated nonzero salt plus complete init-code hash | publish deterministic vectors and fuzz distinct tuples |
| CREATE2 squatting | exact factory is the only deployer at the derived namespace; mismatched existing code fails | reconcile factory and code before acceptance |
| front-run exact deployment | caller-independent exact creation is permissionless and benign after verification | ensure no caller, refund, or owner field exists |
| front-run altered deployment | altered tuple changes init-code hash/address | independently reproduce complete tuple |
| forced ETH to counterfactual/deployed account | unexpected balance blocks lifecycle/funding acceptance | cannot prevent force-send; maintain reconciliation |
| malicious account version | accepted manifest, source/build reproduction, separate factory/address | independent review and version rollback protection |
| manifest substitution/rollback | bind version IDs and hashes; require current accepted manifest | protect repository/release governance and audit history |
| constructor reentrancy | constructor makes no external call and accepts no value | verify compiler output and linked libraries |
| event spoofing | events are evidence only; verify factory address, code, and state | use receipt plus state, not logs alone |
| factory fund custody | nonpayable creation and no withdrawal/receive path | bytecode and forced-balance behavior tests |
| recovery takeover | factory cannot recover; exact account-local 2-of-3 | implement and audit factor verification later |
| validator-only recovery | prohibited; daily validator is not a recovery factor | retain O.32/O.33 strict bitmap behavior |
| identity-continuity asset seizure | new account has no source claim; old account must execute each transfer | trusted presentation and per-asset reconciliation |
| broad migration sweep | fixed typed per-asset actions only | token-specific and callback tests |
| stale migration authority | fresh nonce, epochs, validity, proof, approval, presence, signature | one-time authority and receipt checks |
| destination trap | destination must be active and release-tested before receiving assets | full local/fork fund lifecycle |
| premature adapter switch | switch only after movement and state reconciliation | atomic local record update and rollback audit |
| destructive retirement | no selfdestruct/admin disable; retirement is local selection state | continue monitoring residual old assets |
| lifecycle status spoof | every transition requires exact evidence | reject stale, ambiguous, or missing evidence |
| credential/identity leakage | public commitments only; no raw labels, keys, witnesses, or endpoint credentials | redaction and artifact scanning |

## Factory Compromise Analysis

### Before factory deployment

A malicious or substituted source/build can derive attacker-controlled
accounts. No factory address is accepted until reviewers independently bind:

- repository source and commit;
- dependency lock;
- compiler and optimizer settings;
- creation/runtime bytecode;
- constructor arguments and immutables;
- deployment transaction and receipt;
- deployed runtime hash;
- absence of ownership, upgrade, delegatecall, or registry paths.

O.35 does not perform this acceptance.

### After factory deployment but before account deployment

If the factory has mutable code selection, ownership, or selfdestruct, it
could create unexpected accounts at different addresses or break liveness.
The selected factory therefore has none. A caller verifies the exact factory
runtime and independently derives the address immediately before deployment.

Factory censorship is a liveness risk. The account address namespace belongs
to that factory, so a broken factory cannot be replaced while preserving the
same address. Recovery is a new reviewed version/factory/address, not a hidden
fallback.

### After account deployment

The account is non-upgradeable and has no factory-authorized selector.
Compromising the factory or its historical deployment key cannot change the
account, validator, recovery factors, or assets.

The account's immutable `factoryBinding` is provenance, not an authorization
check that grants calls from the factory.

## Initialization Attack Analysis

Constructor-only atomic initialization prevents the common uninitialized
proxy/clone takeover. The constructor must reject:

- zero or malformed owner/identity commitments;
- zero validator or key binding;
- unsupported validator verifier;
- validator commitment mismatch;
- validator or recovery epoch other than `1`;
- any missing, zero, duplicate, reordered, or role-incompatible recovery
  commitment;
- recovery-configuration hash mismatch;
- noncanonical delay/expiry;
- wrong chain, EntryPoint, factory, version, security model, or confirmation
  target;
- native value;
- nonempty pending state, lock, module, paymaster, or administrator fields.

The constructor must make no external call, including verifier, token,
EntryPoint, confirmation target, or factory callback. Cryptographic witnesses
are verified later only when exercising account authorization; initialization
stores public commitments.

## CREATE2 Risks

CREATE2 predicts a location, not correctness, deployability, recovery, or
fund safety.

Primary risks:

- wrong creation bytecode or constructor encoding;
- wrong factory or chain;
- compiler metadata/link differences;
- salt ambiguity;
- incomplete security-field binding;
- a pre-existing occupant;
- prefunding before release proof;
- cross-tool derivation disagreement;
- future source changes under a reused version label.

Mitigations:

- canonical ordered tuple and domain-separated salt;
- exact build and creation-code hashes;
- unique immutable version IDs;
- independent derivations and checked-in future vectors;
- collision checks immediately before deployment;
- post-deployment runtime and state verification;
- no funding before `ACTIVE_UNFUNDED`;
- any source/build change creates a new reviewed artifact and address.

Cryptographic collision resistance and EVM CREATE2 semantics remain base
assumptions.

## Version Risks

No version name such as “V2” is sufficient. Acceptance requires a bytes32
account-version ID, security-model ID, exact factory/account artifacts, and
manifest state.

A newer version is not automatically safer or canonical. Version activation
must be explicit, reviewable, and reversible at the local adapter-selection
layer before assets move. A version manifest cannot override deployed account
rules.

Rollback to an older adapter may expose old vulnerabilities or stale
authority. It requires current security-state verification and cannot reverse
asset movement.

## Migration And Retirement Risks

Migration is vulnerable to:

- wrong destination presentation;
- incomplete asset inventory;
- token behavior inconsistent with expected balance deltas;
- stale source authority;
- migration during recovery freeze;
- receipt ambiguity followed by duplicate submission;
- adapter switch before completion;
- residual assets forgotten during retirement.

Mitigations are exact per-asset intents, fresh authority, no broad approvals,
single-attempt submission policies in future live phases, token-specific
post-state checks, and delayed adapter switch until reconciliation.

V1 cannot move its O.27-prefunded balance. Any presentation implying V2 can
recover that balance is a security failure.

Retirement does not disable the old contract. Old security rules remain the
only route for residuals. Local software must keep old adapter metadata
available for monitoring and authorized release.

## Fund Lifecycle Risks

An account can receive assets without proving it can release them. Forced ETH
and unsolicited tokens cannot be completely prevented. Therefore:

- zero predeployment balance is an acceptance condition;
- unexpected holdings fail lifecycle assumptions;
- every planned inbound asset requires a tested typed release path;
- recovery authority is not a release path;
- factory creation is not a release path;
- funding, intended operation, and release use separate approvals;
- source and destination state are reconciled after each migration action;
- unknown/unverifiable tokens block “zero residual” claims.

O.28 remains permanent and takes precedence over schedule or disposability.

## Privacy Analysis

CREATE2 inputs and deployment calldata become public. Only commitments and
public execution bindings belong there.

Prohibited:

- identity or recovery secrets;
- raw local credential IDs or device names;
- public keys beyond what a reviewed commitment/verifier requires;
- attestation objects and raw WebAuthn data;
- proof witnesses;
- approval/presence artifacts;
- private or credential-bearing endpoints.

Commitments reduce passive linkage before factor use but do not guarantee
post-use anonymity. Identity-binding commitment design requires a separate
cryptographic privacy review before implementation.

## Residual Risks And Deferred Work

- exact identity-binding commitment format is not yet defined;
- no Solidity, ABI, bytecode, storage layout, or CREATE2 vector exists;
- production validator/factor verifiers remain future work;
- O.31 validator-plus-one-non-primary cancellation remains unrepresented in
  O.32/O.33, so current behavior is stricter exact 2-of-3;
- token-specific execution and migration edge cases require implementation
  testing;
- factory liveness and chain reorganization handling need operational design;
- public version-manifest governance and rollback protection need a separate
  acceptance design;
- the complete system is not quantum-resistant.

## Phase Boundary

Public mutation count is zero. No factory, account, bytecode, deployment,
wallet, credential, proof, signature, UserOperation, transaction, or funding
artifact was created.
