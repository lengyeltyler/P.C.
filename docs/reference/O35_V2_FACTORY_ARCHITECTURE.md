# O.35 V2 Factory Architecture

Status: `LOCAL_FACTORY_ARCHITECTURE_DESIGN_ONLY`.

O.37.1 compatibility: the exact 20-field constructor and CREATE2 binding
remain unchanged. The three stored commitments and configuration hash use
O.37.1 descriptor/configuration version `2`; complete descriptors travel in
one-time recovery evidence and do not add constructor or storage fields.

O.35 designs the V2 factory and deterministic account-creation boundary. It
does not implement a factory. There is no Solidity, creation bytecode,
deployment, counterfactual wallet artifact, signature, UserOperation, RPC
contact, funding action, or public mutation.

## Baseline And Continuity

The phase began at
`9c139d94b1dcad14314484283a4b02532d32a2fa` on
`codex/device-identity-v1`, with a clean tracked worktree. O.20 through O.34,
the V1 account and factory, the O.32 cryptographic foundation, O.33 validator
engine, and O.34 account core were reviewed.

The canonical identity remains:

- identity: `identity_abab9766da60_24afd015`;
- display name: `My Phil`;
- baseline validator:
  `0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa`;
- validator key ID: `validator_key_3c5b2ebebc4f3f3b`;
- validator key-ID contract binding:
  `0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809`.

The identity is chain-independent. A V2 account is one versioned chain
adapter for that identity, not the identity itself.

V1 source, deployed infrastructure, evidence, and the O.27-prefunded V1
counterfactual address remain frozen. V2 has no proxy or retrofit path.

## Selected Factory Model

The selected model is:

> one non-upgradeable factory per reviewed account implementation version.

A reviewed offchain deployment manifest selects a version-specific factory.
The factory itself does not select from a mutable implementation registry.
It source-binds or embeds one exact account creation artifact, version ID, and
security-model ID.

This is deliberately stricter than a universal factory with an implementation
mapping. A universal mutable registry would make the registry administrator
an account upgrade authority. An immutable allowlist would still couple
unrelated versions and complicate source/address review. A new reviewed
factory gives each version a distinct code, manifest, and counterfactual
address boundary.

The external manifest is evidence, not authority. It cannot cause deployment,
change account validation, or move assets.

## Factory Responsibilities

The future factory may only:

1. accept one complete canonical initialization tuple;
2. reject malformed, incomplete, zero, duplicate, or role-incompatible
   security commitments;
3. derive the domain-separated deployment salt;
4. derive and expose the exact CREATE2 address;
5. deploy the exact version-bound account creation code;
6. route the tuple into constructor-only initialization;
7. return or emit commitment-only creation evidence;
8. return an existing address only after exact code and immutable
   configuration verification.

The future creation entrypoint should be nonpayable. Factory calls must not
accept, retain, forward, refund, or escrow native currency or tokens.

Anyone may transport an exact creation request. Caller identity supplies no
privilege and must not affect the address. Front-running exact deployment is
therefore benign if, and only if, the deployed code and complete configuration
match independently reproduced expectations.

## Forbidden Responsibilities

The factory must never:

- administer, pause, freeze, upgrade, replace, or destroy an account;
- choose or rotate a validator;
- register or exercise recovery authority;
- initialize an existing account;
- execute an account action or call EntryPoint on its behalf;
- custody or release funds;
- grant roles, permissions, approvals, modules, plugins, session keys, or
  paymasters;
- hold identity, validator, recovery, credential, approval, witness, or
  signing secrets;
- bypass Runtime, O.32 hashing, O.33 authority verification, or O.34 account
  enforcement;
- retain a deployer-owner, super-admin, implementation owner, or emergency
  sweep capability.

Factory deployment ownership, if a deployment tool requires a sender, ends
with transaction transport. It creates no role in the deployed factory or
account.

## CREATE2 Derivation

The conceptual address formula is:

```text
initCodeHash =
  keccak256(
    exactAccountCreationCode
    || abi.encode(canonicalInitializationTuple)
  )

deploymentSalt =
  keccak256(
    abi.encode(
      PHILCORE_V2_CREATE2_SALT_V1,
      deploymentChainId,
      accountVersionId,
      securityModelId,
      ownerCommitment,
      identityBindingCommitment,
      userSalt
    )
  )

account =
  last20(
    keccak256(
      0xff
      || factoryAddress
      || deploymentSalt
      || initCodeHash
    )
  )
```

O.35 defines the ordered inputs but does not define an ABI, selector, type
hash, or test vector. Exact encoding and independent vectors require the
future reviewed Solidity creation artifact.

The canonical initialization tuple binds, in order:

1. EntryPoint;
2. deployment chain ID;
3. owner commitment;
4. identity-binding commitment;
5. deploying factory binding;
6. account-version ID;
7. security-model ID;
8. confirmation target;
9. initial validator address;
10. validator verifier kind;
11. validator key-ID binding;
12. validator commitment;
13. validator epoch `1`;
14. primary-device recovery commitment;
15. hardware-security-key commitment;
16. independent recovery-factor commitment;
17. recovery-configuration hash;
18. recovery epoch `1`;
19. recovery delay;
20. recovery expiry.

The `identityBindingCommitment` is a public, domain-separated commitment to
identity continuity. It must not be the repository identity label, a
`phil_secret`, a passphrase, a raw credential identifier, or a reversible
encoding of private identity data. Its exact cryptographic definition is
deferred to the implementation's reviewed hashing phase.

The nonzero `userSalt` is public deployment entropy, not a secret and not an
authorization factor. Reuse of a salt with a different tuple still changes
`initCodeHash`; a different salt always changes the derived address.

## Address-Change Rules

The counterfactual address changes when any creation-bound fact changes:

- factory address;
- deployment chain or EntryPoint;
- identity or owner commitment;
- identity-binding commitment;
- account or security-model version;
- confirmation target;
- initial validator, key binding, verifier kind, or commitment;
- initial recovery commitments/configuration/timing;
- user salt;
- creation bytecode or compiler-linked artifact.

The address does not change when an already active account later:

- rotates its validator under O.34 rules;
- completes recovery;
- rotates recovery configuration;
- advances validator/recovery epochs;
- consumes nonces;
- receives or releases assets.

Changing the proposed initial validator or recovery configuration before
deployment produces a different counterfactual address. After activation,
authorized state transitions update storage at the existing address.

Changing Phil identity changes both identity and owner commitments and must
produce a different account. Preserving the same Phil identity across account
versions preserves those commitments but still produces a new address through
new version, factory, and creation-code bindings.

## Collision And Replay Handling

CREATE2 cannot overwrite code. A future factory may be idempotent only for an
exact existing account:

1. derive the expected address independently;
2. detect existing code;
3. verify runtime bytecode hash;
4. verify every immutable and initial security-state view;
5. return the address only if all checks match;
6. otherwise revert with a collision/configuration error.

No alternate salt, version, implementation, or factory may be selected
automatically. A mismatched occupant is an explicit lifecycle failure.

Cryptographic hash collisions remain a theoretical dependency. The practical
defenses are canonical encoding, domain separation, complete tuple binding,
nonzero salts, independent derivation, source/build reproducibility, and
runtime/configuration verification.

## Constructor-Only Atomic Initialization

The account constructor performs no external call and accepts no native
value. It validates and installs the complete immutable, validator, and
recovery configuration atomically.

There is no public `initialize`, delayed owner registration, temporary
factory ownership, default validator, empty recovery mode, or later activation
transaction. If any required binding fails, contract creation reverts and no
partial onchain account exists.

A successful deployment is `INITIALIZED_ACTIVE_PENDING_INDEPENDENT_VERIFICATION`.
“Pending verification” is an offchain lifecycle status, not an onchain
administrator pause. Funding remains prohibited until independent source,
bytecode, immutable, validator, recovery, nonce, balance, and deposit checks
mark the account `ACTIVE_UNFUNDED`.

## Trust Assumptions

The factory is trusted only for deterministic execution of reviewed code.
PhilCore does not trust:

- the factory deployer;
- the transaction sender;
- an RPC, bundler, explorer, or indexer;
- a manifest without independent code/hash reproduction;
- a claimed counterfactual address without local derivation;
- a successful receipt without post-deployment state checks.

Before accepting a version, reviewers must reproduce source, dependencies,
compiler settings, creation/runtime bytecode, factory bytecode, constructor
encoding, salt, CREATE2 address, and all initial state.

After exact deployment, factory compromise cannot alter the non-upgradeable
account because the factory has no callback, role, registry, implementation
pointer, recovery status, or execution path in the account.

## Phase Boundary

The machine-readable design is
`config/ethereum-sepolia/O35_V2_FACTORY_ACCOUNT_LIFECYCLE_ARCHITECTURE.json`.
It is specification evidence only.

O.35 creates no factory, account, wallet, bytecode, credential, proof,
signature, UserOperation, transaction, funding action, or public mutation.
