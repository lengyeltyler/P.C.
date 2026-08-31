# O.37.3 V2 Solidity Account And Factory Implementation Conflict Review

Status: `STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY`.

O.37.3 was authorized as the first Solidity implementation attempt after the
O.37.1 recovery-interface correction and O.37.2 deterministic fixture phase.
The mandatory entry review found that the frozen recovery-configuration
rotation authority cannot be transported or positively tested from the
accepted interfaces and fixtures. Implementation stopped before dependency,
compiler, contract, bytecode, or test-authority changes.

Public mutations are zero.

## Verified Baseline

The phase began from:

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `2d271b824ba22b234b65b7950de3c6c88b3033ea`;
- tracked worktree: clean;
- upstream relationship without fetching: `origin/main`, ahead `102`,
  behind `0`;
- Node.js: `26.0.0`;
- npm: `11.12.1`;
- lockfile version: `3`.

The O.20 through O.37.2 canonical documents, O.36.1 machine freeze, O.37.1
descriptor/evidence definitions, and O.37.2 public fixture package were
reviewed. Frozen V1 source bindings remained:

- account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

No V2 Solidity source existed at entry.

## Toolchain Entry State

The repository still has the documented pre-implementation toolchain state:

- configured Solidity: `0.8.24`, not frozen V2 `0.8.27`;
- installed `solc`: `0.8.26`;
- OpenZeppelin Contracts: `5.0.2`, not frozen `5.6.1`;
- Account Abstraction installed: `0.7.0`, but declared as floating `^0.7.0`;
- Hardhat: `2.28.4`;
- Hardhat ethers plugin: `3.0.8`;
- ethers: `6.17.0`;
- optimizer: enabled, `200` runs;
- viaIR: enabled;
- V2-only Cancun override: absent.

O.36.1 and O.37.2 explicitly direct the next approved Solidity phase to apply
the exact pins and V2 compiler override. Those changes are mechanically
resolvable and were not themselves the stop reason. They were deliberately
not applied after the authority-interface blocker was confirmed, so no
partial implementation toolchain remains.

## Blocking Combined-Authority Transport Gap

### Frozen authority rule

O.36.1 and O.37.1 require a recovery-configuration rotation request to be
authorized by:

```text
current execution validator
  plus
exact two of the three current recovery factors
```

The validator cannot count as a recovery factor. Removing either side would
weaken the frozen authority model.

### Available validator transport

The only frozen validator transport is
`ValidatorAuthorityEnvelopeV1`, exact canonical ABI encoding of ten static
fields and exactly `320` bytes. It contains one validator signature and no
recovery evidence.

### Available recovery transport

The only current recovery transport is
`RecoveryAuthorityEnvelopeV2`:

```text
RecoveryEvidenceContextV2 context
bytes firstFactorEvidence
bytes secondFactorEvidence
```

It contains two ordered factor witnesses and no validator envelope or
validator signature.

### Missing combined transport

No accepted O.36.1 or O.37.1 type defines:

- a combined validator-plus-threshold envelope;
- whether the validator envelope precedes or follows recovery evidence;
- offsets, length limits, and canonical re-encoding;
- which duplicated context fields must match;
- how malformed or appended combined bytes are classified;
- whether the validator signs the O.32 config-rotation digest while factors
  sign the recovery digest, and how both digests are bound to one envelope.

The O.32 library defines a config-rotation authorization digest, but a digest
definition does not define transport. Historical O.30 prose mentions a
validator-plus-threshold envelope without freezing its ABI fields or encoding.
O.36.1 supersedes historical envelope choices and requires exact canonical
evidence. Importing or inventing an encoding in Solidity would silently
change the frozen security interface.

The required public account function has no separate authority argument;
authority must therefore arrive in `PackedUserOperation.signature`. Without
one canonical combined encoding, the account cannot decode and verify all
three required signatures without redesign.

## Independent Fixture Blockers

The accepted O.37.2 package contains:

- one native-transfer validator signature fixture;
- one action-type-`8` validator-recovery request;
- primary-plus-hardware and primary-plus-recovery evidence for that request.

It contains no:

- recovery-configuration rotation UserOperation;
- validator signature over the config-rotation authorization digest;
- two-factor evidence over the same rotation intent;
- canonical combined authority bytes;
- accepted combined-envelope hash or decode/re-encode vector.

Therefore O.37.3 cannot perform the required positive Solidity test for
current-validator-plus-exact-2-of-3 configuration rotation using only accepted
O.37.2 material.

The accepted native-transfer fixture also binds reserved fixture account
`0x00000000000000000000000000000000000F3702`, reserved fixture EntryPoint
`0x00000000000000000000000000000000000F4337`, validator epoch `3`, and
recovery epoch `2`. Frozen constructor initialization requires epochs `1` and
`1`, and a normal CREATE2 deployment cannot be assumed to land at that
reserved address. O.37.2 provides no accepted transition sequence from the
initial state to the fixture state. A production-account acceptance test
would therefore require unreviewed state injection, a test-only security
override, or newly generated authority. None is an acceptable substitute for
an exact integration vector.

## Secondary Instruction Conflicts

The O.37.3 request also asks the account to keep mutable nonce-lane state,
while O.36.1 explicitly assigns keyed nonce sequences to EntryPoint v0.7 and
forbids a duplicate nonce mapping. The frozen rule must prevail, but the
implementation request should be corrected so future work does not add
forbidden replay storage.

The O.37.3 request asks constructor initialization to validate recovery
descriptors, while the frozen 20-field constructor contains only three
descriptor commitments and a configuration hash. O.37.1 assigns full
descriptor validation to Runtime before atomic deployment; the account can
check only nonzero/distinct commitments and recompute the version-2
configuration hash. Adding descriptors to the constructor would change the
frozen ABI and CREATE2 derivation.

## Unsafe Choices Rejected

O.37.3 does not:

- concatenate validator and recovery envelopes without a type definition;
- wrap both envelopes in a new tuple;
- accept a validator-only or recovery-only config rotation;
- reuse the retired combined-cancellation envelope;
- treat a Runtime Boolean as validator authority;
- add an authority parameter to the frozen function;
- add a registry, module, ERC-1271 path, or external verifier;
- inject fixture account state to manufacture an integration success;
- generate unreviewed replacement fixtures;
- add duplicate nonce storage;
- expand constructor initialization with descriptors.

Each choice either weakens authority or changes frozen ABI, evidence,
storage, fixture, or CREATE2 behavior.

## Required Resolution

A separately reviewed interface/fixture phase must:

1. freeze one canonical combined validator-plus-exact-2-of-3 authority
   envelope, including exact ABI types, offsets, maximum lengths, canonical
   re-encoding, duplicated-field equality, and failure taxonomy;
2. state the exact validator and factor digests verified inside that envelope;
3. update the O.36.1 machine freeze and O.37.1 evidence specification;
4. extend O.37.2 with public accepted and rejected config-rotation
   `PackedUserOperation` and combined-authority fixtures;
5. provide a deployable integration-vector strategy whose account,
   EntryPoint, epochs, and CREATE2 state can be reproduced without storage
   injection or a security override;
6. clarify that EntryPoint owns nonce sequences and that constructor inputs
   remain the frozen commitment-only 20 fields;
7. rerun architecture and security review before Solidity resumes.

Only after that resolution should a fresh implementation phase apply Solidity
`0.8.27`, OpenZeppelin `5.6.1`, exact Account Abstraction `0.7.0`, Cancun, and
the remaining deterministic compiler settings.

## Stop Boundary

No Solidity contract, support library, mock, compiler override, dependency
pin, ABI, storage layout, creation bytecode, runtime bytecode, deployment,
account, credential, signature, UserOperation, RPC call, funding action, or
public mutation was created. V1 remains unchanged. Future Solidity and any
deployment require separate approval after the combined-authority interface
and fixture package are complete.

## O.37.4 Resolution

O.37.4 resolves this documented interface blocker without implementing
Solidity. It preserves the direct 320-byte validator envelope and direct
O.37.1 recovery envelope, and defines one canonical combined envelope for
action type `10`:

```text
abi.encode(
  uint8 envelopeVersion,
  uint8 authorityKind,
  uint8 actionType,
  bytes validatorEvidence,
  bytes recoveryEvidence
)
```

The outer header is exactly version `1`, authority kind `3`, action `10`.
Validator evidence remains the exact O.36.1 envelope; recovery evidence
remains the exact O.37.1 action-`10` envelope. Canonical re-encoding, exact
length bounds, action dispatch, digest separation, failure classification,
and deterministic accepted/rejected vectors are now frozen.

O.37.4 also confirms that EntryPoint exclusively owns keyed nonce sequences
and that initialization remains the 20-field commitment-only constructor.
The historical O.37.2 package is preserved byte-for-byte; its limitation is
addressed by a separate versioned O.37.4 test package.

This resolution removes the transport-design blocker only. Solidity,
toolchain changes, executable UserOperation integration fixtures, ABI,
storage layout, bytecode, and deployment remain subject to a fresh,
separately approved implementation phase.
