# Pre-MVP Security Findings and Dispositions

Status date: 2026-08-20

Phil is pre-production security software. This record summarizes material
security findings that affect the current source tree. It is not an external
audit, a production-readiness certification, or a substitute for independent
review.

## Fixed

### ERC-7562 OP-054 EntryPoint access

The V2 account previously recomputed `getUserOpHash` during `validateUserOp`,
causing a forbidden validation-time `STATICCALL` into EntryPoint code. The
redundant query was removed. The EntryPoint-supplied hash remains nonzero,
bound into the typed authorization request, and verified by the authority
signature.

Regression evidence:

- `test/unit/o37-10-v2-erc7562-op054.test.cjs` traces the real V2 account and
  EntryPoint artifact;
- the trace attributes the exact `validateUserOp` frame and rejects any
  account-originated EntryPoint code or storage access; and
- behavioral tests retain caller, sender, chain, factory, paymaster, fee, and
  authorization-hash checks.

### Runtime redaction traversal limits

The Runtime metadata redactor previously returned an uninspected subtree when
its recursion limit was exceeded. Deeply nested secrets could therefore pass
through redaction and rejection modes. Traversal limits now fail closed:
rejection reports invalid metadata, while redaction replaces the uninspected
subtree and records the issue instead of returning the original container.

Regression evidence is in `test/unit/runtime-redaction.test.cjs` and the
classified product/runtime lane.

### ERC-7562 OP-080 prefund path

The V2 account previously read `address(this).balance` when EntryPoint supplied
nonzero `missingAccountFunds`. Solidity compiled that read to `SELFBALANCE`,
which ERC-7562 blocks for an unstaked account. The account now performs the
narrow value call to EntryPoint without a balance opcode and still fails
closed if the authorized fee cap is exceeded or payment fails.

### ERC-7562 OP-012 GAS adjacency

The compiler placed stack-manipulation opcodes between one `GAS` instruction
and the factory-binding `STATICCALL`. ERC-7562 permits `GAS` only when the next
opcode is a call-family instruction. The binding call now requests the EVM's
maximum available call gas without executing `GAS`; remaining `GAS`
instructions in the validation subtree are immediately followed by their
call-family consumer.

Regression evidence for both OP-080 and OP-012 is in
`test/unit/o37-10-v2-erc7562-validation.test.cjs`.

## Accepted design trade-off

### Recovery quorum outranks validator veto

Validator recovery and recovery cancellation require an exact two-of-three
quorum across the current recovery roles. The active validator is not a fourth
factor and cannot unilaterally veto a valid recovery quorum. This prevents a
compromised or unavailable validator from blocking recovery, while accepting
the residual risk that compromise of any two independently custodied recovery
roles can authorize recovery.

The model is coherent only if the three recovery roles are operationally and
administratively independent. The recovery FSM suite covers the permitted
role pairs, duplicate and ordering rejection, delay, expiry, cancellation,
replay, stale epochs, workflow exclusion, and unrelated-state preservation.

## Current disclosed limitations

- The current `stwo-unlock-keccak-v1` AIR constrains the canonical
  `phil_secret -> identityRoot -> ownerCommitment` relation and its
  action/nullifier context, and the verifier now pins the canonical
  preprocessed-program commitment. It is not a privacy-preserving proof of
  knowledge: serialized STWO queried values expose the direct secret-bit trace
  columns. Proof artifacts must remain local and undisclosed until a reviewed
  witness-hiding construction replaces that layout.
- Apple hardware origin is not cryptographically proven. Native source asks
  for Secure Enclave keys on physical devices and validates WebAuthn
  assertions, but descriptor fields and `appAttestCommitment` do not establish
  Apple attestation. See
  [Secure Enclave Validation Status](./SECURE_ENCLAVE_VALIDATION_STATUS.md).
- No current end-to-end physical-device recovery ceremony has validated the
  full current source.
- No production deployment or public bundler operation is approved. Network
  submission and deployment tooling remains outside the credential-free
  deterministic gate.
- Phil is not fully post-quantum secure. STARK components provide agility, but
  current WebAuthn, validator, account, and recovery authority paths still use
  classical P-256 or secp256k1 cryptography. See
  [Post-Quantum Migration Readiness](../reference/PQ_MIGRATION_READINESS.md).
- Phil-owned code and documentation are generally MIT; the bundled STWO Cairo
  verifier is Apache-2.0; and ten Solidity files retain GPL-3.0-only SPDX
  identifiers. See the root license and third-party notices.
- No external production security audit has been completed. Meaningful assets
  remain prohibited until the documented audit and production gates are met.
- The pinned Slither run reports 97 raw detector signals (1 high, 16 medium,
  48 low, 27 informational, and 5 optimization). All are dispositioned in the
  machine-readable report with zero untriaged, Beta-blocking, or
  production-blocking signals. The high detector signal is the reviewed V2
  native-transfer path protected by the explicit cross-function execution
  lock. This internal triage is not an external audit.
- The current lockfile audit reports no production-dependency vulnerabilities
  and 20 development-tool findings (10 low, 2 moderate, 8 high). The high
  findings are confined to the Hardhat/Solidity toolchain; automatic audit fix
  cannot update them without a major toolchain decision. Public CI therefore
  uses an ephemeral runner, a read-only token, no repository credentials after
  checkout, no secrets, and no deployment or publication authority. The
  machine-readable triage is in
  `config/security/philcore-npm-audit-report.json`.

## Publication boundary

This document intentionally omits internal review transcripts, prompts,
numeric readiness scores, and temporary audit artifacts. Public visibility
also requires a confidential vulnerability-reporting channel and a fresh
review of the exact public candidate.
