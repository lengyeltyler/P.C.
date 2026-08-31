# O.39 Solidity, Test, and Readiness Evidence

## Contract package

The Solidity compiler remains 0.8.27, Cancun, optimizer 200, and `viaIR`.
Dependencies and ABI surface were not expanded.

| Contract | Runtime bytes / hash | Creation bytes / hash | Storage |
| --- | --- | --- | --- |
| Static verifier | 13,048 / `0x665910b9989f3b83c3f025314fb127755d5abfc46e66ee386fbcbbfefc864dd7` | 13,074 / `0xe77412fbb2d5c2e3bc44881822442e38d3fcc7f2e2dd992742111db6f4511494` | zero slots |
| Minimal account | 13,811 / `0x4681ca917e3b5c3fff72bb6020f3fb278a43ab893beb05e36865b50422f64519` | 15,630 / `0x7fa7fd5dd4a886e6df8ca13223c5dd3cb167c358e0abf9b0297c2a4624cb4882` | frozen 15 slots |
| Factory | 18,317 / `0x15eca82e16f99f3ea5d9f8443871fc059bb050a8f30856d017be49d0e97c0d95` | 18,692 / `0xe069c2fe769777cb53c785a05f57aee1b73188a8ea343d0d097503806fe9af84` | zero slots |

Verifier runtime passes 20,480 bytes. Account runtime/creation pass
15,360/18,432 bytes. Factory runtime passes EIP-170.

Account and factory sizes are unchanged from O.37.10 but their hashes change
because the version/configuration constants changed. Verifier grew 403
runtime bytes for the second exact Role 1 tuple and canonical origin-policy
checking. ABI component names and
account storage remain unchanged. Machine-readable ABI and storage-layout
hashes are in
`config/solidity/O39_CONSUMER_RECOVERY_IMPLEMENTATION_EVIDENCE.json`.

Historical V1 sources remain:

- account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

## O.40 historical hash erratum

The original O.39 machine evidence mislabeled three manually entered values
as its initial V2 runtime hashes. They were not hashes of any tracked O.38
artifact. O.40 reproduced commit
`25bffe61ff008a85e29c24a32e8ca2f5550c4855` in a clean tracked-only copy
and obtained the canonical O.38 verifier/account/factory runtime hashes
`0x4597c970…b1b5be`, `0x4f0ea630…1e3c5`, and
`0x4359422d…60e90` exactly. The O.39 pre-change package was that same O.38
package.

The O.39 evidence generator now records both the erroneous historical
strings and the corrected chronology. This is a reporting transcription
error, not compiler drift, repository corruption, or an unexplained
artifact change. The post-change hashes at the top of this document remain
unchanged.

## Fixture and lifecycle coverage

The deterministic O.39 package contains Standard and Enhanced profiles,
three public descriptors each, all six profile/pair envelopes, and 16 named
invalid classifications. Private scalars, recovery codes, production
credential IDs, and production signatures are absent.

The isolated O.32–O.39 regression passed **229 tests** with zero failures;
O.39 contributes 13 focused tests.

Focused tests cover registration policy, secure-storage handoff, backup
flags, offline format/checksum/restoration, duplicate credential/public
material/custody domains, role substitution, validator aliasing, stale
generation, invalid class, prohibited sync, degraded assurance, altered
independence binding, exact one-role rotation, all six real verifier
envelopes, and request/evidence mutation.

The account lifecycle suite covers initialization and CREATE2 reproduction,
EntryPoint replay, native execution, confirmation, validator rotation,
recovery initiation/cancellation/delay/completion/expiry, active-recovery
execution freeze, configuration rotation, reentrancy, deposit release, and
verifier binding. Descriptor-level tests cover replacement of roles 0, 1,
and 2 with exact generation increments. Configuration rotation still
requires current validator plus exact 2-of-3 recovery authority.

Pinned Slither 0.10.4 found the same 23 V2 detector occurrences classified
in O.38: one High, six Medium, seven Low, eight Informational, and one
Optimization. No new detector family appeared. The High/Medium reentrancy
reports remain guarded bounded calls with execution-lock regression
coverage; timestamp, assembly, low-level-call, complexity, numeric-syntax,
and immutable suggestions remain reviewed informational/optimization
findings. Unmitigated High: zero. Unmitigated Critical: zero.

## Readiness decision

Classification:
**B — Recovery enrollment foundation complete, user ceremony required**.

The 20-field tuple is fully dry-runnable with synthetic values, but
production fields 14–17 remain unavailable until the real ceremony.
Infrastructure fields, the final user salt, and any public deployment remain
future work. O.38 artifact hashes are intentionally invalidated; its tooling
now fails closed at artifact comparison.

There were zero public mutations, external RPC calls, production
credentials, production signatures, UserOperations, or deployments in
O.39. External audit remains mandatory before meaningful real-value use.
