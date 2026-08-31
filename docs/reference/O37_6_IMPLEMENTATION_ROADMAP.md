# O.37.6 V2 Minimal Solidity Implementation Roadmap

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION`.

The next phase may implement locally only after separate approval. Its
canonical objective is:

> implement and measure the O.37.6 static verifier, minimal account, and
> minimal version-specific factory without deployment or live authority.

## Implementation Order

### 1. Static authority verifier

- pin the O.37.5 frozen compiler and dependencies;
- implement the exact O.32/O.37.1/O.37.4 verification path;
- use reviewed OpenZeppelin WebAuthn/P-256 fallback behavior;
- expose one versioned view verification function and immutable constants;
- prohibit storage, admin, proxy, registry, callbacks, value, fallback,
  `DELEGATECALL`, and `SELFDESTRUCT`;
- verify O.37.2 and O.37.4 fixtures;
- require runtime size at or below `20480` bytes.

Stop if the verifier alone exceeds its budget. Do not split it without a new
architecture review.

### 2. Minimal account

- keep the exact 20-field constructor;
- implement only actions `1`, `2`, `6`, `7`, `8`, `9`, `10`, `11`;
- reject token action values and selectors;
- retain EntryPoint caller/sender/paymaster/nonce/fee/validity checks;
- obtain immutable verifier binding from the bound factory;
- check verifier code hash and use `STATICCALL` only;
- retain all validator/recovery state and lifecycle transitions;
- require runtime at or below `15360` bytes;
- require creation code at or below `18432` bytes.

### 3. Minimal factory

- fix EntryPoint, chain, confirmation target, version/security identifiers,
  verifier address, and verifier code hash;
- embed only exact minimal account creation code;
- preserve O.35 deployment salt and 20-field constructor encoding;
- accept no caller-supplied code or value;
- require shell at or below `4096` bytes;
- require total runtime at or below `22528` bytes.

### 4. Evidence and adversarial review

Generate deterministic:

- compiler input/output;
- ABI and selector allowlist/denylist;
- storage layout;
- creation/runtime bytecode and hashes;
- opcode report;
- source-map size attribution;
- verifier code-identity vectors;
- CREATE2 vectors;
- O.37.2/O.37.4 fixture results.

Tests must cover wrong verifier address/code hash, missing code, malicious
return data, verifier revert, reentrancy attempt, `STATICCALL` enforcement,
all malformed authority vectors, stale epochs, replay, recovery lifecycle,
unsupported token selectors, and every forbidden ABI/opcode.

## Acceptance Gates

All must be true:

- verifier runtime `<= 20480`;
- account runtime `<= 15360`;
- account creation code `<= 18432`;
- factory shell `<= 4096`;
- factory runtime `<= 22528`;
- no compiler size warning;
- no `DELEGATECALL`, `SELFDESTRUCT`, proxy or admin storage;
- no duplicate nonce;
- O.37.2 and O.37.4 fixtures unchanged and passing;
- V1 and historical O.37.4/O.37.5 hashes unchanged;
- no retained artifact contains absolute paths, credentials, or environment
  values.

Failure of one gate stops the phase before retaining a partial implementation.

## Migration And Capability Versions

The minimal account is a new version and address. It does not retrofit V1 or
the historical O.37.4 full profile. A future token-capable version receives a
new account-version ID and factory. Migration uses fresh typed authority and
only capabilities actually supported by the source account.

There are no modules, plugins, sessions, proxies, or upgrade transactions.

## Stop Boundary

Even after a successful next implementation phase, deployment, RPC, funding,
credentials, production signatures, UserOperations, and public mutation
remain separately gated.
