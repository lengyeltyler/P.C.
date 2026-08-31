# Contributing

PhilCore welcomes careful, bounded contributions. The system has several locked surfaces, so changes should be narrow, testable, and explicit about what they do not change.

## Development Style

Prefer bounded passes:

- lock one exact target
- implement the smallest honest seam
- preserve existing runners and artifacts unless replacement is explicitly required
- add focused regression coverage for the behavior touched
- document final status honestly

Avoid broad rewrites or architecture redesigns inside implementation passes.

## Locked Surfaces

Do not change these casually:

- `phil_secret -> identityRoot -> ownerCommitment`
- `ACTION_UNLOCK`
- Base public tuple semantics
- `proofType = "stwo-unlock-keccak-v1"`
- verified `proofInputHash` as the canonical security object
- `[fact_high, fact_low]` fact shape

If a proposal needs to touch one of these, open a design discussion before writing code.

## Local-First Validation

Use the credential-free deterministic lanes before proposing a change:

```bash
npm run ci:validate-classification
npm run ci:lane:product-runtime
npm run ci:lane:solidity
npm run ci:lane:desktop
```

For proving changes, also run:

```bash
npm run test:proving
```

The broad `test:unit` command also includes environment-dependent, manual, and
historical expected-failure suites. It is not the public green gate.

Pull requests from forks run the credential-free Linux lanes without secrets
or write permissions. The macOS Desktop lane is limited to maintainer branches
and manual dispatch to control hosted-runner cost; maintainers must run it on a
reviewed branch before merge when Desktop code or dependencies change.

## Generated Files

Do not commit generated noise:

- `node_modules/`
- Hardhat `artifacts/` and `cache/`
- Cairo/Rust `target/`
- `proving/out/`
- local `.env` files

If a generated artifact is needed as a public fixture, add it intentionally in a narrowly scoped pass and document why it is safe.

## Secrets

Never commit:

- real private keys
- real RPC credentials
- real API tokens
- real Phil secrets
- production signing material

The local device-signing flow uses deterministic local dev signing material for local drills only. Do not reuse it for real funds or production accounts.

## Pull Request Expectations

A good PR explains:

- the exact behavior changed
- which locked surfaces remain unchanged
- which local commands were run
- whether generated artifacts were intentionally added or ignored
- what remains out of scope

Keep changes reviewable. Source, tests, scripts, and docs should move together when behavior changes.
