# O.38 Clean-Build Reproducibility Report

Status: `REPRODUCIBLE_EXACT_MATCH`.

O.38 copied only the tracked repository state to a disposable directory
outside the active worktree. The copy initially contained no `.git`,
`node_modules`, Hardhat cache, artifacts, ignored configuration, or
environment file. Node `26.0.0` and npm `11.12.1` installed the lockfile-v3
graph with `npm ci --ignore-scripts --no-audit --no-fund`. Hardhat then
compiled 60 Solidity files using the repository-pinned local solc.

The isolated regression passes exposed five historical tests that still
assumed only the O.37.7 verifier existed and one test that intentionally uses
`git ls-files`. This was not artifact drift. O.38 updated those historical
source-boundary assertions to admit exactly the six reviewed O.37.10 V2
sources while leaving each older phase's recorded zero-Solidity/conflict
boundary unchanged. The final isolated regression environment initializes
disposable Git metadata over the tracked snapshot solely for the
`git ls-files` conformance check.

## Reproduced package

| Contract | Runtime keccak256 | Creation keccak256 | Result |
| --- | --- | --- | --- |
| Static verifier | `0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be` | `0xf4b02d44bf35dd9968866754cf59930936f95a939fecf6e5f25ad4631d17f332` | exact |
| Minimal account | `0x4f0ea630700c155eb69d7661161abebdcf74dc734127131ad2dfa48dd141e3c5` | `0x19b09241c4a1c2f4c02bf361cea97bdbfcc3b91cce37b1d99cbb1b9de9ac0d9b` | exact |
| Factory | `0x4359422db2c5320d3c7914a414766fff29779fa45859e0fe28b4af0a67860e90` | `0x5b9263755de1b9a686c240ff0d799bc62a595a42a2471ef0a1d5b84697538632` | exact |

The account, factory, and verifier ABI hashes; account and factory storage
layout hashes; sample account creation-code hash; CREATE2 vectors; and O.37.2
and O.37.4 deterministic fixture packages also matched. No metadata
difference was observed.

The final isolated gate compiled 60 Solidity files, passed TypeScript
typechecking, passed all six deterministic regeneration/runtime checks, and
passed **216** relevant O.32–O.38 tests with zero failures. The O.37.10
deterministic implementation evidence check remained current, and the
isolated tracked snapshot ended without a diff.

Compiler settings remained Solidity `0.8.27`, Cancun, optimizer enabled with
200 runs, `viaIR: true`, literal source content, IPFS bytecode metadata, and
CBOR appended.

Machine evidence:
`config/solidity/O38_REPRODUCIBILITY_EVIDENCE.json`.

This gate reproduced local artifacts only. It created no address, signature,
credential, transaction, or public mutation.
