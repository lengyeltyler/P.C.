# O.38 Dependency Integrity Report

Status: `PASS_FOR_FROZEN_V2_BUILD`.

The clean build used Node `26.0.0`, npm `11.12.1`, and lockfile version 3.
`.node-version`, `engines`, and `packageManager` agree exactly. The compiler
override resolves the installed `solc@0.8.27` package and rejects any other
0.8.27 binary identity.

## V2 build graph

| Package | Declared | Installed | V2 use |
| --- | ---: | ---: | --- |
| `solc` | `0.8.27` | `0.8.27` | compiler |
| `hardhat` | `2.28.4` | `2.28.4` | build driver |
| `@nomicfoundation/hardhat-ethers` | `3.0.8` | `3.0.8` | local test/deployment adapter |
| `@openzeppelin/contracts` | `5.6.1` | `5.6.1` | verifier cryptography |
| `@account-abstraction/contracts` | `0.7.0` | `0.7.0` | EntryPoint interfaces and implementation |
| `ethers` | `6.17.0` | `6.17.0` | evidence and tests, not Solidity source resolution |

Every direct dependency that can alter V2 compilation is an exact version.
The lockfile fixes every transitive package and integrity hash used by
`npm ci`.

One unrelated desktop dependency, `electron`, is declared as `^39.8.10`.
That declaration is not reachable from the Hardhat/Solidity source graph and
the clean build still resolves it from the exact lockfile. It therefore
cannot alter the canonical V2 artifact under the required `npm ci` method.
O.38 records the declaration rather than changing a dependency outside this
phase's frozen package.

No Git branch, Git URL, floating tag, wildcard, or unpinned direct dependency
can affect the V2 compilation. Exact integrity values are retained in
`config/solidity/O38_DEPENDENCY_INTEGRITY_EVIDENCE.json`.
