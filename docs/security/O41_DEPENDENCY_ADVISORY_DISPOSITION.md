# O.41 Development Dependency Advisory Disposition

> Historical O.41 snapshot. For the current lockfile counts and the rule for
> interpreting older reports, see
> [Dependency Advisory Status](./DEPENDENCY_ADVISORY_STATUS.md).

The 2026-07-30 refresh reports zero production dependency vulnerabilities:
`npm audit --omit=dev --json` returned 0 Low, Moderate, High, and Critical.
The complete pinned tree remains 10 Low, 2 Moderate, 8 High, 0 Critical.
O.41 does not change the frozen Solidity, Hardhat, OpenZeppelin, Account
Abstraction, or ethers versions.

| High group | Current range | Path / advisory effect | Fix reported | O.41 enrollment reachability |
| --- | --- | --- | --- | --- |
| `@nomicfoundation/hardhat-ethers` | `<=3.1.3` | Hardhat plugin aggregate | 4.0.15, major | not loaded by recovery startup |
| `adm-zip` | `<0.6.0` | Hardhat; crafted ZIP can allocate excessive memory | Hardhat 3.12.0, major | not loaded |
| `brace-expansion` | `<=5.0.7` | Hardhat → Mocha → glob/minimatch; expansion DoS/OOM | compatible transitive fix reported | not loaded |
| `hardhat` | `0.1.0-rc.0–3.11.1` | aggregate of local Solidity/tooling advisories | 3.12.0, major | lazy, outside enrollment |
| `immutable` | `<=4.3.8` | Hardhat; trie overflow/hash-collision DoS | compatible fix reported | not loaded |
| `serialize-javascript` | `<=7.0.4` | Hardhat → Mocha; crafted-object RCE/CPU exhaustion | compatible fix reported | not loaded |
| `tmp` | `<=0.2.5` | Hardhat/solc; traversal and symlink-sensitive temporary paths | audit proposes incompatible solc change | not loaded |
| `undici` | `<=6.26.0` | Hardhat HTTP/WebSocket handling; injection, smuggling, and DoS groups | Hardhat 3.12.0, major | not loaded |

“Not loaded” is tested, not inferred from the `dev` flag. The desktop
Runtime now lazy-loads the two legacy Hardhat-backed local authorization
modules. Requiring the desktop Runtime and O.41 recovery environment leaves
all eight High groups absent from the Node module cache. O.41 accepts no
untrusted repository, ZIP, glob, serialized object, temporary path, HTTP
response, or WebSocket input. The local HTTPS service uses Node core
`https`, not `undici`.

Hardhat and its vulnerable transitive packages remain in the broad local
Alpha package for pre-existing developer workflows. Invoking those
workflows is outside the recovery enrollment path and remains governed by
the existing development-tooling risk acceptance/Beta gate. Removing or
upgrading them would alter frozen build tooling and requires a separate
compatibility review.

Therefore:

- reachable High/Critical in the production enrollment path: 0;
- packaged but lazy/out-of-path High groups: 8;
- complete-tree Critical: 0;
- Solidity build impact: unchanged;
- Electron recovery impact: no High/Critical module is loaded by startup or
  the O.41 ceremony.
