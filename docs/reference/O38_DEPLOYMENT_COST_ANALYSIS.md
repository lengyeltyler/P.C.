# O.38 Deployment Cost Analysis

Status: `LOCALLY_BOUNDED_LIVE_FEES_NOT_SAMPLED`.

All values below are gas units measured on ephemeral Hardhat chain `31337`
with the exact O.37.10 compiler artifacts and the real
`@account-abstraction/contracts@0.7.0` EntryPoint. They are not live Sepolia
fee estimates.

| Operation | Expected gas | Conservative ceiling | Class |
| --- | ---: | ---: | --- |
| Static verifier deployment | 2,787,109 | 3,350,000 | one-time infrastructure |
| Factory deployment | 4,015,425 | 4,825,000 | one-time infrastructure |
| Account CREATE2 deployment and initialization | 2,995,764 | 3,600,000 | per account |
| Initial EntryPoint deposit transaction | 45,599 | 75,000 | per account; deposit value separate |
| Native ETH UserOperation | 151,886 | 250,000 | per operation |
| Confirmation UserOperation | 211,104 | 300,000 | per operation |
| Validator rotation | 150,660 | 250,000 | per operation |
| Recovery initiation | 348,337 | 500,000 | per recovery |
| Recovery cancellation | 236,101 | 350,000 | per recovery |
| Recovery completion settlement | 50,944 | 100,000 | per recovery |
| Recovery configuration request | 424,904 | 600,000 | per configuration rotation |
| Recovery configuration cancellation | 233,548 | 350,000 | per configuration rotation |
| Recovery configuration completion | 57,474 | 110,000 | per configuration rotation |
| EntryPoint deposit withdrawal | 154,956 | 250,000 | per operation |

The recovery request/cancellation account lifecycle samples use the exact
account and EntryPoint with a fixed test verifier so timing and state
transitions can be exercised against the local account. Their expected rows
conservatively add separately measured real O.37.7 verifier calls:
119,791 gas for a recovery envelope and up to 176,124 gas for a combined
validator/recovery envelope. The ceilings retain additional margin and are
the authorization-relevant values.

Account initialization is constructor work and cannot be paid separately
from account deployment. An EntryPoint deposit is required before sponsored-
free UserOperations unless the account carries enough native ETH for
`missingAccountFunds`; the proposed rehearsal uses a deposit because the
withdrawal release path is explicitly tested.

Variability includes calldata byte mix, WebAuthn evidence length, authority
class, cold/warm accesses, storage transition direction, beneficiary and
recipient behavior, and prefund/deposit state. Any later estimate exceeding
a ceiling invalidates the deployment proposal.

## Bounded first rehearsal

The bounded plan includes 12,650,000 gas of conservative ceilings for the
verifier, factory, account, deposit, confirmation, native transfer, and
deposit-withdrawal sequence. At a separately approved maximum fee ceiling of
10 gwei:

- ceiling gas cost: `0.1265 ETH`;
- 25% gas reserve: `0.031625 ETH`;
- recoverable initial EntryPoint deposit: `0.005 ETH`;
- recoverable native account balance: `0.001 ETH`;
- minimum bounded wallet balance: **`0.164125 ETH`**.

This is an ETH-only funding bound, not a current fee recommendation or
funding approval. The later phase must refresh live fees and stop if its
approved maximum fee exceeds 10 gwei, a gas ceiling changes, or either
release path is not demonstrably available. No funds moved in O.38.

Machine evidence:
`config/solidity/O38_LOCAL_GAS_EVIDENCE.json`.
