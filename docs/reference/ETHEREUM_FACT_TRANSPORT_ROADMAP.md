# Ethereum Fact-Transport Roadmap

This roadmap concerns `ethereum-fact-enforced-v1`; none of these routes is
implemented or accepted by O.18.

| Route | Trust | Cost/latency | Main dependency | Stage fit |
| --- | --- | --- | --- | --- |
| Direct Ethereum verifier | Ethereum cryptography | Highest gas, one verification transaction | EVM-compatible audited verifier | Production candidate if feasible |
| Recursive/optimized verifier | Ethereum verifies compressed proof | Prover complexity, lower gas | New proof system and audit | Beta/production research |
| Dedicated fact registry | Depends on authorized writer/verifier | Moderate; extra publication transaction | Registry governance and replay model | Beta only with explicit trust |
| Authorized attestor/relay | Trusts operator signature | Low gas/latency, censorship risk | Operator custody/availability | Alpha/Beta bridge, never equivalent to STARK verification |
| L2 verification and mirror | L2 verifier plus bridge security | Multiple transactions and finality latency | Starknet/L1/Base route and relayers | Current stronger architecture candidate |
| Validator module consuming fact | Depends on fact source | Efficient execution after publication | Modular account migration | Production architecture candidate |

Every route needs domain binding, duplicate/replay protection, expiry,
availability monitoring, failure recovery, and an explicit operator model.
Upgradeability increases repair options and governance risk; immutable
deployments require migration.

Recommended sequence: run only a human-approved disposable Model A experiment,
continue the existing L2-to-Ethereum fact transport work independently, then
deploy a separately reviewed Model B account. Model A evidence must not be
promoted into Model B evidence.
