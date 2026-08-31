# Onchain STARK Verification Assessment

## Current Finding

The frozen raw `stwo-unlock-keccak-v1` proof format is not currently supported
for direct Solidity verification. The repository has no accepted Solidity
verifier generator or deployed Solidity verifier for these raw STWO bytes.

The decisive verifier spike measured:

- proof-blob calldata gas: `6,832,752`;
- boundary lower-bound gas: `17,110,790`;
- boundary plus authentic verifier slice: `17,126,660`;
- backend-backed gate path: `17,127,260`.

The result was a no-go for direct trustless Base verification of the frozen raw
proof boundary. This was a practical feasibility finding, not merely an
unfinished implementation.

## Existing Contract Boundary

`PhilBaseActionGate` accepts:

- the bounded authorization;
- the proof package;
- raw consumer data.

For `stwo-unlock-keccak-v1`, it calls the configured
`IPhilUnlockProofVerifier`. The production-shaped implementation reads a fact
mirrored through Starknet, Ethereum L1, and Base. The account itself validates
the ERC-4337 signature and restricts the target/selector; it does not parse the
STWO proof.

## Possible Future Locations

| Location | Assessment |
| --- | --- |
| Inside `PhilCore4337Account` | Not recommended. It couples a large evolving verifier to account validation, raises validation-gas risk, and complicates account migration. |
| Validator module | Architecturally cleaner for a future compact proof/signature scheme, but the current account is non-modular and ACP-0002 is still proposed. |
| Dedicated verifier contract | Best separation if a practical EVM-verifiable proof format is produced. ActionGate can bind to a versioned verifier without making the account a proof VM. |
| Mirrored fact verifier | Current production-shaped direction. Verification/fact origin occurs outside Base and a bounded fact is transported to Base. |

## Upgrade And Replay Requirements

Any future verifier must:

- identify the proof and public-input schema version;
- bind the exact eight-field public tuple;
- reject unsupported or retired verifier versions;
- expose a clear verifier allowlist/migration policy;
- preserve `proofInputHash` and fact-pair parity;
- preserve nullifier replay protection in ActionGate;
- account for ERC-4337 validation gas and bundler simulation constraints;
- avoid making a proof result generic signing authority.

Old proofs are bounded by expiry, nullifier use, proof type, verifier
configuration, and policy. A verifier retirement mechanism would require an
explicit architecture/contract change; it does not exist as a generic upgrade
switch in the current immutable account.

## Recommendation

For the first Base Sepolia integration, keep proof generation and verification
local and use the existing exact Runtime/M.9/M.10 binding to release only one
UserOperation signature. Do not claim this is onchain STARK verification.

A later onchain phase should begin only after selecting a practical proof
format or preserving the cross-domain mirrored-fact route, then completing
independent gas, calldata, verifier correctness, upgrade, and bundler
compatibility review.

