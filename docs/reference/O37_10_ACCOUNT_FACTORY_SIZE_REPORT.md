# O.37.10 Account and Factory Size Report

Status: `ALL_SIZE_GATES_ACCEPTED`.

Build: Solidity `0.8.27`, Cancun, optimizer enabled with 200 runs, viaIR,
OpenZeppelin `5.6.1`, Account Abstraction `0.7.0`.

| Contract | Runtime | Creation | EIP-170 reserve | Result |
| --- | ---: | ---: | ---: | --- |
| unchanged verifier | `12645` | `12671` | `11931` | accepted |
| minimal account V2 | `13811` | `15630` | `10765` | preferred gate accepted |
| minimal factory V2 | `18317` | `18692` | `6259` | accepted |

The account runtime is `1549` bytes below the preferred `15360`-byte target
and `6669` bytes below the reviewed `20480`-byte maximum. Its canonical
sample 20-field init code is `16270` bytes, leaving `32882` bytes below the
EIP-3860 limit.

The factory deployment init code, including its five constructor arguments,
is `18852` bytes and leaves `30300` bytes below EIP-3860. Its runtime includes
the exact account creation code and still retains meaningful EIP-170 reserve.

Dominant account contributors are fixed-word canonical ABI decoding and O.32
hashing, complete ERC-4337 checks, factory/verifier static-call binding, and
the delayed recovery transitions. Dominant factory contributors are embedded
account creation code, canonical initialization checks, and CREATE2
derivation/deployment. viaIR inlining makes per-function byte attribution
misleading, so no synthetic byte counts are claimed.

Exact bytecode hashes and measurements are in
`config/solidity/O37_10_SIZE_REPORT.json`.
