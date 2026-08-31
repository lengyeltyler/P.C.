# Sepolia Fact-Enforcement Decision

Status: Conditionally Approved for Disposable Sepolia Preparation

## Decision

PhilCore must preserve two separate execution models:

| Model | Identifier | STWO enforcement | Ethereum enforcement |
| --- | --- | --- | --- |
| Local proof gated | `local-proof-gated-v1` | Runtime and Device Vault require local generation and verification before signing | Exact structured signature, UserOperation hash, EntryPoint, nonce, fixed account call, expiry, and no paymaster |
| Ethereum fact enforced | `ethereum-fact-enforced-v1` | Local checks remain defense in depth | ActionGate additionally requires Ethereum-visible verified-fact evidence |

The existing `PhilCore4337Account` cannot execute from local STWO verification
alone. Its only ordinary execution route calls `ActionGate.verifyAndConsume`,
which requires verifier evidence visible to the EVM. A local verifier result is
not Ethereum state and cannot satisfy that contract.

For one disposable, controlled Ethereum Sepolia experiment, Model A is
approved for guarded deployment preparation and read-only inspection only. The
approval does not authorize deployment, funding, signing, transaction
submission, UserOperation submission, or manifest acceptance. It is not
approved for meaningful assets, mainnet, Beta, or production, and must never
be described as on-chain STARK verification.

## Trust Change

Model A trusts the PhilCore Runtime, Device Vault, fresh platform presence, and
the local operating environment to refuse signing until the proof and all
authorization artifacts match. Ethereum cannot independently detect a forged
local proof result if a compromised local signing boundary signs anyway.

Ethereum still prevents signature forgery, mutation of the signed operation,
nonce replay, alternate EntryPoint/account domains, paymaster injection, expiry
bypass, and execution outside the account's one fixed call.

## Separation

The canonical fact-enforced contracts remain unchanged. Model A uses separately
named contracts and a separately proposed manifest. No deployment may switch
between models.

## Migration

Model B requires an accepted Ethereum-visible fact route: a direct verifier,
fact registry, or independently accepted transport such as the existing
Starknet-to-L1-to-Base design. Migration requires a new accepted deployment and
does not reinterpret Model A receipts as fact-enforced evidence.
