# Ethereum Sepolia Threat Model

Status: O.17 pre-mutation review.

| Threat | Prevention | Detection | Recovery / residual risk |
| --- | --- | --- | --- |
| malicious RPC | chain, code hash, address, receipt and event checks; separate bundler | compare independent evidence | change provider; a coordinated provider attack remains possible |
| malicious bundler | exact signed UserOp only; no generic API; fee and expiry bounds | hash/receipt reconciliation | resubmit only after nonce/receipt reconciliation |
| fee inflation | signed gas/fee fields and total ceiling | compare final UserOp and receipt | require new approval if fields change |
| calldata/target/value substitution | typed envelope, nested call hashes, allowlist, zero value | recompute digest and UserOp hash | reject and invalidate approval |
| chain/EntryPoint substitution | locked chain `11155111`, canonical EntryPoint in all hashes | preflight and signer validation | reject |
| nonce manipulation | EntryPoint read immediately before signing/submission | compare bundler and RPC state | rebuild and reapprove |
| deployment-address substitution | accepted manifest, CREATE2 calculation, bytecode checks | post-deploy code/config verification | reject manifest/deployment |
| replay across chain/account | EntryPoint hash chain/sender plus protected action hash | nonce/nullifier and receipt checks | reject |
| stale authorization | short expiry and one-time approvals | clock/receipt checks | restart workflow |
| compromised renderer/preload | renderer displays only; Runtime creates immutable authority | bridge schema and audit correlation | lock identity, invalidate workflow |
| stolen encrypted state | Keychain/vault protection, fresh presence, no key export | integrity/auth failures and audit | revoke/rotate owner through accepted recovery |
| late user-presence result | digest/session/expiry binding | evidence validation | discard and reauthenticate |
| proof/approval swapping | shared action ID and canonical digest | composition validator | reject |
| malicious test target | immutable allowlist, source/hash review, zero value | event/state verification | stop using deployment; contracts are immutable |
| compromised deployer | no admin rights after immutable deployments; role separation | compare accepted bytecode/constructors | redeploy clean family before account use |
| leaked RPC credential | external references, sanitized logs | provider monitoring | rotate credential |
| denial of service | bounded timeout/retry, alternative approved provider | status reconciliation | no availability guarantee |
| receipt spoofing | verify transaction, EntryPoint event, account, target, nullifier and consumer | independent RPC | do not confirm without complete evidence |
| fact injection | authenticated Starknet anchor plus exact proofInputHash split | anchor/verifier state check | fact route remains a major review dependency |
| local-proof attestation bypass | not implemented by current account | architecture self-check | current route requires on-chain fact until accepted change |

## High-Risk Boundary

The current account does not understand a local STWO verification artifact. It
understands only owner signature plus the ActionGate call it executes. The gate
then requires a verifier for the real proof type. Replacing that with a local
boolean or UI claim would be an authorization bypass.

## Security Stage

The controls are suitable for readiness testing. They do not make the custom
account/factory, proof-to-signature composition, recovery model, or public
operations production ready.

