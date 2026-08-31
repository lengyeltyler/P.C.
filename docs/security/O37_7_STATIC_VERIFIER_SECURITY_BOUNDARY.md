# O.37.7 V2 Static Verifier Security Boundary

Status: `COMPLETE_STATIC_VERIFIER_ONLY`.

O.37.7 implements only the stateless verifier selected by O.37.6. It does not
implement an account, factory, deployment path, recovery state machine, or
validator-management method.

## Enforced By The Verifier

The verifier enforces:

- exact caller/account equality;
- minimal-profile action allowlisting;
- O.37.4 authority-class dispatch;
- canonical outer and nested ABI encoding;
- exact validator address, key-ID, validator epoch, and recovery epoch;
- low-s secp256k1 recovery over the exact validator or configuration-rotation
  digest;
- recovery context parity for account, chain, EntryPoint, authorized intent,
  UserOperation hash, request, validity, epochs, proposals, timing, and
  commitments;
- configuration version `2`, threshold `2`, and bitmap `3`, `5`, or `6`;
- ascending factor-role order and exact descriptor membership;
- complete role-specific descriptor policy;
- WebAuthn RP-ID, UP, UV, single-device backup flags, type, challenge,
  public point, and low-s P-256 signature;
- purpose-bound low-s secp256k1 recovery-factor signatures;
- combined action `10` with distinct validator and exact 2-of-3 recovery
  authority.

OpenZeppelin P-256 first uses the fixed RIP-7212 address and falls back to its
reviewed Solidity implementation. It does not call a selectable verifier.

## Enforced By The Future Account

The verifier cannot know authoritative account state because it has no
storage. The future minimal account must:

- derive every request field from immutable configuration, current storage,
  exact typed calldata, and the exact UserOperation;
- supply its immutable account-version and security-model IDs;
- check the verifier address and runtime code hash before every `STATICCALL`;
- accept only exact success magic and reject malformed return data;
- enforce EntryPoint caller, sender, nonce, fee, validity, freeze, recovery
  state, proposal, timing, and execution transitions;
- never accept request fields or a success Boolean from Runtime.

Calling the verifier directly does not grant account authority. Its result is
meaningful only inside the code-hash-pinned account boundary.

## Static Properties

Compiler storage layout is empty. Executable opcode inspection finds:

- no `SSTORE`;
- no `CREATE` or `CREATE2`;
- no `DELEGATECALL` or `CALLCODE`;
- no `SELFDESTRUCT`;
- no event log opcode.

The verifier has no constructor argument, storage variable, admin, owner,
upgrade, proxy, registry, fallback, receive function, payable method, token
surface, callback, or user-selected external address. Its only external
effects are fixed-address cryptographic precompile `STATICCALL`s used by
OpenZeppelin.

## Preserved Evidence

O.37.2 and O.37.4 validator, recovery, and combined fixtures are consumed
unchanged. O.37.4 transport, exact 2-of-3 recovery, descriptor commitments,
digest types, and EntryPoint nonce ownership are not modified.

The historical descriptors remain fixture inputs. A future minimal account
will pass its new immutable account-version ID, and descriptor membership
must match that request exactly.

## Stop Boundary

Hardhat tests use an ephemeral in-memory deployment solely to execute local
Solidity assertions. No persistent or public deployment, external RPC,
Sepolia interaction, funding, credential, new fixture signature,
production signature, or UserOperation occurs.
