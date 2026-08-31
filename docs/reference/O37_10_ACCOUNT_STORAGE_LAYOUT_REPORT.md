# O.37.10 Account Storage Layout Report

Status: `ACCEPTED_EXACT_O37_9_LAYOUT`.

The compiler layout matches the O.37.9 slots and offsets exactly:

- slot `0`: validator address at offset `0`, validator epoch at `20`,
  recovery state at `28`, verifier kind at `29`, execution lock at `30`;
- slot `1`: validator key-ID binding;
- slots `2`–`4`: three ordered recovery commitments;
- slot `5`: recovery epoch;
- slots `6`–`9`: pending validator-recovery state;
- slots `10`–`14`: pending recovery-configuration state.

The highest mutable slot is `14`. There is no duplicate nonce or replay
mapping, owner/admin slot, implementation slot, storage gap, verifier address
or code-hash slot, module/session/token/paymaster/aggregator registry, or
arbitrary capability state.

The EntryPoint owns all three keyed nonce sequences. Identity binding,
validator commitment, recovery-configuration hashes, proposal hashes, and
timing endpoints are recomputed rather than stored.

The factory and unchanged verifier have zero mutable storage entries; their
configuration uses immutables. The exact compiler layout and deterministic
layout hashes are in
`config/solidity/O37_10_STORAGE_LAYOUT_REPORT.json`.
