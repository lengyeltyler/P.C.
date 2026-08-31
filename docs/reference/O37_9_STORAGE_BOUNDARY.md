# O.37.9 Compressed Account Storage Boundary

Status: `COMPLETE_PROPOSED_STORAGE_FREEZE`.

This is the exact proposed storage policy for a future
`philcore-v2-minimal-account-v2` implementation. It is not a Solidity storage
layout artifact and creates no bytecode.

## Immutable Or Constant Configuration

The future account retains only these account-local immutable values:

1. canonical EntryPoint address;
2. deployment chain ID;
3. owner commitment;
4. factory binding;
5. immutable confirmation target.

The account-version ID, security-model ID, recovery delay, recovery expiry,
identity-binding type data, and commitment type hashes are compile-time
constants. The identity-binding commitment is recomputed from the immutable
owner commitment.

The verifier address and code hash are not account immutables or storage.
They are read from the immutable bound factory exactly as frozen in
[O.37.9 Verifier Binding Resolution](./O37_9_VERIFIER_BINDING_RESOLUTION.md).

The canonical 20-field constructor tuple remains complete. Constructor-only
fields that are deterministic checks may be validated and discarded rather
than duplicated in runtime storage.

## Mutable Layout

The proposed mutable layout occupies slots `0` through `14`:

| Slot | Offset | Value |
| ---: | ---: | --- |
| `0` | `0` | active validator address, 20 bytes |
| `0` | `20` | validator epoch, 8 bytes |
| `0` | `28` | recovery audit state, 1 byte |
| `0` | `29` | validator verifier kind, 1 byte |
| `0` | `30` | execution lock, 1 byte |
| `1` | `0` | validator key-ID binding |
| `2` | `0` | primary-device recovery commitment |
| `3` | `0` | hardware-security-key commitment |
| `4` | `0` | independent recovery-factor commitment |
| `5` | `0` | recovery epoch, 8 bytes |
| `6` | `0` | pending validator-recovery request ID |
| `7` | `0` | pending validator address, 20 bytes |
| `7` | `20` | pending validator epoch, 8 bytes |
| `8` | `0` | pending validator key-ID binding |
| `9` | `0` | pending source validator epoch, 8 bytes |
| `9` | `8` | pending source recovery epoch, 8 bytes |
| `9` | `16` | pending request timestamp, 6 bytes |
| `10` | `0` | pending recovery-config request ID |
| `11` | `0` | proposed primary-device commitment |
| `12` | `0` | proposed hardware-security-key commitment |
| `13` | `0` | proposed independent recovery-factor commitment |
| `14` | `0` | proposed recovery epoch, 8 bytes |
| `14` | `8` | config source validator epoch, 8 bytes |
| `14` | `16` | config source recovery epoch, 8 bytes |
| `14` | `24` | config request timestamp, 6 bytes |

Unused packed bytes are not a storage gap and cannot be used by an upgrade;
the account is non-upgradeable.

## Derived Values

The account recomputes:

- identity-binding commitment from owner commitment;
- validator commitment from verifier kind, validator, and key binding;
- recovery-configuration hash from version `2`, threshold `2`, and the three
  ordered role commitments;
- pending proposed validator commitment from pending validator state;
- pending proposed recovery-configuration hash from proposed commitments;
- `executableAfter = requestedAt + 172800`;
- `expiresAt = requestedAt + 604800`;
- validator-recovery freeze from nonzero pending recovery request ID;
- configuration-rotation activity from nonzero pending config request ID.

These values are not accepted from Runtime or evidence. Constructor and
transition calldata values that include them must match the onchain
recomputation.

## Lifecycle State

Recovery audit state remains:

```text
0 NORMAL
1 RECOVERY_ACTIVE
2 RECOVERY_COMPLETED
3 RECOVERY_CANCELLED
```

Only a nonzero pending validator-recovery request freezes ordinary and
validator-maintenance actions. A pending recovery-configuration rotation
keeps ordinary typed native actions available but blocks conflicting
authority changes. The two pending structures are mutually exclusive.

Terminal audit state does not itself authorize or block a later request.
Current pending IDs, epochs, and EntryPoint nonce sequences control replay.

## Forbidden Storage

The future account must contain no:

- nonce or nonce-sequence mapping;
- consumed-hash or generic replay mapping;
- owner, administrator, or privileged recovery override;
- implementation or proxy slot;
- storage gap;
- module, plugin, adapter, or session registry;
- verifier address, verifier hash, or verifier registry;
- token allowance, receiver, or asset registry;
- paymaster or aggregator state;
- arbitrary capability root.

EntryPoint remains the sole nonce-sequence owner. Request IDs and epochs are
state-transition constraints, not substitute nonces.

## Acceptance

A future compiler storage-layout artifact must match every slot and offset
above. Any additional mutable slot, reordered field, stored derived value, or
forbidden category stops implementation for architecture review.
