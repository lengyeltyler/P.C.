# O.42.1 WebAuthn Security and Contamination

> Historical O.42.1 snapshot. Its advisory counts are not current. See
> [Dependency Advisory Status](./DEPENDENCY_ADVISORY_STATUS.md).

O.42.1 makes zero public mutations and creates no production recovery
authority.

Security properties preserved:

- no unsupported Chromium flags;
- no certificate or TLS bypass;
- no wildcard or mutable keychain group;
- no production credential in an unpackaged or ad-hoc identity;
- no weakening of UV, BE, BS, RP, origin, recovery threshold, or factor
  independence;
- no raw credential ID, private key, certificate private key, pairing
  secret, or offline factor in logs/evidence;
- no crash upload;
- no Sepolia, RPC, bundler, funding, transaction, signature, or
  UserOperation activity.

The complete dependency tree reports 10 Low, 2 Moderate, 7 High, and zero
Critical advisories. Production dependencies report zero advisories. The
seven High groups are the previously accepted, lazy development-tooling
paths (`adm-zip`, `brace-expansion`, `hardhat`, `immutable`,
`serialize-javascript`, `tmp`, and `undici`). Electron is not a reported
High/Critical advisory. Frozen Solidity dependencies were not changed.

The remaining high-severity product blocker is operational, not a bypass:
the exact Developer ID provisioning profile does not exist locally.
Platform WebAuthn remains disabled until that profile is independently
created/reviewed, embedded, and the signed application passes a real launch
and disposable credential restart cycle.
