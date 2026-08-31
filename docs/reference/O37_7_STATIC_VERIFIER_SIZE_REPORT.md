# O.37.7 V2 Static Verifier Size Report

Status: `COMPLETE_STATIC_VERIFIER_ONLY`.

The frozen O.37.7 build produces:

| Measurement | Bytes |
| --- | ---: |
| creation bytecode | `12671` |
| runtime bytecode | `12645` |
| O.37.6 verifier hard maximum | `20480` |
| hard-budget reserve | `7835` |
| EIP-170 maximum | `24576` |
| EIP-170 reserve | `11931` |

Runtime Keccak-256:

```text
0x4597c97018b1fe4b941a035275e229ea5c163db9801545217aa3a93614b1b5be
```

Creation-bytecode Keccak-256:

```text
0xf4b02d44bf35dd9968866754cf59930936f95a939fecf6e5f25ad4631d17f332
```

The artifact passes the `20480`-byte hard gate. No compiler warning is
accepted.

## Frozen Build

- Solidity `0.8.27+commit.40a35a09.Emscripten.clang`;
- Cancun EVM;
- optimizer enabled at `200` runs;
- viaIR enabled;
- literal-content metadata with IPFS hash and appended CBOR;
- OpenZeppelin Contracts `5.6.1`;
- Account Abstraction `0.7.0`;
- Hardhat `2.28.4`;
- ethers `6.17.0`.

The isolated O.37.7 configuration uses the pinned local `solc-js` package and
does not load environment files or define an external network.

## Runtime Attribution

Solidity deployed-source-map instruction attribution gives:

| Source family | Runtime bytes |
| --- | ---: |
| PhilCore verifier source | `9307` |
| OpenZeppelin P-256 | `1443` |
| OpenZeppelin Base64 | `203` |
| OpenZeppelin ECDSA | `84` |
| OpenZeppelin Math | `83` |
| OpenZeppelin Panic | `14` |
| compiler-generated/unattributed | `1511` |
| total | `12645` |

The largest contributor is canonical request/envelope decoding and the
PhilCore verification boundary. OpenZeppelin's P-256 native-precompile path
with Solidity fallback is the largest dependency contributor. The fallback
is retained deliberately; native-only verification remains rejected.

Generated build output remains ignored and reproducible. The durable
measurement is
`config/solidity/O37_7_STATIC_VERIFIER_IMPLEMENTATION_EVIDENCE.json`.
