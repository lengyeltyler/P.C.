# Phil V1 Step 5 Post-Quantum Migration Threat Model

Status: Complete local threat model; exact candidate independently accepted

## Protected properties

Step 5 protects algorithm and authority migration without changing the private
Phil identity root. The relevant assets are:

- exact scheme identities and lifecycle states;
- device, validator, proof, verifier, encryption, and recovery authority;
- per-network enforcement truth;
- policy, registry, device, validator, and recovery epochs;
- recovery-factor independence; and
- the accuracy of Phil's security claims.

It does not protect production funds or a deployed account because this step
creates no deployment or runtime authority.

## Threats and controls

| Threat | Control | Residual risk |
| --- | --- | --- |
| Algorithm substitution under an old name | Network and policy bind the complete registry hash, including exact implementation and compatibility bindings | Source/release or trusted-state compromise remains possible |
| Activate a specification-only algorithm | Policy bundles require `ACTIVE_REFERENCE` lifecycle | Admission review could be wrong |
| Classical-or-PQ downgrade | Multi-scheme factors require AND; OR is rejected | Availability cost and implementation complexity increase |
| Registry rollback | Ceremony registry epoch cannot decrease | External state must persist the accepted epoch |
| Security-mode rollback | Ceremony security mode cannot decrease | Emergency rollback needs a separately designed safe response |
| Partial authority rotation | Device, validator, and recovery epochs all increment exactly once | Production orchestration is not implemented |
| Reuse retiring recovery authority | Independent recovery policy hash and approval are ceremony-bound | Real custody independence cannot be proven solely in code |
| Claim local policy as network enforcement | Network records bind enforcement and path availability; hybrid/PQ requires network evidence | Network upgrades and sequencer/account behavior need monitoring |
| Use a stale or caller-invented capability or policy | Protected trusted state pins registry, network, authority, exact capability and policy hashes, and exact current epochs | Production durable trusted-state storage is not implemented here |
| Block migration to a stronger network record | Ceremony accepts distinct old/new capability records on one network and requires a higher epoch when changed | Exact future hybrid record remains unimplemented |
| Pair a proof with an unrelated verifier | Verifier registry records bind compatible proof IDs; network and policy enforce the pair | Underlying proof/verifier security still needs exact review |
| Treat ML-KEM as a signature | Registry separates key establishment from signatures | Platform documentation still requires device testing |
| Treat a PQ signature as whole-system PQ | Claim assessment includes device, validator, recovery, KEM, proof, verifier, and network | Libraries, OS, hardware, side channels, build chain, and operations remain scoped assumptions |
| Re-enable STWO | STWO record is forbidden and rejected from policy bundles | Separate legacy code remains quarantined elsewhere |
| Use unassessed STARK as PQ proof | Reserved proof/verifier are candidates and cannot activate | A future exact instantiation needs cryptographic review |
| Fake ceremony approval | Hash binds approval digests and review hash | This step does not implement signature verification or durable execution |
| Cross-network capability confusion | Policy binds one exact network capability and registry; ceremony requires one network and one capability authority | Multi-network orchestration remains Step 6 |

## Fail-closed ordering

Factories reject malformed IDs and enums, empty required scheme sets,
duplicates, wrong-kind schemes, forbidden/retired schemes, candidate activation,
mode/component mismatch, incompatible proof/verifier pairs, registry or trusted
state format/hash mismatch, stale/future/untrusted capability and policy records, network
overclaim, policy or authority epoch errors, invalid transition kinds,
incorrect emergency state, and invalid windows.

## Important non-claims

- NIST standardization does not prove Phil's implementation.
- Apple documents Secure Enclave ML-DSA-65 signing and ML-KEM, but Phil has not
  integrated or physically verified either path.
- Programmable Starknet or ERC-4337 validation does not prove a deployed PQ
  verifier or end-to-end PQ account.
- SHA-256, Keccak-256, AES-256, and HKDF classifications do not overcome a
  classical signature or proof dependency.
- Noir/UltraHonk and the accepted Step 3/4 reference path are not PQ.
- No physical device, secret, signer, external prover, RPC, transaction,
  deployment, publication, or production backend is part of Step 5.

## Residual work

The exact local candidate passed independent source review. A later production
implementation must separately test exact PQ libraries, encodings, side-channel behavior,
device custody, backup/restore, recovery loss and corruption, account upgrade
or migration, network limits, fees, interoperability, release provenance, and
incident retirement. None is inferred from this architecture gate.
