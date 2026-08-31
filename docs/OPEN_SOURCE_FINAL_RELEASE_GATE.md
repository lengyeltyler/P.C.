# PhilCore Final Open-Source Release Gate

Status: **preparation; final release not authorized**

The repository is already publicly readable under the licenses recorded in
`LICENSE`, SPDX headers, `LICENSES/`, and `THIRD_PARTY_NOTICES.md`. The final
open-source release is a separate, immutable handoff after controlled Beta
readiness—not a claim that the software is production custody infrastructure.

## Required release contents

- complete source and reproducible lockfiles;
- protocol, architecture, threat-model, recovery, deployment, and integration
  documentation;
- exact Beta source, package, circuit, contract, and evidence hashes;
- Safe and MetaMask integration notes that distinguish supported standards
  from unreviewed product integrations;
- source and packaged SBOMs plus third-party notices;
- clean-room build and test instructions;
- security policy and private vulnerability reporting path;
- all known limitations and residual risks; and
- a permanent signed Git tag and GitHub release archive.

## Material that must never be released

- private keys, mnemonics, RPC credentials, API tokens, signing identities, or
  Apple certificates/provisioning secrets;
- `phil_secret`, identity roots, recovery secrets, raw vault material, device
  private keys, real device identifiers, or personal data;
- ignored local environment files or ceremony ledgers;
- credentials embedded anywhere in reachable Git history; or
- third-party material for which redistribution rights are absent.

## Final gates

1. B0-B8 are closed with an exact Beta verdict.
2. Reachable-history and working-tree secret scans have no confirmed secret.
3. Every shipped file has a compatible license; generated and third-party
   material has provenance and redistribution evidence.
4. Source and package SBOMs contain no undisclosed component.
5. A clean machine reproduces the documented builds and automated lanes.
6. The accepted independent review and final remediation audit hashes match the
   release commit. The controlled Beta uses documented AI review plus owner risk
   acceptance; this is not a professional external audit.
7. GitHub Private Vulnerability Reporting is enabled and its confidential report
   entry point is verified. It was enabled on 2026-08-31; no fictitious report
   was submitted and no response-time guarantee is implied.
8. Release support status is explicit: community/reference handoff with no
   promise of ongoing maintenance unless a maintainer later volunteers.
9. The release notes state testnet scope, local Noir/P-256 verification,
   prohibited mainnet/meaningful-asset use, and all known residual risks.
10. The final tag, archives, checksums, and GitHub release are independently
    reconciled before announcement.

Final-release wording must not say “100% secure.” It may say that the exact
release satisfies its frozen acceptance contract if—and only if—every listed
gate has evidence.
