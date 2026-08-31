# Phil V1 Step 6C-2 Product Wiring Implementation Report

Status: Sixth-corrective exact candidate 4a81b08/tree 188d7d0 independently accepted; Step 6C-2 complete as a local source gate

Date: 2026-08-23

## Outcome

Step 6C-2 now has a bounded, credential-free sixth-corrective iPhone/Desktop
source candidate. The initial candidate `021e703`, first corrective `c40fa2c`,
second corrective `75785f3`, third corrective `965f9ed`, and fourth corrective
`09e5a9e`, and fifth corrective `8a2d906` were independently rejected. This candidate preserves the
earlier reconstruction, lifecycle, enrollment, restart, and routing corrections
while adding the review-required fee/clock checks, product-owned Hardhat
configuration, reachable generation-2 replacement, protected Desktop time, and
crash-recoverable product-wide deletion.

The fourth correction retains the serialized lifecycle and adds a Desktop
ephemeral acknowledgement key to the enrollment QR. Desktop prepares a signed
acceptance bound to the bootstrap and exact enrollment proof digest, destroys
the private key, releases the response only after protected persistence, and
idempotently replays that signed acceptance for a valid retry. The iPhone
retries the same published request once, commits its
pending key only after verifying Desktop's signature, and preserves an
activated-pending key after any ambiguous published failure. It rolls back only
before publication. This closes the generation-split and forged-empty-success
failure modes identified in the third-corrective review.

The candidate also serializes initialization, begin, replacement, deletion,
status, cancellation, and shutdown through one lifecycle; authenticates the
durable deletion command; strict-validates decrypted enrollment before deciding
absence; freezes generations 1 through 64 across iPhone and Desktop; and uses a
pending/activated/committed iPhone rotation with restart recovery. Runtime
provisioning errors now propagate instead of starting enrollment, and only
pre-commit deletion failures reset the lifecycle for a safe retry.

The fifth correction replaces Swift's accidental SHA-256-of-digest acceptance
verification with Security framework prehashed P-256 verification over the
exact Desktop-generated fixture. Both implementations now reject noncanonical
or high-S acceptance DER. Desktop destroys the ephemeral acknowledgement
private key immediately after preparing the signature, stops cached replay at expiry, and
the product model refreshes the displayed active routine-key fingerprint after
authenticated replacement.

Independent review found those implementation corrections complete but
rejected exact candidate `8a2d906`, tree `f7e1b4a`, because a later report
bullet contradicted the source by claiming signing occurred after persistence.
This sixth correction is documentation-only and makes the report consistently
state the actual order: prepare the signed acceptance and destroy the private
key, persist the enrollment, then release the response.

The ordinary Desktop source now attempts to compose the real routine product
host automatically when an RFC1918 interface and OS-protected storage are
available. The first routine action enrolls the separate iPhone routine key;
the next creates, presents, signs, simulates, submits, and verifies the exact
harmless local action. Startup or protection failure leaves the narrow feature
visibly unavailable.

This remains local source evidence. The physical iPhone remained disconnected.
No public RPC, bundler, external prover, deployment, public transaction, real
Phil identity, recovery secret, meaningful asset, publication, or production
signing authority was used.

## Implemented Boundary

The iPhone candidate:

- routes authorization and enrollment only through their separate frozen QR
  namespaces;
- creates a separately tagged Secure Enclave P-256 routine key with
  `WhenUnlockedThisDeviceOnly` and user presence, while Simulator is restricted
  to disclosed synthetic evidence;
- enrolls the complete public record using an expiring RFC1918 bootstrap,
  human-compared fingerprint, and proof of possession over the full record;
- verifies a Desktop P-256 acceptance over the exact bootstrap and enrollment
  proof digest before committing a prepared key, with same-enrollment retry and
  ambiguous-delivery preservation;
- independently rebuilds every nested authorization record and derived digest
  before presentation or signing;
- converts DER signatures to canonical low-S wire form; and
- cancels unpublished pending enrollment or authorization on backgrounding,
  lock, cancellation, replacement, timeout, or termination, while retaining an
  activated-pending enrollment once a request may have reached Desktop.

The Desktop candidate:

- owns strict one-session enrollment and authorization listeners;
- validates the V2 public record, admitted suite/provider/wire identities, key
  fingerprint, proof of possession, and monotonic replacement rules;
- prepares a bootstrap-bound signed acceptance and destroys its ephemeral
  private key before protected enrollment persistence, releases the response
  only after persistence, and idempotently returns the same acceptance for a
  valid unexpired replay;
- persists enrollment, canonical requests, journal keys, and journal frames
  through the OS-protection adapter with durable writes;
- discovers and reconciles incomplete requests on startup, rebuilding matching
  local-chain success or failure evidence and failing closed when the prior
  process-local chain is unavailable;
- provisions a product-owned Hardhat chain-31337 runtime with a fresh random
  deployer, pinned official EntryPoint, enrolled public key, harmless account,
  target, simulation, `handleOps`, and verified receipt;
- exposes only begin, sanitized status, cancel, and exact-phrase disposable
  deletion operations to the renderer; and
- commits deletion durably before atomically clearing the dedicated enrollment,
  request, journal, and key profile; restart finishes an interrupted committed
  deletion without touching identity or recovery data.

The local runtime does not import Step 6C-1 test fixtures, default Hardhat
accounts, recovery authority, STWO/root proofs, public RPC clients, or
production keys. It rejects any non-Hardhat network, chain other than 31337, or
fork-enabled configuration. Because this is a process-owned local chain, a
restart that loses its authenticated scan anchor ends in
`SUBMISSION_OUTCOME_UNKNOWN`; it is never retried or falsely completed.

## Evidence

The deterministic V2 fixture and manifest bind both transport protocols,
enrollment record, proof and acceptance digests, exact Desktop-generated
acceptance JSON, complete source hashes, rejected-candidate history, inherited
accepted Step 6C-1 identities, and 49 focused automated
cases.

The focused lanes comprise:

- six TypeScript authorization-transport cases;
- three TypeScript enrollment and proof-of-possession cases;
- four Desktop listener/host cases;
- two product-owned local-runtime cases, including receipt reconstruction;
- one complete protected enrollment-to-local-receipt product flow;
- five narrow IPC and normal-startup composition cases;
- three protected storage, restart-discovery, and interrupted-deletion cases;
- three product-host ordering, deletion, initialization-race, runtime-failure,
  and pre/post-commit failure cases;
- one enrollment-host case; and
- four renderer-state cases covering first-enrollment/replacement labels,
  stale-poll ownership, and terminal QR removal;
- one pinned secure-origin JavaScript media-type case; and
- sixteen Swift Simulator cases covering cross-language vectors, full request
  reconstruction, UI ordering, scene invalidation, enrollment, cancellation,
  schema rejection, namespace separation, synthetic exchange, and frozen
  fee/device-clock policy enforcement, generation-2 replacement, pre-publication
  rollback, lost-acceptance retry, forged-acceptance rejection, and ambiguous
  activation retention, exact prehashed Desktop acceptance, high-S rejection,
  and displayed replacement-fingerprint refresh.

The broader 37-case Step 6C-1 gate and 43 inherited Step 3-through-6B cases
remain mandatory regression evidence. Independent review bound exact commit
`4a81b08`, tree `188d7d0`, and accepted it with no blocking finding; this report
does not substitute for that separate acceptance record.

## Exact Classification

```text
LOCAL PROTOTYPE: TRUE
STEP 6C-2 SIXTH-CORRECTIVE SOURCE CANDIDATE IMPLEMENTED: TRUE
INDEPENDENTLY REVIEWED SOURCE: TRUE
STEP 6C-2 LOCAL SOURCE GATE COMPLETE: TRUE
PHYSICAL DEVICE VERIFIED: FALSE
PACKAGED PRODUCT VERIFIED: FALSE
TESTNET ADMITTED: FALSE
PRODUCTION ADMITTED: FALSE
POST-QUANTUM ENFORCED: FALSE
EXTERNAL NETWORK: FALSE
MEANINGFUL ASSETS: FALSE
PRODUCTION AUTHORITY: FALSE
STEP 6C COMPLETE: FALSE
```

## Next Gate

Exact sixth-corrective candidate `4a81b08`, tree `188d7d0`, is independently
accepted as the historical Step 6C-2 local source gate. The first separately
authorized Step 6C-3 physical-iPhone ceremony exposed repeat-scanner and
product-state defects and was stopped. The original source acceptance is now
superseded for product use. Exact corrective source `c32d8f8`, tree `12eb24e`,
is independently accepted; a fresh disposable physical ceremony remains
required. See the
[Step 6C-3 physical failure and corrective report](./PHIL_V1_STEP6C3_PHYSICAL_FAILURE_AND_CORRECTIVE_REPORT.md).
