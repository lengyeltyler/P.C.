# Phil V1 Step 2 Finalization Gate

Status: Step 2 exact source candidate independently accepted; gate complete

Date: 2026-08-21

## Outcome

Step 2 reached a reviewable, fail-closed candidate. The local recovery,
device-approval, source-isolation, physical Secure Enclave, interruption, and
restricted device-admission evidence is complete for the bounded candidate.

Step 2 is **accepted and complete** for the bounded foundation candidate. The
first two exact candidates were rejected and corrected; their records remain
preserved. The exact source candidate
`fe583b6aef84a8636736b2041db2a56046a5972e` received
`ACCEPT_STEP_2_EXACT_CANDIDATE` in
[the final review](./PHIL_V1_STEP2_INDEPENDENT_REVIEW_FE583B6.md). Step 3 has
not started and requires separate user direction.

## Literal Gate Ledger

| Requirement | Evidence | Decision |
| --- | --- | --- |
| Local root proving benchmark | Step 2 selects no local root-proof backend | Not applicable; reconsider in Step 3 if local proving is selected |
| Supported-device and resource limits | Executable policy admits only the observed iPhone 17/iOS 26.6 build 23G71 envelope: physical device, Secure Enclave, owner authentication, protected data, at least 7,671 MiB total memory, 100% battery, Low Power Mode off, nominal thermal | Passed for the bounded candidate only; all other profiles and conditions fail closed |
| Interruption and failure behavior | Cancellation, app termination, 60-second lock, reboot, first unlock, persistence, signature verification, and exact deletion passed physically | Passed for bounded candidate |
| Hardware-backed device approval/wrapping | Secure Enclave P-256, ThisDeviceOnly, non-synchronizable, user presence, sign/verify, local-key wrap/unwrap, non-exportability | Passed physically on bounded candidate |
| Protected runtime isolation | Recovery source has no renderer or preload reachability; an adversarial source lock enforces that absence | Passed locally as a foundation boundary; production host composition remains later integration work |
| App Attest authority boundary | App Attest is unused and source lock rejects its addition to this manager | Passed |
| Authenticated encrypted continuity package | AES-256-GCM package and records with exact AAD and public-envelope validation | Passed locally |
| Exact user-controlled `2-of-3` unwrapping | Every pair succeeds; one, duplicate, mixed-set, corrupt, and stale material fails | Passed locally |
| Recovery lifecycle | Delay, expiry, cancellation, notification-evidence binding, destructive-approval binding, audit continuity, full recovery-set replacement, device/recovery/capability epoch rotation, credential revocation, and account reconciliation state | Passed as local foundation primitives; notification delivery and production custody remain later operational integration |
| Independent threat review | `fe583b6aef84a8636736b2041db2a56046a5972e` received `ACCEPT_STEP_2_EXACT_CANDIDATE`; both prior rejections and corrections are preserved | **Passed** |

## Admission Boundary

The executable admission policy is
`apps/phil-device-sdk/src/step2DeviceAdmissionV1.ts`.

It is deliberately more restrictive than a useful shipping policy. That is
the honest consequence of one physical evidence run. It does not infer that
99% battery, a fair thermal state, another OS build, or another iPhone model is
safe merely because those conditions appear likely to work. Those conditions
can be admitted later with bounded evidence without redesigning Phil identity.

An admitted result is classified `bounded-step2-candidate`, always carries
`productionAuthority: false`, and permits only device approval or local-vault
key wrap/unwrap. It does not admit identity/data recovery execution on iOS,
proof generation, an account action, or any network authority.

## Non-Blocking Product Integration Work

The following work is still required before production use but is not being
misclassified as Step 2 foundation evidence:

- notification delivery and issuer trust;
- durable anti-rollback and consumed-nonce storage;
- protected-process IPC composition and recovery UI;
- real recovery-factor custody and replacement operations;
- network-account reconciliation after recovery; and
- broader device, battery, thermal, OS-update, and population support.

Those systems must preserve the accepted primitives and will receive their own
composition gates. None may restore old authority automatically.

## Gate Closure

The exact independent review passed, its findings were adjudicated, and the
local acceptance commands were re-run successfully. The induced metadata-
persistence-failure cleanup remains an honestly disclosed, unadmitted,
non-blocking residual. No new physical-device evidence is required to close
this bounded foundation gate.

## Verdict

`STEP 2 EXACT SOURCE CANDIDATE: fe583b6aef84a8636736b2041db2a56046a5972e`

`STEP 2 INDEPENDENT REVIEW: ACCEPT_STEP_2_EXACT_CANDIDATE`

`STEP 2 COMPLETE: YES`

`STEP 3 STATUS: READY FOR SEPARATE USER DIRECTION; NOT STARTED`
