import CryptoKit
import Foundation
import XCTest
@testable import PhilCoreCompanion

// MARK: - Test doubles

struct FixedCompanionClock: CompanionClock {
    var seconds: UInt64
    var milliseconds: UInt64

    func nowUnixSeconds() -> UInt64 { seconds }
    func nowUnixMilliseconds() -> UInt64 { milliseconds }
}

@MainActor
final class RecordingPairingClientSeam: CompanionPairingRouting {
    private(set) var parseCalls: [String] = []
    private(set) var cancelPendingCalls = 0
    var parseResult: Result<PairingRequest, Error> = .failure(CompanionFailure.invalidRequest)

    func parsePairingQR(_ value: String) async throws -> PairingRequest {
        parseCalls.append(value)
        return try parseResult.get()
    }

    func fingerprint(for request: PairingRequest) -> String {
        CryptoSupport.fingerprint(request.canonicalTranscript)
    }

    func cancelPendingPairing() async {
        cancelPendingCalls += 1
    }
}

// MARK: - RG5 — Exact QR routing

final class CompanionQRRoutingTests: XCTestCase {
    func testRecoveryAndPairingDiscriminatorsAreExactAndMutuallyExclusive() {
        let recovery = "philcore-recovery:v1:payload"
        let pairing = "philcore://pair/v1?request=abc"
        XCTAssertEqual(CompanionQRRouting.classify(recovery), .recovery)
        XCTAssertEqual(CompanionQRRouting.classify(pairing), .pairing)
        XCTAssertNil(CompanionQRRouting.classify(" " + recovery))
        XCTAssertNil(CompanionQRRouting.classify(recovery + " "))
        XCTAssertNil(CompanionQRRouting.classify("\t" + pairing))
        XCTAssertNil(CompanionQRRouting.classify(pairing + "\n"))
        XCTAssertNil(CompanionQRRouting.classify("payload philcore-recovery:v1:x"))
        XCTAssertNil(CompanionQRRouting.classify("https://example/philcore://pair/v1?request=x"))
        XCTAssertNil(CompanionQRRouting.classify("{\"sessionId\":\"x\"}"))
        XCTAssertNil(CompanionQRRouting.classify(""))
        XCTAssertNil(CompanionQRRouting.classify("philcore-recovery:v2:x"))
        XCTAssertNil(CompanionQRRouting.classify("philcore://pair/v2?request=x"))
    }

    func testAmbiguousOrMixedInputRejects() {
        XCTAssertNil(
            CompanionQRRouting.classify(
                "philcore-recovery:v1:x philcore://pair/v1?request=y"
            )
        )
        // Exact pairing prefix still classifies as pairing; the selected parser
        // then validates the entire payload.
        XCTAssertEqual(
            CompanionQRRouting.classify(
                "philcore://pair/v1?request=philcore-recovery:v1:x"
            ),
            .pairing
        )
    }
}

// MARK: - RG6 / RG7 / RG8 — Model lifecycle, background, view projection

@MainActor
final class CompanionModelRecoveryTests: XCTestCase {
    private func makeModel(
        transport: FakeRecoveryTransport,
        signer: RecoverySigner,
        pairing: RecordingPairingClientSeam? = nil,
        clock: FixedCompanionClock = FixedCompanionClock(
            seconds: RecoveryDesktopSimulator.nowSeconds,
            milliseconds: RecoveryDesktopSimulator.nowMilliseconds
        ),
        recoveryApproval: (any LocalRecoveryApproving)? = nil
    ) -> CompanionModel {
        let pairingRouter = pairing ?? RecordingPairingClientSeam()
        let approvalManager = LocalApprovalManager()
        return CompanionModel(
            transport: transport,
            signer: signer,
            clock: clock,
            pairingRouter: pairingRouter,
            credentialManager: SecureEnclaveCredentialManager(),
            approvalManager: approvalManager,
            recoveryApproval: recoveryApproval ?? approvalManager
        )
    }

    func testValidRecoveryScanPublishesReviewWithoutAutomaticApproval() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let model = makeModel(transport: transport, signer: signer)

        XCTAssertEqual(model.recoveryStatus.state, .idle)
        XCTAssertEqual(signer.callCount, 0)

        await model.acceptRecoveryScannedValue(simulator.uri)

        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)
        let presentation = try XCTUnwrap(model.recoveryStatus.presentation)
        XCTAssertEqual(presentation.accountAddress, simulator.validation.request.context.account)
        XCTAssertEqual(presentation.chainId, simulator.validation.request.context.chainId)
        XCTAssertEqual(
            presentation.recoveryEpoch,
            simulator.validation.request.context.recoveryEpoch
        )
        XCTAssertEqual(signer.callCount, 0, "no automatic approval")
        XCTAssertEqual(transport.requests(for: .complete).count, 0)

        let view = RecoveryApprovalViewState.project(
            status: model.recoveryStatus,
            isWorking: model.isWorking,
            isScanning: false
        )
        guard case .review(let fields) = view.phase else {
            return XCTFail("expected review phase, got \(view.phase)")
        }
        XCTAssertEqual(fields.action, presentation.actionText)
        XCTAssertEqual(fields.accountAddress, presentation.accountAddress)
        XCTAssertEqual(fields.network, presentation.networkText)
        XCTAssertEqual(fields.chainId, presentation.chainId)
        XCTAssertEqual(fields.recoveryEpoch, presentation.recoveryEpoch)
        XCTAssertEqual(fields.comparisonFingerprint, presentation.comparisonFingerprint)
        XCTAssertEqual(fields.factorBitmap, presentation.factorBitmap)
        XCTAssertEqual(fields.expiresAtUnixSeconds, presentation.expiresAtUnixSeconds)
        XCTAssertFalse(fields.completionEndpointVisible)
        XCTAssertTrue(view.approveEnabled)
        XCTAssertTrue(view.cancelAvailable)
    }

    func testExplicitApproveRejectCancelAndDoubleApprove() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let model = makeModel(transport: transport, signer: signer)
        await model.acceptRecoveryScannedValue(simulator.uri)
        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)

        await model.approveRecovery()
        XCTAssertEqual(model.recoveryStatus.state, .accepted)
        XCTAssertEqual(signer.callCount, 1)

        await model.approveRecovery()
        XCTAssertEqual(model.recoveryStatus.state, .accepted)
        XCTAssertEqual(signer.callCount, 1, "double approve blocked")

        // Fresh reject path
        let signer2 = RecoveryMockSigner()
        let simulator2 = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "cd", count: 32),
            role1SigningPublicKey: signer2.publicKey
        )
        let model2 = makeModel(
            transport: RecoveryScenario.standard(simulator2),
            signer: signer2
        )
        await model2.acceptRecoveryScannedValue(simulator2.uri)
        await model2.rejectRecovery()
        XCTAssertEqual(model2.recoveryStatus.state, .rejected)
        XCTAssertEqual(signer2.callCount, 0)

        // Cancel path
        let signer3 = RecoveryMockSigner()
        let simulator3 = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "ee", count: 32),
            role1SigningPublicKey: signer3.publicKey
        )
        let model3 = makeModel(
            transport: RecoveryScenario.standard(simulator3),
            signer: signer3
        )
        await model3.acceptRecoveryScannedValue(simulator3.uri)
        await model3.cancelRecovery()
        XCTAssertEqual(model3.recoveryStatus.state, .cancelled)
        XCTAssertEqual(model3.recoveryStatus.failureReason, "recovery_client_cancelled")
    }

    func testReplacementScanIsolatesStaleResults() async throws {
        let signer = RecoveryMockSigner()
        let first = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let second = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "11", count: 32),
            role1SigningPublicKey: signer.publicKey
        )
        let gate = RecoveryTestGate()
        let transport = FakeRecoveryTransport()
        let index = [first.sessionId: first, second.sessionId: second]
        transport.setHandler(.request) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            if simulator === first { await gate.wait() }
            return FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { request in
            let sessionId = try RecoveryDesktopSimulator.sessionId(fromBody: request.body)
            let simulator = try XCTUnwrap(index[sessionId])
            return FakeRecoveryTransport.ok(
                try simulator.acknowledgementBody(for: request.body),
                endpoint: simulator.completionEndpoint
            )
        }
        let model = makeModel(transport: transport, signer: signer)

        let firstTask = Task { await model.acceptRecoveryScannedValue(first.uri) }
        try await Task.sleep(nanoseconds: 80_000_000)
        await model.acceptRecoveryScannedValue(second.uri)
        gate.open()
        await firstTask.value

        XCTAssertEqual(model.recoveryStatus.sessionId, second.sessionId)
        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)
    }

    func testFailureReasonsMapToFixedUserFacingCopy() async throws {
        let typed = TypedErrorRecoverySigner(error: .signer("biometric_approval_denied"))
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: typed.publicKey
        )
        let model = makeModel(
            transport: RecoveryScenario.standard(simulator),
            signer: typed
        )
        await model.acceptRecoveryScannedValue(simulator.uri)
        await model.approveRecovery()
        XCTAssertEqual(model.recoveryStatus.state, .failed)
        XCTAssertEqual(
            CompanionModel.userFacingRecoveryMessage(for: model.recoveryStatus.failureReason),
            "Biometric approval was denied."
        )
        XCTAssertFalse(
            (model.notice ?? "").contains("biometric_approval_denied"),
            "raw internal tokens must never render"
        )
        XCTAssertEqual(
            CompanionModel.userFacingRecoveryMessage(for: "totally_unknown_token"),
            "Recovery approval failed."
        )
        XCTAssertNotEqual(
            CompanionModel.userFacingRecoveryMessage(for: "recovery_client_cancelled"),
            CompanionModel.userFacingRecoveryMessage(for: "recovery_client_session_expired")
        )
    }

    /// Commit 3 RG — cancel during in-flight approval must invalidate the
    /// recovery approval authority, supersede the model operation, and leave
    /// no stale notice/presentation.
    func testCancelDuringInFlightApprovalInvalidatesAndSupersedes() async throws {
        let signer = RecoveryMockSigner(behavior: .delayed(nanoseconds: 5_000_000_000))
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let transport = RecoveryScenario.standard(simulator)
        let approval = TestRecoveryApprovalManager()
        let model = makeModel(
            transport: transport,
            signer: signer,
            recoveryApproval: approval
        )
        await model.acceptRecoveryScannedValue(simulator.uri)
        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)
        XCTAssertNotNil(model.recoveryStatus.presentation)

        let gate = RecoveryTestGate()
        signer.setOnSign { await gate.wait() }
        let approveTask = Task { await model.approveRecovery() }
        try await Task.sleep(nanoseconds: 80_000_000)
        XCTAssertTrue(model.isWorking)

        await model.cancelRecovery()
        XCTAssertEqual(approval.invalidateCallCount, 1)
        XCTAssertEqual(model.recoveryStatus.state, .cancelled)
        XCTAssertNil(model.recoveryStatus.presentation)
        XCTAssertFalse(model.isWorking)

        gate.open()
        await approveTask.value

        XCTAssertEqual(model.recoveryStatus.state, .cancelled)
        XCTAssertNil(model.recoveryStatus.presentation)
        XCTAssertNil(model.notice, "stale success/failure notice must not appear")
        XCTAssertFalse(model.isWorking)
        XCTAssertEqual(transport.requests(for: .complete).count, 0)
        XCTAssertEqual(approval.invalidateCallCount, 1, "invalidation occurs exactly once")
    }

    func testBackgroundCancelsActiveWorkAndPreservesTerminalOutcomes() async throws {
        let signer = RecoveryMockSigner(behavior: .delayed(nanoseconds: 2_000_000_000))
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let gate = RecoveryTestGate()
        let transport = FakeRecoveryTransport()
        transport.setHandler(.request) { request in
            await gate.wait()
            return FakeRecoveryTransport.ok(
                try simulator.deliveryBody(for: request.body),
                endpoint: simulator.requestEndpoint
            )
        }
        transport.setHandler(.complete) { request in
            FakeRecoveryTransport.ok(
                try simulator.acknowledgementBody(for: request.body),
                endpoint: simulator.completionEndpoint
            )
        }
        let pairing = RecordingPairingClientSeam()
        let approval = LocalApprovalManager()
        let model = CompanionModel(
            transport: transport,
            signer: signer,
            clock: FixedCompanionClock(
                seconds: RecoveryDesktopSimulator.nowSeconds,
                milliseconds: RecoveryDesktopSimulator.nowMilliseconds
            ),
            pairingRouter: pairing,
            credentialManager: SecureEnclaveCredentialManager(),
            approvalManager: approval
        )

        let fetchTask = Task { await model.acceptRecoveryScannedValue(simulator.uri) }
        try await Task.sleep(nanoseconds: 60_000_000)
        XCTAssertEqual(model.recoveryStatus.state, .fetchingRequest)

        await model.handleSceneInactivity()
        gate.open()
        await fetchTask.value

        XCTAssertEqual(model.recoveryStatus.state, .cancelled)
        XCTAssertEqual(pairing.cancelPendingCalls, 1)

        // Late result inert — status remains cancelled
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(model.recoveryStatus.state, .cancelled)

        // Accepted terminal remains unchanged across inactivity.
        let signer2 = RecoveryMockSigner()
        let simulator2 = try RecoveryDesktopSimulator(
            bitmap: "6",
            owner: Self.self,
            sessionIdOverride: "0x" + String(repeating: "22", count: 32),
            role1SigningPublicKey: signer2.publicKey
        )
        let model2 = makeModel(
            transport: RecoveryScenario.standard(simulator2),
            signer: signer2,
            pairing: pairing
        )
        await model2.acceptRecoveryScannedValue(simulator2.uri)
        await model2.approveRecovery()
        XCTAssertEqual(model2.recoveryStatus.state, .accepted)
        await model2.handleSceneInactivity()
        XCTAssertEqual(model2.recoveryStatus.state, .accepted)
        await model2.handleSceneInactivity()
        XCTAssertEqual(model2.recoveryStatus.state, .accepted, "idempotent for repeated inactive")
    }

    func testPairingAndRecoveryStatesDoNotOverwriteEachOther() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let pairing = RecordingPairingClientSeam()
        pairing.parseResult = .failure(CompanionFailure.invalidRequest)
        let model = makeModel(
            transport: RecoveryScenario.standard(simulator),
            signer: signer,
            pairing: pairing
        )
        await model.acceptRecoveryScannedValue(simulator.uri)
        let recoverySession = model.recoveryStatus.sessionId
        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)

        await model.acceptPairingScannedValue("philcore://pair/v1?request=not-a-real-payload")
        XCTAssertEqual(model.recoveryStatus.sessionId, recoverySession)
        XCTAssertEqual(model.recoveryStatus.state, .awaitingApproval)
        XCTAssertNil(model.pairingRequest)

        await model.handleSceneInactivity()
        XCTAssertEqual(pairing.cancelPendingCalls, 1)
        XCTAssertNil(model.pairingRequest)
    }

    func testPairTabRejectsRecoveryURIAndRecoveryTabRejectsPairingURI() async throws {
        let signer = RecoveryMockSigner()
        let simulator = try RecoveryDesktopSimulator(
            bitmap: "3",
            owner: Self.self,
            role1SigningPublicKey: signer.publicKey
        )
        let pairing = RecordingPairingClientSeam()
        let model = makeModel(
            transport: RecoveryScenario.standard(simulator),
            signer: signer,
            pairing: pairing
        )

        await model.acceptPairingScannedValue(simulator.uri)
        XCTAssertTrue(pairing.parseCalls.isEmpty)
        XCTAssertEqual(model.recoveryStatus.state, .idle)

        await model.acceptPairingScannedValue("phil-step6c-routine-enrollment-v2:x")
        XCTAssertTrue(pairing.parseCalls.isEmpty)
        XCTAssertEqual(
            model.notice,
            "This is a PhilCore routine request. Open Approve and use Scan routine QR code."
        )

        await model.acceptRecoveryScannedValue("philcore://pair/v1?request=abc")
        XCTAssertEqual(model.recoveryStatus.state, .idle)
    }

    func testViewStateProjectionAllowlist() {
        let idle = RecoveryApprovalViewState.project(
            status: CompanionModel.idleRecoveryStatus,
            isWorking: false,
            isScanning: false
        )
        XCTAssertEqual(idle.phase, .idle)
        XCTAssertFalse(idle.approveEnabled)

        let scanning = RecoveryApprovalViewState.project(
            status: CompanionModel.idleRecoveryStatus,
            isWorking: false,
            isScanning: true
        )
        XCTAssertEqual(scanning.phase, .scanning)

        let fetchingStatus = RecoveryClientStatus(
            state: .fetchingRequest,
            generation: 1,
            sessionId: "0x" + String(repeating: "aa", count: 32),
            expiresAtUnixSeconds: 1,
            presentation: nil,
            acknowledgedStatus: nil,
            failureReason: nil
        )
        let fetching = RecoveryApprovalViewState.project(
            status: fetchingStatus,
            isWorking: true,
            isScanning: false
        )
        XCTAssertEqual(fetching.phase, .fetching)
        XCTAssertTrue(fetching.cancelAvailable)
        XCTAssertFalse(fetching.approveEnabled)

        let presentation = RecoveryPresentation(
            sessionId: "0x" + String(repeating: "bb", count: 32),
            expiresAtUnixSeconds: 99,
            actionText: "Recovery request",
            networkText: "chain 11155111",
            comparisonFingerprint: "ABCD",
            factorBitmap: "6",
            completionEndpoint: "http://10.0.0.1:9/complete",
            accountAddress: "0x" + String(repeating: "11", count: 20),
            chainId: "11155111",
            recoveryEpoch: "1"
        )
        let reviewStatus = RecoveryClientStatus(
            state: .awaitingApproval,
            generation: 1,
            sessionId: presentation.sessionId,
            expiresAtUnixSeconds: 99,
            presentation: presentation,
            acknowledgedStatus: nil,
            failureReason: nil
        )
        let review = RecoveryApprovalViewState.project(
            status: reviewStatus,
            isWorking: false,
            isScanning: false
        )
        XCTAssertTrue(review.approveEnabled)
        if case .review(let fields) = review.phase {
            XCTAssertFalse(fields.completionEndpointVisible)
            XCTAssertFalse(String(describing: fields).contains("complete"))
            XCTAssertFalse(String(describing: fields).contains("digest"))
        } else {
            XCTFail("expected review")
        }

        let submitting = RecoveryApprovalViewState.project(
            status: RecoveryClientStatus(
                state: .submittingApproval,
                generation: 1,
                sessionId: presentation.sessionId,
                expiresAtUnixSeconds: 99,
                presentation: presentation,
                acknowledgedStatus: nil,
                failureReason: nil
            ),
            isWorking: true,
            isScanning: false
        )
        XCTAssertEqual(submitting.phase, .submitting)
        XCTAssertFalse(submitting.approveEnabled)

        let cases: [(RecoveryClientState, String?, RecoveryApprovalViewState.Phase)] = [
            (.accepted, nil, .accepted),
            (.rejected, "recovery_client_rejected_by_desktop", .desktopRejected),
            (.rejected, "recovery_client_rejected_locally", .localRejected),
            (.cancelled, "recovery_client_cancelled", .cancelled),
            (.cancelled, "recovery_client_cancelled_background", .cancelled),
            (.failed, "recovery_client_session_expired", .expired),
            (.failed, "biometric_approval_denied", .signerFailure),
            (.failed, "recovery_client_signer_failed", .failed)
        ]
        for (state, reason, expected) in cases {
            let projected = RecoveryApprovalViewState.project(
                status: RecoveryClientStatus(
                    state: state,
                    generation: 1,
                    sessionId: nil,
                    expiresAtUnixSeconds: nil,
                    presentation: nil,
                    acknowledgedStatus: state == .accepted ? "ACCEPTED" : nil,
                    failureReason: reason
                ),
                isWorking: false,
                isScanning: false
            )
            XCTAssertEqual(projected.phase, expected, "state \(state) reason \(String(describing: reason))")
            XCTAssertFalse(
                String(describing: projected).contains("ciphertext"),
                "raw protocol material must stay out of view state"
            )
        }
    }
}
