import CryptoKit
import Combine
import Security
import XCTest
@testable import PhilCoreCompanion

@MainActor
final class RoutineAuthorizationTests: XCTestCase {
    func testNoncePackingBoundariesAndMalformedInputs() throws {
        let cases:[UInt64] = [0,1,2,3,255,256,65535,UInt64(UInt32.max),1 << 32,UInt64.max]
        for value in cases {
            let actual = try RoutineAuthorizationCanonicalVerifier.shiftedNonce(key:"0",sequence:String(value))
            let suffix = (0..<8).reversed().map { UInt8(truncatingIfNeeded:value >> ($0 * 8)) }
            XCTAssertEqual(actual,Data(repeating:0,count:24)+Data(suffix),"nonce \(value)")
            XCTAssertEqual(actual.startIndex,0)
        }
        let maxKey = "6277101735386680763835789423207666416102355444464034512895"
        XCTAssertEqual(try RoutineAuthorizationCanonicalVerifier.shiftedNonce(key:maxKey,sequence:String(UInt64.max)),Data(repeating:255,count:32))
        for invalid in ["-1","+1","01","1.0","1e0"," 1","","NaN","١","18446744073709551616"] {
            XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.shiftedNonce(key:"0",sequence:invalid))
        }
        XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.shiftedNonce(key:"6277101735386680763835789423207666416102355444464034512896",sequence:"0"))
        XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.shiftedNonce(key:String(repeating:"9",count:79),sequence:"0"))
    }

    func testCommittedNonceOneFixturePassesIndependentSwiftBinding() throws {
        let request = try fixtureRequestObject(name:"successfulNonce1")
        let core = try XCTUnwrap(request["authorizationCore"] as? [String:Any])
        let base = try RoutineAuthorizationBootstrap.decode(expectedQR,now:1_800_000_021)
        let bootstrap = RoutineAuthorizationBootstrap(sessionId:Data(hex:String((core["sessionId"] as! String).dropFirst(2))),
            ipv4:base.ipv4,port:base.port,desktopPublicKey:base.desktopPublicKey,
            requestId:Data(hex:String((request["requestId"] as! String).dropFirst(2))),expiresAt:UInt64(core["expiresAt"] as! String)!)
        let signer = try SyntheticRoutineSigner()
        _ = try RoutineAuthorizationCanonicalVerifier.verify(request,bootstrap:bootstrap,record:signer.activeRecord(),fingerprint:"TEST",now:UInt64(core["issuedAt"] as! String)!+1)
        for representation:Any in [1,1.0,true,NSNull(),"-1","1.0","18446744073709551616"] {
            var changed=request, action=request["action"] as! [String:Any]
            action["nonceSequence"]=representation;changed["action"]=action
            XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verify(changed,bootstrap:bootstrap,record:signer.activeRecord(),fingerprint:"TEST",now:UInt64(core["issuedAt"] as! String)!+1))
        }
    }

    /// Real Desktop listener/storage/local chain + real iOS model/client/URLSession.
    /// Only the camera callback, OS signer and boundary clock are test seams.
    func testRoutineAuthorizationLongitudinalAcceptance() async throws {
        let repository = URL(fileURLWithPath:#filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let control = repository.appendingPathComponent(".local/release-validation/harness-control.json")
        guard let data = try? Data(contentsOf:control), let object = try JSONSerialization.jsonObject(with:data) as? [String:Any],
              let text = object["url"] as? String, let url = URL(string:text) else {
            XCTFail("Required longitudinal backend missing; use canonical Simulator gate");return
        }
        func command(_ op:String,_ requestId:String? = nil) async throws -> [String:Any] {
            var body:[String:Any] = ["op":op];if let requestId { body["requestId"]=requestId }
            var req=URLRequest(url:url);req.httpMethod="POST";req.httpBody=try JSONSerialization.data(withJSONObject:body)
            req.setValue("application/json",forHTTPHeaderField:"Content-Type")
            let (data,response)=try await URLSession.shared.data(for:req)
            let value=try XCTUnwrap(try JSONSerialization.jsonObject(with:data) as? [String:Any])
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw NSError(domain:"LongitudinalBackend",code:1,userInfo:[NSLocalizedDescriptionKey:value["error"] as? String ?? "backend failed"]) }
            return value
        }
        let initial=try await command("stats"),clock=LongitudinalClock(UInt64(initial["now"] as! String)!)
        let signer=try SyntheticRoutineSigner(initialActiveGeneration:nil)
        let transport=RecordingLongitudinalTransport()
        func makeModel()->CompanionModel {
            let approval=LocalApprovalManager()
            return CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),clock:clock,
                pairingRouter:RecordingPairingClientSeam(),credentialManager:SecureEnclaveCredentialManager(),
                approvalManager:approval,recoveryApproval:approval,routineTransport:transport,routineApproval:signer)
        }
        var model=makeModel(), transitions:[String]=[]
        func require(_ phase:RoutineAuthorizationPhase) throws {
            XCTAssertEqual(model.routineStatus.phase,phase,"\(String(describing:model.routineStatus.failure)) / \(model.routineStatus.bindingField ?? "none")")
            guard model.routineStatus.phase == phase else { throw NSError(domain:"LongitudinalPhase",code:1) }
            transitions.append(String(describing:phase))
        }
        func scan(_ request:[String:Any]) async throws {
            clock.set(UInt64(request["now"] as! String)!)
            await model.acceptRoutineScannedValue(try XCTUnwrap(request["qrPayload"] as? String))
            try require(.comparingFingerprint)
            let status=try await command("status",request["requestId"] as? String)
            XCTAssertEqual(model.routineStatus.fingerprint,status["comparisonFingerprint"] as? String)
            await model.confirmRoutineFingerprint()
        }
        let enrollment=try await command("begin")
        await model.acceptRoutineScannedValue(enrollment["qrPayload"] as! String)
        try require(.comparingFingerprint)
        await model.confirmRoutineFingerprint();try require(.accepted)
        let originalRecord=try signer.activeRecord()
        let enrolled=try await command("status",enrollment["requestId"] as? String)
        XCTAssertEqual(enrolled["state"] as? String,"completed")
        let baseline=try await command("baseline")
        XCTAssertEqual(baseline["pendingRequestCount"] as? Int,0);XCTAssertEqual(baseline["expectedNonce"] as? String,"0")
        let signaturesAfterEnrollment=signer.signCount

        let q1=try await command("begin");XCTAssertEqual(q1["nonce"] as? String,"0")
        try await scan(q1);try require(.reviewing)
        await model.approveRoutine();try require(.accepted)
        let approvedFrame=try XCTUnwrap(transport.lastBound)
        var status=try await command("status",q1["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,9);XCTAssertEqual(status["executions"] as? Int,1)

        // Same model, signer, Desktop runtime and account: nonce one must review.
        let q2=try await command("begin");XCTAssertEqual(q2["nonce"] as? String,"1")
        XCTAssertNotEqual(q1["requestId"] as? String,q2["requestId"] as? String)
        let replay=try await transport.replay(approvedFrame)
        XCTAssertEqual(replay.statusCode,409)
        try await scan(q2);try require(.reviewing)
        await model.denyRoutine();try require(.denied)
        status=try await command("status",q2["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,20);XCTAssertEqual(status["terminalReason"] as? String,"rejected")
        XCTAssertEqual(status["executions"] as? Int,1);XCTAssertEqual(signer.signCount,signaturesAfterEnrollment+1)
        let rejectedFrame=try XCTUnwrap(transport.lastBound)

        // Passive expiry: no phone packet is needed to expire the Desktop host.
        let q3=try await command("begin");XCTAssertEqual(q3["nonce"] as? String,"1")
        status=try await command("expire",q3["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,21)
        clock.set(UInt64(status["now"] as! String)!)
        await model.acceptRoutineScannedValue(q3["qrPayload"] as! String);try require(.expired)
        let cancelled=try await command("begin")
        clock.set(UInt64(cancelled["now"] as! String)!)
        await model.acceptRoutineScannedValue(cancelled["qrPayload"] as! String);try require(.comparingFingerprint)
        await model.cancelRoutineOnDesktop();try require(.cancelled)
        status=try await command("status",cancelled["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,20);XCTAssertTrue(status["terminalReason"] is NSNull)

        let q4=try await command("begin");XCTAssertEqual(q4["nonce"] as? String,"1")
        // Use the original deadline only while valid; at expiry a raw stale frame
        // still must not acquire current request ownership on the host.
        try await scan(q4);try require(.reviewing)
        await model.approveRoutine();try require(.accepted)
        status=try await command("status",q4["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,9);XCTAssertEqual(status["executions"] as? Int,2)
        XCTAssertNotEqual(rejectedFrame.requestId,q4["requestId"] as? String)

        // Real product reinitialization, preserving durable Desktop stores and
        // the signer abstraction representing a persistent hardware key.
        let restarted=try await command("restart")
        XCTAssertEqual(restarted["publicKeyFingerprint"] as? String,originalRecord.publicKeyFingerprint)
        model=makeModel();try require(.idle)
        XCTAssertEqual(try signer.activeRecord(),originalRecord)
        let q5=try await command("begin");XCTAssertEqual(q5["nonce"] as? String,"0","new local chain/account after Desktop restart")
        try await scan(q5);try require(.reviewing)
        await model.approveRoutine();try require(.accepted)
        status=try await command("status",q5["requestId"] as? String)
        XCTAssertEqual(status["state"] as? Int,9);XCTAssertEqual(status["executions"] as? Int,3)
        let stats=try await command("stats")
        XCTAssertEqual(stats["requests"] as? Int,6);XCTAssertEqual(stats["restarts"] as? Int,1)
        XCTAssertEqual(signer.signCount,signaturesAfterEnrollment+3)
        XCTAssertEqual(stats["publicMutations"] as? Int,0)
        let evidence:[String:Any] = ["test":"routine_authorization_longitudinal_acceptance","result":"PASS",
            "physicalEquivalence":"MEDIUM","transitions":transitions,
            "executions":try XCTUnwrap(stats["executions"] as? Int),"requests":try XCTUnwrap(stats["requests"] as? Int),
            "desktopReinitializations":try XCTUnwrap(stats["restarts"] as? Int),
            "signaturesAfterEnrollment":signer.signCount-signaturesAfterEnrollment,
            "publicMutations":try XCTUnwrap(stats["publicMutations"] as? Int)]
        try JSONSerialization.data(withJSONObject:evidence,options:[.prettyPrinted,.sortedKeys]).write(to:repository.appendingPathComponent(".local/release-validation/longitudinal-result.json"))
    }

    func testMalformedSignatureHasFieldDiagnosticAndIsNeverSubmitted() async throws {
        let bootstrap=try RoutineAuthorizationBootstrap.decode(expectedQR,now:1_800_000_021)
        let signer=try SyntheticRoutineSigner();signer.returnMalformedSignature=true
        let transport=SyntheticRoutineTransport(bootstrap:bootstrap,requestJSON:try fixtureRequest())
        let client=RoutineAuthorizationClient(transport:transport,signer:signer)
        await client.start(scannedValue:expectedQR,now:1_800_000_021);client.confirmFingerprint(now:1_800_000_021)
        await client.approve(now:1_800_000_021)
        XCTAssertEqual(client.status.failure,.bindingMismatch);XCTAssertEqual(client.status.bindingField,"signature.der")
        XCTAssertEqual(signer.signCount,1);XCTAssertEqual(transport.completeCount,0)
    }

    func testTerminalAcknowledgmentBindsEveryFieldAndRejectsBooleanVersion() async throws {
        let bootstrap=try RoutineAuthorizationBootstrap.decode(expectedQR,now:1_800_000_021)
        for field in ["purpose","sessionId","requestId","outcome","protocolVersion"] {
            let signer=try SyntheticRoutineSigner()
            let transport=SyntheticRoutineTransport(bootstrap:bootstrap,requestJSON:try fixtureRequest(),changedAckField:field)
            let client=RoutineAuthorizationClient(transport:transport,signer:signer)
            await client.start(scannedValue:expectedQR,now:1_800_000_021);client.confirmFingerprint(now:1_800_000_021)
            await client.deny()
            XCTAssertEqual(client.status.phase,.failed);XCTAssertEqual(signer.signCount,0)
            if field=="protocolVersion" { XCTAssertEqual(client.status.failure,.malformedRequest) }
            else { XCTAssertEqual(client.status.failure,.bindingMismatch);XCTAssertEqual(client.status.bindingField,"terminalAck."+field) }
        }
    }

    func testBindingMismatchFieldSurvivesSafeDiagnosticPersistence() async throws {
        var request=try fixtureRequestObject(),action=request["action"] as! [String:Any]
        action["userOpNonce"]="1";request["action"]=action
        let bootstrap=try RoutineAuthorizationBootstrap.decode(expectedQR,now:1_800_000_021)
        let transport=SyntheticRoutineTransport(bootstrap:bootstrap,requestJSON:try JSONSerialization.data(withJSONObject:request))
        let signer=try SyntheticRoutineSigner(),client=RoutineAuthorizationClient(transport:transport,signer:signer)
        await client.start(scannedValue:expectedQR,now:1_800_000_021);client.confirmFingerprint(now:1_800_000_021)
        XCTAssertEqual(client.status.failure,.bindingMismatch);XCTAssertEqual(client.status.bindingField,"action.userOpNonce")
        XCTAssertEqual(signer.signCount,0)
        let suite="philcore-diagnostic-test-"+UUID().uuidString,defaults=try XCTUnwrap(UserDefaults(suiteName:suite))
        defer { defaults.removePersistentDomain(forName:suite) }
        RoutineEnrollmentDiagnosticPersistence.save(client.status,defaults:defaults)
        XCTAssertEqual(RoutineEnrollmentDiagnosticPersistence.loadFailure(defaults:defaults)?.bindingField,"action.userOpNonce")
        let recorded=try XCTUnwrap(defaults.dictionary(forKey:RoutineEnrollmentDiagnosticPersistence.defaultsKey))
        XCTAssertEqual(Set(recorded.keys),["schemaVersion","phase","failure","bindingField","updatedAt"])
        XCTAssertFalse(String(describing:recorded).contains("0x"))
    }

    func testCancellationDuringBeginWaitsForRemoteAcknowledgement() async throws {
        let events=(0..<2).map { expectation(description:"cancel transport \($0)") }
        let transport=try suspendedScanTransport { index in events[index].fulfill() }
        let signer=try SyntheticRoutineSigner(),client=RoutineAuthorizationClient(transport:transport,signer:signer)
        let begin=Task { await client.start(scannedValue:expectedQR,now:1_800_000_021) }
        await fulfillment(of:[events[0]],timeout:5)
        let cancelling=expectation(description:"waiting for cancellation acknowledgement")
        let observation=client.$status.sink { if $0.phase == .submitting { cancelling.fulfill() } }
        let cancellation=Task { await client.cancelOnDesktop() }
        await fulfillment(of:[cancelling],timeout:5);XCTAssertEqual(client.status.phase,.submitting)
        withExtendedLifetime(observation) {}
        transport.finish(0);await begin.value
        await fulfillment(of:[events[1]],timeout:5)
        XCTAssertEqual(client.status.phase,.submitting,"cancellation is not acknowledged yet")
        transport.finish(1);await cancellation.value
        XCTAssertEqual(client.status.phase,.cancelled);XCTAssertEqual(signer.signCount,0)
    }

    private var expectedTransport: [String: Any] {
        let url = Bundle(for: Self.self).url(forResource: "PHIL_V1_STEP6C2_PRODUCT_WIRING_FIXTURE", withExtension: "json")!
        let root = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        return root["transport"] as! [String: Any]
    }

    private var expectedQR: String {
        expectedTransport["qrPayload"] as! String
    }

    func testNewScanShowsLoadingInsteadOfSupersededEnrollmentCancellation() async throws {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        let reachedHandshake = expectation(description: "new scan handshake suspended")
        let transport = SuspendedRoutineTransport(
            base: SyntheticRoutineTransport(bootstrap: bootstrap, requestJSON: try fixtureRequest()),
            onStart: { _ in reachedHandshake.fulfill() }
        )
        let signer = try SyntheticRoutineSigner()
        let model = scanModel(transport: transport, signer: signer)
        // A prior enrollment presentation must be cleared without displaying its cancellation.
        await model.acceptRoutineScannedValue(SyntheticEnrollmentTransport.placeholder().bootstrap.encoded)
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        var observed: [RoutineAuthorizationPhase] = []
        let observation = model.$routineStatus.sink { observed.append($0.phase) }
        let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [reachedHandshake], timeout: 5)
        XCTAssertEqual(model.routineStatus.phase, .exchangingKeys,
                       "new request is loading, not cancelled by prior enrollment cleanup")
        XCTAssertFalse(observed.contains(.cancelled), "internal cleanup must not flash Request Cancelled")
        XCTAssertEqual(signer.signCount, 0)
        transport.finish(0)
        await scan.value
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        withExtendedLifetime(observation) {}
    }

    private func scanModel(transport: any RoutineAuthorizationTransporting, signer: SyntheticRoutineSigner,
                           recorder: ((RoutineAuthorizationStatus) -> Void)? = nil,
                           loader: (() -> RoutineAuthorizationStatus?)? = nil) -> CompanionModel {
        let approval = LocalApprovalManager()
        return CompanionModel(transport: FakeRecoveryTransport(), signer: RecoveryMockSigner(),
            clock: FixedCompanionClock(seconds: 1_800_000_021, milliseconds: 1_800_000_021_000),
            pairingRouter: RecordingPairingClientSeam(), credentialManager: SecureEnclaveCredentialManager(),
            approvalManager: approval, recoveryApproval: approval, routineTransport: transport, routineApproval: signer,
            routineDiagnosticRecorder: recorder, routineDiagnosticLoader: loader)
    }

    func testGenuineEnrollmentCancellationStillRecordsCurrentTerminalDiagnostic() async throws {
        let signer = try SyntheticRoutineSigner()
        var recorded: [RoutineAuthorizationPhase] = []
        let model = scanModel(transport: SyntheticEnrollmentTransport.placeholder(), signer: signer,
                              recorder: { recorded.append($0.phase) })
        await model.acceptRoutineScannedValue(SyntheticEnrollmentTransport.placeholder().bootstrap.encoded)
        XCTAssertEqual(recorded.last, .comparingFingerprint)
        XCTAssertFalse(recorded.contains(.cancelled), "superseded cleanup must not be recorded as current cancellation")
        model.cancelRoutine()
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        XCTAssertEqual(recorded.last, .cancelled)
    }

    func testActiveRequestCancellationSurvivesLateTransportFailure() async throws {
        let started = expectation(description: "active request loading")
        let transport = try suspendedScanTransport { _ in started.fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started], timeout: 5)
        model.cancelRoutine()
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        XCTAssertEqual(model.routineStatus.failure, .userCancelled)
        transport.finish(0, failure: .transportFailure)
        await scan.value
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        XCTAssertEqual(model.routineClient.status.phase, .cancelled)
        XCTAssertEqual(signer.signCount, 0)
    }

    func testActiveRequestRejectionSurvivesLateTransportSuccess() async throws {
        let started = expectation(description: "active request loading")
        let transport = try suspendedScanTransport { _ in started.fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started], timeout: 5)
        await model.denyRoutine()
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        transport.finish(0)
        await scan.value
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        XCTAssertEqual(model.routineClient.status.phase, .cancelled)
        XCTAssertEqual(signer.signCount, 0)
    }

    func testCurrentRequestExpiryAndErrorsAreNotSuppressed() async throws {
        for failure in [RoutineAuthorizationFailure.expired, .transportFailure, .userCancelled] {
            let started = expectation(description: "active request loading \(failure)")
            let transport = try suspendedScanTransport { _ in started.fulfill() }
            let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
            let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
            await fulfillment(of: [started], timeout: 5)
            XCTAssertEqual(model.routineStatus.phase, .exchangingKeys)
            transport.finish(0, failure: failure)
            await scan.value
            XCTAssertEqual(model.routineStatus.phase, failure == .expired ? .expired : failure == .userCancelled ? .cancelled : .failed)
            XCTAssertEqual(model.routineStatus.failure, failure)
            XCTAssertEqual(signer.signCount, 0)
        }
    }

    func testRapidSequentialScansIgnoreSupersededSuccessAndTerminalEvents() async throws {
        let started = (0..<3).map { expectation(description: "scan \($0) loading") }
        let transport = try suspendedScanTransport { index in started[index].fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        let first = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started[0]], timeout: 5)
        let second = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started[1]], timeout: 5)
        let third = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started[2]], timeout: 5)
        XCTAssertEqual(model.routineStatus.phase, .exchangingKeys)
        transport.finish(1, failure: .userCancelled)
        await second.value
        XCTAssertEqual(model.routineStatus.phase, .exchangingKeys)
        XCTAssertEqual(model.routineClient.status.phase, .exchangingKeys)
        transport.finish(2)
        await third.value
        let currentFingerprint = model.routineStatus.fingerprint
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        transport.finish(0)
        await first.value
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        XCTAssertEqual(model.routineStatus.fingerprint, currentFingerprint)
        XCTAssertEqual(model.routineClient.status.phase, .comparingFingerprint)
        XCTAssertEqual(signer.signCount, 0)
    }

    func testSupersededRoutineCompletionCannotReplaceNewEnrollmentPresentation() async throws {
        let started = expectation(description: "old routine loading")
        let transport = try suspendedScanTransport { _ in started.fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        let oldScan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started], timeout: 5)
        var observed: [RoutineAuthorizationPhase] = []
        let observation = model.$routineStatus.sink { observed.append($0.phase) }
        let enrollment = SyntheticEnrollmentTransport.placeholder().bootstrap
        await model.acceptRoutineScannedValue(enrollment.encoded)
        XCTAssertFalse(observed.contains(.cancelled), "replacement cleanup must not become a new enrollment cancellation")
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        XCTAssertEqual(model.routineStatus.fingerprint, enrollment.fingerprint)
        transport.finish(0, failure: .userCancelled)
        await oldScan.value
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        XCTAssertEqual(model.routineStatus.fingerprint, enrollment.fingerprint)
        model.cancelRoutine()
        XCTAssertEqual(model.routineStatus.phase, .cancelled, "active enrollment cancellation must still be visible")
        withExtendedLifetime(observation) {}
    }

    func testRestoredUnknownSurvivesBackgroundAndKeyActions() async throws {
        let signer=try SyntheticRoutineSigner(),transport=SyntheticEnrollmentTransport.placeholder()
        var persisted=RoutineAuthorizationStatus(phase:.failed,fingerprint:nil,presentation:nil,failure:.outcomeUnknown)
        for _ in 0..<2 {
            let model=scanModel(transport:transport,signer:signer,recorder:{persisted=$0},loader:{persisted})
            XCTAssertEqual(model.routineClient.status.failure,.outcomeUnknown)
            await model.handleSceneInactivity()
            model.createRoutineApprovalKey();model.deleteRoutineApprovalKey();model.cancelRoutine()
            await model.acceptRoutineScannedValue(expectedQR)
            XCTAssertEqual(model.routineStatus.failure,.outcomeUnknown)
            XCTAssertEqual(persisted.failure,.outcomeUnknown)
            XCTAssertEqual(signer.deleteCount,0);XCTAssertEqual(signer.createCount,0);XCTAssertEqual(signer.signCount,0)
        }
    }

    func testSubmittedApprovalCannotBeSupersededIntoFalseCancellation() async throws {
        let started=(0..<2).map { expectation(description:"transport operation \($0)") }
        let transport=try suspendedScanTransport { index in started[index].fulfill() }
        let signer=try SyntheticRoutineSigner(),model=scanModel(transport:transport,signer:signer)
        let first=Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of:[started[0]],timeout:5);transport.finish(0);await first.value
        await model.confirmRoutineFingerprint();XCTAssertEqual(model.routineStatus.phase,.reviewing)
        let approval=Task { await model.approveRoutine() }
        await fulfillment(of:[started[1]],timeout:5)
        await model.acceptRoutineScannedValue(expectedQR)
        XCTAssertEqual(model.routineStatus.phase,.submitting,"a submitted approval cannot be silently replaced")
        transport.finish(1,failure:.userCancelled);await approval.value
        XCTAssertEqual(model.routineStatus.phase,.failed)
        XCTAssertEqual(model.routineStatus.failure,.outcomeUnknown)
        await model.acceptRoutineScannedValue(expectedQR)
        XCTAssertEqual(model.routineStatus.failure,.outcomeUnknown)
        XCTAssertEqual(signer.signCount,1)
    }

    func testSupersededEnrollmentEventsCannotContaminateNewRoutinePresentation() async throws {
        let started = expectation(description: "new routine loading")
        let transport = try suspendedScanTransport { _ in started.fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        await model.acceptRoutineScannedValue(SyntheticEnrollmentTransport.placeholder().bootstrap.encoded)
        let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started], timeout: 5)
        // The old enrollment observer must retain its old presentation identity.
        model.routineEnrollmentClient.cancel()
        XCTAssertEqual(model.routineStatus.phase, .exchangingKeys)
        transport.finish(0)
        await scan.value
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        model.routineEnrollmentClient.cancel()
        XCTAssertEqual(model.routineStatus.phase, .comparingFingerprint)
        XCTAssertEqual(signer.signCount, 0)
    }

    func testBackgroundCancellationOfLoadingRequestRemainsFailClosed() async throws {
        let started = expectation(description: "request loading before background")
        let transport = try suspendedScanTransport { _ in started.fulfill() }
        let signer = try SyntheticRoutineSigner(), model = scanModel(transport: transport, signer: signer)
        let scan = Task { await model.acceptRoutineScannedValue(expectedQR) }
        await fulfillment(of: [started], timeout: 5)
        await model.handleSceneInactivity()
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        transport.finish(0)
        await scan.value
        XCTAssertEqual(model.routineStatus.phase, .cancelled)
        XCTAssertEqual(signer.signCount, 0)
    }

    private func suspendedScanTransport(onStart: @escaping (Int) -> Void) throws -> SuspendedRoutineTransport {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        return SuspendedRoutineTransport(base: SyntheticRoutineTransport(bootstrap: bootstrap, requestJSON: try fixtureRequest()), onStart: onStart)
    }

    func testScannerDeliveryGateResetsForEveryPresentation() {
        let gate = QRScannerDeliveryGate()
        gate.beginPresentation()
        XCTAssertNil(gate.claimDecodedValue(nil), "malformed metadata must not consume the presentation")
        XCTAssertEqual(gate.claimDecodedValue("first"), "first")
        XCTAssertNil(gate.claimDecodedValue("duplicate"))
        gate.beginPresentation()
        XCTAssertEqual(gate.claimDecodedValue("second"), "second", "a retained scanner controller must deliver after sheet re-presentation")
        XCTAssertNil(gate.claimDecodedValue("duplicate"))
    }

    func testRoutineTransportWaitsForInitialLocalNetworkPermissionResolution() {
        let configuration = URLSessionRoutineAuthorizationTransport.makeConfiguration()
        XCTAssertTrue(configuration.waitsForConnectivity)
        XCTAssertFalse(configuration.allowsCellularAccess)
        XCTAssertFalse(configuration.allowsExpensiveNetworkAccess)
        XCTAssertFalse(configuration.allowsConstrainedNetworkAccess)
        XCTAssertEqual(configuration.httpMaximumConnectionsPerHost, 1)
        XCTAssertEqual(configuration.timeoutIntervalForRequest,10)
        XCTAssertEqual(configuration.timeoutIntervalForResource,15)
        XCTAssertTrue(RoutineAuthorizationFailure.localNetworkUnavailable.localizedDescription.contains("Privacy & Security > Local Network"))
    }

    func testEnrollmentPreflightUsesProductionURLSessionRequestAndMapsNetworkFailures() async throws {
        let control=RoutinePreflightLoopbackControl.shared;control.reset()
        let transport=URLSessionRoutineAuthorizationTransport(additionalProtocolClasses:[RoutinePreflightLoopbackURLProtocol.self])
        let url="http://192.168.7.9:43124"+RoutineDeviceEnrollmentBootstrap.preflightPath
        let sessionId="0x"+String(repeating:"11",count:32),expiresAt=UInt64(Date().timeIntervalSince1970)+60
        try await transport.preflight(url:url,sessionId:sessionId,expiresAt:expiresAt)
        let request=try XCTUnwrap(control.requests.first)
        XCTAssertEqual(request.httpMethod,"HEAD");XCTAssertEqual(request.url?.absoluteString,url)
        XCTAssertEqual(request.value(forHTTPHeaderField:"Cache-Control"),"no-store")
        XCTAssertEqual(request.value(forHTTPHeaderField:"Connection"),"close")
        XCTAssertEqual(request.value(forHTTPHeaderField:"X-PhilCore-Enrollment-Session"),sessionId)
        XCTAssertNil(request.httpBody)

        control.stub = .init(failure:.notConnectedToInternet)
        do { try await transport.preflight(url:url,sessionId:sessionId,expiresAt:expiresAt);XCTFail("local-network failure must fail closed") }
        catch { XCTAssertEqual(error as? RoutineAuthorizationFailure,.localNetworkUnavailable) }
        control.stub = .init(failure:.cannotConnectToHost)
        do { try await transport.preflight(url:url,sessionId:sessionId,expiresAt:expiresAt);XCTFail("unreachable Desktop must fail closed") }
        catch { XCTAssertEqual(error as? RoutineAuthorizationFailure,.desktopUnavailable) }
    }

    func testTransientSceneInactivityDoesNotCancelPermissionOrAuthenticationPrompts() {
        XCTAssertFalse(PhilCoreCompanionApp.shouldInvalidateRoutine(for: .active))
        XCTAssertFalse(PhilCoreCompanionApp.shouldInvalidateRoutine(for: .inactive))
        XCTAssertTrue(PhilCoreCompanionApp.shouldInvalidateRoutine(for: .background))
    }

    func testCrossLanguageQRAndFingerprintVector() throws {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        XCTAssertEqual(bootstrap.encode(), expectedQR)
        XCTAssertEqual(bootstrap.dottedIPv4, "192.168.7.9")
        XCTAssertEqual(bootstrap.port, 43_123)
        let iphone = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let handshake = try RoutineAuthorizationHandshake(bootstrap: bootstrap, privateKey: iphone)
        XCTAssertEqual(handshake.fingerprint, expectedTransport["comparisonFingerprint"] as? String)
        XCTAssertEqual(hex(handshake.transcriptHash), expectedTransport["transcriptHash"] as? String)
        XCTAssertThrowsError(try RoutineAuthorizationBootstrap.decode(expectedQR + "=", now: 1_800_000_021))
    }

    func testFrameRejectsWrongDirectionAndTampering() throws {
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let nonce = try AES.GCM.Nonce(data: Data(repeating: 8, count: 12))
        let frame = try RoutineAuthorizationFrame.seal(Data("request".utf8), key: key, aad: Data("request-aad".utf8), nonce: nonce)
        XCTAssertEqual(try RoutineAuthorizationFrame.open(frame, key: key, aad: Data("request-aad".utf8)), Data("request".utf8))
        XCTAssertThrowsError(try RoutineAuthorizationFrame.open(frame, key: key, aad: Data("response-aad".utf8)))
        var changed = frame; changed[20] ^= 1
        XCTAssertThrowsError(try RoutineAuthorizationFrame.open(changed, key: key, aad: Data("request-aad".utf8)))
    }

    func testNoSignatureBeforePresentationAndFullSyntheticExchange() async throws {
        let fixture = try fixtureRequest()
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        let transport = SyntheticRoutineTransport(bootstrap: bootstrap, requestJSON: fixture)
        let signer = try SyntheticRoutineSigner()
        let client = RoutineAuthorizationClient(transport: transport, signer: signer)

        await client.start(scannedValue: expectedQR, now: 1_800_000_021)
        XCTAssertEqual(client.status.phase, .comparingFingerprint)
        XCTAssertEqual(signer.signCount, 0)
        XCTAssertEqual(transport.completeCount, 0)

        client.confirmFingerprint(now: 1_800_000_021)
        XCTAssertEqual(client.status.phase, .reviewing, "\(String(describing: client.status.failure))")
        XCTAssertEqual(client.status.presentation?.action, "Record Harmless Local Value")
        XCTAssertEqual(client.status.presentation?.network, "Local Hardhat Chain 31337")
        XCTAssertEqual(signer.signCount, 0)

        await client.approve(now: 1_800_000_021)
        XCTAssertEqual(client.status.phase, .accepted)
        XCTAssertEqual(signer.signCount, 1)
        XCTAssertEqual(transport.completeCount, 1)
        XCTAssertTrue(transport.responseSignatureVerified)
    }

    func testSepoliaMintRequestIsIndependentlyRebuiltBeforeReviewAndDirectApprovalSigning() throws {
        let url=try XCTUnwrap(Bundle(for:Self.self).url(forResource:"PHIL_SEPOLIA_MINT_DEVICE_REQUEST_FIXTURE",withExtension:"json"))
        let fixture=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:url)) as? [String:Any])
        let qr=try XCTUnwrap(fixture["qrPayload"] as? String)
        let root=try XCTUnwrap(fixture["request"] as? [String:Any])
        let bootstrap=try RoutineAuthorizationBootstrap.decode(qr,now:1_800_000_010)
        let record=try SyntheticRoutineSigner().activeRecord()
        let verified=try RoutineAuthorizationCanonicalVerifier.verifySepoliaMint(root,bootstrap:bootstrap,
            record:record,fingerprint:"ABCD-EF01-2345-6789-ABCD-EF01",now:1_800_000_010)
        XCTAssertEqual(verified.signingDigest,Data(hex:String(verified.approvalDigest.dropFirst(2))))
        XCTAssertEqual(verified.presentation.network,"Ethereum Sepolia (chain 11155111)")
        XCTAssertEqual(verified.presentation.action,"Mint one harmless, non-transferable Phil test pass")
        XCTAssertEqual(verified.presentation.value,"0 ETH")
        XCTAssertEqual(verified.responseFormatVersionHash,RoutineApprovalKeyManager.hex(RecoveryKeccak.keccak256(Data("PHIL_SEPOLIA_MINT_DEVICE_RESPONSE_V1".utf8))))

        for key in ["deviceApprovalDigest","humanPresentationHash","requestId","platformSigningDigest","approvalNonce","approvalExpiresAt"] {
            var candidate=root;candidate[key]=mutate(try XCTUnwrap(root[key]))
            XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verifySepoliaMint(candidate,
                bootstrap:bootstrap,record:record,fingerprint:"ABCD-EF01-2345-6789-ABCD-EF01",now:1_800_000_010),key)
        }
        for nestedName in ["bindings","authorizationEnvelope"] {
            let authorization=try XCTUnwrap(root["authorization"] as? [String:Any])
            let nested=try XCTUnwrap(authorization[nestedName] as? [String:Any])
            for key in nested.keys {
                // Exceptional-envelope digests intentionally exclude the root
                // nullifier to avoid a proof/digest cycle. Composition verifies
                // that separate proof public input before any execution release.
                if nestedName=="authorizationEnvelope" && key=="rootProofNullifier" { continue }
                var candidate=root,variedAuthorization=authorization,variedNested=nested
                variedNested[key]=mutate(try XCTUnwrap(nested[key]));variedAuthorization[nestedName]=variedNested
                candidate["authorization"]=variedAuthorization
                XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verifySepoliaMint(candidate,
                    bootstrap:bootstrap,record:record,fingerprint:"ABCD-EF01-2345-6789-ABCD-EF01",now:1_800_000_010),"\(nestedName).\(key)")
            }
        }
    }

    func testCancelAndBackgroundInvalidateBeforeSignature() async throws {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        let signer = try SyntheticRoutineSigner()
        let transport = SyntheticRoutineTransport(bootstrap: bootstrap, requestJSON: try fixtureRequest())
        let client = RoutineAuthorizationClient(transport: transport, signer: signer)
        await client.start(scannedValue: expectedQR, now: 1_800_000_021)
        client.invalidateForBackgroundOrLock()
        XCTAssertEqual(client.status.phase, .cancelled)
        XCTAssertEqual(signer.signCount, 0)
        XCTAssertGreaterThan(signer.invalidateCount, 0)
        XCTAssertTrue(transport.cancelled)
    }

    func testProductSceneInactivityForwardsToRoutineCancellation() async throws {
        let bootstrap=try RoutineAuthorizationBootstrap.decode(expectedQR,now:1_800_000_021),signer=try SyntheticRoutineSigner()
        let routineTransport=SyntheticRoutineTransport(bootstrap:bootstrap,requestJSON:try fixtureRequest()),approval=LocalApprovalManager()
        let model=CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),
            clock:FixedCompanionClock(seconds:1_800_000_021,milliseconds:1_800_000_021_000),pairingRouter:RecordingPairingClientSeam(),
            credentialManager:SecureEnclaveCredentialManager(),approvalManager:approval,recoveryApproval:approval,
            routineTransport:routineTransport,routineApproval:signer)
        await model.acceptRoutineScannedValue(expectedQR);XCTAssertEqual(model.routineStatus.phase,.comparingFingerprint)
        await model.handleSceneInactivity();XCTAssertEqual(model.routineStatus.phase,.cancelled);XCTAssertEqual(signer.signCount,0)
        XCTAssertGreaterThan(signer.invalidateCount,0);XCTAssertTrue(routineTransport.cancelled);XCTAssertFalse(model.isRoutineScanning)
    }

    func testDuplicateRequestFieldFailsBeforePresentationOrSignature() async throws {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        let original = try fixtureRequest(), requestId = "0x33b6ad9554a13507c8e352904fd1615139230d668c9ee9ee46ef138fbb9c0708"
        var duplicate = original; duplicate.removeLast();duplicate.append(Data(",\"requestId\":\"\(requestId)\"}".utf8))
        let signer = try SyntheticRoutineSigner()
        let client = RoutineAuthorizationClient(
            transport: SyntheticRoutineTransport(bootstrap: bootstrap, requestJSON: duplicate), signer: signer
        )
        await client.start(scannedValue: expectedQR, now: 1_800_000_021)
        XCTAssertEqual(client.status.phase, .comparingFingerprint)
        client.confirmFingerprint(now: 1_800_000_021)
        XCTAssertEqual(client.status.phase, .failed)
        XCTAssertEqual(client.status.failure, .malformedRequest)
        XCTAssertEqual(signer.signCount, 0)
    }

    func testQRNamespacesRemainMutuallyExclusive() {
        XCTAssertEqual(CompanionQRRouting.classify(expectedQR), .routine)
        XCTAssertNil(CompanionQRRouting.classify(" \(expectedQR)"))
        XCTAssertEqual(CompanionQRRouting.classify("philcore-recovery:v1:x"), .recovery)
        XCTAssertEqual(CompanionQRRouting.classify("philcore://pair/v1?request=x"), .pairing)
        XCTAssertEqual(CompanionQRRouting.classify("phil-step6c-routine-enrollment-v2:x"), .routine)
    }

    func testCrossLanguageEnrollmentProofOfPossessionCompletesOnlyAfterFingerprintConfirmation() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x11,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x22,count:32),expiresAt:1_800_000_500,expectedGeneration:1,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let evidence=try step6C2EnrollmentFixture()
        XCTAssertEqual(bootstrap.encoded,evidence["qrPayload"] as? String)
        XCTAssertEqual(bootstrap.fingerprint,evidence["comparisonFingerprint"] as? String)
        let signer=try SyntheticRoutineSigner(),record=try signer.activeRecord()
        XCTAssertEqual(RoutineApprovalKeyManager.hex(try RoutineDeviceEnrollmentClient.proofDigest(bootstrap:bootstrap,record:record)),
            evidence["proofDigest"] as? String)
        XCTAssertEqual(RoutineApprovalKeyManager.hex(try RoutineDeviceEnrollmentClient.acceptanceDigest(bootstrap:bootstrap,record:record)),evidence["acceptanceDigest"] as? String)
        let exactAcceptance=Data(try XCTUnwrap(evidence["acceptanceResponseJson"] as? String).utf8)
        let acceptanceObject=try XCTUnwrap(try JSONSerialization.jsonObject(with:exactAcceptance) as? [String:Any])
        let acceptanceDER=try XCTUnwrap(RoutineApprovalKeyManager.hexData(try XCTUnwrap(acceptanceObject["acceptanceSignatureDER"] as? String)))
        let acceptanceSignature=try P256.Signing.ECDSASignature(derRepresentation:acceptanceDER)
        XCTAssertFalse(desktopAckKey.publicKey.isValidSignature(acceptanceSignature,for:try RoutineDeviceEnrollmentClient.acceptanceDigest(bootstrap:bootstrap,record:record)),"CryptoKit Data verification must not replace prehashed verification")
        XCTAssertTrue(RoutineDeviceEnrollmentClient.verifyPrehashedAcceptance(signatureDER:acceptanceDER,digest:try RoutineDeviceEnrollmentClient.acceptanceDigest(bootstrap:bootstrap,record:record),publicKeyX963:desktopAckKey.publicKey.x963Representation))
        let transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record,fixedAcceptanceBody:exactAcceptance)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        var phases:[RoutineAuthorizationPhase]=[];client.observeStatus { phases.append($0.phase) }
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001)
        XCTAssertEqual(client.status.phase,.comparingFingerprint);XCTAssertEqual(signer.signCount,0);XCTAssertEqual(transport.completeCount,0)
        await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.phase,.accepted);XCTAssertEqual(signer.signCount,1);XCTAssertEqual(transport.completeCount,1);XCTAssertTrue(transport.proofVerified)
        XCTAssertEqual(transport.preflightCount,1);XCTAssertTrue(phases.contains(.exchangingKeys));XCTAssertTrue(phases.contains(.signing));XCTAssertTrue(phases.contains(.submitting))
    }

    func testGenerationTwoReplacementCommitsOnlyAfterDesktopAcceptanceAndRollsBackBeforePublication() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x31,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x32,count:32),expiresAt:1_800_000_500,expectedGeneration:2,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let acceptedSigner=try SyntheticRoutineSigner(),acceptedRecord=try acceptedSigner.previewRecord(generation:2)
        let acceptedTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:acceptedRecord),acceptedClient=RoutineDeviceEnrollmentClient(transport:acceptedTransport,signer:acceptedSigner)
        acceptedClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await acceptedClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(acceptedClient.status.phase,.accepted);XCTAssertEqual(try acceptedSigner.activeRecord().generation,2)
        XCTAssertNil(try acceptedSigner.preparedDisposableRecord(generation:2));XCTAssertTrue(acceptedTransport.proofVerified)

        let rejectedSigner=try SyntheticRoutineSigner(failEnrollmentSigning:true),rejectedRecord=try rejectedSigner.previewRecord(generation:2)
        let rejectedTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:rejectedRecord),rejectedClient=RoutineDeviceEnrollmentClient(transport:rejectedTransport,signer:rejectedSigner)
        rejectedClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await rejectedClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(rejectedClient.status.phase,.failed);XCTAssertEqual(try rejectedSigner.activeRecord().generation,1)
        XCTAssertNil(try rejectedSigner.preparedDisposableRecord(generation:2));XCTAssertEqual(rejectedTransport.completeCount,0)
    }

    func testEnrollmentReachabilityFailureStopsBeforeSecureEnclaveSigningOrPublication() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x51,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x52,count:32),expiresAt:1_800_000_500,expectedGeneration:1,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let signer=try SyntheticRoutineSigner(),record=try signer.activeRecord()
        let transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record,preflightFailure:.localNetworkUnavailable)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001)
        await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.phase,.failed);XCTAssertEqual(client.status.failure,.localNetworkUnavailable)
        XCTAssertEqual(transport.preflightCount,1);XCTAssertEqual(signer.signCount,0);XCTAssertEqual(transport.completeCount,0)
    }

    func testOlderDesktopGenerationProducesActionableRoutineKeyRepairFailure() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x71,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x72,count:32),expiresAt:1_800_000_500,expectedGeneration:1,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let signer=try SyntheticRoutineSigner(initialActiveGeneration:2),record=try signer.previewRecord(generation:1)
        let transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001)
        await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.phase,.failed)
        XCTAssertEqual(client.status.failure,.routineKeyGenerationMismatch)
        XCTAssertTrue(client.status.failure?.localizedDescription.contains("Delete only the disposable routine key") == true)
        XCTAssertEqual(transport.preflightCount,1);XCTAssertEqual(signer.signCount,0);XCTAssertEqual(transport.completeCount,0)
    }

    func testEnrollmentSurfacesUnauthenticatedEndpointRejectionAfterSigning() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x61,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x62,count:32),expiresAt:1_800_000_500,expectedGeneration:1,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let signer=try SyntheticRoutineSigner(),record=try signer.activeRecord()
        let transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record,responseStatusCode:400)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001)
        await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.phase,.failed);XCTAssertEqual(client.status.failure,.desktopRejected)
        XCTAssertTrue(client.status.failure?.localizedDescription.contains("unsigned rejection") == true)
        XCTAssertEqual(signer.signCount,1);XCTAssertEqual(transport.completeCount,1)
    }

    func testEnrollmentExpiryDuringPreflightStopsBeforeKeyPreparationOrFaceID() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x53,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x54,count:32),expiresAt:1_800_000_010,expectedGeneration:2,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        var current:UInt64=1_800_000_001
        let signer=try SyntheticRoutineSigner(),record=try signer.previewRecord(generation:2)
        let transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record,afterPreflight:{ current=bootstrap.expiresAt })
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer,currentUnixSeconds:{ current })
        client.start(scannedValue:bootstrap.encoded,now:current);await client.confirmAndEnroll(now:current)
        XCTAssertEqual(client.status.phase,.expired);XCTAssertEqual(client.status.failure,.expired)
        XCTAssertEqual(transport.preflightCount,1);XCTAssertEqual(signer.signCount,0);XCTAssertEqual(transport.completeCount,0)
        XCTAssertEqual(try signer.activeRecord().generation,1);XCTAssertNil(try signer.preparedDisposableRecord(generation:2))
    }

    func testEnrollmentRetriesLostAuthenticatedAcceptanceAndRetainsPendingActivationOnForgedAcceptance() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x41,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x42,count:32),expiresAt:1_800_000_500,expectedGeneration:2,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let retrySigner=try SyntheticRoutineSigner(),retryRecord=try retrySigner.previewRecord(generation:2)
        let retryTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:retryRecord,loseFirstResponse:true)
        let retryClient=RoutineDeviceEnrollmentClient(transport:retryTransport,signer:retrySigner)
        retryClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await retryClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(retryClient.status.phase,.accepted);XCTAssertEqual(retryTransport.completeCount,2)
        XCTAssertEqual(try retrySigner.activeRecord().generation,2);XCTAssertNil(try retrySigner.preparedDisposableRecord(generation:2))

        let forgedSigner=try SyntheticRoutineSigner(),forgedRecord=try forgedSigner.previewRecord(generation:2)
        let forgedTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:forgedRecord,forgeAcceptance:true)
        let forgedClient=RoutineDeviceEnrollmentClient(transport:forgedTransport,signer:forgedSigner)
        forgedClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await forgedClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(forgedClient.status.phase,.failed);XCTAssertEqual(try forgedSigner.activeRecord().generation,2)
        XCTAssertNotNil(try forgedSigner.preparedDisposableRecord(generation:2))
        let recoveredTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:forgedRecord),recoveredClient=RoutineDeviceEnrollmentClient(transport:recoveredTransport,signer:forgedSigner)
        recoveredClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await recoveredClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(recoveredClient.status.phase,.accepted);XCTAssertEqual(try forgedSigner.activeRecord().generation,2)
        XCTAssertNil(try forgedSigner.preparedDisposableRecord(generation:2))

        let highSSigner=try SyntheticRoutineSigner(),highSRecord=try highSSigner.previewRecord(generation:2)
        let highSTransport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:highSRecord,highSAcceptance:true),highSClient=RoutineDeviceEnrollmentClient(transport:highSTransport,signer:highSSigner)
        highSClient.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await highSClient.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(highSClient.status.phase,.failed);XCTAssertNotNil(try highSSigner.preparedDisposableRecord(generation:2))
    }

    func testProductModelRefreshesDisplayedRoutineFingerprintAfterAuthenticatedReplacement() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x51,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x52,count:32),expiresAt:1_800_000_500,expectedGeneration:2,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let signer=try SyntheticRoutineSigner(),replacement=try signer.previewRecord(generation:2),transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:replacement)
        let approval=LocalApprovalManager(),model=CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),
            clock:FixedCompanionClock(seconds:1_800_000_001,milliseconds:1_800_000_001_000),pairingRouter:RecordingPairingClientSeam(),
            credentialManager:SecureEnclaveCredentialManager(),approvalManager:approval,recoveryApproval:approval,routineTransport:transport,routineApproval:signer)
        XCTAssertEqual(model.routineApprovalRecord?.generation,1)
        await model.acceptRoutineScannedValue(bootstrap.encoded);await model.confirmRoutineFingerprint()
        XCTAssertEqual(model.routineStatus.phase,.accepted);XCTAssertEqual(model.routineApprovalRecord?.generation,2)
        XCTAssertEqual(model.routineApprovalRecord?.publicKeyFingerprint,replacement.publicKeyFingerprint)
    }

    func testProductModelDoesNotReportAcceptedWhenCommittedRoutineKeyCannotBeReloaded() async throws {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x61,count:32),ipv4:0xc0a80709,port:43125,
            challenge:Data(repeating:0x62,count:32),expiresAt:1_800_000_500,expectedGeneration:2,desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let signer=try SyntheticRoutineSigner(),replacement=try signer.previewRecord(generation:2),transport=SyntheticEnrollmentTransport(bootstrap:bootstrap,record:replacement)
        let approval=LocalApprovalManager(),model=CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),
            clock:FixedCompanionClock(seconds:1_800_000_001,milliseconds:1_800_000_001_000),pairingRouter:RecordingPairingClientSeam(),
            credentialManager:SecureEnclaveCredentialManager(),approvalManager:approval,recoveryApproval:approval,routineTransport:transport,routineApproval:signer)
        signer.setPreflightFailureAfterCommit(.routineKeyUnavailable)
        await model.acceptRoutineScannedValue(bootstrap.encoded);await model.confirmRoutineFingerprint()
        XCTAssertEqual(model.routineStatus.phase,.failed);XCTAssertEqual(model.routineStatus.failure,.routineKeyCommitFailed)
        XCTAssertNil(model.routineApprovalRecord)
    }

    func testProductModelBlocksScanningWhenMetadataOutlivesSecureEnclaveKey() throws {
        let signer=try SyntheticRoutineSigner(preflightFailure:.routineKeyUnavailable)
        let approval=LocalApprovalManager(),model=CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),
            clock:FixedCompanionClock(seconds:1_800_000_001,milliseconds:1_800_000_001_000),pairingRouter:RecordingPairingClientSeam(),
            credentialManager:SecureEnclaveCredentialManager(),approvalManager:approval,recoveryApproval:approval,
            routineTransport:SyntheticEnrollmentTransport.placeholder(),routineApproval:signer)
        XCTAssertNil(model.routineApprovalRecord)
        XCTAssertEqual(model.routineStatus.failure,.routineKeyUnavailable)
        XCTAssertTrue(model.routineKeyRequiresRepair)
        model.createRoutineApprovalKey()
        XCTAssertNil(model.routineApprovalRecord)
        XCTAssertTrue(model.routineKeyRequiresRepair)
        XCTAssertTrue(model.notice?.contains("Delete only that routine key") == true)
    }

    func testRoutineFailureDiagnosticSurvivesIdleLaunchAndRestoresOnlyAllowlistedFailure() throws {
        let suite="RoutineAuthorizationTests.\(UUID().uuidString)",defaults=try XCTUnwrap(UserDefaults(suiteName:suite))
        defer { defaults.removePersistentDomain(forName:suite) }
        let failure=RoutineAuthorizationStatus(phase:.failed,fingerprint:nil,presentation:nil,failure:.routineKeyUnavailable)
        RoutineEnrollmentDiagnosticPersistence.save(failure,defaults:defaults,now:Date(timeIntervalSince1970:1_800_000_001))
        XCTAssertEqual(RoutineEnrollmentDiagnosticPersistence.loadFailure(defaults:defaults),failure)

        var recorded:[RoutineAuthorizationStatus]=[]
        let signer=try SyntheticRoutineSigner(),approval=LocalApprovalManager()
        let model=CompanionModel(transport:FakeRecoveryTransport(),signer:RecoveryMockSigner(),
            clock:FixedCompanionClock(seconds:1_800_000_001,milliseconds:1_800_000_001_000),pairingRouter:RecordingPairingClientSeam(),
            credentialManager:SecureEnclaveCredentialManager(),approvalManager:approval,recoveryApproval:approval,
            routineTransport:SyntheticEnrollmentTransport.placeholder(),routineApproval:signer,
            routineDiagnosticRecorder:{ recorded.append($0) },routineDiagnosticLoader:{ RoutineEnrollmentDiagnosticPersistence.loadFailure(defaults:defaults) })
        XCTAssertEqual(model.routineStatus,failure)
        XCTAssertNotNil(model.routineApprovalRecord)
        XCTAssertTrue(recorded.isEmpty,"observer registration must not erase the restored failure with idle")
        RoutineEnrollmentDiagnosticPersistence.save(RoutineAuthorizationStatus(phase:.idle,fingerprint:nil,presentation:nil,failure:nil),defaults:defaults)
        XCTAssertNil(RoutineEnrollmentDiagnosticPersistence.loadFailure(defaults:defaults),"an explicit repaired idle state clears the stored failure")
    }

    func testPostFaceIDKeyMismatchStopsBeforeEnrollmentPublication() async throws {
        let (bootstrap,transport)=try enrollmentFixture(expectedGeneration:1)
        let signer=try SyntheticRoutineSigner(enrollmentSigningFailure:.routineKeyMismatch)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.failure,.routineKeyMismatch)
        XCTAssertEqual(signer.signCount,1);XCTAssertEqual(transport.completeCount,0)
    }

    func testPreparedKeyActivationFailureRollsBackBeforePublication() async throws {
        let (bootstrap,transport)=try enrollmentFixture(expectedGeneration:2)
        let signer=try SyntheticRoutineSigner(failActivation:true)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.failure,.routineKeyActivationFailed)
        XCTAssertEqual(try signer.activeRecord().generation,1)
        XCTAssertNil(try signer.preparedDisposableRecord(generation:2));XCTAssertEqual(transport.completeCount,0)
    }

    func testPostAcceptanceCommitFailureRetainsActivatedKeyForReconciliation() async throws {
        let (bootstrap,transport)=try enrollmentFixture(expectedGeneration:2)
        let signer=try SyntheticRoutineSigner(failCommit:true)
        let client=RoutineDeviceEnrollmentClient(transport:transport,signer:signer)
        client.start(scannedValue:bootstrap.encoded,now:1_800_000_001);await client.confirmAndEnroll(now:1_800_000_001)
        XCTAssertEqual(client.status.failure,.routineKeyCommitFailed)
        XCTAssertEqual(try signer.activeRecord().generation,2)
        XCTAssertNotNil(try signer.preparedDisposableRecord(generation:2));XCTAssertEqual(transport.completeCount,1)
    }

    func testEveryNestedRecordFieldAndDerivedIdentityIsRebuiltBeforeDisplay() throws {
        let bootstrap = try RoutineAuthorizationBootstrap.decode(expectedQR, now: 1_800_000_021)
        let signer = try SyntheticRoutineSigner(), publicRecord = try signer.activeRecord()
        let names = ["executionEnvironment","adapterManifest","signatureRegistry","deviceEnrollment",
            "accountConfiguration","capabilityPolicy","action","authorizationEnvelope",
            "unsignedDeviceApproval","humanPresentation","authorizationCore"]
        for name in names {
            let original = try fixtureRequestObject(), nested = try XCTUnwrap(original[name] as? [String: Any])
            for key in nested.keys {
                var root = original, changed = nested; changed[key] = mutate(try XCTUnwrap(nested[key]));root[name] = changed
                XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verify(
                    root, bootstrap: bootstrap, record: publicRecord, fingerprint: "D626-1AEE-2CAF-87B4-9DAB-05B4", now: 1_800_000_021
                ), "\(name).\(key) must be independently rejected")
            }
        }
        let top = ["formatVersionHash","executionEnvironmentHash","adapterManifestHash","signatureRegistryHash",
            "deviceEnrollmentHash","accountConfigurationHash","catalogHash","capabilityPolicyHash","actionHash",
            "authorizationEnvelopeDigest","humanPresentationHash","authorizationCoreDigest","approvalNonce",
            "deviceApprovalDigest","requestId","platformSigningDigest","targetCalldata"]
        for key in top { var root = try fixtureRequestObject();root[key] = mutate(try XCTUnwrap(root[key]));XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verify(root, bootstrap: bootstrap, record: publicRecord, fingerprint: "D626-1AEE-2CAF-87B4-9DAB-05B4", now: 1_800_000_021), "\(key) must be independently rejected") }
        for index in 0..<6 {
            let original = try fixtureRequestObject(), entries = try XCTUnwrap(original["catalogEntries"] as? [[String:Any]])
            for key in entries[index].keys { var root=original,varied=entries,entry=entries[index];entry[key]=mutate(try XCTUnwrap(entry[key]));varied[index]=entry;root["catalogEntries"]=varied;XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.verify(root, bootstrap:bootstrap,record:publicRecord,fingerprint:"D626-1AEE-2CAF-87B4-9DAB-05B4",now:1_800_000_021)) }
        }
    }

    func testCoherentPolicyBoundsRejectOverCeilingFeeAndFutureIssuedClock() throws {
        XCTAssertNoThrow(try RoutineAuthorizationCanonicalVerifier.validateDevicePolicyBounds(actionMaximumTotalFeeWei:"20000000",policyMaximumTotalFeeWei:"20000000",issuedAt:100,expiresAt:220,deviceNow:95))
        XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.validateDevicePolicyBounds(actionMaximumTotalFeeWei:"20000001",policyMaximumTotalFeeWei:"20000000",issuedAt:100,expiresAt:220,deviceNow:100))
        XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.validateDevicePolicyBounds(actionMaximumTotalFeeWei:"20000000",policyMaximumTotalFeeWei:"20000000",issuedAt:100,expiresAt:220,deviceNow:94))
        XCTAssertNoThrow(try RoutineAuthorizationCanonicalVerifier.validateDevicePolicyBounds(actionMaximumTotalFeeWei:"20000000",policyMaximumTotalFeeWei:"20000000",issuedAt:100,expiresAt:220,deviceNow:220))
        XCTAssertThrowsError(try RoutineAuthorizationCanonicalVerifier.validateDevicePolicyBounds(actionMaximumTotalFeeWei:"20000000",policyMaximumTotalFeeWei:"20000000",issuedAt:100,expiresAt:220,deviceNow:221))
    }

    private func fixtureRequest() throws -> Data {
        try JSONSerialization.data(withJSONObject: fixtureRequestObject(), options: [.sortedKeys])
    }

    private func enrollmentFixture(expectedGeneration:UInt64)throws->(RoutineDeviceEnrollmentBootstrap,SyntheticEnrollmentTransport) {
        let desktopAckKey=try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x71,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x72,count:32),expiresAt:1_800_000_500,expectedGeneration:expectedGeneration,
            desktopAckPublicKeyX963:desktopAckKey.publicKey.x963Representation)
        let preview=try SyntheticRoutineSigner(),record=try preview.previewRecord(generation:expectedGeneration)
        return (bootstrap,SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record))
    }

    private func step6C2EnrollmentFixture() throws -> [String:Any] {
        let url=try XCTUnwrap(Bundle(for:Self.self).url(forResource:"PHIL_V1_STEP6C2_PRODUCT_WIRING_FIXTURE",withExtension:"json"))
        let root=try XCTUnwrap(try JSONSerialization.jsonObject(with:Data(contentsOf:url)) as? [String:Any])
        return try XCTUnwrap(root["enrollment"] as? [String:Any])
    }

    private func fixtureRequestObject(name:String = "failedNonce0") throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "PHIL_V1_STEP6C_LOCAL_COMPOSITION_FIXTURE", withExtension: "json"))
        let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let requests = try XCTUnwrap(root["requests"] as? [String: Any])
        let failed = try XCTUnwrap(requests[name] as? [String: Any])
        return try XCTUnwrap(failed["request"] as? [String: Any])
    }

    private func mutate(_ value: Any) -> Any {
        if let text=value as? String { if text.hasPrefix("0x") { return String(text.dropLast())+(text.last=="0" ? "1":"0") };if UInt64(text) != nil { return text=="0" ? "1":"0" };return text+"X" }
        if let flag=value as? Bool { return !flag };if let number=value as? Int { return number+1 };return NSNull()
    }

    private func hex(_ data: Data) -> String { "0x" + data.map { String(format: "%02x", $0) }.joined() }
}

@MainActor
private final class SyntheticRoutineSigner: RoutineApprovalSigning {
    private let keys: [UInt64:P256.Signing.PrivateKey]
    private let enrollmentSigningFailure:RoutineAuthorizationFailure?
    private var preflightFailure:RoutineAuthorizationFailure?
    private var preflightFailureAfterCommit:RoutineAuthorizationFailure?
    private let failActivation:Bool,failCommit:Bool
    private var activeGeneration:UInt64?,pendingGeneration:UInt64?,rollbackGeneration:UInt64?
    var returnMalformedSignature = false
    var deleteCount = 0
    var createCount = 0
    var signCount = 0
    var invalidateCount = 0
    init(failEnrollmentSigning:Bool=false,enrollmentSigningFailure:RoutineAuthorizationFailure?=nil,
         preflightFailure:RoutineAuthorizationFailure?=nil,failActivation:Bool=false,failCommit:Bool=false,
         initialActiveGeneration:UInt64?=1) throws {
        self.enrollmentSigningFailure=enrollmentSigningFailure ?? (failEnrollmentSigning ? .bindingMismatch:nil)
        self.preflightFailure=preflightFailure;self.failActivation=failActivation;self.failCommit=failCommit;self.activeGeneration=initialActiveGeneration
        keys=[1:try P256.Signing.PrivateKey(rawRepresentation:Data(hex:"2897c8d199907ffab6db9e3a1e67b88349a8233cf2693edf10c7dfb0244acbb4")),
                         2:try P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x2a,count:32))] }
    func activeRecord() throws -> RoutineApprovalPublicRecord {
        guard let activeGeneration else { throw RoutineAuthorizationFailure.bindingMismatch };return try record(activeGeneration)
    }
    func activeRecordIfPresent() throws -> RoutineApprovalPublicRecord? { try activeGeneration.map(record) }
    func activeRecordWithKeyPreflight() throws -> RoutineApprovalPublicRecord? { if let preflightFailure { throw preflightFailure };return try activeRecordIfPresent() }
    func setPreflightFailureAfterCommit(_ failure:RoutineAuthorizationFailure?) { preflightFailureAfterCommit=failure }
    func createDisposableRecord() throws -> RoutineApprovalPublicRecord { createCount += 1;return try activeRecord() }
    func preparedDisposableRecord(generation:UInt64)throws->RoutineApprovalPublicRecord? { pendingGeneration==generation ? try record(generation):nil }
    func prepareDisposableRecord(generation:UInt64)throws->RoutineApprovalPublicRecord {
        if pendingGeneration==generation { return try record(generation) }
        guard generation==(activeGeneration ?? 0)+1,keys[generation] != nil else { throw RoutineAuthorizationFailure.bindingMismatch }
        pendingGeneration=generation;return try record(generation)
    }
    func activatePreparedDisposableRecord(generation:UInt64)throws { if failActivation { throw RoutineAuthorizationFailure.bindingMismatch };guard pendingGeneration==generation else { throw RoutineAuthorizationFailure.bindingMismatch };rollbackGeneration=activeGeneration;activeGeneration=generation }
    func commitPreparedDisposableRecord(generation:UInt64)throws { if failCommit { throw RoutineAuthorizationFailure.bindingMismatch };guard pendingGeneration==generation,activeGeneration==generation else { throw RoutineAuthorizationFailure.bindingMismatch };pendingGeneration=nil;rollbackGeneration=nil;preflightFailure=preflightFailureAfterCommit }
    func rollbackPreparedDisposableRecord(generation:UInt64)throws {
        guard pendingGeneration==nil||pendingGeneration==generation else { throw RoutineAuthorizationFailure.bindingMismatch }
        if pendingGeneration != nil { if let rollbackGeneration { activeGeneration=rollbackGeneration } else if activeGeneration==generation { activeGeneration=nil };pendingGeneration=nil;rollbackGeneration=nil }
    }
    func deleteDisposableRecord() throws { deleteCount += 1 }
    func signRoutineDigest(_ digest: Data) async throws -> Data { signCount += 1;if returnMalformedSignature { return Data([0]) }; return try directSignature(digest:digest,key:key(try activeRecord().generation)) }
    func signRoutineEnrollmentDigest(_ digest: Data,generation:UInt64) async throws -> Data { signCount += 1;if let enrollmentSigningFailure { throw enrollmentSigningFailure };guard pendingGeneration==generation||activeGeneration==generation else { throw RoutineAuthorizationFailure.bindingMismatch };return try directSignature(digest:digest,key:key(generation)) }
    func invalidate() { invalidateCount += 1 }
    func previewRecord(generation:UInt64)throws->RoutineApprovalPublicRecord { try record(generation) }
    private func directSignature(digest:Data,key privateKey:P256.Signing.PrivateKey)throws->Data {
        let attributes:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeyClass as String:kSecAttrKeyClassPrivate,kSecAttrKeySizeInBits as String:256]
        var error:Unmanaged<CFError>?
        guard let key=SecKeyCreateWithData((privateKey.publicKey.x963Representation+privateKey.rawRepresentation) as CFData,attributes as CFDictionary,&error),
              let der=SecKeyCreateSignature(key,.ecdsaSignatureDigestX962SHA256,digest as CFData,&error) as Data? else { throw RoutineAuthorizationFailure.routineSigningFailed }
        let normalized=try RoutineP256DER.parseAndNormalize(der)
        return try P256.Signing.ECDSASignature(rawRepresentation:normalized.r+normalized.s).derRepresentation
    }
    private func key(_ generation:UInt64)throws->P256.Signing.PrivateKey { guard let key=keys[generation] else { throw RoutineAuthorizationFailure.bindingMismatch };return key }
    private func record(_ generation:UInt64)throws->RoutineApprovalPublicRecord {
        let key=try key(generation)
        return RoutineApprovalPublicRecord(schemaVersion:2,generation:generation,
            deviceId:generation==1 ? "0x5c7b39d87dae4df3ee687b4bd7a59bafb2a27848cc92c9797205eb593c13750f":"0x"+String(repeating:"6c",count:32),
            deviceKeyId:generation==1 ? "0xb945e237adbfa47a7093c52d85fb7d3253249d04acccbacadbabafd46f4a140c":"0x"+String(repeating:"6d",count:32),
            keyTag:"synthetic-step6c2-g\(generation)",publicKeyX963:hex(key.publicKey.x963Representation),
            publicKeyFingerprint:hex(Data(SHA256.hash(data:key.publicKey.x963Representation))),secureEnclaveBacked:false,userPresenceRequired:false)
    }
    private func hex(_ data: Data) -> String { "0x" + data.map { String(format: "%02x", $0) }.joined() }
}

private final class RoutinePreflightLoopbackControl:@unchecked Sendable {
    struct Stub { var failure:URLError.Code? }
    static let shared=RoutinePreflightLoopbackControl()
    private let lock=NSLock();private var stubStorage=Stub(),requestsStorage:[URLRequest]=[]
    var stub:Stub { get { lock.withLock { stubStorage } } set { lock.withLock { stubStorage=newValue } } }
    var requests:[URLRequest] { lock.withLock { requestsStorage } }
    func reset() { lock.withLock { stubStorage=Stub();requestsStorage=[] } }
    func record(_ request:URLRequest)->Stub { lock.withLock { requestsStorage.append(request);return stubStorage } }
}

private final class RoutinePreflightLoopbackURLProtocol:URLProtocol {
    override class func canInit(with request:URLRequest)->Bool { true }
    override class func canonicalRequest(for request:URLRequest)->URLRequest { request }
    override func startLoading() {
        let stub=RoutinePreflightLoopbackControl.shared.record(request)
        if let failure=stub.failure { client?.urlProtocol(self,didFailWithError:URLError(failure));return }
        let headers=["Content-Length":"0","Cache-Control":"no-store","Connection":"close"]
        guard let url=request.url,let response=HTTPURLResponse(url:url,statusCode:204,httpVersion:"HTTP/1.1",headerFields:headers) else {
            client?.urlProtocol(self,didFailWithError:URLError(.badServerResponse));return
        }
        client?.urlProtocol(self,didReceive:response,cacheStoragePolicy:.notAllowed);client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

// Deliberately completes despite cancel(), to exercise stale asynchronous delivery.
private final class SuspendedRoutineTransport: RoutineAuthorizationTransporting, @unchecked Sendable {
    private let base: any RoutineAuthorizationTransporting
    private let onStart: (Int) -> Void
    private let lock = NSLock()
    private var pending: [CheckedContinuation<Void, Error>?] = []

    init(base: any RoutineAuthorizationTransporting, onStart: @escaping (Int) -> Void) {
        self.base = base; self.onStart = onStart
    }
    func preflight(url: String, sessionId: String, expiresAt: UInt64) async throws {
        try await base.preflight(url: url, sessionId: sessionId, expiresAt: expiresAt)
    }
    func post(url: String, contentType: String, body: Data, expiresAt: UInt64) async throws -> RoutineTransportExchange {
        let result = try await base.post(url: url, contentType: contentType, body: body, expiresAt: expiresAt)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let index = lock.withLock { pending.append(continuation); return pending.count - 1 }
            onStart(index)
        }
        return result
    }
    func finish(_ index: Int, failure: RoutineAuthorizationFailure? = nil) {
        let continuation = lock.withLock { let value = pending[index]; pending[index] = nil; return value }
        if let failure { continuation?.resume(throwing: failure) } else { continuation?.resume() }
    }
    func cancel() {}
}

private final class SyntheticRoutineTransport: RoutineAuthorizationTransporting, @unchecked Sendable {
    private let bootstrap: RoutineAuthorizationBootstrap
    private let requestJSON: Data
    private let changedAckField: String?
    private let desktopKey: P256.KeyAgreement.PrivateKey
    private var key: SymmetricKey?
    private var iphonePublicKey: Data?
    private let lock = NSLock()
    private(set) var completeCount = 0
    private(set) var responseSignatureVerified = false
    private(set) var cancelled = false

    init(bootstrap: RoutineAuthorizationBootstrap, requestJSON: Data, changedAckField: String? = nil) {
        self.changedAckField=changedAckField
        self.bootstrap = bootstrap; self.requestJSON = requestJSON
        self.desktopKey = try! P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
    }

    func preflight(url: String, sessionId: String, expiresAt: UInt64) async throws {
        XCTFail("ordinary authorization must not invoke enrollment preflight")
    }

    func post(url: String, contentType: String, body: Data, expiresAt: UInt64) async throws -> RoutineTransportExchange {
        if url.hasSuffix(RoutineAuthorizationBootstrap.beginPath) {
            let json = try JSONSerialization.jsonObject(with: body) as! [String: Any]
            let iphoneHex = json["iphonePublicKey"] as! String
            let iphone = Data(hex: String(iphoneHex.dropFirst(2)))
            let transcript = RoutineAuthorizationHandshake.transcriptHash(bootstrap: bootstrap, iphonePublicKey: iphone)
            let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: iphone)
            let shared = try desktopKey.sharedSecretFromKeyAgreement(with: publicKey)
            let traffic = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: transcript,
                sharedInfo: Data(RoutineAuthorizationBootstrap.hkdfInfo.utf8), outputByteCount: 32)
            lock.withLock { key = traffic; iphonePublicKey = iphone }
            let aad = aad(label: "DESKTOP_TO_IPHONE_ROUTINE_AUTHORIZATION_V1")
            let frame = try RoutineAuthorizationFrame.seal(requestJSON, key: traffic, aad: aad)
            return RoutineTransportExchange(statusCode: 200, contentType: "application/octet-stream", contentLength: frame.count,
                cacheControl: "no-store", connection: "close", contentEncoding: nil, transferEncoding: nil, finalURL: url, body: frame)
        }
        let traffic = lock.withLock { key! }
        if url.hasSuffix(RoutineAuthorizationBootstrap.terminalPath) {
            let plain=try RoutineAuthorizationFrame.open(body,key:traffic,aad:aad(label:"IPHONE_TO_DESKTOP_ROUTINE_TERMINAL_V1"))
            var value=try JSONSerialization.jsonObject(with:plain) as! [String:Any]
            XCTAssertEqual(value["purpose"] as? String,"PHIL_ROUTINE_TERMINAL_RESULT_V1")
            value["purpose"]="PHIL_ROUTINE_TERMINAL_ACK_V1"
            if let changedAckField { value[changedAckField] = changedAckField == "protocolVersion" ? true : "wrong" as Any }
            let response=try RoutineAuthorizationFrame.seal(JSONSerialization.data(withJSONObject:value),key:traffic,aad:aad(label:"DESKTOP_TO_IPHONE_ROUTINE_TERMINAL_ACK_V1"))
            return RoutineTransportExchange(statusCode:200,contentType:"application/octet-stream",contentLength:response.count,cacheControl:"no-store",connection:"close",contentEncoding:nil,transferEncoding:nil,finalURL:url,body:response)
        }
        let plaintext = try RoutineAuthorizationFrame.open(body, key: traffic, aad: aad(label: "IPHONE_TO_DESKTOP_ROUTINE_AUTHORIZATION_V1"))
        let response = try JSONSerialization.jsonObject(with: plaintext) as! [String: Any]
        let r = Data(hex: String((response["signatureR"] as! String).dropFirst(2)))
        let s = Data(hex: String((response["signatureS"] as! String).dropFirst(2)))
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: r + s)
        let publicKey = try P256.Signing.PublicKey(x963Representation: Data(hex: "04e314d95ae35d27098435c67ab20b30ee05edde043ebd589129bba3d02ce5cabec76be73181d190cef8c6926322957470ef57b92f1ef6cd8e906671526445139c"))
        responseSignatureVerified = RoutineDeviceEnrollmentClient.verifyPrehashedAcceptance(signatureDER:signature.derRepresentation,digest:Data(hex:String((response["platformSigningDigest"] as! String).dropFirst(2))),publicKeyX963:publicKey.x963Representation)
        completeCount += 1
        return RoutineTransportExchange(statusCode: 204, contentType: nil, contentLength: 0,
            cacheControl: "no-store", connection: "close", contentEncoding: nil, transferEncoding: nil, finalURL: url, body: Data())
    }

    func cancel() { cancelled = true }
    private func aad(label: String) -> Data { var out = Data(label.utf8); out.append(0x7c); out.append(bootstrap.sessionId); out.append(0x7c); out.append(bootstrap.requestId); return out }
}

private final class SyntheticEnrollmentTransport: RoutineAuthorizationTransporting, @unchecked Sendable {
    let bootstrap:RoutineDeviceEnrollmentBootstrap,record:RoutineApprovalPublicRecord
    let loseFirstResponse:Bool,forgeAcceptance:Bool,highSAcceptance:Bool
    private let responseStatusCode:Int
    private let preflightFailure:RoutineAuthorizationFailure?
    private let afterPreflight:(() -> Void)?
    private let fixedAcceptanceBody:Data?
    private var acceptanceBody:Data?
    private(set) var preflightCount=0,completeCount=0,proofVerified=false
    init(bootstrap:RoutineDeviceEnrollmentBootstrap,record:RoutineApprovalPublicRecord,loseFirstResponse:Bool=false,forgeAcceptance:Bool=false,highSAcceptance:Bool=false,fixedAcceptanceBody:Data?=nil,preflightFailure:RoutineAuthorizationFailure?=nil,afterPreflight:(() -> Void)?=nil,responseStatusCode:Int=200) {
        self.bootstrap=bootstrap;self.record=record;self.loseFirstResponse=loseFirstResponse;self.forgeAcceptance=forgeAcceptance;self.highSAcceptance=highSAcceptance;self.fixedAcceptanceBody=fixedAcceptanceBody;self.preflightFailure=preflightFailure;self.afterPreflight=afterPreflight;self.responseStatusCode=responseStatusCode
    }
    @MainActor static func placeholder() -> SyntheticEnrollmentTransport {
        let acknowledgement=try! P256.Signing.PrivateKey(rawRepresentation:Data(repeating:0x05,count:32))
        let bootstrap=RoutineDeviceEnrollmentBootstrap(sessionId:Data(repeating:0x73,count:32),ipv4:0xc0a80709,port:43124,
            challenge:Data(repeating:0x74,count:32),expiresAt:1_800_000_500,expectedGeneration:1,
            desktopAckPublicKeyX963:acknowledgement.publicKey.x963Representation)
        let signer=try! SyntheticRoutineSigner(),record=try! signer.activeRecord()
        return SyntheticEnrollmentTransport(bootstrap:bootstrap,record:record)
    }
    func preflight(url:String,sessionId:String,expiresAt:UInt64) async throws {
        preflightCount+=1
        XCTAssertEqual(url,bootstrap.origin+RoutineDeviceEnrollmentBootstrap.preflightPath)
        XCTAssertEqual(sessionId,RoutineApprovalKeyManager.hex(bootstrap.sessionId));XCTAssertEqual(expiresAt,bootstrap.expiresAt)
        afterPreflight?()
        if let preflightFailure { throw preflightFailure }
    }
    func post(url:String,contentType:String,body:Data,expiresAt:UInt64) async throws -> RoutineTransportExchange {
        XCTAssertEqual(contentType,"application/json");XCTAssertEqual(url,bootstrap.origin+RoutineDeviceEnrollmentBootstrap.completePath)
        let object=try JSONSerialization.jsonObject(with:body) as! [String:Any]
        XCTAssertEqual(object["sessionId"] as? String,"0x"+bootstrap.sessionId.map { String(format:"%02x",$0) }.joined())
        let signature=try P256.Signing.ECDSASignature(derRepresentation:Data(hex:String((object["proofSignatureDER"] as! String).dropFirst(2))))
        let key=try P256.Signing.PublicKey(x963Representation:Data(hex:String(record.publicKeyX963.dropFirst(2))))
        proofVerified=RoutineDeviceEnrollmentClient.verifyPrehashedAcceptance(signatureDER:signature.derRepresentation,digest:try RoutineDeviceEnrollmentClient.proofDigest(bootstrap:bootstrap,record:record),publicKeyX963:key.x963Representation);completeCount+=1
        if acceptanceBody==nil {
            if let fixedAcceptanceBody { acceptanceBody=fixedAcceptanceBody }
            else {
                let digest=try RoutineDeviceEnrollmentClient.acceptanceDigest(bootstrap:bootstrap,record:record),signature=try directAcceptanceSignature(digest:digest)
                acceptanceBody=try JSONSerialization.data(withJSONObject:["protocolVersion":2,"sessionId":RoutineApprovalKeyManager.hex(bootstrap.sessionId),
                    "challenge":RoutineApprovalKeyManager.hex(bootstrap.challenge),"enrollmentProofDigest":RoutineApprovalKeyManager.hex(try RoutineDeviceEnrollmentClient.proofDigest(bootstrap:bootstrap,record:record)),
                    "acceptanceSignatureDER":RoutineApprovalKeyManager.hex(signature)],options:[.sortedKeys])
            }
        }
        if loseFirstResponse&&completeCount==1 { throw RoutineAuthorizationFailure.transportFailure }
        let response=acceptanceBody!
        return RoutineTransportExchange(statusCode:responseStatusCode,contentType:"application/json",contentLength:response.count,cacheControl:"no-store",connection:"close",
            contentEncoding:nil,transferEncoding:nil,finalURL:url,body:response)
    }
    func cancel() {}
    private func directAcceptanceSignature(digest:Data)throws->Data {
        let rawPrivate=Data(repeating:forgeAcceptance ? 0x06:0x05,count:32),privateKey=try P256.Signing.PrivateKey(rawRepresentation:rawPrivate)
        let attributes:[String:Any]=[kSecAttrKeyType as String:kSecAttrKeyTypeECSECPrimeRandom,kSecAttrKeyClass as String:kSecAttrKeyClassPrivate,kSecAttrKeySizeInBits as String:256]
        var error:Unmanaged<CFError>?
        guard let key=SecKeyCreateWithData((privateKey.publicKey.x963Representation+rawPrivate) as CFData,attributes as CFDictionary,&error),
              let generated=SecKeyCreateSignature(key,.ecdsaSignatureDigestX962SHA256,digest as CFData,&error) as Data? else { throw RoutineAuthorizationFailure.transportFailure }
        let parsed=try P256.Signing.ECDSASignature(derRepresentation:generated),raw=parsed.rawRepresentation
        let order=Array(Data(hex:"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")),half=Array(Data(hex:"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8"))
        let r=Data(raw.prefix(32)),originalS=Array(raw.suffix(32)),isHigh=half.lexicographicallyPrecedes(originalS)
        let s=(isHigh==highSAcceptance) ? originalS:Self.subtract(order,originalS)
        return try P256.Signing.ECDSASignature(rawRepresentation:r+Data(s)).derRepresentation
    }
    private static func subtract(_ left:[UInt8],_ right:[UInt8])->[UInt8] {
        var output=Array(repeating:UInt8(0),count:left.count),borrow=0
        for index in stride(from:left.count-1,through:0,by:-1) { var value=Int(left[index])-Int(right[index])-borrow;if value<0 { value+=256;borrow=1 } else { borrow=0 };output[index]=UInt8(value) }
        return output
    }
}

private extension Data {
    init(hex: String) { self.init(stride(from: 0, to: hex.count, by: 2).map { offset in let start = hex.index(hex.startIndex, offsetBy: offset); let end = hex.index(start, offsetBy: 2); return UInt8(hex[start..<end], radix: 16)! }) }
}

private extension NSLock {
    func withLock<T>(_ body: () -> T) -> T { lock(); defer { unlock() }; return body() }
}

private final class LongitudinalClock: CompanionClock, @unchecked Sendable {
    private let lock=NSLock();private var seconds:UInt64
    init(_ seconds:UInt64) { self.seconds=seconds }
    func set(_ value:UInt64) { lock.withLock { seconds=value } }
    func nowUnixSeconds()->UInt64 { lock.withLock { seconds } }
    func nowUnixMilliseconds()->UInt64 { nowUnixSeconds()*1000 }
}
private final class RecordingLongitudinalTransport: RoutineAuthorizationTransporting, @unchecked Sendable {
    struct Bound { let url:String,contentType:String,body:Data,expiresAt:UInt64,requestId:String }
    private let base=URLSessionRoutineAuthorizationTransport(),lock=NSLock()
    private var captured:Bound?
    var lastBound:Bound? { lock.withLock { captured } }
    func preflight(url:String,sessionId:String,expiresAt:UInt64) async throws { try await base.preflight(url:url,sessionId:sessionId,expiresAt:expiresAt) }
    func post(url:String,contentType:String,body:Data,expiresAt:UInt64) async throws->RoutineTransportExchange { try await base.post(url:url,contentType:contentType,body:body,expiresAt:expiresAt) }
    func postBound(url:String,contentType:String,body:Data,expiresAt:UInt64,requestId:String) async throws->RoutineTransportExchange {
        let value=Bound(url:url,contentType:contentType,body:body,expiresAt:expiresAt,requestId:requestId)
        lock.withLock { captured=value };return try await replay(value)
    }
    func replay(_ value:Bound) async throws->RoutineTransportExchange { try await base.postBound(url:value.url,contentType:value.contentType,body:value.body,expiresAt:value.expiresAt,requestId:value.requestId) }
    func cancel() { base.cancel() }
}
