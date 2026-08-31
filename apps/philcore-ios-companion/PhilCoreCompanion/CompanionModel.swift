import Foundation
import Combine
import LocalAuthentication

enum RoutineEnrollmentDiagnosticPersistence {
    static let defaultsKey = "philcore.localalpha.routineEnrollmentDiagnosticV1"

    static func save(_ status: RoutineAuthorizationStatus, defaults: UserDefaults = .standard, now: Date = Date()) {
        let phase: String
        switch status.phase {
        case .idle:
            defaults.removeObject(forKey: defaultsKey)
            return
        case .exchangingKeys: phase = "preflight"
        case .comparingFingerprint: phase = "fingerprint"
        case .reviewing: phase = "reviewing"
        case .signing: phase = "signing"
        case .submitting: phase = "submitting"
        case .accepted: phase = "accepted"
        case .denied: phase = "denied"
        case .cancelled: phase = "cancelled"
        case .expired: phase = "expired"
        case .failed: phase = "failed"
        }
        defaults.set([
            "schemaVersion": 1,
            "phase": phase,
            "failure": status.failure?.rawValue ?? "none",
            "bindingField": status.bindingField ?? "none",
            "updatedAt": UInt64(now.timeIntervalSince1970)
        ], forKey: defaultsKey)
    }

    static func saveAcceptanceBaseline(_ status:RoutineAuthorizationStatus,record:RoutineApprovalPublicRecord?,defaults:UserDefaults = .standard) {
        let bundle=Bundle.main
#if targetEnvironment(simulator)
        let simulator=true
#else
        let simulator=false
#endif
        defaults.set(["schemaVersion":1,"observedAt":String(UInt64(Date().timeIntervalSince1970)),
            "simulator":simulator,"secureEnclaveBacked":record?.secureEnclaveBacked ?? false,"userPresenceRequired":record?.userPresenceRequired ?? false,
            "phase":String(describing:status.phase),"pendingRequestCount":status.phase == .idle ? 0 : 1,
            "pairingState":record == nil ? "missing":"enrolled","pairingGeneration":record.map { String($0.generation) } ?? "none",
            "pairingFingerprint":record?.publicKeyFingerprint ?? "none",
            "build":bundle.object(forInfoDictionaryKey:"CFBundleVersion") as? String ?? "unknown",
            "sourceCommit":bundle.object(forInfoDictionaryKey:"PhilCoreSourceCommit") as? String ?? "unknown",
            "sourceTree":bundle.object(forInfoDictionaryKey:"PhilCoreSourceTree") as? String ?? "unknown"],
            forKey:"philcore.routineAcceptanceBaselineV1")
    }

    /// Only a terminal, allowlisted failure is restored. In-progress state is
    /// never resumed across launch and no request/key/signature data is stored.
    static func loadFailure(defaults: UserDefaults = .standard) -> RoutineAuthorizationStatus? {
        guard let value = defaults.dictionary(forKey: defaultsKey),
              (value["schemaVersion"] as? Int) == 1,
              value["phase"] as? String == "failed",
              let token = value["failure"] as? String,
              let failure = RoutineAuthorizationFailure(rawValue: token) else { return nil }
        let field = value["bindingField"] as? String
        let safeField = field.flatMap { $0.count <= 96 && $0.range(of:"^[A-Za-z][A-Za-z0-9.\\[\\]]*$",options:.regularExpression) != nil && $0 != "none" ? $0 : nil }
        return RoutineAuthorizationStatus(phase: .failed, fingerprint: nil, presentation: nil, failure: failure, bindingField: safeField)
    }
}

// MARK: - Clocks and pairing seam

protocol CompanionClock: Sendable {
    func nowUnixSeconds() -> UInt64
    func nowUnixMilliseconds() -> UInt64
}

struct SystemCompanionClock: CompanionClock {
    func nowUnixSeconds() -> UInt64 {
        UInt64(Date().timeIntervalSince1970)
    }

    func nowUnixMilliseconds() -> UInt64 {
        UInt64(Date().timeIntervalSince1970 * 1000)
    }
}

@MainActor
protocol CompanionPairingRouting: AnyObject {
    func parsePairingQR(_ value: String) async throws -> PairingRequest
    func fingerprint(for request: PairingRequest) -> String
    func cancelPendingPairing() async
}

/// Exact, mutually exclusive QR discriminators. No whitespace trimming, no
/// substring search, no raw-JSON fallback, and no parser guessing.
enum CompanionQRRouting {
    static let recoveryPrefix = "philcore-recovery:v1:"
    static let pairingPrefix = "philcore://pair/v1?request="
    static let routinePrefix = RoutineAuthorizationBootstrap.prefix
    static let routineEnrollmentPrefix = RoutineDeviceEnrollmentBootstrap.prefix

    enum Kind: Equatable {
        case recovery
        case pairing
        case routine
    }

    static func classify(_ value: String) -> Kind? {
        if value.contains(where: { $0.isWhitespace }) {
            return nil
        }
        let isRecovery = value.hasPrefix(recoveryPrefix)
        let isPairing = value.hasPrefix(pairingPrefix)
        let isRoutine = value.hasPrefix(routinePrefix) || value.hasPrefix(routineEnrollmentPrefix)
        switch (isRecovery, isPairing, isRoutine) {
        case (true, false, false):
            return .recovery
        case (false, true, false):
            return .pairing
        case (false, false, true):
            return .routine
        default:
            return nil
        }
    }
}

enum CompanionRecoveryCopy {
    static func userFacingMessage(for reason: String?) -> String {
        switch reason {
        case "recovery_client_cancelled",
             "recovery_client_cancelled_background":
            return "Recovery approval was cancelled."
        case "recovery_client_session_expired":
            return "This recovery request expired."
        case "biometric_approval_denied":
            return "Biometric approval was denied."
        case "recovery_credential_missing",
             "recovery_credential_key_missing",
             "recovery_credential_nonproduction",
             "recovery_credential_simulator_only",
             "recovery_credential_not_secure_enclave",
             "recovery_credential_simulator_production_forbidden":
            return "No recovery credential is available on this iPhone."
        case "recovery_client_rejected_by_desktop":
            return "PhilCore Desktop rejected the recovery approval."
        case "recovery_client_rejected_locally":
            return "Recovery approval was rejected on this iPhone."
        case let value?
            where value.contains("protocol")
                || value.contains("malformed")
                || value.contains("bootstrap")
                || value.contains("prb1")
                || value.contains("transport"):
            return "The recovery request was malformed."
        case nil:
            return "Recovery approval failed."
        default:
            return "Recovery approval failed."
        }
    }
}

@MainActor
final class LivePairingRouter: CompanionPairingRouting {
    private let client: PairingClient

    init(client: PairingClient = PairingClient()) {
        self.client = client
    }

    func parsePairingQR(_ value: String) async throws -> PairingRequest {
        try await client.parse(value)
    }

    func fingerprint(for request: PairingRequest) -> String {
        CryptoSupport.fingerprint(request.canonicalTranscript)
    }

    func cancelPendingPairing() async {
        await client.cancelPending()
    }
}

// MARK: - Allowlisted recovery view projection

struct RecoveryReviewFields: Equatable {
    let action: String
    let accountAddress: String
    let network: String
    let chainId: String
    let recoveryEpoch: String
    let comparisonFingerprint: String
    let factorBitmap: String
    let expiresAtUnixSeconds: UInt64
    /// Technical completion endpoint is intentionally never projected for the
    /// ordinary approval card.
    let completionEndpointVisible: Bool
}

struct RecoveryApprovalViewState: Equatable {
    enum Phase: Equatable {
        case idle
        case scanning
        case fetching
        case review(RecoveryReviewFields)
        case submitting
        case accepted
        case desktopRejected
        case localRejected
        case cancelled
        case expired
        case signerFailure
        case failed
    }

    let phase: Phase
    let approveEnabled: Bool
    let cancelAvailable: Bool
    let userFacingMessage: String?

    static func project(
        status: RecoveryClientStatus,
        isWorking: Bool,
        isScanning: Bool
    ) -> RecoveryApprovalViewState {
        if isScanning {
            return RecoveryApprovalViewState(
                phase: .scanning,
                approveEnabled: false,
                cancelAvailable: true,
                userFacingMessage: nil
            )
        }

        switch status.state {
        case .idle, .bootstrapValidated, .requestValidated:
            return RecoveryApprovalViewState(
                phase: .idle,
                approveEnabled: false,
                cancelAvailable: false,
                userFacingMessage: nil
            )
        case .fetchingRequest:
            return RecoveryApprovalViewState(
                phase: .fetching,
                approveEnabled: false,
                cancelAvailable: true,
                userFacingMessage: nil
            )
        case .awaitingApproval:
            guard let presentation = status.presentation else {
                return RecoveryApprovalViewState(
                    phase: .idle,
                    approveEnabled: false,
                    cancelAvailable: true,
                    userFacingMessage: nil
                )
            }
            let fields = RecoveryReviewFields(
                action: presentation.actionText,
                accountAddress: presentation.accountAddress,
                network: presentation.networkText,
                chainId: presentation.chainId,
                recoveryEpoch: presentation.recoveryEpoch,
                comparisonFingerprint: presentation.comparisonFingerprint,
                factorBitmap: presentation.factorBitmap,
                expiresAtUnixSeconds: presentation.expiresAtUnixSeconds,
                completionEndpointVisible: false
            )
            return RecoveryApprovalViewState(
                phase: .review(fields),
                approveEnabled: !isWorking,
                cancelAvailable: true,
                userFacingMessage: nil
            )
        case .submittingApproval, .awaitingAcknowledgement:
            return RecoveryApprovalViewState(
                phase: .submitting,
                approveEnabled: false,
                cancelAvailable: true,
                userFacingMessage: nil
            )
        case .accepted:
            return RecoveryApprovalViewState(
                phase: .accepted,
                approveEnabled: false,
                cancelAvailable: false,
                userFacingMessage: "Recovery approval accepted."
            )
        case .rejected:
            let phase: Phase =
                status.failureReason == "recovery_client_rejected_locally"
                ? .localRejected
                : .desktopRejected
            return RecoveryApprovalViewState(
                phase: phase,
                approveEnabled: false,
                cancelAvailable: false,
                userFacingMessage: CompanionRecoveryCopy.userFacingMessage(
                    for: status.failureReason
                )
            )
        case .cancelled:
            return RecoveryApprovalViewState(
                phase: .cancelled,
                approveEnabled: false,
                cancelAvailable: false,
                userFacingMessage: CompanionRecoveryCopy.userFacingMessage(
                    for: status.failureReason
                )
            )
        case .failed:
            let phase: Phase
            switch status.failureReason {
            case "recovery_client_session_expired":
                phase = .expired
            case "biometric_approval_denied",
                 "recovery_client_signer_public_key_mismatch":
                phase = .signerFailure
            default:
                phase = .failed
            }
            return RecoveryApprovalViewState(
                phase: phase,
                approveEnabled: false,
                cancelAvailable: false,
                userFacingMessage: CompanionRecoveryCopy.userFacingMessage(
                    for: status.failureReason
                )
            )
        }
    }
}

// MARK: - Companion model

@MainActor
final class CompanionModel: ObservableObject {
    static let idleRecoveryStatus = RecoveryClientStatus(
        state: .idle,
        generation: 0,
        sessionId: nil,
        expiresAtUnixSeconds: nil,
        presentation: nil,
        acknowledgedStatus: nil,
        failureReason: nil
    )

    @Published var selectedTab: CompanionTab = .home
    @Published var record: PublicCredentialRecord?
    @Published var pairingRequest: PairingRequest?
    @Published var pairingFingerprint = ""
    @Published var pairingApproved = false
    @Published var isWorking = false
    @Published var notice: String?
    @Published var recoveryStatus: RecoveryClientStatus = CompanionModel.idleRecoveryStatus
    @Published var isRecoveryScanning = false
    @Published var isRoutineScanning = false
    @Published var routineStatus = RoutineAuthorizationStatus(phase: .idle, fingerprint: nil, presentation: nil, failure: nil)
    @Published var routineApprovalRecord: RoutineApprovalPublicRecord?

    let credentialManager: SecureEnclaveCredentialManager
    let approvalManager: LocalApprovalManager
    /// Recovery-specific approval authority. Production wiring uses the same
    /// `LocalApprovalManager` instance as `approvalManager` / the production
    /// signing coordinator — never a second independent production manager.
    let recoveryApproval: any LocalRecoveryApproving
    let pairingClient: PairingClient
    let recoveryClient: RecoveryClient
    let routineClient: RoutineAuthorizationClient
    let routineEnrollmentClient: RoutineDeviceEnrollmentClient
    let routineApproval: any RoutineApprovalSigning

    private let clock: any CompanionClock
    private let pairingRouter: any CompanionPairingRouting
    private let routineDiagnosticRecorder: ((RoutineAuthorizationStatus) -> Void)?
    private var recoveryOperationGeneration: UInt64 = 0
    private var routineEnrollmentActive = false
    /// Presentation identity only; never part of an approval, digest, or transport request.
    private struct RoutinePresentationFlow: Equatable {
        let id = UUID()
        let enrollment: Bool
    }
    private var activeRoutinePresentation: RoutinePresentationFlow?
    private var routinePresentationObservation: AnyCancellable?

    /// Production defaults: URLSession transport, production signer coordinator,
    /// existing credential and approval managers. Does not call the
    /// `RecoveryClient` actor from `init`.
    convenience init() {
        let credentials = SecureEnclaveCredentialManager()
        let approval = LocalApprovalManager()
        let pairing = PairingClient()
        let coordinator = ProductionRecoverySigningCoordinator(
            credentials: credentials,
            approval: approval
        )
        let routineApproval = RoutineApprovalKeyManager(approval: LocalApprovalManager())
        self.init(
            transport: URLSessionRecoveryTransport(),
            signer: ProductionRecoverySigner(coordinator: coordinator),
            clock: SystemCompanionClock(),
            pairingRouter: LivePairingRouter(client: pairing),
            credentialManager: credentials,
            approvalManager: approval,
            recoveryApproval: approval,
            pairingClient: pairing,
            routineTransport: URLSessionRoutineAuthorizationTransport(),
            routineApproval: routineApproval,
            routineDiagnosticRecorder: { RoutineEnrollmentDiagnosticPersistence.save($0) },
            routineDiagnosticLoader: { RoutineEnrollmentDiagnosticPersistence.loadFailure() }
        )
#if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        let fixtureArgument = arguments.firstIndex(of: "--philcore-ui-test-state").flatMap { index in
            arguments.indices.contains(index + 1) ? arguments[index + 1] : nil
        }
        applyUITestFixture(fixtureArgument ?? ProcessInfo.processInfo.environment["PHILCORE_UI_TEST_STATE"])
#endif
    }

    init(
        transport: RecoveryTransporting,
        signer: RecoverySigner,
        clock: any CompanionClock,
        pairingRouter: any CompanionPairingRouting,
        credentialManager: SecureEnclaveCredentialManager,
        approvalManager: LocalApprovalManager,
        recoveryApproval: (any LocalRecoveryApproving)? = nil,
        pairingClient: PairingClient = PairingClient(),
        routineTransport: (any RoutineAuthorizationTransporting)? = nil,
        routineApproval: (any RoutineApprovalSigning)? = nil,
        routineDiagnosticRecorder: ((RoutineAuthorizationStatus) -> Void)? = nil,
        routineDiagnosticLoader: (() -> RoutineAuthorizationStatus?)? = nil
    ) {
        self.credentialManager = credentialManager
        self.approvalManager = approvalManager
        self.recoveryApproval = recoveryApproval ?? approvalManager
        self.pairingClient = pairingClient
        self.clock = clock
        self.pairingRouter = pairingRouter
        self.routineDiagnosticRecorder = routineDiagnosticRecorder
        self.recoveryClient = RecoveryClient(transport: transport, signer: signer)
        let actualRoutineApproval = routineApproval ?? RoutineApprovalKeyManager(approval: LocalApprovalManager())
        self.routineApproval = actualRoutineApproval
        let actualRoutineTransport = routineTransport ?? URLSessionRoutineAuthorizationTransport()
        self.routineClient = RoutineAuthorizationClient(
            transport: actualRoutineTransport,
            signer: actualRoutineApproval
        )
        self.routineEnrollmentClient = RoutineDeviceEnrollmentClient(
            transport: actualRoutineTransport, signer: actualRoutineApproval,
            currentUnixSeconds: { clock.nowUnixSeconds() }
        )
        let restoredRoutineStatus = routineDiagnosticLoader?()
        self.routineStatus = restoredRoutineStatus ?? self.routineStatus
        self.recoveryStatus = Self.idleRecoveryStatus
        self.record = credentialManager.loadPublicRecord()
        do { self.routineApprovalRecord = try actualRoutineApproval.activeRecordWithKeyPreflight() }
        catch let failure as RoutineAuthorizationFailure {
            self.routineApprovalRecord = nil
            let status = RoutineAuthorizationStatus(phase:.failed,fingerprint:nil,presentation:nil,failure:failure)
            self.routineStatus = status;routineDiagnosticRecorder?(status)
        }
        catch {
            self.routineApprovalRecord = nil
            let status = RoutineAuthorizationStatus(phase:.failed,fingerprint:nil,presentation:nil,failure:.routineSigningFailed)
            self.routineStatus = status;routineDiagnosticRecorder?(status)
        }
        if restoredRoutineStatus?.failure == .outcomeUnknown {
            routineClient.restoreUnknownOutcome()
            routineStatus = routineClient.status
            routineDiagnosticRecorder?(routineStatus)
        }
        if routineDiagnosticRecorder != nil { RoutineEnrollmentDiagnosticPersistence.saveAcceptanceBaseline(routineStatus,record:routineApprovalRecord) }
    }

    var routineKeyRequiresRepair: Bool {
        let failure = routineStatus.failure
        return (failure == .routineKeyUnavailable || failure == .routineKeyMismatch || failure == .routineKeyGenerationMismatch)
    }

#if DEBUG
    private func applyUITestFixture(_ fixture: String?) {
        guard let fixture else { return }
        let presentation = RoutineAuthorizationPresentation(
            application: "PhilCore Desktop",
            action: "Record one harmless local value",
            network: "Local test environment",
            account: "0x1111111111111111111111111111111111111111",
            target: "Local demonstration",
            parameters: "Record the disclosed harmless value",
            value: "0 wei",
            maximumFee: "0 wei",
            expiresAt: 1_900_000_000,
            comparisonFingerprint: "A1B2-C3D4-E5F6-G7H8"
        )
        let routineRecord = RoutineApprovalPublicRecord(
            schemaVersion: 2,
            generation: 1,
            deviceId: "ui-test-device",
            deviceKeyId: "ui-test-key",
            keyTag: "ui-test-only",
            publicKeyX963: "ui-test-public-key",
            publicKeyFingerprint: "A1B2-C3D4-E5F6-G7H8",
            secureEnclaveBacked: true,
            userPresenceRequired: true
        )
        switch fixture {
        case "pair-review":
            selectedTab = .pair
            pairingRequest = PairingRequest(
                protocolVersion: 1,
                sessionId: "ui-test-session",
                expiresAt: "2030-03-17T17:46:40Z",
                endpoint: "http://192.168.1.2:4040",
                desktopEphemeralPublicKey: "ui-test-public-key",
                challenge: "ui-test-challenge",
                philCoreIdentityCommitment: "ui-test-identity",
                accountVersionId: "ui-test-account",
                securityModelId: "ui-test-security-model",
                recoveryEpoch: 1,
                requestedGeneration: 1,
                applicationIdentity: "PhilCore Desktop"
            )
            pairingFingerprint = "A1B2-C3D4-E5F6-G7H8"
        case "routine-waiting":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .exchangingKeys, fingerprint: nil, presentation: nil, failure: nil)
        case "routine-review":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .reviewing, fingerprint: presentation.comparisonFingerprint, presentation: presentation, failure: nil)
        case "routine-signing":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .signing, fingerprint: presentation.comparisonFingerprint, presentation: presentation, failure: nil)
        case "routine-success":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .accepted, fingerprint: nil, presentation: presentation, failure: nil)
        case "routine-rejected":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .denied, fingerprint: nil, presentation: nil, failure: .userDenied)
        case "routine-failure":
            selectedTab = .routine
            routineApprovalRecord = routineRecord
            routineStatus = RoutineAuthorizationStatus(phase: .failed, fingerprint: nil, presentation: nil, failure: .transportFailure)
        default:
            break
        }
    }
#endif

    var deviceSupportText: String {
#if targetEnvironment(simulator)
        "Simulator test mode — never production"
#else
        credentialManager.secureEnclaveAvailable ? "Secure Enclave available" : "Unsupported device"
#endif
    }

    var approvalSupportText: String {
        approvalManager.capability().label
    }

    var recoveryViewState: RecoveryApprovalViewState {
        RecoveryApprovalViewState.project(
            status: recoveryStatus,
            isWorking: isWorking,
            isScanning: isRecoveryScanning
        )
    }

    // MARK: - Fixed user-facing copy

    static func userFacingRecoveryMessage(for reason: String?) -> String {
        CompanionRecoveryCopy.userFacingMessage(for: reason)
    }

    // MARK: - Pairing entry (pairing QR only)

    func acceptPairingScannedValue(_ value: String) async {
        let kind = CompanionQRRouting.classify(value)
        guard kind == .pairing else {
            notice = kind == .routine
                ? "This is a PhilCore routine request. Open Approve and use Scan routine QR code."
                : "That QR code is not a PhilCore pairing request."
            return
        }
        do {
            let request = try await pairingRouter.parsePairingQR(value)
            pairingRequest = request
            pairingFingerprint = pairingRouter.fingerprint(for: request)
            pairingApproved = false
            notice = nil
        } catch {
            notice = (error as? LocalizedError)?.errorDescription ?? "The QR code was rejected."
        }
    }

    /// Compatibility alias used by the Pair tab.
    func acceptScannedValue(_ value: String) async {
        await acceptPairingScannedValue(value)
    }

    // MARK: - Routine authorization entry (routine QR only)

    private func publishRoutinePresentation(_ status: RoutineAuthorizationStatus, for flow: RoutinePresentationFlow) {
        guard activeRoutinePresentation == flow else { return }
        routineStatus = status
        routineDiagnosticRecorder?(status)
        if routineDiagnosticRecorder != nil { RoutineEnrollmentDiagnosticPersistence.saveAcceptanceBaseline(status,record:routineApprovalRecord) }
    }

    func acceptRoutineScannedValue(_ value: String) async {
        guard routineStatus.failure != .outcomeUnknown && routineClient.status.phase != .submitting && routineClient.status.failure != .outcomeUnknown else { return }
        guard CompanionQRRouting.classify(value) == .routine else {
            notice = "That QR code is not a PhilCore routine authorization request."
            return
        }
        selectedTab = .routine
        isRoutineScanning = false
        let flow = RoutinePresentationFlow(enrollment: value.hasPrefix(RoutineDeviceEnrollmentBootstrap.prefix))
        // Retire the previous presentation BEFORE internal cleanup publishes any terminal event.
        activeRoutinePresentation = flow
        routinePresentationObservation = nil
        routineEnrollmentActive = flow.enrollment
        publishRoutinePresentation(RoutineAuthorizationStatus(phase: .exchangingKeys, fingerprint: nil, presentation: nil, failure: nil), for: flow)
        if flow.enrollment {
            routineClient.cancel()
            // start() performs internal cleanup through the previous, now-superseded observer.
            routineEnrollmentClient.start(scannedValue: value, now: clock.nowUnixSeconds())
            routineEnrollmentClient.observeStatus { [weak self] status in
                self?.publishRoutinePresentation(status, for: flow)
            }
            publishRoutinePresentation(routineEnrollmentClient.status, for: flow)
        } else {
            routineEnrollmentClient.cancel() // old observer carries the superseded flow identity
            routinePresentationObservation = routineClient.$status.dropFirst().sink { [weak self] status in
                // start() resets the client to idle internally before validating the new QR.
                guard status.phase != .idle else { return }
                self?.publishRoutinePresentation(status, for: flow)
            }
            await routineClient.start(scannedValue: value, now: clock.nowUnixSeconds())
            publishRoutinePresentation(routineClient.status, for: flow)
        }
    }

    func confirmRoutineFingerprint() async {
        guard let flow = activeRoutinePresentation else { return }
        if routineEnrollmentActive {
            await routineEnrollmentClient.confirmAndEnroll(now: clock.nowUnixSeconds())
            guard activeRoutinePresentation == flow else { return }
            publishRoutinePresentation(routineEnrollmentClient.status, for: flow)
            if routineStatus.phase == .accepted {
                do {
                    guard let record = try routineApproval.activeRecordWithKeyPreflight() else {
                        throw RoutineAuthorizationFailure.routineKeyUnavailable
                    }
                    routineApprovalRecord = record
                } catch let failure as RoutineAuthorizationFailure {
                    routineApprovalRecord = nil
                    routineStatus = RoutineAuthorizationStatus(
                        phase: .failed,
                        fingerprint: nil,
                        presentation: nil,
                        failure: failure == .routineKeyCommitFailed ? failure : .routineKeyCommitFailed
                    )
                } catch {
                    routineApprovalRecord = nil
                    routineStatus = RoutineAuthorizationStatus(
                        phase: .failed,
                        fingerprint: nil,
                        presentation: nil,
                        failure: .routineKeyCommitFailed
                    )
                }
            }
        } else {
            routineClient.confirmFingerprint(now: clock.nowUnixSeconds())
            publishRoutinePresentation(routineClient.status, for: flow)
        }
    }

    func approveRoutine() async {
        guard let flow = activeRoutinePresentation, !flow.enrollment else { return }
        await routineClient.approve(now: clock.nowUnixSeconds())
        publishRoutinePresentation(routineClient.status, for: flow)
    }

    func denyRoutine() async {
        guard let flow = activeRoutinePresentation else { return }
        if flow.enrollment { routineEnrollmentClient.cancel();publishRoutinePresentation(routineEnrollmentClient.status,for:flow) }
        else { await routineClient.deny();publishRoutinePresentation(routineClient.status,for:flow) }
    }

    func cancelRoutineOnDesktop() async {
        guard let flow = activeRoutinePresentation else { return }
        if flow.enrollment { cancelRoutine() }
        else { await routineClient.cancelOnDesktop();publishRoutinePresentation(routineClient.status,for:flow) }
    }

    func cancelRoutine() {
        activeRoutinePresentation = nil
        if routineEnrollmentActive { routineEnrollmentClient.cancel();routineStatus = routineEnrollmentClient.status }
        else { routineClient.cancel();routineStatus = routineClient.status }
        routineDiagnosticRecorder?(routineStatus)
    }

    func createRoutineApprovalKey() {
        guard routineStatus.failure != .outcomeUnknown && routineClient.status.failure != .outcomeUnknown && routineClient.status.phase != .submitting else {
            notice = "The previous approval outcome is unresolved. Reconcile Desktop status before changing the routine key."
            return
        }
        activeRoutinePresentation = nil
        do {
            if let existing = try routineApproval.activeRecordWithKeyPreflight() {
                routineApprovalRecord = existing
                notice = "The existing separate routine-approval key is ready on this iPhone."
            } else {
                routineApprovalRecord = try routineApproval.createDisposableRecord()
                notice = "A separate disposable routine-approval key is ready on this iPhone."
            }
            routineStatus = RoutineAuthorizationStatus(phase:.idle,fingerprint:nil,presentation:nil,failure:nil)
            routineDiagnosticRecorder?(routineStatus)
        } catch let failure as RoutineAuthorizationFailure where failure == .routineKeyUnavailable || failure == .routineKeyMismatch {
            routineApprovalRecord = nil
            let status = RoutineAuthorizationStatus(phase:.failed,fingerprint:nil,presentation:nil,failure:failure)
            routineStatus = status;routineDiagnosticRecorder?(status)
            notice = "The saved disposable routine key is unusable. Delete only that routine key, then create a new one. Phil identity and recovery keys are unaffected."
        } catch {
            routineApprovalRecord = nil
            notice = "The disposable routine-approval key could not be created on this device."
        }
    }

    func deleteRoutineApprovalKey() {
        guard routineStatus.failure != .outcomeUnknown && routineClient.status.failure != .outcomeUnknown && routineClient.status.phase != .submitting else {
            notice = "The previous approval outcome is unresolved. Reconcile Desktop status before changing the routine key."
            return
        }
        activeRoutinePresentation = nil
        routineClient.cancel()
        routineEnrollmentClient.cancel()
        routineStatus = routineClient.status
        routineDiagnosticRecorder?(routineStatus)
        do {
            try routineApproval.deleteDisposableRecord()
            routineApprovalRecord = nil
            routineStatus = RoutineAuthorizationStatus(phase:.idle,fingerprint:nil,presentation:nil,failure:nil)
            routineDiagnosticRecorder?(routineStatus)
            notice = "The disposable routine-approval key was deleted. Recovery and Phil identity keys were not changed."
        } catch {
            notice = "Deletion of the disposable routine-approval key could not be proven."
        }
    }

    // MARK: - Recovery entry (recovery QR only)

    func acceptRecoveryScannedValue(_ value: String) async {
        guard CompanionQRRouting.classify(value) == .recovery else {
            notice = "That QR code is not a PhilCore recovery request."
            return
        }

        selectedTab = .approval
        isRecoveryScanning = false
        activeRoutinePresentation = nil
        routineClient.invalidateForBackgroundOrLock()
        routineEnrollmentClient.cancel()
        routineStatus = routineClient.status
        routineDiagnosticRecorder?(routineStatus)
        isRoutineScanning = false
        recoveryOperationGeneration &+= 1
        let operation = recoveryOperationGeneration
        isWorking = true
        defer {
            if operation == recoveryOperationGeneration {
                isWorking = false
            }
        }

        do {
            try await recoveryClient.startSession(
                uri: value,
                nowSeconds: clock.nowUnixSeconds()
            )
            await synchronizeRecoveryStatus()
            guard operation == recoveryOperationGeneration else { return }

            // Publish an active loading state before suspending on transport so
            // the user can cancel a suspended fetch.
            recoveryStatus = RecoveryClientStatus(
                state: .fetchingRequest,
                generation: recoveryStatus.generation,
                sessionId: recoveryStatus.sessionId,
                expiresAtUnixSeconds: recoveryStatus.expiresAtUnixSeconds,
                presentation: nil,
                acknowledgedStatus: nil,
                failureReason: nil
            )

            try await recoveryClient.fetchRequest(
                nowMilliseconds: clock.nowUnixMilliseconds()
            )
            await synchronizeRecoveryStatus()
            guard operation == recoveryOperationGeneration else { return }

            try await recoveryClient.prepareApproval()
            await synchronizeRecoveryStatus()
        } catch let error as RecoveryClientError {
            await synchronizeRecoveryStatus()
            if error.kind != .sessionReplaced {
                notice = Self.userFacingRecoveryMessage(for: error.reason)
            }
        } catch {
            await synchronizeRecoveryStatus()
            notice = Self.userFacingRecoveryMessage(for: nil)
        }
    }

    func approveRecovery() async {
        guard recoveryStatus.state == .awaitingApproval, !isWorking else { return }
        recoveryOperationGeneration &+= 1
        let operation = recoveryOperationGeneration
        isWorking = true
        defer {
            if operation == recoveryOperationGeneration {
                isWorking = false
            }
        }
        do {
            // Reflect submission early so Cancel remains available during the
            // signer prompt and `/complete` wait.
            if let presentation = recoveryStatus.presentation {
                recoveryStatus = RecoveryClientStatus(
                    state: .submittingApproval,
                    generation: recoveryStatus.generation,
                    sessionId: recoveryStatus.sessionId,
                    expiresAtUnixSeconds: recoveryStatus.expiresAtUnixSeconds,
                    presentation: presentation,
                    acknowledgedStatus: nil,
                    failureReason: nil
                )
            }
            try await recoveryClient.approve()
            guard operation == recoveryOperationGeneration else { return }
            await synchronizeRecoveryStatus()
        } catch let error as RecoveryClientError {
            guard operation == recoveryOperationGeneration else { return }
            await synchronizeRecoveryStatus()
            if error.kind != .sessionReplaced {
                notice = Self.userFacingRecoveryMessage(for: error.reason)
            }
        } catch {
            guard operation == recoveryOperationGeneration else { return }
            await synchronizeRecoveryStatus()
            notice = Self.userFacingRecoveryMessage(for: nil)
        }
    }

    func rejectRecovery() async {
        guard !recoveryStatus.state.isTerminal else { return }
        do {
            try await recoveryClient.reject()
            await synchronizeRecoveryStatus()
        } catch let error as RecoveryClientError {
            await synchronizeRecoveryStatus()
            notice = Self.userFacingRecoveryMessage(for: error.reason)
        } catch {
            await synchronizeRecoveryStatus()
            notice = Self.userFacingRecoveryMessage(for: nil)
        }
    }

    func cancelRecovery() async {
        // Supersede any in-flight approve/fetch task before tearing down the
        // session so a late resume cannot restore working state or notices.
        recoveryOperationGeneration &+= 1
        isWorking = false
        recoveryApproval.invalidate()
        await recoveryClient.cancel()
        await synchronizeRecoveryStatus()
        notice = nil
    }

    // MARK: - Scene lifecycle

    /// Idempotent handler for a real background scene transition. Invalidates the
    /// current LocalAuthentication context, cancels non-terminal recovery via
    /// `cancelForBackground`, synchronizes recovery status, cancels pairing,
    /// and clears only pairing UI state. Does not claim generation increments.
    func handleSceneInactivity() async {
        activeRoutinePresentation = nil
        recoveryApproval.invalidate()
        routineClient.invalidateForBackgroundOrLock()
        routineEnrollmentClient.cancel()
        routineStatus = routineClient.status
        routineDiagnosticRecorder?(routineStatus)
        isRoutineScanning = false

        let status = await recoveryClient.status()
        if !status.state.isTerminal {
            await recoveryClient.cancelForBackground()
        }
        await synchronizeRecoveryStatus()

        await pairingRouter.cancelPendingPairing()
        pairingRequest = nil
        pairingApproved = false
        pairingFingerprint = ""
        isRecoveryScanning = false
    }

    /// Legacy entry point retained for older call sites; forwards to the
    /// bounded inactivity handler.
    func invalidatePendingApproval() {
        Task { await handleSceneInactivity() }
    }

    private func synchronizeRecoveryStatus() async {
        recoveryStatus = await recoveryClient.status()
    }

    // MARK: - Existing pairing / credential helpers

    func createDisposableAndTest() async {
        isWorking = true
        defer { isWorking = false }
        do {
            let created = try credentialManager.createDisposableCredential()
            let digest = CryptoSupport.sha256(
                Data("O43_DISPOSABLE_IOS_SECURE_ENCLAVE_RECOVERY_TEST_ONLY".utf8)
            )
            _ = try credentialManager.signDigest(digest, record: created)
            var tested = created
            tested.lastSuccessfulTestAt = Date()
            try credentialManager.updatePublicRecord(tested)
            record = tested
            notice = "Disposable key created and synthetic signature completed. It is not production authority."
        } catch {
            notice = (error as? LocalizedError)?.errorDescription ?? "Disposable test failed."
        }
    }

    func approveAndPair() async {
        guard pairingApproved, let request = pairingRequest else { return }
        isWorking = true
        defer { isWorking = false }
        do {
            let active: PublicCredentialRecord
            if let record, record.generation == request.requestedGeneration {
                active = record
            } else {
#if targetEnvironment(simulator)
                active = try credentialManager.createDisposableCredential(
                    generation: request.requestedGeneration
                )
#else
                active = try credentialManager.createProductionCandidate(
                    generation: request.requestedGeneration
                )
#endif
            }
            let authenticationContext = try await approvalManager.approve(
                reason: "Enroll this iPhone as PhilCore recovery Role 1 after comparing the fingerprint on both devices."
            )
            defer { approvalManager.finish() }
            let result = try await pairingClient.complete(
                request: request,
                credentialManager: credentialManager,
                record: active,
                authenticationContext: authenticationContext
            )
            record = result.record
            pairingRequest = nil
            pairingApproved = false
            notice = "PhilCore Desktop verified the encrypted enrollment response."
        } catch {
            notice = (error as? LocalizedError)?.errorDescription ?? "Pairing failed."
        }
    }

    func deleteCredential() {
        do {
            try credentialManager.deleteActiveCredential()
            record = nil
            pairingRequest = nil
            notice = "The local credential reference and private key were deleted."
        } catch {
            notice = (error as? LocalizedError)?.errorDescription ?? "Deletion could not be proven."
        }
    }
}
