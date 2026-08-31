import SwiftUI

private let philBlue = PhilPalette.active

enum ControlledBetaRelease {
    static let title = "Controlled Sepolia Beta"
    static let network = "Ethereum Sepolia"
    static let stage = "Completed"
    static let finalNonce = "3"
    static let entryPointDeposit = "0.001297280743685756 ETH"
    static let nativeBalance = "0 ETH"
    static let passBalance = "2 test passes"
    static let recovery = "Deferred"
    static let safetyBoundary = "Test-only Sepolia. Not mainnet, not production custody, and no meaningful assets."
    static let cryptographyBoundary = "Current Beta authorization uses classical cryptography and is not currently post-quantum secure."
}

enum ControlledBetaEvidence {
    static let release = "controlled-sepolia-beta-2026-08-29"
    static let smartAccount = "0xb72053013089F089502B075009c0BD807349eCC6"
    static let entryPoint = "0x0000000071727De22E5E9d8BAf0edAc6f37da032 · v0.7"
    static let p2Transaction = "0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934"
    static let p2UserOperation = "0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670"
    static let p2Block = "11573471"
    static let p3Transaction = "0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0"
    static let p3UserOperation = "0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d"
    static let p3Block = "11579252"
    static let p5Transaction = "0xceb00a759a8347aa7d70299afb46f7fd18e2f0ba4b3e41ea379b15bca21f5c2d"
    static let p5UserOperation = "0xe3f05bbe887dd752f5bd51e0ee36c5048e9975c73c8dd3a5f0880fc9625917c0"
    static let p5Lineage = "p5-attempt-0002"
    static let reconciliation = "Successful · bundler, primary provider, and independent provider agreed"
}

enum PhilBetaGuidance {
    static let identity = "Phil is your recovery and security sidekick. Phil helps protect your digital identity and explains requests before protected signing."
    static let controlledBeta = "The Controlled Sepolia Beta uses Ethereum's Sepolia test network and test-only assets. It is not mainnet or production custody."
    static let waitingForPhone = "This request is waiting for the enrolled iPhone. Compare the fingerprint before continuing."
    static let reviewOnPhone = "Check who is asking, what will happen, where it will happen, the value, maximum cost, and expiry before approving."
    static let localProof = "Phil is checking that this request matches your protected identity. This check happens locally."
    static let protectedSigning = "The protected signing key is being used only for the action you approved."
    static let success = "The approved local action completed and its receipt was verified."
    static let rejected = "You rejected the request. No approval was granted."
    static let expired = "The request expired and did not proceed. Start a fresh request if you still want to continue."
    static let recoveryDeferred = "Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared."
    static let providerUnavailable = "A required network provider is unavailable. Phil cannot confirm the public status right now."
    static let providerDisagreement = "The network providers disagree. Phil cannot confirm the public status; do not retry until the status is checked."
    static let networkTimeout = "The network did not answer in time. Phil cannot confirm the public status; check it before trying again."
    static let ambiguousPublicStatus = "The public status is unclear. Do not retry or assume the action failed until the status is reconciled."

    static func expiryText(_ unixSeconds: UInt64) -> String {
        Date(timeIntervalSince1970: TimeInterval(unixSeconds))
            .formatted(date: .abbreviated, time: .shortened)
    }

    static func expiryText(_ iso8601: String) -> String {
        guard let date = try? Date(iso8601, strategy: .iso8601) else { return "Unavailable" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    static func failureMessage(_ failure: RoutineAuthorizationFailure?) -> String {
        switch failure {
        case .outcomeUnknown:
            "The action may have been submitted. Do not retry; reconcile Desktop status first."
        case .userDenied:
            rejected
        case .expired:
            expired
        case .localNetworkUnavailable, .desktopUnavailable:
            "Phil cannot reach the enrolled Mac. Keep both devices available on the same private Wi-Fi network, then create a fresh request."
        case .bindingMismatch, .authenticationFailure, .presentationMismatch,
             .routineKeyMismatch, .routineKeyGenerationMismatch, .desktopRejected:
            "The request binding did not match. No approval was submitted. Review the field diagnostic before trying again."
        case .routineSigningFailed:
            "The protected signing key could not sign this approved request. No response was sent to the Mac."
        case .userCancelled:
            "The request was cancelled. No approval was granted."
        case .malformedBootstrap, .malformedRequest:
            "The request was not valid, so Phil rejected it before approval."
        case .transportFailure:
            networkTimeout
        case .routineKeyUnavailable, .routineKeyActivationFailed, .routineKeyCommitFailed,
             .sessionReplaced, .none:
            "Phil stopped because a required check could not be completed. Review the reason before trying again."
        }
    }
}

private struct PhilHelpAnswer: Identifiable {
    let question: String
    let answer: String
    var id: String { question }
}

private let philHelpAnswers = [
    PhilHelpAnswer(question: "What is Phil?", answer: PhilBetaGuidance.identity),
    PhilHelpAnswer(question: "Why do I need my phone?", answer: "Your enrolled iPhone provides a separate device-bound approval. Compare the fingerprint so you know the request belongs to this Mac."),
    PhilHelpAnswer(question: "What am I approving?", answer: "Only the action shown in the summary, for the listed destination, value, maximum cost, and expiry."),
    PhilHelpAnswer(question: "What happens if I reject this?", answer: "No approval is granted. The protected action does not continue."),
    PhilHelpAnswer(question: "What does locked mean?", answer: "Your protected identity is closed. Unlock it on the Mac before Phil can prepare a local approval request."),
    PhilHelpAnswer(question: "What is the Sepolia Beta?", answer: PhilBetaGuidance.controlledBeta),
    PhilHelpAnswer(question: "Is this using real money?", answer: "No meaningful asset is used in this Beta. Sepolia assets and fees are test-only."),
    PhilHelpAnswer(question: "Is Phil post-quantum secure?", answer: "Not currently. Today's authorization uses classical cryptography; future migration support does not make the current Beta post-quantum secure."),
    PhilHelpAnswer(question: "Why isn't recovery available yet?", answer: PhilBetaGuidance.recoveryDeferred)
]

struct RootView: View {
    @EnvironmentObject private var model: CompanionModel
    @State private var helpPresented = false

    init() { PhilAppearance.configure() }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            TabView(selection: $model.selectedTab) {
                NavigationStack { WelcomeView() }
                    .tabItem { Label("Status", systemImage: "iphone.gen3") }
                    .tag(CompanionTab.home)
                NavigationStack { PairView() }
                    .tabItem { Label("Pair", systemImage: "qrcode.viewfinder") }
                    .tag(CompanionTab.pair)
                NavigationStack { RoutineAuthorizationView() }
                    .tabItem { Label("Approve", systemImage: "checkmark.shield") }
                    .tag(CompanionTab.routine)
                NavigationStack { DeferredRecoveryView() }
                    .tabItem { Label("Recovery", systemImage: "clock.badge.exclamationmark") }
                    .tag(CompanionTab.approval)
                NavigationStack { SettingsView() }
                    .tabItem { Label("Settings", systemImage: "gearshape.fill") }
                    .tag(CompanionTab.settings)
            }
            .toolbarBackground(PhilPalette.background, for: .tabBar)
            .toolbarBackground(.visible, for: .tabBar)
            Button {
                helpPresented = true
            } label: {
                Image(systemName: "questionmark.bubble.fill")
                    .font(.title2)
                    .foregroundStyle(Color.black)
                    .frame(width: 48, height: 48)
                    .background(PhilPalette.active, in: Circle())
                    .overlay(Circle().stroke(Color.white.opacity(0.32), lineWidth: 1))
                    .shadow(color: PhilPalette.active.opacity(0.35), radius: 12)
            }
            .padding(.trailing, 16)
            .padding(.top, 12)
            .accessibilityLabel("Ask Phil")
            .accessibilityIdentifier("phil.help.button")
        }
        .tint(philBlue)
        .philScreen()
        .sheet(isPresented: $helpPresented) {
            PhilHelpView()
        }
        .alert("PhilCore", isPresented: Binding(
            get: { model.notice != nil },
            set: { if !$0 { model.notice = nil } }
        )) {
            Button("OK") { model.notice = nil }
        } message: {
            Text(model.notice ?? "")
        }
    }
}

struct PhilHelpView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    PhilBrandHeader(title: "Ask Phil", subtitle: "Your identity, explained")
                    PhilGuideCard(
                        asset: "phil_wave",
                        title: "Short, factual answers",
                        message: "Choose a question. This help is built into the Beta and does not send a request to an AI service.",
                        accessibilityLabel: "Phil waving hello"
                    )
                    ForEach(philHelpAnswers) { item in
                        DisclosureGroup(item.question) {
                            Text(item.answer)
                                .font(PhilFont.body(15))
                                .foregroundStyle(PhilPalette.muted)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.top, 8)
                        }
                        .font(PhilFont.heading(17))
                        .accessibilityIdentifier("phil.help.question.\(item.id)")
                    }
                }
                .padding()
                .safeAreaPadding(.bottom)
            }
            .philScreen()
            .navigationTitle("How Phil works")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

struct RoutineAuthorizationView: View {
    @EnvironmentObject private var model: CompanionModel
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if showsRoutineGuide {
                    routineGuide
                }
                content
            }
            .padding()
            .safeAreaPadding(.bottom)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .philScreen()
        .navigationTitle("Routine approval")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $scanning) {
            ZStack(alignment: .topTrailing) {
                QRScannerView { value in
                    scanning = false; model.isRoutineScanning = false
                    Task { await model.acceptRoutineScannedValue(value) }
                }.ignoresSafeArea()
                VStack {
                    HStack {
                        Spacer()
                        Button("Cancel") { scanning = false; model.isRoutineScanning = false }
                            .buttonStyle(.philSecondary)
                            .padding()
                            .accessibilityLabel("Cancel routine QR scanning")
                    }
                    Spacer()
                    Text("Point this camera at the Desktop QR")
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.text)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color.black.opacity(0.72), in: Capsule())
                        .padding(.bottom, 28)
                        .accessibilityHidden(false)
                }
            }
        }
        .onChange(of: scanning) { _, value in model.isRoutineScanning = value }
    }

    private var showsRoutineGuide: Bool {
        switch model.routineStatus.phase {
        case .idle, .comparingFingerprint, .reviewing, .failed, .expired, .cancelled: true
        default: false
        }
    }

    private var routineGuide: some View {
        let scene: (String, String, String, String)
        switch model.routineStatus.phase {
        case .exchangingKeys, .comparingFingerprint:
            scene = ("phil_waiting", "Waiting for your Mac", PhilBetaGuidance.waitingForPhone, "Phil waiting while the devices compare")
        case .reviewing:
            scene = ("avastar_thoughtful_review", "Review before approval", PhilBetaGuidance.reviewOnPhone, "The Avastar reviewing a protected request")
        case .signing:
            scene = ("avastar_working_focus", "Protected signing", PhilBetaGuidance.protectedSigning, "The Avastar protecting the approved signing request")
        case .submitting:
            scene = ("avastar_working_focus", "Completing locally", model.routineStatus.terminalDecision == nil ? "Phil is sending the signed response only to the paired Mac for this local demonstration." : "Waiting for Desktop to acknowledge your decision. No approval is being signed.", "The Avastar completing the local request")
        case .accepted:
            scene = ("phil_success_jump", "Completed", PhilBetaGuidance.success, "Phil celebrating a verified request")
        case .denied:
            scene = ("avastar_failed_tired", "Not approved", PhilBetaGuidance.rejected, "The Avastar showing that the request was rejected")
        case .expired:
            scene = ("avastar_failed_tired", "Request expired", PhilBetaGuidance.expired, "The Avastar showing that the request expired")
        case .cancelled, .failed:
            scene = ("avastar_failed_tired", "Request stopped", PhilBetaGuidance.failureMessage(model.routineStatus.failure), "The Avastar showing that the request stopped")
        case .idle:
            scene = ("phil_waiting", "Ready when you are", "Scan the routine QR shown by PhilCore Desktop to approve one harmless local action.", "Phil waiting for a routine request")
        }
        let message = scene.2 + (model.routineStatus.bindingField.map { " Diagnostic field: \($0)." } ?? "")
        return PhilGuideCard(asset: scene.0, title: scene.1, message: message, accessibilityLabel: scene.3, compact: true)
    }

    @ViewBuilder private var content: some View {
        switch model.routineStatus.phase {
        case .idle:
            VStack(spacing: 18) {
                Image(systemName: "iphone.and.arrow.forward").font(.system(size: 52)).foregroundStyle(philBlue)
                Text(routineTerminalTitle).font(PhilFont.heading())
                Text(routineTerminalMessage)
                    .multilineTextAlignment(.center).foregroundStyle(PhilPalette.muted)
                if let record = model.routineApprovalRecord {
                    SecurityCard(title: "Disposable routine key ready", detail: record.publicKeyFingerprint, icon: "key.viewfinder")
                    Button { scanning = true } label: { Label("Scan routine QR code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity) }
                        .buttonStyle(.philPrimary).accessibilityIdentifier("routine.scan.button")
                    Button("Delete disposable routine key", role: .destructive) { model.deleteRoutineApprovalKey() }
                        .buttonStyle(.philDestructive)
                        .accessibilityIdentifier("routine.key.delete")
                } else {
                    if model.routineKeyRequiresRepair {
                        Button("Delete unusable routine key", role: .destructive) { model.deleteRoutineApprovalKey() }
                            .buttonStyle(.philDestructive)
                            .accessibilityIdentifier("routine.key.repair.delete")
                        Text("This removes only the disposable routine key. Phil identity and recovery keys are not changed.")
                            .font(.caption).foregroundStyle(.secondary)
                    } else {
                        Button("Create disposable routine key") { model.createRoutineApprovalKey() }
                            .buttonStyle(.philPrimary).accessibilityIdentifier("routine.key.create")
                        Text("Creation uses Secure Enclave and ThisDeviceOnly protection on a supported physical iPhone. Simulator builds cannot create this key.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }.frame(maxWidth: .infinity).accessibilityIdentifier("routine.empty.state")
        case .cancelled, .denied, .expired, .failed:
            PhilStateCard(
                tone: routineTerminalTone,
                title: routineTerminalTitle,
                message: routineTerminalMessage
            )
            .accessibilityIdentifier("routine.terminal.state")
            if model.routineApprovalRecord != nil && model.routineStatus.failure != .outcomeUnknown {
                Button { scanning = true } label: {
                    Label("Scan a fresh routine QR code", systemImage: "qrcode.viewfinder").frame(maxWidth: .infinity)
                }
                .buttonStyle(.philPrimary)
                .accessibilityIdentifier("routine.scan.button")
            }
        case .exchangingKeys:
            PhilProgressCard(
                stage: "Waiting for your Mac",
                detail: "Phil is checking the private, expiring session with your Mac."
            )
            cancelRoutineButton
        case .comparingFingerprint:
            SecurityCard(title: "Compare on both devices", detail: model.routineStatus.fingerprint ?? "", icon: "rectangle.2.swap")
                .accessibilityIdentifier("routine.fingerprint.card")
            Text("The encrypted request has not been opened. Continue only if this fingerprint exactly matches your Mac.")
                .foregroundStyle(.secondary)
            Button("Fingerprint matches") { Task { await model.confirmRoutineFingerprint() } }
                .buttonStyle(.philPrimary).frame(maxWidth: .infinity)
                .accessibilityIdentifier("routine.fingerprint.confirm")
            cancelRoutineButton
        case .reviewing:
            if let p = model.routineStatus.presentation {
                PhilSurface(tone: .elevated) {
                    VStack(alignment: .leading, spacing: 11) {
                        Text("Authorization summary").font(PhilFont.heading(20))
                        routineSummaryLabel("Who", p.application)
                        routineSummaryLabel("What", p.action)
                        routineSummaryLabel("Where", "\(p.network) · \(p.target)")
                        routineSummaryLabel("Value", p.value)
                        routineSummaryLabel("Maximum cost", p.maximumFee)
                        routineSummaryLabel("Expires", PhilBetaGuidance.expiryText(p.expiresAt))
                        routineSummaryLabel("Why Phil allows it", "The request matched the paired local session and the fingerprint you compared.")
                        DisclosureGroup("Details") {
                            VStack(alignment: .leading, spacing: 10) {
                                routineDetailLabel("Account", p.account)
                                routineDetailLabel("Parameters", p.parameters)
                                routineDetailLabel("Comparison fingerprint", p.comparisonFingerprint)
                            }
                            .padding(.top, 8)
                        }
                        .accessibilitySortPriority(-1)
                    }
                }
                .accessibilityIdentifier("routine.review.card")
                .accessibilitySortPriority(2)
            }
            Button { Task { await model.approveRoutine() } } label: { Label("Approve harmless local action", systemImage: "faceid").frame(maxWidth: .infinity) }
                .buttonStyle(.philPrimary).accessibilityIdentifier("routine.approve.button")
            Button("Deny", role: .destructive) { Task { await model.denyRoutine() } }.frame(maxWidth: .infinity)
                .buttonStyle(.philDestructive)
                .accessibilityIdentifier("routine.deny.button")
            cancelRoutineButton
        case .signing:
            PhilProgressCard(
                stage: "Protected signing",
                detail: "Waiting for Face ID or passcode to approve this exact action."
            )
            cancelRoutineButton
        case .submitting:
            PhilProgressCard(
                stage: model.routineStatus.terminalDecision == nil ? "Verifying local receipt" : "Notifying Desktop",
                detail: model.routineStatus.terminalDecision == nil
                    ? "Phil is confirming the paired Mac completed the approved local action."
                    : "Waiting for Desktop to acknowledge your decision. No approval is being signed."
            )
            cancelRoutineButton
        case .accepted:
            PhilStateCard(
                tone: .success,
                title: model.routineStatus.presentation == nil ? "Routine key enrolled" : "Approval sent",
                message: model.routineStatus.presentation == nil ? "The paired Mac acknowledged this routine key." : "Check Desktop for the verified result before making another request. This phone does not independently verify the execution receipt."
            )
                .accessibilityIdentifier("routine.accepted.state")
            Button {
                scanning = true
            } label: {
                Label(
                    model.routineStatus.presentation == nil
                        ? "Scan authorization QR code"
                        : "Scan another routine QR code",
                    systemImage: "qrcode.viewfinder"
                )
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.philPrimary)
            .accessibilityIdentifier("routine.accepted.scan.button")
        }
    }

    private var cancelRoutineButton: some View {
        Button("Cancel", role: .cancel) { Task { await model.cancelRoutineOnDesktop() } }.frame(maxWidth: .infinity).disabled(model.routineStatus.phase == .submitting)
            .buttonStyle(.philSecondary)
            .accessibilityIdentifier("routine.cancel.button")
    }

    private var routineTerminalTitle: String {
        switch model.routineStatus.phase {
        case .denied: "Request not approved"
        case .expired: "Request expired"
        case .cancelled: "Request cancelled"
        case .failed: "Request stopped"
        default: "Approve a harmless local action"
        }
    }

    private var routineTerminalTone: PhilStateTone {
        switch model.routineStatus.phase {
        case .denied: .rejected
        case .expired, .cancelled: .blocked
        case .failed: .failed
        default: .unknown
        }
    }

    private var routineTerminalMessage: String {
        switch model.routineStatus.phase {
        case .denied: "Start a fresh request if you still want to continue."
        case .expired: "Start a fresh request if you still want to continue."
        case .cancelled: "The request was cancelled. No approval was granted."
        case .failed: model.routineStatus.failure == .outcomeUnknown ? "Do not retry; reconcile Desktop status first." : "Review Phil's reason above before starting a fresh request."
        default: "Scan an expiring PhilCore Desktop QR code. No public network, meaningful asset, root secret, or recovery key is used."
        }
    }

    private func routineSummaryLabel(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(PhilFont.body(16)).fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private func routineDetailLabel(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.callout, design: .monospaced)).fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct WelcomeView: View {
    @EnvironmentObject private var model: CompanionModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PhilBrandHeader(title: "Phil", subtitle: "Controlled Sepolia Beta companion")
                PhilGuideCard(
                    asset: model.routineApprovalRecord == nil ? "phil_wave" : "phil_success_jump",
                    title: model.routineApprovalRecord == nil ? "I'm your security sidekick" : "Routine approval is ready",
                    message: model.routineApprovalRecord == nil
                        ? "I explain what is being requested and make sure you know what you are approving before protected signing."
                        : "This iPhone can approve one bounded local routine request after you review it.",
                    accessibilityLabel: model.routineApprovalRecord == nil ? "Phil waving hello" : "Phil celebrating routine approval readiness",
                    compact: true
                )
                PhilSectionLabel(text: "Beta status")
                SecurityCard(
                    title: "Controlled Sepolia Beta completed",
                    detail: PhilBetaGuidance.controlledBeta,
                    icon: "checkmark.seal.fill"
                )
                PhilSurface(tone: .elevated) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("What this iPhone can do").font(PhilFont.heading(19)).foregroundStyle(PhilPalette.active)
                        Label("Compare a private local session", systemImage: "rectangle.2.swap")
                        Label("Approve one bounded routine request", systemImage: "checkmark.shield")
                        Label("Keep its private key on this device", systemImage: "lock.iphone")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                PhilSurface {
                    Label {
                        Text(PhilBetaGuidance.recoveryDeferred)
                            .font(PhilFont.body(15))
                            .foregroundStyle(PhilPalette.muted)
                    } icon: {
                        Image(systemName: "clock.badge.exclamationmark")
                            .foregroundStyle(PhilPalette.active)
                    }
                }
                    .accessibilityIdentifier("beta.safety.boundary")
                StatusRows()
            }
            .padding()
            .safeAreaPadding(.bottom)
        }
        .philScreen()
        .navigationTitle("Device status")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct StatusRows: View {
    @EnvironmentObject private var model: CompanionModel
    var body: some View {
        PhilSurface {
            VStack(spacing: 0) {
                StatusRow(label: "Device protection", value: model.deviceSupportText)
                Divider().overlay(PhilPalette.edge)
                StatusRow(label: "Controlled Beta", value: ControlledBetaRelease.stage)
                Divider().overlay(PhilPalette.edge)
                StatusRow(label: "Network", value: ControlledBetaRelease.network)
                Divider().overlay(PhilPalette.edge)
                StatusRow(label: "Routine approval", value: model.routineApprovalRecord == nil ? "Not set up" : "Ready")
                Divider().overlay(PhilPalette.edge)
                StatusRow(label: "Recovery", value: ControlledBetaRelease.recovery)
                Divider().overlay(PhilPalette.edge)
                StatusRow(label: "App version", value: appVersion)
            }
        }
    }

    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        return "\(version) (\(build))"
    }

}

struct PairView: View {
    @EnvironmentObject private var model: CompanionModel
    @State private var scanning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PhilSectionLabel(text: "Secure connection")
                PhilGuideCard(
                    asset: model.pairingRequest == nil ? "phil_idle" : "phil_waiting",
                    title: model.pairingRequest == nil ? "Bring your devices together" : "Compare before pairing",
                    message: model.pairingRequest == nil
                        ? "The QR starts a private, expiring local session with PhilCore Desktop."
                        : "Make sure the code on your phone matches this Mac before pairing them.",
                    accessibilityLabel: "Phil and the Avastar pairing the iPhone with the Mac",
                    compact: true
                )
                PhilSurface {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Scan the expiring QR code shown by PhilCore Desktop. The QR contains public session data only.")
                        Text("Local pairing does not activate recovery. Recovery is deferred in this Beta.")
                            .font(PhilFont.label(13))
                            .foregroundStyle(PhilPalette.muted)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                if let request = model.pairingRequest {
                    SecurityCard(
                        title: "Compare on both devices",
                        detail: model.pairingFingerprint,
                        icon: "rectangle.2.swap"
                    )
                    .accessibilitySortPriority(3)
                    Label("Expires \(PhilBetaGuidance.expiryText(request.expiresAt))", systemImage: "clock")
                        .font(PhilFont.label(13))
                        .foregroundStyle(PhilPalette.text)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(Color.black.opacity(0.72), in: Capsule())
                    Toggle(
                        "The fingerprint exactly matches my Mac",
                        isOn: $model.pairingApproved
                    )
                    .font(.headline)
                    .accessibilitySortPriority(2)
                    Button {
                        Task { await model.approveAndPair() }
                    } label: {
                        Label("Approve local pairing", systemImage: "checkmark.shield")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.philPrimary)
                    .disabled(!model.pairingApproved || model.isWorking)
                    .accessibilitySortPriority(1)
                    Button("Cancel pairing", role: .cancel) {
                        model.pairingRequest = nil
                        model.pairingApproved = false
                    }
                    .frame(maxWidth: .infinity)
                    .buttonStyle(.philSecondary)
                } else {
                    Button {
                        scanning = true
                    } label: {
                        Label("Scan desktop QR code", systemImage: "qrcode.viewfinder")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.philPrimary)
                }
            }
            .padding()
            .safeAreaPadding(.bottom)
        }
        .philScreen()
        .navigationTitle("Pair with desktop")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $scanning) {
            ZStack(alignment: .topTrailing) {
                QRScannerView { value in
                    scanning = false
                    Task { await model.acceptPairingScannedValue(value) }
                }
                .ignoresSafeArea()
                VStack {
                    HStack {
                        Spacer()
                        Button("Cancel") { scanning = false }
                            .buttonStyle(.philSecondary)
                            .padding()
                            .accessibilityLabel("Cancel QR scanning")
                    }
                    Spacer()
                    Text("Point this camera at the Desktop QR")
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.text)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color.black.opacity(0.72), in: Capsule())
                        .padding(.bottom, 28)
                }
            }
        }
    }
}

struct DeferredRecoveryView: View {
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PhilStateCard(
                    tone: .blocked,
                    title: "Recovery deferred",
                    message: PhilBetaGuidance.recoveryDeferred
                )
                .accessibilityIdentifier("recovery.deferred.state")
                .accessibilitySortPriority(2)
                PhilSurface {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("What this means").font(PhilFont.heading(19))
                        Label("No recovery request can be scanned or approved here", systemImage: "nosign")
                        Label("Local pairing does not enroll a recovery factor", systemImage: "iphone.slash")
                        Label("Future recovery requires a separate reviewed release", systemImage: "lock.doc")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding()
            .safeAreaPadding(.bottom)
        }
        .philScreen()
        .navigationTitle("Recovery")
        .navigationBarTitleDisplayMode(.inline)
    }
}

struct RecoveryApprovalView: View {
    @EnvironmentObject private var model: CompanionModel
    @State private var scanning = false

    private var viewState: RecoveryApprovalViewState { model.recoveryViewState }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PhilGuideCard(
                    asset: "avastar_meditation",
                    title: "Recovery guardian",
                    message: "Recovery uses a separate key and requires another approved factor. It cannot authorize an ordinary action.",
                    accessibilityLabel: "The Avastar guarding recovery",
                    compact: true
                )
                content
            }
            .padding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .philScreen()
        .navigationTitle("Recovery approval")
        .sheet(isPresented: $scanning) {
            ZStack(alignment: .topTrailing) {
                QRScannerView { value in
                    scanning = false
                    model.isRecoveryScanning = false
                    Task { await model.acceptRecoveryScannedValue(value) }
                }
                .ignoresSafeArea()
                VStack {
                    HStack {
                        Spacer()
                        Button("Cancel") {
                            scanning = false
                            model.isRecoveryScanning = false
                        }
                        .buttonStyle(.philSecondary)
                        .padding()
                        .accessibilityLabel("Cancel recovery QR scanning")
                    }
                    Spacer()
                    Text("Point this camera at the Desktop QR")
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.text)
                        .padding(.horizontal, 16)
                        .padding(.vertical, 10)
                        .background(Color.black.opacity(0.72), in: Capsule())
                        .padding(.bottom, 28)
                }
            }
        }
        .onChange(of: scanning) { _, isScanning in
            model.isRecoveryScanning = isScanning
        }
    }

    @ViewBuilder
    private var content: some View {
        switch viewState.phase {
        case .idle, .scanning:
            emptyState
        case .fetching:
            loadingState(title: "Fetching recovery request…")
            if viewState.cancelAvailable {
                cancelButton
            }
        case .review(let fields):
            reviewCard(fields)
            actionButtons
        case .submitting:
            loadingState(title: "Submitting recovery approval…")
            if viewState.cancelAvailable {
                cancelButton
            }
        case .accepted:
            resultState(
                title: "Recovery accepted",
                detail: viewState.userFacingMessage ?? "Recovery approval accepted.",
                icon: "checkmark.seal.fill"
            )
        case .desktopRejected:
            resultState(
                title: "Desktop rejected",
                detail: viewState.userFacingMessage ?? "PhilCore Desktop rejected the recovery approval.",
                icon: "xmark.seal"
            )
        case .localRejected:
            resultState(
                title: "Rejected on this iPhone",
                detail: viewState.userFacingMessage ?? "Recovery approval was rejected on this iPhone.",
                icon: "xmark.circle"
            )
        case .cancelled:
            resultState(
                title: "Cancelled",
                detail: viewState.userFacingMessage ?? "Recovery approval was cancelled.",
                icon: "minus.circle"
            )
        case .expired:
            resultState(
                title: "Expired",
                detail: viewState.userFacingMessage ?? "This recovery request expired.",
                icon: "clock.badge.exclamationmark"
            )
        case .signerFailure, .failed:
            resultState(
                title: "Approval failed",
                detail: viewState.userFacingMessage ?? "Recovery approval failed.",
                icon: "exclamationmark.triangle"
            )
        }
    }

    private var emptyState: some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.shield")
                .font(.system(size: 58))
                .foregroundStyle(philBlue)
            Text("No recovery request")
                .font(PhilFont.heading())
            Text("Scan a PhilCore recovery QR code. This iPhone shows the account, action, network, recovery epoch, and expiry before any signature.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button {
                scanning = true
            } label: {
                Label("Scan recovery QR code", systemImage: "qrcode.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.philPrimary)
            .accessibilityIdentifier("recovery.scan.button")
            .accessibilityLabel("Scan recovery QR code")
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("recovery.empty.state")
    }

    private func loadingState(title: String) -> some View {
        VStack(spacing: 16) {
            ProgressView()
            Text(title)
                .font(.headline)
            Text("You can cancel while this request is still in progress.")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .accessibilityIdentifier("recovery.loading.state")
    }

    private func reviewCard(_ fields: RecoveryReviewFields) -> some View {
        PhilSurface(tone: .elevated) {
            VStack(alignment: .leading, spacing: 12) {
                Text("Review recovery request")
                    .font(PhilFont.heading(20))
                labeled("Action", fields.action)
                labeled("Account", fields.accountAddress)
                labeled("Network", fields.network)
                labeled("Chain ID", fields.chainId)
                labeled("Recovery epoch", fields.recoveryEpoch)
                labeled("Comparison fingerprint", fields.comparisonFingerprint)
                labeled("Factor bitmap", fields.factorBitmap)
                labeled("Expires at", String(fields.expiresAtUnixSeconds))
            }
        }
        .accessibilityIdentifier("recovery.review.card")
    }

    private var actionButtons: some View {
        VStack(spacing: 12) {
            Button {
                Task { await model.approveRecovery() }
            } label: {
                Label("Approve Recovery", systemImage: "checkmark.shield")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.philPrimary)
            .disabled(!viewState.approveEnabled)
            .accessibilityIdentifier("recovery.approve.button")
            .accessibilityLabel("Approve Recovery")

            Button(role: .destructive) {
                Task { await model.rejectRecovery() }
            } label: {
                Label("Reject", systemImage: "xmark.circle")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.philDestructive)
            .accessibilityIdentifier("recovery.reject.button")

            if viewState.cancelAvailable {
                cancelButton
            }
        }
    }

    private var cancelButton: some View {
        Button("Cancel", role: .cancel) {
            Task { await model.cancelRecovery() }
        }
        .frame(maxWidth: .infinity)
        .buttonStyle(.philSecondary)
        .accessibilityIdentifier("recovery.cancel.button")
        .accessibilityLabel("Cancel recovery")
    }

    private func resultState(title: String, detail: String, icon: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundStyle(philBlue)
            Text(title).font(.title2.bold())
            Text(detail)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button {
                scanning = true
            } label: {
                Label("Scan recovery QR code", systemImage: "qrcode.viewfinder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.philPrimary)
            .accessibilityIdentifier("recovery.scan.button")
        }
        .frame(maxWidth: .infinity)
        .accessibilityIdentifier("recovery.result.state")
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.body, design: .monospaced))
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject private var model: CompanionModel
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PhilBrandHeader(title: "Device controls", subtitle: "Routine approval, pairing, and Beta information")
                PhilGuideCard(
                    asset: "phil_seated_rest",
                    title: "Your identity remains yours",
                    message: "These controls manage local routine approval and pairing. They do not enable recovery or public-chain authority.",
                    accessibilityLabel: "Phil resting beside the device settings",
                    compact: true
                )
                PhilSectionLabel(text: "Routine approval")
                PhilSurface {
                    VStack(spacing: 0) {
                        StatusRow(label: "Device-bound key", value: model.routineApprovalRecord == nil ? "Not set up" : "Ready")
                        Divider().overlay(PhilPalette.edge)
                        StatusRow(label: "Scope", value: "Bounded local requests")
                        if let record = model.routineApprovalRecord {
                            Divider().overlay(PhilPalette.edge)
                            VStack(alignment: .leading, spacing: 5) {
                                Text("Public fingerprint").font(PhilFont.label()).foregroundStyle(PhilPalette.muted)
                                Text(record.publicKeyFingerprint).font(.system(.caption, design: .monospaced))
                            }
                            .padding()
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                PhilSectionLabel(text: "Local pairing")
                PhilSurface {
                    StatusRow(label: "Pairing record", value: model.record?.pairedIdentityCommitment == nil ? "Not paired" : "Present on this device")
                }
                PhilSectionLabel(text: "About this Beta")
                PhilSurface {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Phil — Controlled Sepolia Beta")
                            .font(PhilFont.heading(19))
                            .foregroundStyle(PhilPalette.active)
                            .fixedSize(horizontal: false, vertical: true)
                        StatusRow(label: "Stage", value: ControlledBetaRelease.title)
                        Divider().overlay(PhilPalette.edge)
                        StatusRow(label: "Network", value: ControlledBetaRelease.network)
                        Divider().overlay(PhilPalette.edge)
                        StatusRow(label: "Recovery", value: ControlledBetaRelease.recovery)
                        Text(ControlledBetaRelease.safetyBoundary)
                            .font(PhilFont.body(15))
                            .foregroundStyle(PhilPalette.muted)
                            .fixedSize(horizontal: false, vertical: true)
                        Text(ControlledBetaRelease.cryptographyBoundary)
                            .font(PhilFont.body(15))
                            .foregroundStyle(PhilPalette.muted)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                DisclosureGroup("Advanced Beta evidence") {
                    VStack(alignment: .leading, spacing: 10) {
                        advancedEvidence("Release", ControlledBetaEvidence.release)
                        advancedEvidence("App version", appVersion)
                        advancedEvidence("Source commit", sourceCommit)
                        advancedEvidence("Source tree", sourceTree)
                        advancedEvidence("Smart account", ControlledBetaEvidence.smartAccount)
                        advancedEvidence("EntryPoint", ControlledBetaEvidence.entryPoint)
                        advancedEvidence("Final nonce", ControlledBetaRelease.finalNonce)
                        advancedEvidence("Final native balance", ControlledBetaRelease.nativeBalance)
                        advancedEvidence("Final EntryPoint deposit", ControlledBetaRelease.entryPointDeposit)
                        advancedEvidence("Final pass balance", ControlledBetaRelease.passBalance)
                        advancedEvidence("P2 transaction", ControlledBetaEvidence.p2Transaction)
                        advancedEvidence("P2 UserOperation", ControlledBetaEvidence.p2UserOperation)
                        advancedEvidence("P2 block", ControlledBetaEvidence.p2Block)
                        advancedEvidence("P3 transaction", ControlledBetaEvidence.p3Transaction)
                        advancedEvidence("P3 UserOperation", ControlledBetaEvidence.p3UserOperation)
                        advancedEvidence("P3 block", ControlledBetaEvidence.p3Block)
                        advancedEvidence("P5 transaction", ControlledBetaEvidence.p5Transaction)
                        advancedEvidence("P5 UserOperation", ControlledBetaEvidence.p5UserOperation)
                        advancedEvidence("P5 lineage", ControlledBetaEvidence.p5Lineage)
                        advancedEvidence("Reconciliation", ControlledBetaEvidence.reconciliation)
                    }
                    .padding(.top, 8)
                }
                .font(PhilFont.heading(17))
                .accessibilityIdentifier("beta.advanced.evidence")
                .accessibilitySortPriority(-1)
                if model.routineApprovalRecord != nil {
                    Button("Delete local routine key", role: .destructive) {
                        model.deleteRoutineApprovalKey()
                    }
                    .buttonStyle(.philDestructive)
                }
                Text("Deleting a routine key affects only future local routine approvals. Recovery remains unavailable in this Beta.")
                    .font(PhilFont.label(13))
                    .foregroundStyle(PhilPalette.muted)
            }
            .padding()
            .safeAreaPadding(.bottom)
        }
        .philScreen()
        .navigationTitle("Settings")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var appVersion: String {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
        let build = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "—"
        return "\(version) (\(build))"
    }

    private var sourceCommit: String {
        Bundle.main.object(forInfoDictionaryKey: "PhilCoreSourceCommit") as? String ?? "—"
    }

    private var sourceTree: String {
        Bundle.main.object(forInfoDictionaryKey: "PhilCoreSourceTree") as? String ?? "—"
    }

    private func advancedEvidence(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(PhilFont.label()).foregroundStyle(PhilPalette.muted)
            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

struct SecurityCard: View {
    let title: String
    let detail: String
    let icon: String
    var body: some View {
        PhilSurface(tone: .elevated) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: icon).font(.title2).foregroundStyle(philBlue)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title)
                        .font(PhilFont.heading(19))
                        .foregroundStyle(PhilPalette.active)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(detail)
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct StatusRow: View {
    let label: String
    let value: String
    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .firstTextBaseline) {
                Text(label).font(PhilFont.label())
                Spacer(minLength: 12)
                Text(value)
                    .font(PhilFont.body(15))
                    .foregroundStyle(PhilPalette.muted)
                    .multilineTextAlignment(.trailing)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text(label).font(PhilFont.label())
                Text(value)
                    .font(PhilFont.body(15))
                    .foregroundStyle(PhilPalette.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding()
        .accessibilityElement(children: .combine)
    }
}

#Preview("Small iPhone") {
    RootView().environmentObject(CompanionModel())
}
