import SwiftUI

@main
struct PhilCoreCompanionApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = CompanionModel()

    var body: some Scene {
        WindowGroup {
            configuredRootView
                .environmentObject(model)
                .onChange(of: scenePhase) { _, phase in
                    if Self.shouldInvalidateRoutine(for: phase) {
                        Task { await model.handleSceneInactivity() }
                    }
                }
        }
    }

    @ViewBuilder
    private var configuredRootView: some View {
#if DEBUG
        if ProcessInfo.processInfo.arguments.contains("--philcore-ui-test-large-type") {
            RootView().dynamicTypeSize(.accessibility3)
        } else {
            RootView()
        }
#else
        RootView()
#endif
    }

    /// System permission and authentication sheets transiently make a scene
    /// inactive. Only a real background transition is authority-invalidating;
    /// otherwise the first local-network permission prompt cancels itself.
    static func shouldInvalidateRoutine(for phase: ScenePhase) -> Bool {
        phase == .background
    }
}
