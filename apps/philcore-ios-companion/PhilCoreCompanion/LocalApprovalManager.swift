import LocalAuthentication

@MainActor
final class LocalApprovalManager {
    private var activeContext: LAContext?

    func capability() -> (available: Bool, label: String) {
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        return (available, available ? "Face ID / passcode ready" : "Device security unavailable")
    }

    func approve(reason: String) async throws -> LAContext {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.localizedFallbackTitle = "Use Device Passcode"
        var capabilityError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &capabilityError) else {
            throw CompanionFailure.deviceSecurityUnavailable
        }
        activeContext = context
        do {
            let approved = try await context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            )
            if !approved { throw CompanionFailure.userDenied }
            return context
        } catch let error as LAError {
            activeContext = nil
            switch error.code {
            case .userCancel, .appCancel, .systemCancel:
                throw CompanionFailure.userCancelled
            case .userFallback:
                throw CompanionFailure.userCancelled
            default:
                throw CompanionFailure.userDenied
            }
        }
    }

    func finish() {
        activeContext = nil
    }

    func invalidate() {
        activeContext?.invalidate()
        activeContext = nil
    }
}
