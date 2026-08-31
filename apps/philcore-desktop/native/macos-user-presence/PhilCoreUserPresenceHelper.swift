import Foundation
import LocalAuthentication

struct UserPresenceRequest: Decodable {
    let version: Int
    let operation: String
    let reason: String
    let policy: String
}

struct UserPresenceResult: Encodable {
    let version: Int
    let status: String
    let outcome: String
    let evidenceClass: String
    let provider: String
    let policy: String
    let biometricDataReturned: Bool
    let rawAuthenticationMaterialReturned: Bool
    let limitation: String
}

func emit(_ result: UserPresenceResult) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    if let data = try? encoder.encode(result), let json = String(data: data, encoding: .utf8) {
        print(json)
    } else {
        print("{\"version\":1,\"status\":\"helper_error\",\"outcome\":\"helper_error\",\"evidenceClass\":\"helper_error\",\"provider\":\"macos_local_authentication_helper\",\"policy\":\"unknown\",\"biometricDataReturned\":false,\"rawAuthenticationMaterialReturned\":false,\"limitation\":\"json_encoding_failed\"}")
    }
    exit(result.status == "user_presence_verified" ? 0 : 2)
}

func failure(_ status: String, _ outcome: String, _ policy: String = "unknown", _ limitation: String) -> Never {
    emit(UserPresenceResult(
        version: 1,
        status: status,
        outcome: outcome,
        evidenceClass: outcome,
        provider: "macos_local_authentication_helper",
        policy: policy,
        biometricDataReturned: false,
        rawAuthenticationMaterialReturned: false,
        limitation: limitation
    ))
}

let stdin = FileHandle.standardInput.readDataToEndOfFile()
guard stdin.count <= 16_384 else {
    failure("helper_error", "malformed_request", "unknown", "request_too_large")
}

let request: UserPresenceRequest
do {
    request = try JSONDecoder().decode(UserPresenceRequest.self, from: stdin)
} catch {
    failure("helper_error", "malformed_request", "unknown", "request_json_invalid")
}

guard request.version == 1 else {
    failure("helper_error", "malformed_request", request.policy, "unsupported_request_version")
}
guard request.operation == "request_user_presence" else {
    failure("helper_error", "unsupported_operation", request.policy, "unsupported_operation")
}
guard request.reason.count >= 8 && request.reason.count <= 180 else {
    failure("helper_error", "malformed_request", request.policy, "reason_length_invalid")
}

let laPolicy: LAPolicy
let evidenceClass: String
switch request.policy {
case "device_owner_authentication":
    laPolicy = .deviceOwnerAuthentication
    evidenceClass = "device_owner_authentication_verified"
case "device_owner_authentication_with_biometrics":
    laPolicy = .deviceOwnerAuthenticationWithBiometrics
    evidenceClass = "touch_id_biometric_verified"
default:
    failure("helper_error", "unsupported_policy", request.policy, "unsupported_policy")
}

let context = LAContext()
context.localizedReason = request.reason
var authError: NSError?
guard context.canEvaluatePolicy(laPolicy, error: &authError) else {
    if let error = authError as? LAError {
        switch error.code {
        case .biometryNotAvailable:
            failure("biometry_unavailable", "biometry_unavailable", request.policy, "local_authentication_policy_unavailable")
        case .biometryNotEnrolled:
            failure("biometry_not_enrolled", "biometry_not_enrolled", request.policy, "local_authentication_policy_unavailable")
        case .biometryLockout:
            failure("biometry_lockout", "biometry_lockout", request.policy, "local_authentication_policy_unavailable")
        case .passcodeNotSet:
            failure("device_authentication_unavailable", "device_authentication_unavailable", request.policy, "passcode_or_password_not_available")
        default:
            failure("device_authentication_unavailable", "device_authentication_unavailable", request.policy, "local_authentication_policy_unavailable")
        }
    }
    failure("device_authentication_unavailable", "device_authentication_unavailable", request.policy, "local_authentication_policy_unavailable")
}

let semaphore = DispatchSemaphore(value: 0)
var success = false
var completionError: Error?
context.evaluatePolicy(laPolicy, localizedReason: request.reason) { evaluated, error in
    success = evaluated
    completionError = error
    semaphore.signal()
}

_ = semaphore.wait(timeout: .now() + 60)

if success {
    emit(UserPresenceResult(
        version: 1,
        status: "user_presence_verified",
        outcome: "user_presence_verified",
        evidenceClass: evidenceClass,
        provider: "macos_local_authentication_helper",
        policy: request.policy,
        biometricDataReturned: false,
        rawAuthenticationMaterialReturned: false,
        limitation: request.policy == "device_owner_authentication"
            ? "macos_does_not_disclose_exact_factor_for_broad_policy"
            : "biometric_success_classified_by_requested_policy"
    ))
}

if let error = completionError as? LAError {
    switch error.code {
    case .userCancel, .systemCancel, .appCancel:
        failure("user_cancelled", "user_cancelled", request.policy, "local_authentication_cancelled")
    case .authenticationFailed:
        failure("authentication_failed", "authentication_failed", request.policy, "local_authentication_failed")
    case .biometryLockout:
        failure("biometry_lockout", "biometry_lockout", request.policy, "biometry_lockout")
    case .notInteractive:
        failure("interaction_not_allowed", "interaction_not_allowed", request.policy, "interaction_not_allowed")
    default:
        failure("authentication_failed", "authentication_failed", request.policy, "local_authentication_failed")
    }
}

failure("authentication_failed", "authentication_failed", request.policy, "local_authentication_failed")
