export const PHIL_STEP2_DEVICE_PROFILE_V1 = Object.freeze({
  profileId: "iphone-17-ios-26.6-23g71-step2-candidate-v1",
  marketingModel: "iPhone 17",
  operatingSystemVersion: "26.6",
  operatingSystemBuild: "23G71",
  minimumPhysicalMemoryMiB: 7_671,
  requiredBatteryPercent: 100,
  requiredThermalState: "nominal" as const,
  lowPowerModeRequired: false,
  evidenceClassification: "bounded-physical-candidate-only" as const
});

export type PhilStep2DeviceOperationV1 =
  | "device_approval"
  | "local_vault_key_wrap"
  | "local_vault_key_unwrap";

export type PhilStep2ThermalStateV1 =
  | "nominal"
  | "fair"
  | "serious"
  | "critical"
  | "unknown";

export interface PhilStep2DeviceAdmissionInputV1 {
  readonly profileId: string;
  readonly marketingModel: string;
  readonly operatingSystemVersion: string;
  readonly operatingSystemBuild: string;
  readonly physicalDevice: boolean;
  readonly secureEnclaveAvailable: boolean;
  readonly deviceOwnerAuthenticationAvailable: boolean;
  readonly protectedDataAvailable: boolean;
  readonly physicalMemoryMiB: number;
  readonly batteryPercent: number | null;
  readonly lowPowerMode: boolean;
  readonly thermalState: PhilStep2ThermalStateV1;
  readonly operation: PhilStep2DeviceOperationV1;
}

export type PhilStep2DeviceAdmissionReasonV1 =
  | "PROFILE_NOT_ADMITTED"
  | "OPERATION_NOT_ADMITTED"
  | "SIMULATOR_OR_NONPHYSICAL_DEVICE"
  | "SECURE_ENCLAVE_UNAVAILABLE"
  | "DEVICE_OWNER_AUTHENTICATION_UNAVAILABLE"
  | "PROTECTED_DATA_UNAVAILABLE"
  | "PHYSICAL_MEMORY_BELOW_EVIDENCE_FLOOR"
  | "BATTERY_STATE_OUTSIDE_EVIDENCE"
  | "LOW_POWER_MODE_OUTSIDE_EVIDENCE"
  | "THERMAL_STATE_OUTSIDE_EVIDENCE";

export type PhilStep2DeviceAdmissionDecisionV1 = Readonly<{
  admitted: boolean;
  classification: "bounded-step2-candidate";
  productionAuthority: false;
  reasons: readonly PhilStep2DeviceAdmissionReasonV1[];
}>;

/**
 * Fail-closed admission for the exact Step 2 physical evidence envelope.
 *
 * This is intentionally not a general iPhone support claim. An unmeasured
 * model, OS/build, battery state, Low Power Mode state, thermal state, or
 * memory class is rejected until separately admitted with evidence.
 */
export function assessPhilStep2DeviceAdmissionV1(
  input: PhilStep2DeviceAdmissionInputV1
): PhilStep2DeviceAdmissionDecisionV1 {
  const profile = PHIL_STEP2_DEVICE_PROFILE_V1;
  const reasons: PhilStep2DeviceAdmissionReasonV1[] = [];
  if (input.profileId !== profile.profileId
    || input.marketingModel !== profile.marketingModel
    || input.operatingSystemVersion !== profile.operatingSystemVersion
    || input.operatingSystemBuild !== profile.operatingSystemBuild) {
    reasons.push("PROFILE_NOT_ADMITTED");
  }
  if (input.operation !== "device_approval"
    && input.operation !== "local_vault_key_wrap"
    && input.operation !== "local_vault_key_unwrap") {
    reasons.push("OPERATION_NOT_ADMITTED");
  }
  if (!input.physicalDevice) reasons.push("SIMULATOR_OR_NONPHYSICAL_DEVICE");
  if (!input.secureEnclaveAvailable) reasons.push("SECURE_ENCLAVE_UNAVAILABLE");
  if (!input.deviceOwnerAuthenticationAvailable) {
    reasons.push("DEVICE_OWNER_AUTHENTICATION_UNAVAILABLE");
  }
  if (!input.protectedDataAvailable) reasons.push("PROTECTED_DATA_UNAVAILABLE");
  if (!Number.isSafeInteger(input.physicalMemoryMiB)
    || input.physicalMemoryMiB < profile.minimumPhysicalMemoryMiB) {
    reasons.push("PHYSICAL_MEMORY_BELOW_EVIDENCE_FLOOR");
  }
  if (!Number.isInteger(input.batteryPercent)
    || input.batteryPercent !== profile.requiredBatteryPercent) {
    reasons.push("BATTERY_STATE_OUTSIDE_EVIDENCE");
  }
  if (input.lowPowerMode !== profile.lowPowerModeRequired) {
    reasons.push("LOW_POWER_MODE_OUTSIDE_EVIDENCE");
  }
  if (input.thermalState !== profile.requiredThermalState) {
    reasons.push("THERMAL_STATE_OUTSIDE_EVIDENCE");
  }
  return Object.freeze({
    admitted: reasons.length === 0,
    classification: "bounded-step2-candidate" as const,
    productionAuthority: false as const,
    reasons: Object.freeze(reasons)
  });
}
