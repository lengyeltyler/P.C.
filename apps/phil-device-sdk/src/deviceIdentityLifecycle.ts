import { AbiCoder, keccak256, toUtf8Bytes } from "ethers";

import type { PhilIdentityPublic } from "./identity.ts";
import type {
  PhilDeviceIdentityProviderKind,
  PhilDevicePublicMetadata
} from "./deviceIdentity.ts";
import type { Hex } from "./hashes.ts";

const abiCoder = AbiCoder.defaultAbiCoder();

export const PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION =
  "phil-device-credential-registry-v1" as const;
export const PHIL_DEVICE_CREDENTIAL_REGISTRY_DOMAIN_LABEL =
  "PHIL_DEVICE_CREDENTIAL_REGISTRY_V1" as const;
export const PHIL_DEVICE_CREDENTIAL_REGISTRY_DOMAIN_HASH = keccak256(
  toUtf8Bytes(PHIL_DEVICE_CREDENTIAL_REGISTRY_DOMAIN_LABEL)
) as Hex;

export type PhilCredentialStatus =
  | "active"
  | "pending"
  | "revoked"
  | "recovery-only"
  | "archived";

export type PhilCredentialDeviceType =
  | "platform"
  | "mobile"
  | "hardware-security-key"
  | "secure-enclave"
  | "local-dev"
  | "unknown";

export type PhilCredentialManagementAction =
  | "addCredential"
  | "revokeCredential"
  | "archiveCredential"
  | "rotateCredential"
  | "renameCredential"
  | "listCredentials";

export type PhilRecoveryState =
  | "normal"
  | "recovery-pending"
  | "recovery-approved"
  | "recovery-completed";

export type PhilRecoveryMechanism =
  | "secondary-active-credential"
  | "recovery-credential"
  | "future-recovery-committee"
  | "future-hardware-recovery-path";

export type PhilCredentialAuditEventType =
  | "credential-added"
  | "credential-renamed"
  | "credential-revoked"
  | "credential-archived"
  | "credential-rotated"
  | "credential-used"
  | "recovery-started"
  | "recovery-approved"
  | "recovery-completed"
  | "registry-created"
  | "registry-loaded"
  | "registry-saved"
  | "registry-migrated"
  | "registry-exported"
  | "registry-imported"
  | "registry-load-failed"
  | "registry-tamper-detected"
  | "storage-key-created"
  | "storage-key-rotation-started"
  | "storage-key-rotation-completed"
  | "storage-key-rotation-failed"
  | "storage-key-retired"
  | "storage-key-revoked";

export interface PhilCredentialTransportInfo {
  readonly transports: readonly string[];
  readonly authenticatorAttachment?: string;
}

export interface PhilCredentialRecord {
  readonly credentialId: string;
  readonly providerKind: PhilDeviceIdentityProviderKind | string;
  readonly algorithm: string;
  readonly label: string;
  readonly createdAt: string;
  readonly lastUsedAt?: string;
  readonly status: PhilCredentialStatus;
  readonly signCount?: number;
  readonly deviceType: PhilCredentialDeviceType;
  readonly transport: PhilCredentialTransportInfo;
  readonly priority: number;
  readonly deviceKeyId?: Hex;
  readonly publicKey?: Hex;
  readonly publicKeyHash?: Hex;
}

export interface PhilRecoveryPolicy {
  readonly state: PhilRecoveryState;
  readonly mechanisms: readonly PhilRecoveryMechanism[];
  readonly requiresStrongerThanOrdinaryAuthentication: true;
  readonly pending?: {
    readonly recoveryId: Hex;
    readonly mechanism: PhilRecoveryMechanism;
    readonly reason?: string;
    readonly requestedAt: string;
    readonly requestedByCredentialId?: string;
  };
  readonly approvedAt?: string;
  readonly completedAt?: string;
  readonly completedByCredentialId?: string;
}

export interface PhilCredentialAuditEvent {
  readonly eventId: Hex;
  readonly eventType: PhilCredentialAuditEventType;
  readonly ownerCommitment: Hex;
  readonly credentialId?: string;
  readonly relatedCredentialId?: string;
  readonly actorCredentialId?: string;
  readonly occurredAt: string;
  readonly details: Readonly<Record<string, unknown>>;
}

export interface PhilCredentialRegistrySnapshot {
  readonly version: typeof PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION;
  readonly philIdentity: PhilIdentityPublic;
  readonly credentials: readonly PhilCredentialRecord[];
  readonly recoveryPolicy: PhilRecoveryPolicy;
  readonly auditTrail: readonly PhilCredentialAuditEvent[];
  readonly warnings: readonly string[];
}

export interface PhilCredentialActionAuthorization {
  readonly actorCredentialId?: string;
  readonly recoveryApproved?: boolean;
  readonly strongerThanOrdinaryAuthentication?: boolean;
}

export interface PhilCredentialDestructiveConfirmation {
  readonly confirmed: boolean;
  readonly reason?: string;
}

export interface PhilCredentialRegistryOptions {
  readonly philIdentity: PhilIdentityPublic;
  readonly credentials?: readonly PhilCredentialRecord[];
  readonly recoveryPolicy?: Partial<PhilRecoveryPolicy>;
  readonly auditTrail?: readonly PhilCredentialAuditEvent[];
  readonly now?: () => string;
}

export interface PhilAddCredentialInput {
  readonly credential: PhilCredentialRecord;
  readonly authorization?: PhilCredentialActionAuthorization;
}

export interface PhilRevokeCredentialInput {
  readonly credentialId: string;
  readonly authorization?: PhilCredentialActionAuthorization;
  readonly confirmation?: PhilCredentialDestructiveConfirmation;
}

export interface PhilArchiveCredentialInput {
  readonly credentialId: string;
  readonly authorization?: PhilCredentialActionAuthorization;
  readonly confirmation?: PhilCredentialDestructiveConfirmation;
}

export interface PhilRotateCredentialInput {
  readonly oldCredentialId: string;
  readonly newCredential: PhilCredentialRecord;
  readonly archiveOldCredential?: boolean;
  readonly authorization?: PhilCredentialActionAuthorization;
  readonly confirmation?: PhilCredentialDestructiveConfirmation;
}

export interface PhilRenameCredentialInput {
  readonly credentialId: string;
  readonly label: string;
  readonly authorization?: PhilCredentialActionAuthorization;
}

export interface PhilStartRecoveryInput {
  readonly mechanism: PhilRecoveryMechanism;
  readonly reason?: string;
  readonly authorization: PhilCredentialActionAuthorization;
}

export interface PhilApproveRecoveryInput {
  readonly authorization: PhilCredentialActionAuthorization;
}

export interface PhilCompleteRecoveryInput {
  readonly completedByCredentialId: string;
  readonly authorization: PhilCredentialActionAuthorization;
}

export const PHIL_CREDENTIAL_ACTION_AUTHORIZATION_REQUIREMENTS: Readonly<
  Record<PhilCredentialManagementAction, string>
> = Object.freeze({
  addCredential:
    "Requires an active credential, an approved recovery flow, or empty-registry bootstrap.",
  revokeCredential:
    "Requires an active credential or approved recovery, plus explicit confirmation.",
  archiveCredential:
    "Requires an active credential or approved recovery, plus explicit confirmation.",
  rotateCredential:
    "Requires the old credential to be active and an authorization from an active credential; old credentials are not destroyed automatically.",
  renameCredential:
    "Requires an active credential or approved recovery.",
  listCredentials:
    "Allowed for local registry reads; callers should still protect local storage."
});

export class PhilCredentialRegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PhilCredentialRegistryError";
  }
}

function sortCredentials(credentials: readonly PhilCredentialRecord[]): PhilCredentialRecord[] {
  return [...credentials].sort((left, right) => {
    if (left.priority !== right.priority) {
      return left.priority - right.priority;
    }
    return left.createdAt.localeCompare(right.createdAt)
      || left.credentialId.localeCompare(right.credentialId);
  });
}

function cloneCredential(credential: PhilCredentialRecord): PhilCredentialRecord {
  return Object.freeze({
    ...credential,
    transport: Object.freeze({
      transports: Object.freeze([...credential.transport.transports]),
      authenticatorAttachment: credential.transport.authenticatorAttachment
    })
  });
}

function freezeRecoveryPolicy(policy: PhilRecoveryPolicy): PhilRecoveryPolicy {
  return Object.freeze({
    ...policy,
    mechanisms: Object.freeze([...policy.mechanisms]),
    pending: policy.pending === undefined ? undefined : Object.freeze({ ...policy.pending })
  });
}

function deriveEventId(input: {
  ownerCommitment: Hex;
  eventType: PhilCredentialAuditEventType;
  credentialId?: string;
  relatedCredentialId?: string;
  occurredAt: string;
  sequence: number;
}): Hex {
  return keccak256(
    abiCoder.encode(
      ["bytes32", "bytes32", "string", "string", "string", "string", "uint256"],
      [
        PHIL_DEVICE_CREDENTIAL_REGISTRY_DOMAIN_HASH,
        input.ownerCommitment,
        input.eventType,
        input.credentialId ?? "",
        input.relatedCredentialId ?? "",
        input.occurredAt,
        input.sequence
      ]
    )
  ) as Hex;
}

function credentialFromMetadata(input: {
  metadata: PhilDevicePublicMetadata;
  label: string;
  algorithm?: string;
  status?: PhilCredentialStatus;
  deviceType?: PhilCredentialDeviceType;
  priority?: number;
  createdAt?: string;
}): PhilCredentialRecord {
  return Object.freeze({
    credentialId: input.metadata.credentialId ?? input.metadata.deviceKeyId,
    providerKind: input.metadata.providerKind,
    algorithm: input.algorithm ?? "provider-native",
    label: input.label,
    createdAt: input.createdAt ?? input.metadata.createdAt ?? new Date(0).toISOString(),
    status: input.status ?? "active",
    signCount: undefined,
    deviceType: input.deviceType ?? (input.metadata.hardwareBacked ? "platform" : "local-dev"),
    transport: Object.freeze({
      transports: Object.freeze([...(input.metadata.transports ?? [])]),
      authenticatorAttachment: input.metadata.authenticatorAttachment
    }),
    priority: input.priority ?? 100,
    deviceKeyId: input.metadata.deviceKeyId,
    publicKey: input.metadata.publicKey ?? input.metadata.credentialPublicKey,
    publicKeyHash: input.metadata.publicKeyHash
  });
}

function defaultRecoveryPolicy(): PhilRecoveryPolicy {
  return freezeRecoveryPolicy({
    state: "normal",
    mechanisms: Object.freeze(["secondary-active-credential", "recovery-credential"]),
    requiresStrongerThanOrdinaryAuthentication: true
  });
}

function assertKnownCredential(
  credentials: readonly PhilCredentialRecord[],
  credentialId: string
): PhilCredentialRecord {
  const found = credentials.find((credential) => credential.credentialId === credentialId);
  if (found === undefined) {
    throw new PhilCredentialRegistryError(`Unknown credential: ${credentialId}`);
  }
  return found;
}

export function createPhilCredentialRecordFromDeviceMetadata(input: {
  metadata: PhilDevicePublicMetadata;
  label: string;
  algorithm?: string;
  status?: PhilCredentialStatus;
  deviceType?: PhilCredentialDeviceType;
  priority?: number;
  createdAt?: string;
}): PhilCredentialRecord {
  return credentialFromMetadata(input);
}

export function createPhilCredentialRegistry(options: PhilCredentialRegistryOptions) {
  let credentials = sortCredentials(options.credentials ?? []).map(cloneCredential);
  let recoveryPolicy = freezeRecoveryPolicy({
    ...defaultRecoveryPolicy(),
    ...options.recoveryPolicy,
    mechanisms: Object.freeze([
      ...(options.recoveryPolicy?.mechanisms ?? defaultRecoveryPolicy().mechanisms)
    ]),
    requiresStrongerThanOrdinaryAuthentication: true
  });
  let auditTrail = [...(options.auditTrail ?? [])].map((event) => Object.freeze({
    ...event,
    details: Object.freeze({ ...event.details })
  }));
  const warnings = new Set<string>();
  const now = options.now ?? (() => new Date().toISOString());

  function activeCredentials(): PhilCredentialRecord[] {
    return credentials.filter((credential) => credential.status === "active");
  }

  function hasRecoveryPath(): boolean {
    return credentials.some((credential) => credential.status === "recovery-only")
      || activeCredentials().length > 1
      || recoveryPolicy.state === "recovery-approved";
  }

  function addWarning(message: string) {
    warnings.add(message);
  }

  function recordEvent(input: {
    eventType: PhilCredentialAuditEventType;
    credentialId?: string;
    relatedCredentialId?: string;
    actorCredentialId?: string;
    details?: Readonly<Record<string, unknown>>;
  }): PhilCredentialAuditEvent {
    const occurredAt = now();
    const event = Object.freeze({
      eventId: deriveEventId({
        ownerCommitment: options.philIdentity.ownerCommitment,
        eventType: input.eventType,
        credentialId: input.credentialId,
        relatedCredentialId: input.relatedCredentialId,
        occurredAt,
        sequence: auditTrail.length
      }),
      eventType: input.eventType,
      ownerCommitment: options.philIdentity.ownerCommitment,
      credentialId: input.credentialId,
      relatedCredentialId: input.relatedCredentialId,
      actorCredentialId: input.actorCredentialId,
      occurredAt,
      details: Object.freeze({ ...(input.details ?? {}) })
    });
    auditTrail = Object.freeze([...auditTrail, event]) as PhilCredentialAuditEvent[];
    return event;
  }

  function assertActiveAuthorization(
    authorization: PhilCredentialActionAuthorization | undefined,
    action: PhilCredentialManagementAction
  ) {
    if (authorization?.recoveryApproved === true && recoveryPolicy.state === "recovery-approved") {
      return;
    }
    if (credentials.length === 0 && action === "addCredential") {
      return;
    }
    if (authorization?.actorCredentialId === undefined) {
      throw new PhilCredentialRegistryError(`${action} requires credential authorization`);
    }
    const actor = assertKnownCredential(credentials, authorization.actorCredentialId);
    if (actor.status !== "active") {
      throw new PhilCredentialRegistryError(`${action} requires an active actor credential`);
    }
  }

  function assertDestructiveConfirmation(
    confirmation: PhilCredentialDestructiveConfirmation | undefined,
    action: PhilCredentialManagementAction
  ) {
    if (confirmation?.confirmed !== true) {
      throw new PhilCredentialRegistryError(`${action} requires explicit confirmation`);
    }
  }

  function recomputeAntiLockoutWarnings(nextCredentials: readonly PhilCredentialRecord[]) {
    if (nextCredentials.filter((credential) => credential.status === "active").length === 0) {
      addWarning("No active credential remains for this Phil identity.");
    }
    if (!nextCredentials.some((credential) => credential.status === "recovery-only")
      && nextCredentials.filter((credential) => credential.status === "active").length < 2) {
      addWarning("No recovery path exists; add a second active or recovery-only credential.");
    }
  }

  function replaceCredential(
    credentialId: string,
    update: (credential: PhilCredentialRecord) => PhilCredentialRecord
  ) {
    credentials = sortCredentials(credentials.map((credential) => (
      credential.credentialId === credentialId ? cloneCredential(update(credential)) : credential
    )));
  }

  return Object.freeze({
    getSnapshot(): PhilCredentialRegistrySnapshot {
      return Object.freeze({
        version: PHIL_DEVICE_CREDENTIAL_REGISTRY_VERSION,
        philIdentity: Object.freeze({ ...options.philIdentity }),
        credentials: Object.freeze(credentials.map(cloneCredential)),
        recoveryPolicy: freezeRecoveryPolicy(recoveryPolicy),
        auditTrail: Object.freeze([...auditTrail]),
        warnings: Object.freeze([...warnings])
      });
    },

    listCredentials(): readonly PhilCredentialRecord[] {
      return Object.freeze(credentials.map(cloneCredential));
    },

    getCredential(credentialId: string): PhilCredentialRecord | undefined {
      const credential = credentials.find((entry) => entry.credentialId === credentialId);
      return credential === undefined ? undefined : cloneCredential(credential);
    },

    assertCredentialCanAuthorize(credentialId: string): PhilCredentialRecord {
      const credential = assertKnownCredential(credentials, credentialId);
      if (credential.status !== "active") {
        throw new PhilCredentialRegistryError(
          `Credential ${credentialId} cannot authorize ordinary actions while ${credential.status}`
        );
      }
      return cloneCredential(credential);
    },

    addCredential(input: PhilAddCredentialInput): PhilCredentialRegistrySnapshot {
      assertActiveAuthorization(input.authorization, "addCredential");
      if (credentials.some((credential) => credential.credentialId === input.credential.credentialId)) {
        throw new PhilCredentialRegistryError(
          `Credential already exists: ${input.credential.credentialId}`
        );
      }
      credentials = sortCredentials([...credentials, cloneCredential(input.credential)]);
      recomputeAntiLockoutWarnings(credentials);
      recordEvent({
        eventType: "credential-added",
        credentialId: input.credential.credentialId,
        actorCredentialId: input.authorization?.actorCredentialId,
        details: {
          status: input.credential.status,
          providerKind: input.credential.providerKind,
          label: input.credential.label
        }
      });
      return this.getSnapshot();
    },

    revokeCredential(input: PhilRevokeCredentialInput): PhilCredentialRegistrySnapshot {
      assertActiveAuthorization(input.authorization, "revokeCredential");
      assertDestructiveConfirmation(input.confirmation, "revokeCredential");
      const credential = assertKnownCredential(credentials, input.credentialId);
      replaceCredential(input.credentialId, (current) => Object.freeze({
        ...current,
        status: "revoked"
      }));
      recomputeAntiLockoutWarnings(credentials);
      recordEvent({
        eventType: "credential-revoked",
        credentialId: input.credentialId,
        actorCredentialId: input.authorization?.actorCredentialId,
        details: {
          previousStatus: credential.status,
          confirmationReason: input.confirmation?.reason
        }
      });
      return this.getSnapshot();
    },

    archiveCredential(input: PhilArchiveCredentialInput): PhilCredentialRegistrySnapshot {
      assertActiveAuthorization(input.authorization, "archiveCredential");
      assertDestructiveConfirmation(input.confirmation, "archiveCredential");
      const credential = assertKnownCredential(credentials, input.credentialId);
      replaceCredential(input.credentialId, (current) => Object.freeze({
        ...current,
        status: "archived"
      }));
      recomputeAntiLockoutWarnings(credentials);
      recordEvent({
        eventType: "credential-archived",
        credentialId: input.credentialId,
        actorCredentialId: input.authorization?.actorCredentialId,
        details: {
          previousStatus: credential.status,
          confirmationReason: input.confirmation?.reason
        }
      });
      return this.getSnapshot();
    },

    rotateCredential(input: PhilRotateCredentialInput): PhilCredentialRegistrySnapshot {
      assertActiveAuthorization(input.authorization, "rotateCredential");
      const oldCredential = assertKnownCredential(credentials, input.oldCredentialId);
      if (oldCredential.status !== "active") {
        throw new PhilCredentialRegistryError("rotateCredential requires an active old credential");
      }
      if (credentials.some((credential) => credential.credentialId === input.newCredential.credentialId)) {
        throw new PhilCredentialRegistryError(
          `Credential already exists: ${input.newCredential.credentialId}`
        );
      }
      credentials = sortCredentials([...credentials, cloneCredential(input.newCredential)]);
      if (input.archiveOldCredential === true) {
        assertDestructiveConfirmation(input.confirmation, "archiveCredential");
        replaceCredential(input.oldCredentialId, (current) => Object.freeze({
          ...current,
          status: "archived"
        }));
      }
      recomputeAntiLockoutWarnings(credentials);
      recordEvent({
        eventType: "credential-rotated",
        credentialId: input.oldCredentialId,
        relatedCredentialId: input.newCredential.credentialId,
        actorCredentialId: input.authorization?.actorCredentialId,
        details: {
          newCredentialStatus: input.newCredential.status,
          oldCredentialArchived: input.archiveOldCredential === true
        }
      });
      return this.getSnapshot();
    },

    renameCredential(input: PhilRenameCredentialInput): PhilCredentialRegistrySnapshot {
      assertActiveAuthorization(input.authorization, "renameCredential");
      const credential = assertKnownCredential(credentials, input.credentialId);
      replaceCredential(input.credentialId, (current) => Object.freeze({
        ...current,
        label: input.label
      }));
      recordEvent({
        eventType: "credential-renamed",
        credentialId: input.credentialId,
        actorCredentialId: input.authorization?.actorCredentialId,
        details: {
          previousLabel: credential.label,
          label: input.label
        }
      });
      return this.getSnapshot();
    },

    markCredentialUsed(input: {
      credentialId: string;
      signCount?: number;
      usedAt?: string;
    }): PhilCredentialRegistrySnapshot {
      const credential = this.assertCredentialCanAuthorize(input.credentialId);
      replaceCredential(input.credentialId, (current) => Object.freeze({
        ...current,
        lastUsedAt: input.usedAt ?? now(),
        signCount: input.signCount ?? current.signCount
      }));
      recordEvent({
        eventType: "credential-used",
        credentialId: input.credentialId,
        actorCredentialId: input.credentialId,
        details: {
          previousSignCount: credential.signCount,
          signCount: input.signCount ?? credential.signCount
        }
      });
      return this.getSnapshot();
    },

    startRecovery(input: PhilStartRecoveryInput): PhilCredentialRegistrySnapshot {
      if (input.authorization.strongerThanOrdinaryAuthentication !== true) {
        throw new PhilCredentialRegistryError(
          "startRecovery requires stronger-than-ordinary authentication"
        );
      }
      if (input.authorization.actorCredentialId !== undefined) {
        const actor = assertKnownCredential(credentials, input.authorization.actorCredentialId);
        if (actor.status !== "active" && actor.status !== "recovery-only") {
          throw new PhilCredentialRegistryError(
            "startRecovery requires an active or recovery-only credential"
          );
        }
      }
      const requestedAt = now();
      recoveryPolicy = freezeRecoveryPolicy({
        ...recoveryPolicy,
        state: "recovery-pending",
        pending: {
          recoveryId: keccak256(
            abiCoder.encode(
              ["bytes32", "bytes32", "string", "string"],
              [
                PHIL_DEVICE_CREDENTIAL_REGISTRY_DOMAIN_HASH,
                options.philIdentity.ownerCommitment,
                input.mechanism,
                requestedAt
              ]
            )
          ) as Hex,
          mechanism: input.mechanism,
          reason: input.reason,
          requestedAt,
          requestedByCredentialId: input.authorization.actorCredentialId
        }
      });
      recordEvent({
        eventType: "recovery-started",
        actorCredentialId: input.authorization.actorCredentialId,
        details: {
          mechanism: input.mechanism,
          reason: input.reason
        }
      });
      return this.getSnapshot();
    },

    approveRecovery(input: PhilApproveRecoveryInput): PhilCredentialRegistrySnapshot {
      if (recoveryPolicy.state !== "recovery-pending") {
        throw new PhilCredentialRegistryError("Recovery is not pending");
      }
      if (input.authorization.strongerThanOrdinaryAuthentication !== true) {
        throw new PhilCredentialRegistryError(
          "approveRecovery requires stronger-than-ordinary authentication"
        );
      }
      recoveryPolicy = freezeRecoveryPolicy({
        ...recoveryPolicy,
        state: "recovery-approved",
        approvedAt: now()
      });
      recordEvent({
        eventType: "recovery-approved",
        actorCredentialId: input.authorization.actorCredentialId,
        details: {
          mechanism: recoveryPolicy.pending?.mechanism
        }
      });
      return this.getSnapshot();
    },

    completeRecovery(input: PhilCompleteRecoveryInput): PhilCredentialRegistrySnapshot {
      if (recoveryPolicy.state !== "recovery-approved") {
        throw new PhilCredentialRegistryError("Recovery is not approved");
      }
      if (input.authorization.strongerThanOrdinaryAuthentication !== true) {
        throw new PhilCredentialRegistryError(
          "completeRecovery requires stronger-than-ordinary authentication"
        );
      }
      this.assertCredentialCanAuthorize(input.completedByCredentialId);
      recoveryPolicy = freezeRecoveryPolicy({
        ...recoveryPolicy,
        state: "recovery-completed",
        completedAt: now(),
        completedByCredentialId: input.completedByCredentialId
      });
      recomputeAntiLockoutWarnings(credentials);
      recordEvent({
        eventType: "recovery-completed",
        credentialId: input.completedByCredentialId,
        actorCredentialId: input.authorization.actorCredentialId,
        details: {
          mechanism: recoveryPolicy.pending?.mechanism
        }
      });
      return this.getSnapshot();
    },

    hasRecoveryPath(): boolean {
      return hasRecoveryPath();
    }
  });
}
