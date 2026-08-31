import { createUserSessionContext } from "./helpers.ts";
import type {
  UserSessionContext,
  UserSessionSnapshot
} from "./types.ts";

export type EphemeralUserSessionStoreStatus =
  | "empty"
  | "set"
  | "replaced"
  | "cleared"
  | "invalid";

export interface EphemeralUserSessionStoreOptions {
  readonly initialSessionContext?: UserSessionContext;
}

export interface EphemeralUserSessionStoreState {
  readonly hasSessionContext: boolean;
  readonly sessionId?: string;
  readonly snapshot?: UserSessionSnapshot;
}

export interface EphemeralUserSessionStoreResult {
  readonly status: EphemeralUserSessionStoreStatus;
  readonly state: EphemeralUserSessionStoreState;
  readonly context?: UserSessionContext;
  readonly snapshot?: UserSessionSnapshot;
  readonly errors?: readonly string[];
}

export interface EphemeralUserSessionStore {
  setSessionContext(context: UserSessionContext): EphemeralUserSessionStoreResult;
  getSessionContext(): UserSessionContext | undefined;
  hasSessionContext(): boolean;
  clearSessionContext(): EphemeralUserSessionStoreResult;
  replaceSessionContext(context: UserSessionContext): EphemeralUserSessionStoreResult;
  getSnapshot(): UserSessionSnapshot | undefined;
  getState(): EphemeralUserSessionStoreState;
}

function freezeSnapshot(snapshot: UserSessionSnapshot): UserSessionSnapshot {
  return Object.freeze({
    context: snapshot.context,
    capturedAt: snapshot.capturedAt
  });
}

function normalizeSessionContext(context: UserSessionContext): {
  readonly context?: UserSessionContext;
  readonly snapshot?: UserSessionSnapshot;
  readonly errors?: readonly string[];
} {
  const result = createUserSessionContext({
    sessionId: context.sessionId,
    ownerCommitment: context.ownerCommitment,
    status: context.status,
    activeApplicationId: context.activeApplicationId,
    activeCapabilityIds: context.activeCapabilityIds,
    pendingIntentIds: context.pendingIntentIds,
    policyMode: context.policyMode,
    recoveryState: context.recoveryState,
    timeout: context.timeout,
    metadata: context.metadata
  });

  if (result.status !== "approved" || !result.context || !result.snapshot) {
    return {
      errors: result.errors ?? ["session context failed shape validation"]
    };
  }

  return {
    context: result.context,
    snapshot: freezeSnapshot(result.snapshot)
  };
}

export function createEphemeralUserSessionStore(
  options: EphemeralUserSessionStoreOptions = {}
): EphemeralUserSessionStore {
  let currentContext: UserSessionContext | undefined;
  let currentSnapshot: UserSessionSnapshot | undefined;

  function state(): EphemeralUserSessionStoreState {
    return Object.freeze({
      hasSessionContext: currentContext !== undefined,
      sessionId: currentContext?.sessionId,
      snapshot: currentSnapshot
    });
  }

  function result(status: EphemeralUserSessionStoreStatus, errors?: readonly string[]): EphemeralUserSessionStoreResult {
    return Object.freeze({
      status,
      state: state(),
      context: currentContext,
      snapshot: currentSnapshot,
      errors
    });
  }

  function storeContext(
    context: UserSessionContext,
    statusWhenValid: "set" | "replaced"
  ): EphemeralUserSessionStoreResult {
    const normalized = normalizeSessionContext(context);
    if (!normalized.context || !normalized.snapshot) {
      return result("invalid", normalized.errors);
    }

    currentContext = normalized.context;
    currentSnapshot = normalized.snapshot;
    return result(statusWhenValid);
  }

  const store: EphemeralUserSessionStore = {
    setSessionContext(context) {
      return storeContext(context, currentContext ? "replaced" : "set");
    },
    getSessionContext() {
      return currentContext;
    },
    hasSessionContext() {
      return currentContext !== undefined;
    },
    clearSessionContext() {
      currentContext = undefined;
      currentSnapshot = undefined;
      return result("cleared");
    },
    replaceSessionContext(context) {
      return storeContext(context, "replaced");
    },
    getSnapshot() {
      return currentSnapshot;
    },
    getState() {
      return state();
    }
  };

  if (options.initialSessionContext) {
    store.setSessionContext(options.initialSessionContext);
  }

  return store;
}
