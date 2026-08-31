import { createAuditCorrelationId } from "./helpers.ts";
import { sanitizeAuditEventDraftInput } from "./redaction.ts";
import type {
  AdapterId,
  ApplicationId,
  AuditEvent,
  CapabilityName
} from "./types.ts";
import type { RuntimeRequestKind } from "./intake.ts";

export type AuditEventDraftCategory =
  | "runtime"
  | "capability"
  | "intent"
  | "trust"
  | "application"
  | "adapter"
  | "authorization_request"
  | "future_ai";

export type AuditEventDraftOutcome =
  | "validation_succeeded"
  | "validation_failed"
  | "unsupported"
  | "malformed";

export interface AuditEventDraftInput {
  readonly category: AuditEventDraftCategory;
  readonly outcome: AuditEventDraftOutcome;
  readonly requestKind?: RuntimeRequestKind | string;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly intentId?: string;
  readonly capabilityId?: string;
  readonly capability?: CapabilityName;
  readonly adapterId?: AdapterId;
  readonly summary: string;
  readonly redactedDetails?: Readonly<Record<string, unknown>>;
  readonly auditCorrelationId?: string;
  readonly timestamp?: string;
}

export interface AuditEventDraft {
  readonly eventDraftId: string;
  readonly timestamp: string;
  readonly category: AuditEventDraftCategory;
  readonly outcome: AuditEventDraftOutcome;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly intentId?: string;
  readonly capabilityId?: string;
  readonly capability?: CapabilityName;
  readonly adapterId?: AdapterId;
  readonly requestKind?: RuntimeRequestKind | string;
  readonly summary: string;
  readonly redactedDetails?: Readonly<Record<string, unknown>>;
  readonly auditCorrelationId: string;
  readonly persisted: false;
  readonly encryptedByDefault: AuditEvent["encryptedByDefault"];
}

export interface AuditEventDraftResult {
  readonly auditEventDraft: AuditEventDraft;
}

export type AuditDraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface AuditDraftFilter {
  readonly category?: AuditEventDraftCategory;
  readonly outcome?: AuditEventDraftOutcome;
  readonly sessionId?: string;
  readonly applicationId?: ApplicationId;
  readonly intentId?: string;
  readonly capabilityId?: string;
  readonly capability?: CapabilityName;
  readonly adapterId?: AdapterId;
  readonly requestKind?: RuntimeRequestKind | string;
  readonly auditCorrelationId?: string;
  readonly since?: string;
  readonly until?: string;
}

export interface AuditDraftQuery {
  readonly filter?: AuditDraftFilter;
  readonly limit?: number;
  readonly offset?: number;
}

export interface AuditDraftCollection {
  readonly drafts: readonly AuditEventDraft[];
  readonly count: number;
  readonly maxDraftCount: number;
}

export interface AuditDraftCollectionResult {
  readonly status: AuditDraftCollectionStatus;
  readonly draft?: AuditEventDraft;
  readonly removedDraft?: AuditEventDraft;
  readonly evictedDrafts?: readonly AuditEventDraft[];
  readonly collection: AuditDraftCollection;
  readonly reason?: string;
}

export interface AuditDraftCollector {
  addDraft(draft: AuditEventDraft): AuditDraftCollectionResult;
  removeDraft(eventDraftId: string): AuditDraftCollectionResult;
  clear(): AuditDraftCollectionResult;
  count(): number;
  getById(eventDraftId: string): AuditEventDraft | undefined;
  getAll(): readonly AuditEventDraft[];
  query(query: AuditDraftQuery): readonly AuditEventDraft[];
  filter(filter: AuditDraftFilter): readonly AuditEventDraft[];
}

export interface InMemoryAuditDraftCollectorOptions {
  readonly maxDraftCount?: number;
}

export function createAuditEventDraft(input: AuditEventDraftInput): AuditEventDraft {
  const sanitizedInput = sanitizeAuditEventDraftInput(input);
  const timestamp = sanitizedInput.timestamp ?? new Date().toISOString();
  const auditCorrelationId = sanitizedInput.auditCorrelationId
    ?? createAuditCorrelationId([
      sanitizedInput.applicationId ?? "runtime",
      sanitizedInput.sessionId ?? "",
      sanitizedInput.requestKind ?? "request",
      sanitizedInput.intentId
        ?? sanitizedInput.capabilityId
        ?? sanitizedInput.capability
        ?? "shape-validation",
      sanitizedInput.outcome
    ]);

  return {
    eventDraftId: `${auditCorrelationId}:draft`,
    timestamp,
    category: sanitizedInput.category,
    outcome: sanitizedInput.outcome,
    sessionId: sanitizedInput.sessionId,
    applicationId: sanitizedInput.applicationId,
    intentId: sanitizedInput.intentId,
    capabilityId: sanitizedInput.capabilityId,
    capability: sanitizedInput.capability,
    adapterId: sanitizedInput.adapterId,
    requestKind: sanitizedInput.requestKind,
    summary: sanitizedInput.summary,
    redactedDetails: sanitizedInput.redactedDetails,
    auditCorrelationId,
    persisted: false,
    encryptedByDefault: true
  };
}

function normalizeMaxDraftCount(maxDraftCount?: number): number {
  if (maxDraftCount === undefined) {
    return 100;
  }
  if (!Number.isFinite(maxDraftCount)) {
    return 100;
  }
  return Math.max(1, Math.floor(maxDraftCount));
}

function freezeDraft(draft: AuditEventDraft): AuditEventDraft {
  return Object.freeze({
    ...draft,
    redactedDetails: draft.redactedDetails
      ? Object.freeze({ ...draft.redactedDetails })
      : undefined
  });
}

function matchesFilter(draft: AuditEventDraft, filter: AuditDraftFilter): boolean {
  if (filter.category !== undefined && draft.category !== filter.category) return false;
  if (filter.outcome !== undefined && draft.outcome !== filter.outcome) return false;
  if (filter.sessionId !== undefined && draft.sessionId !== filter.sessionId) return false;
  if (filter.applicationId !== undefined && draft.applicationId !== filter.applicationId) return false;
  if (filter.intentId !== undefined && draft.intentId !== filter.intentId) return false;
  if (filter.capabilityId !== undefined && draft.capabilityId !== filter.capabilityId) return false;
  if (filter.capability !== undefined && draft.capability !== filter.capability) return false;
  if (filter.adapterId !== undefined && draft.adapterId !== filter.adapterId) return false;
  if (filter.requestKind !== undefined && draft.requestKind !== filter.requestKind) return false;
  if (
    filter.auditCorrelationId !== undefined
    && draft.auditCorrelationId !== filter.auditCorrelationId
  ) return false;
  if (filter.since !== undefined && draft.timestamp < filter.since) return false;
  if (filter.until !== undefined && draft.timestamp > filter.until) return false;
  return true;
}

export function createInMemoryAuditDraftCollector(
  options: InMemoryAuditDraftCollectorOptions = {}
): AuditDraftCollector {
  const maxDraftCount = normalizeMaxDraftCount(options.maxDraftCount);
  const drafts = new Map<string, AuditEventDraft>();

  function getAll(): readonly AuditEventDraft[] {
    return Object.freeze(Array.from(drafts.values()));
  }

  function collection(): AuditDraftCollection {
    return Object.freeze({
      drafts: getAll(),
      count: drafts.size,
      maxDraftCount
    });
  }

  function filterDrafts(filter: AuditDraftFilter): readonly AuditEventDraft[] {
    return Object.freeze(getAll().filter((draft) => matchesFilter(draft, filter)));
  }

  return {
    addDraft(draft) {
      if (drafts.has(draft.eventDraftId)) {
        return {
          status: "rejected_duplicate",
          draft: drafts.get(draft.eventDraftId),
          collection: collection(),
          reason: "Audit event draft IDs must be unique within an in-memory collector."
        };
      }

      const evictedDrafts: AuditEventDraft[] = [];
      if (drafts.size >= maxDraftCount) {
        const oldestDraftId = drafts.keys().next().value as string | undefined;
        if (oldestDraftId !== undefined) {
          const oldestDraft = drafts.get(oldestDraftId);
          drafts.delete(oldestDraftId);
          if (oldestDraft) {
            evictedDrafts.push(oldestDraft);
          }
        }
      }

      const storedDraft = freezeDraft(draft);
      drafts.set(storedDraft.eventDraftId, storedDraft);

      return {
        status: evictedDrafts.length > 0 ? "evicted_oldest" : "collected",
        draft: storedDraft,
        evictedDrafts: Object.freeze(evictedDrafts),
        collection: collection()
      };
    },
    removeDraft(eventDraftId) {
      const removedDraft = drafts.get(eventDraftId);
      if (!removedDraft) {
        return {
          status: "not_found",
          collection: collection(),
          reason: "No audit event draft with that ID exists in this in-memory collector."
        };
      }
      drafts.delete(eventDraftId);
      return {
        status: "removed",
        removedDraft,
        collection: collection()
      };
    },
    clear() {
      drafts.clear();
      return {
        status: "cleared",
        collection: collection()
      };
    },
    count() {
      return drafts.size;
    },
    getById(eventDraftId) {
      return drafts.get(eventDraftId);
    },
    getAll,
    query(query) {
      const offset = Math.max(0, Math.floor(query.offset ?? 0));
      const limit = query.limit === undefined
        ? undefined
        : Math.max(0, Math.floor(query.limit));
      const filtered = query.filter ? filterDrafts(query.filter) : getAll();
      const sliced = limit === undefined
        ? filtered.slice(offset)
        : filtered.slice(offset, offset + limit);
      return Object.freeze(sliced);
    },
    filter: filterDrafts
  };
}
