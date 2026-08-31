import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { keccak256, toUtf8Bytes } from "ethers";
import { UNLOCK_PROOF_TYPE, type Hex } from "../hashes.ts";
import {
  createAuditEventDraft,
  type AuditDraftCollectionResult,
  type AuditDraftCollector,
  type AuditEventDraft
} from "./audit.ts";
import {
  type FinalizedAuthorizationPackage,
  validateFinalizedAuthorizationPackageShape
} from "./actionUnlockProofFinalization.ts";
import {
  createAuditCorrelationId,
  runtimeDenied,
  runtimeOk,
  type RuntimeValidationResult
} from "./helpers.ts";
import type { RuntimeResult } from "./types.ts";

const FELT_MAX = (1n << 252n) - 1n;
const SELECTOR_MASK = (1n << 250n) - 1n;
const ENTRYPOINT = "verify_proof_input_hash_slice_and_send_to_l1";
const EXPECTED_PAYLOAD = "[fact_high, fact_low]";

export type StarknetFactPublicationStatus =
  | "transaction_draft_created"
  | "transaction_draft_rejected"
  | "transaction_draft_malformed";

export type StarknetFactPublicationOutcome =
  | "transaction_draft_created"
  | "publication_config_ineligible"
  | "artifact_binding_invalid"
  | "deployment_address_missing"
  | "account_model_unresolved"
  | "account_address_missing"
  | "entrypoint_mismatch"
  | "abi_mismatch"
  | "proof_payload_invalid"
  | "claim_payload_invalid"
  | "message_binding_invalid"
  | "l1_recipient_invalid"
  | "network_mismatch"
  | "calldata_encoding_failed"
  | "fee_estimate_unavailable"
  | "nonce_unresolved"
  | "resource_bounds_unresolved"
  | "expired"
  | "malformed"
  | "unsupported";

export type StarknetFactPublicationReason =
  | "ready_for_future_signing_review"
  | "configuration_rejected"
  | "artifact_revalidation_failed"
  | "proof_claim_correlation_failed"
  | "account_or_fee_boundary_unresolved"
  | "calldata_encoded";

export interface StarknetFactPublicationAccountReference {
  readonly accountModel: "permissionless_or_infrastructure_publisher";
  readonly accountAddress?: string;
  readonly accountAddressStatus: "resolved" | "unresolved";
  readonly signingAuthorityProvided: false;
  readonly externalExecutionDependency: true;
}

export interface StarknetFactPublicationResourceBounds {
  readonly status: "resolved" | "unresolved";
  readonly feeToken: string;
  readonly l1Gas?: string;
  readonly l1DataGas?: string;
  readonly l2Gas?: string;
  readonly maxOverallFee?: string;
  readonly freshness: "fixture" | "unresolved" | "read_only_estimate";
}

export interface StarknetFactPublicationFeeEstimateReference {
  readonly status: "estimated" | "unavailable" | "unresolved";
  readonly feeToken: string;
  readonly estimatedFee?: string;
  readonly source: "fixture" | "none";
  readonly freshUntil?: string;
}

export interface StarknetFactPublicationNonceReference {
  readonly status: "resolved" | "unresolved";
  readonly nonce?: string;
  readonly source: "fixture" | "none";
  readonly freshUntil?: string;
  readonly reservationCreated: false;
  readonly revalidateBeforeSigning: true;
}

export interface StarknetPublicationMessagePreview {
  readonly destinationL1Address: string;
  readonly senderStarknetContractAddress: string;
  readonly payloadLength: 2;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly messageEmitted: false;
  readonly messageAvailableOnL1: false;
  readonly messageConsumedOnL1: false;
}

export interface StarknetFactPublicationBinding {
  readonly finalizedAuthorizationPackageId: string;
  readonly proofInputHash: Hex;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly proofArgsSha256: string;
  readonly summarySha256: string;
  readonly configProfileId: string;
  readonly auditCorrelationId: string;
}

export interface StarknetFactPublicationCall {
  readonly contractAddress: string;
  readonly entrypoint: typeof ENTRYPOINT;
  readonly selector: string;
  readonly calldata: readonly string[];
  readonly calldataLength: number;
  readonly calldataHash: string;
  readonly fullCalldataExposedToApplications: false;
  readonly proofCalldataLogged: false;
}

export interface StarknetFactPublicationCalldataSummary {
  readonly l1Recipient: string;
  readonly proofArgumentFeltCount: number;
  readonly claimIncluded: true;
  readonly proofInputHash: Hex;
  readonly factHigh: Hex;
  readonly factLow: Hex;
  readonly calldataHash: string;
}

export type StarknetTransactionVersion = "3";
export type StarknetDataAvailabilityMode = "L1" | "L2" | "unresolved";

export interface StarknetResourceBoundsMapping {
  readonly l1Gas: StarknetFactPublicationResourceBounds;
  readonly l1DataGas: StarknetFactPublicationResourceBounds;
  readonly l2Gas: StarknetFactPublicationResourceBounds;
}

export interface StarknetAccountExecutionCall {
  readonly to: string;
  readonly selector: string;
  readonly calldata: readonly string[];
  readonly entrypoint: typeof ENTRYPOINT;
}

export interface StarknetAccountMulticallDraft {
  readonly calls: readonly StarknetAccountExecutionCall[];
  readonly callCount: 1;
}

export interface UnsignedStarknetInvokeTransaction {
  readonly transactionType: "INVOKE";
  readonly version: StarknetTransactionVersion;
  readonly senderAddress?: string;
  readonly senderAddressStatus: "resolved" | "unresolved";
  readonly nonce: StarknetFactPublicationNonceReference;
  readonly fee: StarknetFactPublicationFeeEstimateReference;
  readonly resourceBounds: StarknetFactPublicationResourceBounds;
  readonly accountMulticall: StarknetAccountMulticallDraft;
  readonly dataAvailabilityMode: StarknetDataAvailabilityMode;
  readonly signature: readonly [];
  readonly signable: false;
  readonly submittable: false;
}

export interface StarknetFactPublicationTransactionDraft {
  readonly starknetFactPublicationTransactionDraftId: string;
  readonly status: "transaction_draft_created";
  readonly outcome: "transaction_draft_created";
  readonly binding: StarknetFactPublicationBinding;
  readonly call: StarknetFactPublicationCall;
  readonly calldataSummary: StarknetFactPublicationCalldataSummary;
  readonly account: StarknetFactPublicationAccountReference;
  readonly unsignedInvokeTransaction: UnsignedStarknetInvokeTransaction;
  readonly messagePreview: StarknetPublicationMessagePreview;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly limitations: readonly StarknetFactPublicationLimitation[];
  readonly transactionPrepared: true;
  readonly transactionSigned: false;
  readonly transactionSubmitted: false;
  readonly factVerifiedOnStarknet: false;
  readonly l2ToL1MessageEmitted: false;
  readonly l1MessageConsumed: false;
  readonly chainStateMutated: false;
  readonly applicationExecutionAllowed: false;
  readonly auditEventDraft?: AuditEventDraft;
  readonly auditDraftCollectionResult?: AuditDraftCollectionResult;
  readonly collectionResult?: StarknetFactPublicationTransactionDraftCollectionResult;
}

export type StarknetFactPublicationLimitation =
  | "unsigned_draft_only"
  | "not_signable"
  | "not_submittable"
  | "fee_nonce_revalidation_required"
  | "deployment_configuration_must_match"
  | "no_l1_or_base_behavior"
  | "message_not_emitted";

export interface StarknetTransactionFeeEstimator {
  estimateFee(
    request: StarknetFeeEstimateRequest
  ): StarknetFeeEstimateResult;
}

export interface StarknetFeeEstimateRequest {
  readonly call: StarknetAccountExecutionCall;
  readonly accountAddress: string;
  readonly networkProfileId: string;
}

export interface StarknetFeeEstimateResult {
  readonly status: "estimated" | "unavailable" | "failed";
  readonly feeToken: string;
  readonly estimatedFee?: string;
  readonly l1Gas?: string;
  readonly l1DataGas?: string;
  readonly l2Gas?: string;
  readonly freshUntil?: string;
  readonly source: "fixture" | "none";
  readonly error?: string;
}

export interface StarknetNonceReader {
  readNonce(request: StarknetNonceReadRequest): StarknetNonceReadResult;
}

export interface StarknetNonceReadRequest {
  readonly accountAddress: string;
  readonly networkProfileId: string;
}

export interface StarknetNonceReadResult {
  readonly status: "resolved" | "unresolved" | "failed";
  readonly nonce?: string;
  readonly freshUntil?: string;
  readonly source: "fixture" | "none";
  readonly error?: string;
}

export interface StarknetFactPublicationPreparationRequest {
  readonly requestId: string;
  readonly finalizedAuthorizationPackage: FinalizedAuthorizationPackage;
  readonly publicationConfig: StarknetPublicationConfig;
  readonly readinessManifest: StarknetPublicationReadinessManifest;
  readonly proofInputHashSliceArgs: readonly string[];
  readonly proofInputHashSliceSummary: StarknetProofInputHashSliceSummary;
  readonly publicationContractAddress?: string;
  readonly l1Recipient?: string;
  readonly publisherAccountAddress?: string;
  readonly issueTime: string;
  readonly expiresAt: string;
  readonly auditCorrelationId?: string;
  readonly feeEstimator?: StarknetTransactionFeeEstimator;
  readonly nonceReader?: StarknetNonceReader;
  readonly draftStore?: StarknetFactPublicationTransactionDraftStore;
  readonly auditDraftCollector?: AuditDraftCollector;
}

export type StarknetFactPublicationPreparationResult =
  RuntimeResult<StarknetFactPublicationTransactionDraft>;

export interface StarknetPublicationConfig {
  readonly profileId: string;
  readonly artifactBinding: Readonly<Record<string, unknown>>;
  readonly publication: Readonly<Record<string, unknown>>;
  readonly l1RecipientBinding: Readonly<Record<string, unknown>>;
  readonly expectedL2SenderBinding: Readonly<Record<string, unknown>>;
  readonly accountCallerModel: Readonly<Record<string, unknown>>;
  readonly feeNonceModel: Readonly<Record<string, unknown>>;
  readonly networkProfiles: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
}

export interface StarknetPublicationReadinessManifest {
  readonly status: Readonly<Record<string, unknown>>;
  readonly package: Readonly<Record<string, unknown>>;
  readonly artifacts: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly messageShape: Readonly<Record<string, unknown>>;
  readonly toolchain: Readonly<Record<string, unknown>>;
}

export interface StarknetProofInputHashSliceSummary {
  readonly proofType: string;
  readonly version: string;
  readonly proofInputHash: Hex;
  readonly expectedFactPayload: readonly [Hex, Hex];
  readonly proofInputHashSliceProof?: Readonly<Record<string, unknown>>;
}

export type StarknetFactPublicationTransactionDraftCollectionStatus =
  | "collected"
  | "evicted_oldest"
  | "rejected_duplicate"
  | "removed"
  | "not_found"
  | "cleared";

export interface StarknetFactPublicationTransactionDraftCollectionResult {
  readonly status: StarknetFactPublicationTransactionDraftCollectionStatus;
  readonly draft?: StarknetFactPublicationTransactionDraft;
  readonly removedDraft?: StarknetFactPublicationTransactionDraft;
  readonly evictedDrafts?: readonly StarknetFactPublicationTransactionDraft[];
  readonly collection: {
    readonly drafts: readonly StarknetFactPublicationTransactionDraft[];
    readonly count: number;
    readonly maxDraftCount: number;
  };
}

export interface StarknetFactPublicationTransactionDraftStore {
  addDraft(draft: StarknetFactPublicationTransactionDraft): StarknetFactPublicationTransactionDraftCollectionResult;
  removeDraft(draftId: string): StarknetFactPublicationTransactionDraftCollectionResult;
  clear(): StarknetFactPublicationTransactionDraftCollectionResult;
  count(): number;
  getById(draftId: string): StarknetFactPublicationTransactionDraft | undefined;
  getAll(): readonly StarknetFactPublicationTransactionDraft[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function validation(errors: string[]): RuntimeValidationResult {
  return { valid: errors.length === 0, errors };
}

function normalizeHex(value: string): string {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.replace(/^0+/, "") || "0";
  return `0x${normalized.toLowerCase()}`;
}

function isFelt(value: unknown): value is string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]+$/.test(value)) return false;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n && parsed <= FELT_MAX;
  } catch {
    return false;
  }
}

function isNonZeroFelt(value: unknown): value is string {
  return isFelt(value) && BigInt(value) !== 0n;
}

function isHex32(value: unknown): value is Hex {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sha256Json(value: unknown): string {
  return sha256Text(JSON.stringify(value));
}

function sha256FixtureJson(value: unknown): string {
  return sha256Text(JSON.stringify(value, null, 2));
}

function sha256File(repoRoot: string, relativePath: string): string | undefined {
  const fullPath = join(repoRoot, relativePath);
  if (!existsSync(fullPath)) return undefined;
  return createHash("sha256").update(readFileSync(fullPath)).digest("hex");
}

export function deriveStarknetSelector(entrypoint: string): string {
  const hash = BigInt(keccak256(toUtf8Bytes(entrypoint)));
  return `0x${(hash & SELECTOR_MASK).toString(16)}`;
}

export function encodeStarknetFactPublicationCalldata(
  l1Recipient: string,
  proofInputHashSliceArgs: readonly string[]
): readonly string[] {
  return Object.freeze([
    normalizeHex(l1Recipient),
    ...proofInputHashSliceArgs.map((arg) => normalizeHex(arg))
  ]);
}

export function validateStarknetFactPublicationPreparationRequest(
  request: StarknetFactPublicationPreparationRequest,
  repoRoot = process.cwd()
): RuntimeValidationResult {
  const errors: string[] = [];
  const packageShape = validateFinalizedAuthorizationPackageShape(
    request.finalizedAuthorizationPackage
  );
  errors.push(...packageShape.errors);

  if (!request.requestId) errors.push("requestId is required");
  if (Number.isNaN(Date.parse(request.issueTime))) errors.push("issueTime must be a date");
  if (Number.isNaN(Date.parse(request.expiresAt))) errors.push("expiresAt must be a date");
  if (Date.parse(request.expiresAt) <= Date.parse(request.issueTime)) {
    errors.push("expiresAt must be after issueTime");
  }
  if (Date.now() > Date.parse(request.expiresAt)) errors.push("preparation request expired");

  const config = request.publicationConfig;
  const readiness = request.readinessManifest;
  const binding = config.artifactBinding;
  const publication = config.publication;
  const messageShape = isRecord(publication.messageShape)
    ? publication.messageShape
    : undefined;
  const profile = config.networkProfiles?.[config.profileId];

  if (!profile) errors.push("network profile missing");
  if (profile && profile.enabled !== true) errors.push("network profile is not enabled");
  if (profile && profile.usableForTransactionPreparation !== true) {
    errors.push("network profile is not usable for transaction preparation");
  }
  if (profile && profile.publicationContractDeploymentStatus !== "deployed") {
    errors.push("publication contract is not deployed");
  }

  const expectedArtifacts: readonly [string, string, string][] = [
    ["sierra", "sierraPath", "sierraSha256"],
    ["casm", "compiledClassPath", "compiledClassSha256"],
    ["packageSierra", "packageSierraPath", "packageSierraSha256"],
    ["starknetArtifacts", "starknetArtifactsPath", "starknetArtifactsSha256"]
  ];
  for (const [manifestKey, pathKey, hashKey] of expectedArtifacts) {
    const manifestArtifact = readiness.artifacts[manifestKey];
    if (!manifestArtifact) {
      errors.push(`${manifestKey} missing from readiness manifest`);
      continue;
    }
    if (binding[pathKey] !== manifestArtifact.path) {
      errors.push(`${pathKey} mismatch`);
    }
    if (binding[hashKey] !== manifestArtifact.sha256) {
      errors.push(`${hashKey} mismatch`);
    }
    if (
      typeof binding[pathKey] === "string"
      && sha256File(repoRoot, binding[pathKey]) !== binding[hashKey]
    ) {
      errors.push(`${hashKey} does not match artifact file`);
    }
  }

  if (binding.packageName !== readiness.package.name) errors.push("package name mismatch");
  if (binding.contractName !== readiness.package.contractName) errors.push("contract name mismatch");
  if (binding.entrypoint !== ENTRYPOINT || readiness.package.entrypoint !== ENTRYPOINT) {
    errors.push("entrypoint mismatch");
  }
  const selector = deriveStarknetSelector(ENTRYPOINT);
  if (binding.entrypointSelector !== selector) errors.push("entrypoint selector mismatch");
  if (typeof binding.abiSha256 !== "string" || typeof binding.entrypointAbiSha256 !== "string") {
    errors.push("abi hash missing");
  }
  if (typeof binding.starknetClassHash !== "string" || !isFelt(binding.starknetClassHash)) {
    errors.push("starknet class hash missing");
  }
  if (typeof binding.compiledClassHash !== "string" || !isFelt(binding.compiledClassHash)) {
    errors.push("compiled class hash missing");
  }
  if (typeof binding.sierraPath === "string" && existsSync(join(repoRoot, binding.sierraPath))) {
    const contractClass = JSON.parse(readFileSync(join(repoRoot, binding.sierraPath), "utf8")) as {
      abi?: unknown[];
    };
    if (sha256Json(contractClass.abi) !== binding.abiSha256) errors.push("abi hash mismatch");
    const entrypoint = contractClass.abi?.find((item) =>
      isRecord(item) && item.type === "function" && item.name === ENTRYPOINT
    );
    if (!entrypoint) {
      errors.push("entrypoint missing from abi");
    } else if (sha256Json(entrypoint) !== binding.entrypointAbiSha256) {
      errors.push("entrypoint abi hash mismatch");
    }
  }
  if (publication.proofType !== UNLOCK_PROOF_TYPE) errors.push("proof type mismatch");
  if (messageShape?.payload !== EXPECTED_PAYLOAD) errors.push("message shape mismatch");
  if (JSON.stringify(messageShape?.l2ToL1PayloadOrdering) !== JSON.stringify(["fact_high", "fact_low"])) {
    errors.push("high/low ordering mismatch");
  }

  const l1Recipient =
    request.l1Recipient
    ?? (config.l1RecipientBinding.configuredL1RecipientAddress as string | undefined);
  if (!isNonZeroFelt(l1Recipient)) errors.push("l1 recipient invalid or missing");

  const publicationAddress =
    request.publicationContractAddress
    ?? (config.expectedL2SenderBinding.publicationContractAddress as string | undefined);
  if (!isNonZeroFelt(publicationAddress)) errors.push("deployment address missing");

  const accountModel = config.accountCallerModel;
  if (accountModel.recommendedModel !== "permissionless_or_infrastructure_publisher") {
    errors.push("account model unsupported");
  }
  if (accountModel.status !== "resolved") errors.push("account model unresolved");
  const accountAddress = request.publisherAccountAddress ?? (accountModel.accountAddress as string | undefined);
  if (!isNonZeroFelt(accountAddress)) errors.push("account address missing");

  if (!Array.isArray(request.proofInputHashSliceArgs) || request.proofInputHashSliceArgs.length === 0) {
    errors.push("proof args missing");
  }
  if (!request.proofInputHashSliceArgs.every(isFelt)) errors.push("proof args contain non-felt value");
  const argsHash = sha256FixtureJson(request.proofInputHashSliceArgs);
  const readinessArgsHash = readiness.artifacts.proofInputHashSliceArgs?.sha256;
  if (argsHash !== readinessArgsHash) errors.push("proof args hash mismatch");

  const summary = request.proofInputHashSliceSummary;
  const finalized = request.finalizedAuthorizationPackage;
  if (summary.proofType !== UNLOCK_PROOF_TYPE) errors.push("summary proof type mismatch");
  if (!isHex32(summary.proofInputHash)) errors.push("summary proofInputHash invalid");
  if (summary.proofInputHash !== finalized.actionUnlockAuthorization?.proofInputHash) {
    errors.push("proofInputHash mismatch");
  }
  if (summary.expectedFactPayload?.[0] !== finalized.factShapePreview?.factHigh) {
    errors.push("fact high mismatch");
  }
  if (summary.expectedFactPayload?.[1] !== finalized.factShapePreview?.factLow) {
    errors.push("fact low mismatch");
  }
  if (JSON.stringify(summary.expectedFactPayload) !== JSON.stringify(readiness.messageShape.expectedFactPayload)) {
    errors.push("message binding mismatch");
  }
  if (messageShape?.proofInputHash !== summary.proofInputHash) {
    errors.push("config proofInputHash mismatch");
  }

  return validation(errors);
}

function outcomeForErrors(errors: readonly string[]): StarknetFactPublicationOutcome {
  const joined = errors.join(" | ");
  if (joined.includes("deployment address")) return "deployment_address_missing";
  if (joined.includes("account address")) return "account_address_missing";
  if (joined.includes("account model")) return "account_model_unresolved";
  if (joined.includes("l1 recipient")) return "l1_recipient_invalid";
  if (joined.includes("entrypoint")) return "entrypoint_mismatch";
  if (joined.includes("abi")) return "abi_mismatch";
  if (joined.includes("proof args")) return "proof_payload_invalid";
  if (joined.includes("proofInputHash")) return "claim_payload_invalid";
  if (joined.includes("fact") || joined.includes("message")) return "message_binding_invalid";
  if (joined.includes("network") || joined.includes("profile")) return "network_mismatch";
  if (joined.includes("artifact") || joined.includes("hash")) return "artifact_binding_invalid";
  if (joined.includes("expired")) return "expired";
  return "malformed";
}

function createPreparationAuditDraft(
  input: {
    request: StarknetFactPublicationPreparationRequest;
    outcome: StarknetFactPublicationOutcome;
    errors?: readonly string[];
    calldataHash?: string;
  }
): AuditEventDraft {
  return createAuditEventDraft({
    category: "authorization_request",
    outcome: input.outcome === "transaction_draft_created"
      ? "validation_succeeded"
      : "validation_failed",
    requestKind: "requestStarknetFactPublicationTransactionPreparation",
    applicationId: input.request.finalizedAuthorizationPackage.binding.applicationId,
    sessionId: input.request.finalizedAuthorizationPackage.binding.sessionId,
    summary: input.outcome === "transaction_draft_created"
      ? "Unsigned Starknet fact-publication transaction draft created."
      : "Unsigned Starknet fact-publication transaction preparation rejected.",
    auditCorrelationId: input.request.auditCorrelationId,
    redactedDetails: {
      outcome: input.outcome,
      errors: input.errors,
      packageId: input.request.finalizedAuthorizationPackage.finalizedAuthorizationPackageId,
      entrypoint: ENTRYPOINT,
      calldataHash: input.calldataHash,
      proofInputHash: input.request.proofInputHashSliceSummary.proofInputHash,
      factPair: input.request.proofInputHashSliceSummary.expectedFactPayload
    }
  });
}

export function validateStarknetFactPublicationTransactionDraft(
  draft: unknown
): RuntimeValidationResult {
  const errors: string[] = [];
  if (!isRecord(draft)) return validation(["draft must be an object"]);
  if (draft.status !== "transaction_draft_created") errors.push("status mismatch");
  for (const field of [
    "transactionPrepared"
  ]) {
    if (draft[field] !== true) errors.push(`${field} must be true`);
  }
  for (const field of [
    "transactionSigned",
    "transactionSubmitted",
    "factVerifiedOnStarknet",
    "l2ToL1MessageEmitted",
    "l1MessageConsumed",
    "chainStateMutated",
    "applicationExecutionAllowed"
  ]) {
    if (draft[field] !== false) errors.push(`${field} must be false`);
  }
  return validation(errors);
}

export function isStarknetFactPublicationStatus(
  value: unknown
): value is StarknetFactPublicationStatus {
  return value === "transaction_draft_created"
    || value === "transaction_draft_rejected"
    || value === "transaction_draft_malformed";
}

export function isStarknetFactPublicationOutcome(
  value: unknown
): value is StarknetFactPublicationOutcome {
  return typeof value === "string" && [
    "transaction_draft_created",
    "publication_config_ineligible",
    "artifact_binding_invalid",
    "deployment_address_missing",
    "account_model_unresolved",
    "account_address_missing",
    "entrypoint_mismatch",
    "abi_mismatch",
    "proof_payload_invalid",
    "claim_payload_invalid",
    "message_binding_invalid",
    "l1_recipient_invalid",
    "network_mismatch",
    "calldata_encoding_failed",
    "fee_estimate_unavailable",
    "nonce_unresolved",
    "resource_bounds_unresolved",
    "expired",
    "malformed",
    "unsupported"
  ].includes(value);
}

export function prepareStarknetFactPublicationTransaction(
  request: StarknetFactPublicationPreparationRequest,
  repoRoot = process.cwd()
): StarknetFactPublicationPreparationResult {
  const validationResult = validateStarknetFactPublicationPreparationRequest(request, repoRoot);
  if (!validationResult.valid) {
    const outcome = outcomeForErrors(validationResult.errors);
    const auditEventDraft = createPreparationAuditDraft({
      request,
      outcome,
      errors: validationResult.errors
    });
    request.auditDraftCollector?.addDraft(auditEventDraft);
    return runtimeDenied({
      code: "STARKNET_FACT_PUBLICATION_PREPARATION_REJECTED",
      category: "unsupported_operation",
      message: "Starknet fact-publication transaction preparation was rejected.",
      recoverable: true,
      details: {
        outcome,
        errors: validationResult.errors,
        auditEventId: auditEventDraft.eventDraftId
      }
    });
  }

  const config = request.publicationConfig;
  const l1Recipient = request.l1Recipient
    ?? config.l1RecipientBinding.configuredL1RecipientAddress as string;
  const contractAddress = request.publicationContractAddress
    ?? config.expectedL2SenderBinding.publicationContractAddress as string;
  const accountAddress = request.publisherAccountAddress
    ?? config.accountCallerModel.accountAddress as string;
  const profile = config.networkProfiles[config.profileId];
  const selector = deriveStarknetSelector(ENTRYPOINT);
  const calldata = encodeStarknetFactPublicationCalldata(
    l1Recipient,
    request.proofInputHashSliceArgs
  );
  const calldataHash = sha256Json(calldata);
  const call: StarknetAccountExecutionCall = Object.freeze({
    to: normalizeHex(contractAddress),
    selector,
    calldata,
    entrypoint: ENTRYPOINT
  });

  const nonceRead = request.nonceReader?.readNonce({
    accountAddress,
    networkProfileId: config.profileId
  }) ?? { status: "unresolved" as const, source: "none" as const };
  const feeEstimate: StarknetFeeEstimateResult = request.feeEstimator?.estimateFee({
    call,
    accountAddress,
    networkProfileId: config.profileId
  }) ?? {
    status: "unavailable",
    feeToken: String(config.feeNonceModel.feeToken ?? "unresolved"),
    source: "none"
  };
  const nonce: StarknetFactPublicationNonceReference = Object.freeze({
    status: nonceRead.status === "resolved" ? "resolved" : "unresolved",
    nonce: nonceRead.nonce,
    source: nonceRead.source,
    freshUntil: nonceRead.freshUntil,
    reservationCreated: false,
    revalidateBeforeSigning: true
  });
  const fee: StarknetFactPublicationFeeEstimateReference = Object.freeze({
    status: feeEstimate.status === "estimated" ? "estimated" : "unresolved",
    feeToken: feeEstimate.feeToken,
    estimatedFee: feeEstimate.estimatedFee,
    source: feeEstimate.source,
    freshUntil: feeEstimate.freshUntil
  });
  const resourceBounds: StarknetFactPublicationResourceBounds = Object.freeze({
    status: fee.status === "estimated" ? "resolved" : "unresolved",
    feeToken: fee.feeToken,
    l1Gas: feeEstimate.l1Gas,
    l1DataGas: feeEstimate.l1DataGas,
    l2Gas: feeEstimate.l2Gas,
    maxOverallFee: fee.estimatedFee,
    freshness: fee.status === "estimated" ? "fixture" : "unresolved"
  });

  const auditCorrelationId = request.auditCorrelationId
    ?? createAuditCorrelationId([
      request.requestId,
      request.finalizedAuthorizationPackage.finalizedAuthorizationPackageId,
      "starknet-publication-preparation"
    ]);
  const draftBase = {
    starknetFactPublicationTransactionDraftId: createAuditCorrelationId([
      auditCorrelationId,
      calldataHash,
      "unsigned-starknet-invoke"
    ]),
    status: "transaction_draft_created" as const,
    outcome: "transaction_draft_created" as const,
    binding: {
      finalizedAuthorizationPackageId:
        request.finalizedAuthorizationPackage.finalizedAuthorizationPackageId,
      proofInputHash: request.proofInputHashSliceSummary.proofInputHash,
      factHigh: request.proofInputHashSliceSummary.expectedFactPayload[0],
      factLow: request.proofInputHashSliceSummary.expectedFactPayload[1],
      proofArgsSha256: sha256FixtureJson(request.proofInputHashSliceArgs),
      summarySha256: sha256FixtureJson(request.proofInputHashSliceSummary),
      configProfileId: config.profileId,
      auditCorrelationId
    },
    call: {
      contractAddress: normalizeHex(contractAddress),
      entrypoint: ENTRYPOINT as typeof ENTRYPOINT,
      selector,
      calldata,
      calldataLength: calldata.length,
      calldataHash,
      fullCalldataExposedToApplications: false as const,
      proofCalldataLogged: false as const
    },
    calldataSummary: {
      l1Recipient: normalizeHex(l1Recipient),
      proofArgumentFeltCount: request.proofInputHashSliceArgs.length,
      claimIncluded: true as const,
      proofInputHash: request.proofInputHashSliceSummary.proofInputHash,
      factHigh: request.proofInputHashSliceSummary.expectedFactPayload[0],
      factLow: request.proofInputHashSliceSummary.expectedFactPayload[1],
      calldataHash
    },
    account: {
      accountModel: "permissionless_or_infrastructure_publisher" as const,
      accountAddress: normalizeHex(accountAddress),
      accountAddressStatus: "resolved" as const,
      signingAuthorityProvided: false as const,
      externalExecutionDependency: true as const
    },
    unsignedInvokeTransaction: {
      transactionType: "INVOKE" as const,
      version: "3" as const,
      senderAddress: normalizeHex(accountAddress),
      senderAddressStatus: "resolved" as const,
      nonce,
      fee,
      resourceBounds,
      accountMulticall: {
        calls: [call],
        callCount: 1 as const
      },
      dataAvailabilityMode: "unresolved" as const,
      signature: [] as const,
      signable: false as const,
      submittable: false as const
    },
    messagePreview: {
      destinationL1Address: normalizeHex(l1Recipient),
      senderStarknetContractAddress: normalizeHex(contractAddress),
      payloadLength: 2 as const,
      factHigh: request.proofInputHashSliceSummary.expectedFactPayload[0],
      factLow: request.proofInputHashSliceSummary.expectedFactPayload[1],
      messageEmitted: false as const,
      messageAvailableOnL1: false as const,
      messageConsumedOnL1: false as const
    },
    issuedAt: request.issueTime,
    expiresAt: request.expiresAt,
    limitations: [
      "unsigned_draft_only",
      "not_signable",
      "not_submittable",
      "fee_nonce_revalidation_required",
      "deployment_configuration_must_match",
      "no_l1_or_base_behavior",
      "message_not_emitted"
    ] as const,
    transactionPrepared: true as const,
    transactionSigned: false as const,
    transactionSubmitted: false as const,
    factVerifiedOnStarknet: false as const,
    l2ToL1MessageEmitted: false as const,
    l1MessageConsumed: false as const,
    chainStateMutated: false as const,
    applicationExecutionAllowed: false as const
  };

  const auditEventDraft = createPreparationAuditDraft({
    request: {
      ...request,
      auditCorrelationId
    },
    outcome: "transaction_draft_created",
    calldataHash
  });
  const auditDraftCollectionResult = request.auditDraftCollector?.addDraft(auditEventDraft);
  const draft: StarknetFactPublicationTransactionDraft = Object.freeze({
    ...draftBase,
    auditEventDraft,
    auditDraftCollectionResult
  });
  const collectionResult = request.draftStore?.addDraft(draft);
  return runtimeOk(Object.freeze({
    ...draft,
    collectionResult
  }));
}

export const requestStarknetFactPublicationTransactionPreparation =
  prepareStarknetFactPublicationTransaction;

function freezeDraft(draft: StarknetFactPublicationTransactionDraft): StarknetFactPublicationTransactionDraft {
  return Object.freeze({
    ...draft,
    call: Object.freeze({
      ...draft.call,
      calldata: Object.freeze([...draft.call.calldata])
    }),
    unsignedInvokeTransaction: Object.freeze({
      ...draft.unsignedInvokeTransaction,
      signature: Object.freeze([]) as readonly [],
      accountMulticall: Object.freeze({
        calls: Object.freeze([...draft.unsignedInvokeTransaction.accountMulticall.calls]),
        callCount: 1
      })
    })
  });
}

export function createInMemoryStarknetFactPublicationTransactionDraftStore(
  options: { readonly maxDraftCount?: number } = {}
): StarknetFactPublicationTransactionDraftStore {
  const maxDraftCount = Math.max(1, Math.floor(options.maxDraftCount ?? 25));
  const drafts = new Map<string, StarknetFactPublicationTransactionDraft>();

  function collection() {
    return Object.freeze({
      drafts: Object.freeze(Array.from(drafts.values()).map(freezeDraft)),
      count: drafts.size,
      maxDraftCount
    });
  }

  return {
    addDraft(draft) {
      if (drafts.has(draft.starknetFactPublicationTransactionDraftId)) {
        return {
          status: "rejected_duplicate",
          draft: freezeDraft(draft),
          collection: collection()
        };
      }
      const evictedDrafts: StarknetFactPublicationTransactionDraft[] = [];
      while (drafts.size >= maxDraftCount) {
        const firstKey = drafts.keys().next().value as string | undefined;
        if (!firstKey) break;
        const evicted = drafts.get(firstKey);
        drafts.delete(firstKey);
        if (evicted) evictedDrafts.push(evicted);
      }
      drafts.set(draft.starknetFactPublicationTransactionDraftId, freezeDraft(draft));
      return {
        status: evictedDrafts.length > 0 ? "evicted_oldest" : "collected",
        draft: freezeDraft(draft),
        evictedDrafts: Object.freeze(evictedDrafts.map(freezeDraft)),
        collection: collection()
      };
    },
    removeDraft(draftId) {
      const removedDraft = drafts.get(draftId);
      drafts.delete(draftId);
      return {
        status: removedDraft ? "removed" : "not_found",
        removedDraft: removedDraft ? freezeDraft(removedDraft) : undefined,
        collection: collection()
      };
    },
    clear() {
      drafts.clear();
      return { status: "cleared", collection: collection() };
    },
    count() {
      return drafts.size;
    },
    getById(draftId) {
      const draft = drafts.get(draftId);
      return draft ? freezeDraft(draft) : undefined;
    },
    getAll() {
      return collection().drafts;
    }
  };
}

export function createFixtureStarknetTransactionFeeEstimator(
  estimate: Omit<StarknetFeeEstimateResult, "status" | "source">
): StarknetTransactionFeeEstimator {
  return {
    estimateFee() {
      return {
        ...estimate,
        status: "estimated",
        source: "fixture"
      };
    }
  };
}

export function createUnavailableStarknetTransactionFeeEstimator(
  error = "fee unavailable"
): StarknetTransactionFeeEstimator {
  return {
    estimateFee() {
      return {
        status: "failed",
        feeToken: "unresolved",
        source: "none",
        error
      };
    }
  };
}

export function createFixtureStarknetNonceReader(
  nonce: string,
  freshUntil?: string
): StarknetNonceReader {
  return {
    readNonce() {
      return {
        status: "resolved",
        nonce,
        freshUntil,
        source: "fixture"
      };
    }
  };
}
