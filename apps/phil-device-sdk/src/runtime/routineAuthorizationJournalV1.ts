import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { AbiCoder, getAddress, getBytes, hexlify, keccak256, toUtf8Bytes, type BytesLike } from "ethers";

import type { Hex } from "../hashes.ts";
import {
  derivePhilOfficialUserOperationHashV07,
  parsePhilStrictJsonObjectV1,
  validatePhilRoutineAuthorizationRequestV1,
  verifyPhilRoutineAuthorizationReceiptV1,
  verifyPhilRoutineAuthorizationResponseV1,
  type PhilRoutineAuthorizationReceiptV1,
  type PhilRoutineAuthorizationRequestV1,
  type PhilRoutineAuthorizationResponseV1,
  type PhilRoutineReceiptLogV1
} from "../routineAuthorizationV1.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const PHIL_ZERO_BYTES32 = `0x${"00".repeat(32)}` as Hex;
export const PHIL_ROUTINE_JOURNAL_RECORD_V1_HASH = keccak256(
  toUtf8Bytes("PHIL_ROUTINE_JOURNAL_RECORD_V1")
) as Hex;
export const PHIL_ROUTINE_JOURNAL_FRAME_AAD_V1_HASH = keccak256(
  toUtf8Bytes("PHIL_ROUTINE_JOURNAL_FRAME_AAD_V1")
) as Hex;
export const PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS =
  "0x0000000000000000000000000000000000000000" as const;

export const PHIL_ROUTINE_PHONE_REJECTED_V1_HASH = keccak256(toUtf8Bytes("PHIL_ROUTINE_PHONE_REJECTED_V1")) as Hex;

export const PHIL_ROUTINE_JOURNAL_STATE_V1 = Object.freeze({
  REQUEST_CREATED: 1,
  TRANSPORT_WAITING: 2,
  DEVICE_APPROVED: 3,
  RESPONSE_VERIFIED: 4,
  SIMULATION_PASSED: 5,
  SUBMISSION_COMMITTED: 6,
  SUBMITTED: 7,
  RECEIPT_VERIFIED: 8,
  COMPLETED: 9,
  CANCELLED: 20,
  EXPIRED: 21,
  FAILED_PRE_SUBMISSION: 22,
  FAILED_EXECUTION: 23,
  RECEIPT_INVALID: 24,
  SUBMISSION_OUTCOME_UNKNOWN: 25
} as const);

export type PhilRoutineJournalStateV1 =
  typeof PHIL_ROUTINE_JOURNAL_STATE_V1[keyof typeof PHIL_ROUTINE_JOURNAL_STATE_V1];

export interface PhilRoutineJournalRecordV1 {
  readonly formatVersionHash: Hex;
  readonly generation: string;
  readonly previousRecordHash: Hex;
  readonly requestId: Hex;
  readonly sessionId: Hex;
  readonly state: PhilRoutineJournalStateV1;
  readonly entryPoint: string;
  readonly sender: string;
  readonly userOperationNonce: string;
  readonly serializedUserOperationHash: Hex;
  readonly officialUserOperationHash: Hex;
  readonly packedUserOperationBytes: Hex;
  readonly target: string;
  readonly targetRecordedValueBefore: Hex;
  readonly targetRecordedSequenceBefore: string;
  readonly targetPreStateHash: Hex;
  readonly scanStartBlockNumber: string;
  readonly scanStartBlockHash: Hex;
  readonly localTransactionHash: Hex;
  readonly localBlockHash: Hex;
  readonly receiptHash: Hex;
  readonly recordedAt: string;
  readonly reasonHash: Hex;
  readonly recordHash: Hex;
}

export interface PhilRoutineJournalFrameV1 {
  readonly version: 1;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export class PhilRoutineAuthorizationJournalV1Error extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PhilRoutineAuthorizationJournalV1Error";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PhilRoutineAuthorizationJournalV1Error(code, message);
}

function b32(value: BytesLike, label: string, zero = true): Hex {
  let normalized: Hex;
  try { normalized = hexlify(value).toLowerCase() as Hex; }
  catch { return fail("PHIL_ROUTINE_JOURNAL_BYTES32_INVALID", `${label} must be bytes32`); }
  if (getBytes(normalized).length !== 32 || (!zero && normalized === PHIL_ZERO_BYTES32)) {
    fail("PHIL_ROUTINE_JOURNAL_BYTES32_INVALID", `${label} must be ${zero ? "" : "non-zero "}bytes32`);
  }
  return normalized;
}

function address(value: string, label: string, zero = true): string {
  try {
    const normalized = getAddress(value).toLowerCase();
    if (!zero && normalized === PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS) throw new Error("zero");
    return normalized;
  } catch { return fail("PHIL_ROUTINE_JOURNAL_ADDRESS_INVALID", `${label} must be an EVM address`); }
}

function uint(value: string | number | bigint, bits: 64 | 256, label: string, positive = false): string {
  let parsed: bigint;
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new Error("unsafe");
    if (typeof value === "string" && !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error("noncanonical");
    parsed = BigInt(value);
  } catch { return fail("PHIL_ROUTINE_JOURNAL_UNSIGNED_INVALID", `${label} must be canonical uint${bits}`); }
  if (parsed < 0n || parsed >= (1n << BigInt(bits)) || (positive && parsed === 0n)) {
    fail("PHIL_ROUTINE_JOURNAL_UNSIGNED_INVALID", `${label} must fit uint${bits}`);
  }
  return parsed.toString();
}

function packed(value: BytesLike): Hex {
  let normalized: Hex;
  try { normalized = hexlify(value).toLowerCase() as Hex; }
  catch { return fail("PHIL_ROUTINE_JOURNAL_PACKED_OPERATION_INVALID", "packed operation must be bytes"); }
  return normalized;
}

function state(value: number): PhilRoutineJournalStateV1 {
  if (!Object.values(PHIL_ROUTINE_JOURNAL_STATE_V1).includes(value as PhilRoutineJournalStateV1)) {
    fail("PHIL_ROUTINE_JOURNAL_STATE_INVALID", "journal state is unsupported");
  }
  return value as PhilRoutineJournalStateV1;
}

const publicTransitions = new Map<PhilRoutineJournalStateV1, readonly PhilRoutineJournalStateV1[]>([
  [1,[2,20,21,22]], [2,[3,4,20,21,22]], [3,[4,20,21,22]], [4,[5,20,21,22]],
  [5,[6,20,21,22]], [6,[7,25]], [7,[25]]
]);
const verifiedTransitions = new Map<PhilRoutineJournalStateV1, readonly PhilRoutineJournalStateV1[]>([
  [6,[8,23,25]], [7,[8,23,24,25]], [8,[9]], [25,[8,23]]
]);

function normalize(input: Omit<PhilRoutineJournalRecordV1,"recordHash">): Omit<PhilRoutineJournalRecordV1,"recordHash"> {
  return Object.freeze({
    formatVersionHash:b32(input.formatVersionHash,"formatVersionHash"),generation:uint(input.generation,64,"generation",true),
    previousRecordHash:b32(input.previousRecordHash,"previousRecordHash"),requestId:b32(input.requestId,"requestId",false),
    sessionId:b32(input.sessionId,"sessionId",false),state:state(input.state),entryPoint:address(input.entryPoint,"entryPoint"),
    sender:address(input.sender,"sender"),userOperationNonce:uint(input.userOperationNonce,256,"userOperationNonce"),
    serializedUserOperationHash:b32(input.serializedUserOperationHash,"serializedUserOperationHash"),
    officialUserOperationHash:b32(input.officialUserOperationHash,"officialUserOperationHash"),
    packedUserOperationBytes:packed(input.packedUserOperationBytes),target:address(input.target,"target"),
    targetRecordedValueBefore:b32(input.targetRecordedValueBefore,"targetRecordedValueBefore"),
    targetRecordedSequenceBefore:uint(input.targetRecordedSequenceBefore,64,"targetRecordedSequenceBefore"),
    targetPreStateHash:b32(input.targetPreStateHash,"targetPreStateHash"),
    scanStartBlockNumber:uint(input.scanStartBlockNumber,64,"scanStartBlockNumber"),
    scanStartBlockHash:b32(input.scanStartBlockHash,"scanStartBlockHash"),
    localTransactionHash:b32(input.localTransactionHash,"localTransactionHash"),localBlockHash:b32(input.localBlockHash,"localBlockHash"),
    receiptHash:b32(input.receiptHash,"receiptHash"),recordedAt:uint(input.recordedAt,64,"recordedAt",true),
    reasonHash:b32(input.reasonHash,"reasonHash")
  });
}

export function derivePhilRoutineTargetPreStateHashV1(input: {
  readonly target: string; readonly approvedTargetRuntimeCodeHash: BytesLike;
  readonly recordedValueBefore: BytesLike; readonly recordedSequenceBefore: string | number | bigint;
  readonly scanStartBlockNumber: string | number | bigint; readonly scanStartBlockHash: BytesLike;
}): Hex {
  return keccak256(abiCoder.encode(["address","bytes32","bytes32","uint64","uint64","bytes32"],
    [address(input.target,"target",false),b32(input.approvedTargetRuntimeCodeHash,"approvedTargetRuntimeCodeHash",false),
      b32(input.recordedValueBefore,"recordedValueBefore"),BigInt(uint(input.recordedSequenceBefore,64,"recordedSequenceBefore")),
      BigInt(uint(input.scanStartBlockNumber,64,"scanStartBlockNumber")),b32(input.scanStartBlockHash,"scanStartBlockHash",false)])) as Hex;
}

export function derivePhilRoutineJournalRecordHashV1(
  input: Omit<PhilRoutineJournalRecordV1,"recordHash">
): Hex {
  const r=normalize(input);
  return keccak256(abiCoder.encode(
    ["bytes32","uint64","bytes32","bytes32","bytes32","uint8","address","address","uint256","bytes32","bytes32","bytes","address","bytes32","uint64","bytes32","uint64","bytes32","bytes32","bytes32","bytes32","uint64","bytes32"],
    [r.formatVersionHash,BigInt(r.generation),r.previousRecordHash,r.requestId,r.sessionId,r.state,r.entryPoint,r.sender,
      BigInt(r.userOperationNonce),r.serializedUserOperationHash,r.officialUserOperationHash,r.packedUserOperationBytes,
      r.target,r.targetRecordedValueBefore,BigInt(r.targetRecordedSequenceBefore),r.targetPreStateHash,
      BigInt(r.scanStartBlockNumber),r.scanStartBlockHash,r.localTransactionHash,r.localBlockHash,r.receiptHash,
      BigInt(r.recordedAt),r.reasonHash]
  )) as Hex;
}

function withHash(input: Omit<PhilRoutineJournalRecordV1,"recordHash"> | PhilRoutineJournalRecordV1): PhilRoutineJournalRecordV1 {
  const expectedKeys=["entryPoint","formatVersionHash","generation","localBlockHash","localTransactionHash",
    "officialUserOperationHash","packedUserOperationBytes","previousRecordHash","reasonHash","receiptHash","recordedAt",
    "requestId","scanStartBlockHash","scanStartBlockNumber","sender","serializedUserOperationHash","sessionId","state",
    "target","targetPreStateHash","targetRecordedSequenceBefore","targetRecordedValueBefore","userOperationNonce"];
  if ("recordHash" in input) expectedKeys.push("recordHash");
  if (Object.keys(input).sort().join("\u0000")!==expectedKeys.sort().join("\u0000")) {
    fail("PHIL_ROUTINE_JOURNAL_SCHEMA_INVALID","journal record schema is not exact");
  }
  const normalized=normalize(input);
  if (normalized.formatVersionHash!==PHIL_ROUTINE_JOURNAL_RECORD_V1_HASH) {
    fail("PHIL_ROUTINE_JOURNAL_FORMAT_INVALID","journal format identity is invalid");
  }
  const derived=derivePhilRoutineJournalRecordHashV1(normalized);
  if ("recordHash" in input && b32(input.recordHash,"recordHash",false)!==derived) {
    fail("PHIL_ROUTINE_JOURNAL_RECORD_HASH_INVALID","stored journal record hash does not match its exact fields");
  }
  return Object.freeze({...normalized,recordHash:derived});
}

export function createPhilRoutineJournalRecordV1(input: {
  readonly requestId: BytesLike; readonly sessionId: BytesLike; readonly recordedAt: string | number | bigint;
}): PhilRoutineJournalRecordV1 {
  return withHash({formatVersionHash:PHIL_ROUTINE_JOURNAL_RECORD_V1_HASH,generation:"1",
    previousRecordHash:PHIL_ZERO_BYTES32,requestId:b32(input.requestId,"requestId",false),sessionId:b32(input.sessionId,"sessionId",false),
    state:PHIL_ROUTINE_JOURNAL_STATE_V1.REQUEST_CREATED,entryPoint:PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS,
    sender:PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS,userOperationNonce:"0",serializedUserOperationHash:PHIL_ZERO_BYTES32,
    officialUserOperationHash:PHIL_ZERO_BYTES32,packedUserOperationBytes:"0x",target:PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS,
    targetRecordedValueBefore:PHIL_ZERO_BYTES32,targetRecordedSequenceBefore:"0",targetPreStateHash:PHIL_ZERO_BYTES32,
    scanStartBlockNumber:"0",scanStartBlockHash:PHIL_ZERO_BYTES32,localTransactionHash:PHIL_ZERO_BYTES32,
    localBlockHash:PHIL_ZERO_BYTES32,receiptHash:PHIL_ZERO_BYTES32,recordedAt:uint(input.recordedAt,64,"recordedAt",true),
    reasonHash:PHIL_ZERO_BYTES32});
}

function transitionRecord(input: {
  readonly current: PhilRoutineJournalRecordV1; readonly expectedGeneration: string | number | bigint;
  readonly expectedRecordHash: BytesLike; readonly nextState: PhilRoutineJournalStateV1;
  readonly recordedAt: string | number | bigint;
  readonly evidence?: Partial<Omit<PhilRoutineJournalRecordV1,"formatVersionHash"|"generation"|"previousRecordHash"|"requestId"|"sessionId"|"state"|"recordedAt"|"recordHash">>;
}, verifiedOutcome: boolean): PhilRoutineJournalRecordV1 {
  const current=withHash(input.current);
  if (current.recordHash!==b32(input.expectedRecordHash,"expectedRecordHash",false)
    || current.generation!==uint(input.expectedGeneration,64,"expectedGeneration",true)) {
    fail("PHIL_ROUTINE_JOURNAL_CAS_CONFLICT","journal generation or hash changed");
  }
  const next=state(input.nextState);
  const allowed=verifiedOutcome ? verifiedTransitions : publicTransitions;
  if (!(allowed.get(current.state)??[]).includes(next)) {
    fail("PHIL_ROUTINE_JOURNAL_TRANSITION_INVALID",`${current.state} -> ${next} is forbidden`);
  }
  const e=input.evidence??{};
  const {recordHash: _currentRecordHash,...currentFields}=current;
  const candidate=withHash({...currentFields,...e,formatVersionHash:PHIL_ROUTINE_JOURNAL_RECORD_V1_HASH,
    generation:(BigInt(current.generation)+1n).toString(),previousRecordHash:current.recordHash,
    requestId:current.requestId,sessionId:current.sessionId,state:next,recordedAt:uint(input.recordedAt,64,"recordedAt",true)});
  if (BigInt(candidate.recordedAt)<BigInt(current.recordedAt)) fail("PHIL_ROUTINE_JOURNAL_TIME_ROLLBACK","recordedAt rolled back");
  if (next===6) {
    if (candidate.entryPoint===PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS || candidate.sender===PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS
      || candidate.target===PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS || candidate.serializedUserOperationHash===PHIL_ZERO_BYTES32
      || candidate.officialUserOperationHash===PHIL_ZERO_BYTES32 || candidate.packedUserOperationBytes==="0x"
      || candidate.targetPreStateHash===PHIL_ZERO_BYTES32 || candidate.scanStartBlockHash===PHIL_ZERO_BYTES32) {
      fail("PHIL_ROUTINE_JOURNAL_COMMIT_EVIDENCE_INCOMPLETE","submission commit requires exact operation and pre-state evidence");
    }
    if (keccak256(candidate.packedUserOperationBytes)!==candidate.serializedUserOperationHash) {
      fail("PHIL_ROUTINE_JOURNAL_SERIALIZED_HASH_MISMATCH","packed operation hash does not match committed bytes");
    }
    let decoded: ReturnType<typeof abiCoder.decode>;
    const types=["address","uint256","bytes","bytes","bytes32","uint256","bytes32","bytes","bytes"] as const;
    try { decoded=abiCoder.decode(types,candidate.packedUserOperationBytes); }
    catch { return fail("PHIL_ROUTINE_JOURNAL_PACKED_OPERATION_INVALID","packed v0.7 operation ABI is invalid"); }
    if (abiCoder.encode(types,[...decoded]).toLowerCase()!==candidate.packedUserOperationBytes
      || address(decoded[0],"packed.sender",false)!==candidate.sender
      || uint(decoded[1],256,"packed.nonce")!==candidate.userOperationNonce
      || derivePhilOfficialUserOperationHashV07({packedUserOperationBytes:candidate.packedUserOperationBytes,
        entryPoint:candidate.entryPoint,chainId:31337})!==candidate.officialUserOperationHash) {
      fail("PHIL_ROUTINE_JOURNAL_PACKED_OPERATION_INVALID","packed operation identity does not match commit evidence");
    }
  }
  if (next===7 && candidate.localTransactionHash===PHIL_ZERO_BYTES32) {
    fail("PHIL_ROUTINE_JOURNAL_SUBMISSION_EVIDENCE_INCOMPLETE","submitted state requires transaction hash");
  }
  if (next===8 && (candidate.localTransactionHash===PHIL_ZERO_BYTES32
    || candidate.receiptHash===PHIL_ZERO_BYTES32 || candidate.localBlockHash===PHIL_ZERO_BYTES32)) {
    fail("PHIL_ROUTINE_JOURNAL_RECEIPT_EVIDENCE_INCOMPLETE","receipt-verified state requires transaction, receipt, and block hashes");
  }
  if ([22,23,24,25].includes(next) && candidate.reasonHash===PHIL_ZERO_BYTES32) {
    fail("PHIL_ROUTINE_JOURNAL_REASON_REQUIRED","failure or unknown state requires a reason hash");
  }
  return candidate;
}

export function transitionPhilRoutineJournalRecordV1(input: Parameters<typeof transitionRecord>[0]): PhilRoutineJournalRecordV1 {
  return transitionRecord(input,false);
}

export function validatePhilRoutineJournalChainV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1;
  readonly records: readonly PhilRoutineJournalRecordV1[];
}): readonly PhilRoutineJournalRecordV1[] {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request);
  if (!Array.isArray(input.records) || input.records.length===0) {
    fail("PHIL_ROUTINE_JOURNAL_CHAIN_INVALID","journal chain must contain its genesis record");
  }
  const records=input.records.map((record)=>withHash(record));
  const first=records[0]!;
  const expectedFirst=createPhilRoutineJournalRecordV1({requestId:request.requestId,
    sessionId:request.authorizationCore.sessionId,recordedAt:first.recordedAt});
  if (first.recordHash!==expectedFirst.recordHash) {
    fail("PHIL_ROUTINE_JOURNAL_CHAIN_INVALID","journal chain genesis is invalid");
  }
  for (let index=0;index<records.length;index+=1) {
    const current=records[index]!;
    if (current.requestId!==request.requestId || current.sessionId!==request.authorizationCore.sessionId) {
      fail("PHIL_ROUTINE_JOURNAL_CHAIN_INVALID","journal chain request/session identity changed");
    }
    if (index===0) continue;
    const previous=records[index-1]!;
    const allowed=new Set([...(publicTransitions.get(previous.state)??[]),...(verifiedTransitions.get(previous.state)??[])]);
    if (current.generation!==(BigInt(previous.generation)+1n).toString()
      || current.previousRecordHash!==previous.recordHash || BigInt(current.recordedAt)<BigInt(previous.recordedAt)
      || !allowed.has(current.state)) {
      fail("PHIL_ROUTINE_JOURNAL_CHAIN_INVALID","journal generation, predecessor hash, time, or transition is invalid");
    }
  }
  return Object.freeze(records);
}

export function derivePhilRoutineJournalFrameAadV1(input: {
  readonly disposableProfileId: BytesLike; readonly generation: string | number | bigint;
}): Hex {
  const aad=abiCoder.encode(["bytes32","bytes32","uint64"],
    [PHIL_ROUTINE_JOURNAL_FRAME_AAD_V1_HASH,b32(input.disposableProfileId,"disposableProfileId",false),
      BigInt(uint(input.generation,64,"generation",true))]) as Hex;
  if (getBytes(aad).length!==96) fail("PHIL_ROUTINE_JOURNAL_AAD_INVALID","journal AAD must be 96 bytes");
  return aad;
}

function b64url(input: Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

function decodeB64url(input: string, label: string): Uint8Array {
  if (typeof input!=="string" || input.length===0 || /[=+\/\s]/.test(input) || !/^[A-Za-z0-9_-]+$/.test(input)) {
    fail("PHIL_ROUTINE_JOURNAL_BASE64URL_INVALID",`${label} is not canonical base64url`);
  }
  const decoded=Buffer.from(input,"base64url");
  if (b64url(decoded)!==input) fail("PHIL_ROUTINE_JOURNAL_BASE64URL_INVALID",`${label} is not shortest canonical base64url`);
  return decoded;
}

function normalizeFrame(frame: PhilRoutineJournalFrameV1): PhilRoutineJournalFrameV1 {
  if (frame.version!==1 || Object.keys(frame).sort().join(",")!=="ciphertext,nonce,tag,version") {
    fail("PHIL_ROUTINE_JOURNAL_FRAME_SCHEMA_INVALID","journal frame schema is not exact");
  }
  const nonce=decodeB64url(frame.nonce,"nonce"),ciphertext=decodeB64url(frame.ciphertext,"ciphertext"),
    tag=decodeB64url(frame.tag,"tag");
  if (nonce.length!==12 || tag.length!==16 || ciphertext.length===0) {
    fail("PHIL_ROUTINE_JOURNAL_FRAME_INPUT_INVALID","journal frame lengths are invalid");
  }
  return Object.freeze({version:1,nonce:b64url(nonce),ciphertext:b64url(ciphertext),tag:b64url(tag)});
}

function encryptPhilRoutineJournalFrameV1(input: {
  readonly key: BytesLike; readonly nonce: BytesLike; readonly aad: BytesLike; readonly plaintext: BytesLike;
}): PhilRoutineJournalFrameV1 {
  const key=getBytes(input.key),nonce=getBytes(input.nonce),aad=getBytes(input.aad),plaintext=getBytes(input.plaintext);
  if (key.length!==32 || nonce.length!==12 || aad.length!==96 || plaintext.length===0) {
    fail("PHIL_ROUTINE_JOURNAL_FRAME_INPUT_INVALID","AES-256-GCM key/nonce/AAD/plaintext lengths are invalid");
  }
  const cipher=createCipheriv("aes-256-gcm",key,nonce);cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(plaintext),cipher.final()]);const tag=cipher.getAuthTag();
  return Object.freeze({version:1,nonce:b64url(nonce),ciphertext:b64url(ciphertext),tag:b64url(tag)});
}

function decryptPhilRoutineJournalFrameV1(input: {
  readonly key: BytesLike; readonly aad: BytesLike; readonly frame: PhilRoutineJournalFrameV1;
}): Hex {
  const frame=normalizeFrame(input.frame);
  const key=getBytes(input.key),aad=getBytes(input.aad),nonce=decodeB64url(frame.nonce,"nonce"),
    ciphertext=decodeB64url(frame.ciphertext,"ciphertext"),tag=decodeB64url(frame.tag,"tag");
  if (key.length!==32 || aad.length!==96 || nonce.length!==12 || tag.length!==16 || ciphertext.length===0) {
    fail("PHIL_ROUTINE_JOURNAL_FRAME_INPUT_INVALID","journal frame lengths are invalid");
  }
  try {
    const decipher=createDecipheriv("aes-256-gcm",key,nonce);decipher.setAAD(aad);decipher.setAuthTag(tag);
    return hexlify(Buffer.concat([decipher.update(ciphertext),decipher.final()])) as Hex;
  } catch { return fail("PHIL_ROUTINE_JOURNAL_AUTHENTICATION_FAILED","journal frame authentication failed"); }
}

export function serializePhilRoutineJournalRecordJsonV1(record: PhilRoutineJournalRecordV1): string {
  return JSON.stringify(withHash(record));
}

export function parsePhilRoutineJournalRecordJsonV1(input: string | Uint8Array): PhilRoutineJournalRecordV1 {
  return withHash(parsePhilStrictJsonObjectV1(input) as unknown as PhilRoutineJournalRecordV1);
}

export function serializePhilRoutineJournalFrameJsonV1(frame: PhilRoutineJournalFrameV1): string {
  return JSON.stringify(normalizeFrame(frame));
}

export function parsePhilRoutineJournalFrameJsonV1(input: string | Uint8Array): PhilRoutineJournalFrameV1 {
  return normalizeFrame(parsePhilStrictJsonObjectV1(input) as unknown as PhilRoutineJournalFrameV1);
}

export class PhilRoutineJournalFrameCipherV1 {
  readonly #key: Uint8Array;
  readonly #disposableProfileId: Hex;
  readonly #randomNonce: () => Uint8Array;
  readonly #encryptedNonces = new Set<string>();
  readonly #decryptedNonces = new Set<string>();
  #destroyed = false;

  constructor(input: {
    readonly key: BytesLike;
    readonly disposableProfileId: BytesLike;
    readonly randomNonce?: () => Uint8Array;
  }) {
    this.#key=getBytes(input.key);
    if (this.#key.length!==32) fail("PHIL_ROUTINE_JOURNAL_FRAME_INPUT_INVALID","journal key must be 32 bytes");
    this.#disposableProfileId=b32(input.disposableProfileId,"disposableProfileId",false);
    this.#randomNonce=input.randomNonce??(()=>randomBytes(12));
  }

  encryptRecord(recordInput: PhilRoutineJournalRecordV1): string {
    if (this.#destroyed) fail("PHIL_ROUTINE_JOURNAL_KEY_DESTROYED","journal key was destroyed");
    const record=withHash(recordInput),nonce=getBytes(this.#randomNonce());
    if (nonce.length!==12) fail("PHIL_ROUTINE_JOURNAL_FRAME_INPUT_INVALID","generated journal nonce must be 12 bytes");
    const nonceIdentity=hexlify(nonce).toLowerCase();
    if (this.#encryptedNonces.has(nonceIdentity)) fail("PHIL_ROUTINE_JOURNAL_NONCE_REUSE","journal encryption nonce was reused");
    this.#encryptedNonces.add(nonceIdentity);
    const aad=derivePhilRoutineJournalFrameAadV1({disposableProfileId:this.#disposableProfileId,generation:record.generation});
    const frame=encryptPhilRoutineJournalFrameV1({key:this.#key,nonce,aad,
      plaintext:Buffer.from(serializePhilRoutineJournalRecordJsonV1(record),"utf8")});
    return serializePhilRoutineJournalFrameJsonV1(frame);
  }

  decryptRecord(input: {
    readonly frameJson: string | Uint8Array;
    readonly expectedGeneration: string | number | bigint;
  }): PhilRoutineJournalRecordV1 {
    if (this.#destroyed) fail("PHIL_ROUTINE_JOURNAL_KEY_DESTROYED","journal key was destroyed");
    const frame=parsePhilRoutineJournalFrameJsonV1(input.frameJson),nonceIdentity=frame.nonce;
    if (this.#decryptedNonces.has(nonceIdentity)) fail("PHIL_ROUTINE_JOURNAL_NONCE_REUSE","journal decryption nonce was reused");
    this.#decryptedNonces.add(nonceIdentity);
    const expectedGeneration=uint(input.expectedGeneration,64,"expectedGeneration",true);
    const aad=derivePhilRoutineJournalFrameAadV1({disposableProfileId:this.#disposableProfileId,generation:expectedGeneration});
    const plaintext=decryptPhilRoutineJournalFrameV1({key:this.#key,aad,frame});
    const record=parsePhilRoutineJournalRecordJsonV1(getBytes(plaintext));
    if (record.generation!==expectedGeneration) {
      fail("PHIL_ROUTINE_JOURNAL_GENERATION_MISMATCH","decrypted record generation does not match frame AAD");
    }
    return record;
  }

  destroy(): void {
    this.#key.fill(0);this.#encryptedNonces.clear();this.#decryptedNonces.clear();this.#destroyed=true;
  }
}

export interface PhilRoutineSyntheticSimulationV1 {
  readonly entryPoint: string; readonly sender: string; readonly userOperationNonce: string | number | bigint;
  readonly serializedUserOperationHash: BytesLike; readonly officialUserOperationHash: BytesLike;
  readonly packedUserOperationBytes: BytesLike; readonly target: string; readonly targetRecordedValueBefore: BytesLike;
  readonly targetRecordedSequenceBefore: string | number | bigint; readonly targetPreStateHash: BytesLike;
  readonly scanStartBlockNumber: string | number | bigint; readonly scanStartBlockHash: BytesLike;
}

export type PhilRoutineReceiptEvidenceV1 = Parameters<typeof verifyPhilRoutineAuthorizationReceiptV1>[0]["evidence"];

export interface PhilRoutineSyntheticSuccessfulOutcomeV1 {
  readonly kind: "success";
  readonly receipt: PhilRoutineAuthorizationReceiptV1;
  readonly evidence: PhilRoutineReceiptEvidenceV1;
}

export interface PhilRoutineFailedExecutionEvidenceV1 {
  readonly scanStartBlockNumber: string | number | bigint; readonly scanStartBlockHash: BytesLike;
  readonly capturedHeadBlockNumber: string | number | bigint; readonly capturedHeadBlockHash: BytesLike;
  readonly eventBlockNumber: string | number | bigint; readonly transactionStatus: string | number | bigint;
  readonly transactionHash: BytesLike; readonly blockHash: BytesLike; readonly logs: readonly PhilRoutineReceiptLogV1[];
  readonly entryPointNonceAfter: string | number | bigint; readonly targetCodeHash: BytesLike;
  readonly targetRecordedValueAfter: BytesLike; readonly targetRecordedSequenceAfter: string | number | bigint;
}

export interface PhilRoutineUnknownReconciliationEvidenceV1 {
  readonly scanStartBlockNumber: string | number | bigint; readonly scanStartBlockHash: BytesLike;
  readonly chainAccessible: boolean; readonly capturedHeadBlockNumber: string | number | bigint;
  readonly capturedHeadBlockHash: BytesLike; readonly matchingUserOperationLogs: readonly PhilRoutineReceiptLogV1[];
  readonly entryPointNonceAfter: string | number | bigint; readonly targetCodeHash: BytesLike;
  readonly targetRecordedValueAfter: BytesLike; readonly targetRecordedSequenceAfter: string | number | bigint;
}

export type PhilRoutineSyntheticExecutionOutcomeV1 = PhilRoutineSyntheticSuccessfulOutcomeV1 | Readonly<{
  kind: "failed"; evidence: PhilRoutineFailedExecutionEvidenceV1;
}>;

export type PhilRoutineSyntheticReconciliationOutcomeV1 = PhilRoutineSyntheticExecutionOutcomeV1 | Readonly<{
  kind: "unknown"; evidence: PhilRoutineUnknownReconciliationEvidenceV1;
}>;

export interface PhilRoutineSyntheticTrustedStateV1 {
  readonly request: PhilRoutineAuthorizationRequestV1;
  readonly desktopUnlocked: boolean;
  readonly iphoneSessionCurrent: boolean;
}

const VERIFIED_OUTCOME = Symbol("PHIL_ROUTINE_VERIFIED_OUTCOME_V1");
interface VerifiedOutcomeV1 {
  readonly [VERIFIED_OUTCOME]: true;
  readonly currentRecordHash: Hex;
  readonly nextState: PhilRoutineJournalStateV1;
  readonly evidence: Partial<PhilRoutineJournalRecordV1>;
}

function topicAddress(value: string): Hex {
  return `0x${"0".repeat(24)}${address(value,"topicAddress").slice(2)}` as Hex;
}

function normalizedLog(log: PhilRoutineReceiptLogV1): Readonly<{
  address: string; topics: readonly Hex[]; data: Hex; index: string;
  transactionHash: Hex; blockHash: Hex; removed: boolean;
}> {
  const keys=["address","blockHash","data","index","removed","topics","transactionHash"];
  if (Object.keys(log).sort().join("\u0000")!==keys.join("\u0000") || !Array.isArray(log.topics)
    || log.topics.length<1 || log.topics.length>4 || typeof log.removed!=="boolean") {
    fail("PHIL_ROUTINE_RECONCILIATION_LOG_INVALID","reconciliation log schema is not exact");
  }
  return Object.freeze({address:address(log.address,"log.address",false),topics:Object.freeze(log.topics.map((v,i)=>b32(v,`log.topic[${i}]`))),
    data:packed(log.data),index:uint(log.index,256,"log.index"),transactionHash:b32(log.transactionHash,"log.transactionHash",false),
    blockHash:b32(log.blockHash,"log.blockHash",false),removed:log.removed});
}

function validateCommittedOperation(request: PhilRoutineAuthorizationRequestV1, journal: PhilRoutineJournalRecordV1): void {
  if (![6,7,8,25].includes(journal.state) || journal.requestId!==request.requestId
    || journal.sessionId!==request.authorizationCore.sessionId || journal.entryPoint!==request.executionEnvironment.entryPoint
    || journal.sender!==request.action.account || journal.target!==request.action.target
    || BigInt(journal.userOperationNonce)!==BigInt(request.action.userOpNonce)
    || keccak256(journal.packedUserOperationBytes)!==journal.serializedUserOperationHash
    || derivePhilOfficialUserOperationHashV07({packedUserOperationBytes:journal.packedUserOperationBytes,
      entryPoint:journal.entryPoint,chainId:request.executionEnvironment.chainId})!==journal.officialUserOperationHash
    || derivePhilRoutineTargetPreStateHashV1({target:journal.target,
      approvedTargetRuntimeCodeHash:request.accountConfiguration.approvedTargetRuntimeCodeHash,
      recordedValueBefore:journal.targetRecordedValueBefore,recordedSequenceBefore:journal.targetRecordedSequenceBefore,
      scanStartBlockNumber:journal.scanStartBlockNumber,scanStartBlockHash:journal.scanStartBlockHash})!==journal.targetPreStateHash) {
    fail("PHIL_ROUTINE_RECONCILIATION_COMMIT_INVALID","durable submission commit does not match the request");
  }
}

function verified(current: PhilRoutineJournalRecordV1, nextState: PhilRoutineJournalStateV1,
  evidence: Partial<PhilRoutineJournalRecordV1> = {}): VerifiedOutcomeV1 {
  return Object.freeze({[VERIFIED_OUTCOME]:true as const,currentRecordHash:current.recordHash,nextState,evidence});
}

export function verifyPhilRoutineSuccessfulOutcomeV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly journal: PhilRoutineJournalRecordV1;
  readonly outcome: PhilRoutineSyntheticSuccessfulOutcomeV1;
}): VerifiedOutcomeV1 {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request),journal=withHash(input.journal);
  validateCommittedOperation(request,journal);
  const receipt=verifyPhilRoutineAuthorizationReceiptV1({request,receipt:input.outcome.receipt,
    submissionCommit:journal,evidence:input.outcome.evidence});
  if (journal.state===7 && journal.localTransactionHash!==receipt.transactionHash) {
    fail("PHIL_ROUTINE_RECONCILIATION_TRANSACTION_MISMATCH","submitted transaction differs from verified receipt");
  }
  if (journal.state===8 && (journal.localTransactionHash!==receipt.transactionHash
    || journal.localBlockHash!==receipt.blockHash || journal.receiptHash!==receipt.receiptHash)) {
    fail("PHIL_ROUTINE_RECONCILIATION_RECEIPT_MISMATCH","stored receipt evidence differs from re-verification");
  }
  return verified(journal,journal.state===8 ? PHIL_ROUTINE_JOURNAL_STATE_V1.COMPLETED
    : PHIL_ROUTINE_JOURNAL_STATE_V1.RECEIPT_VERIFIED,journal.state===8 ? {} : {
      localTransactionHash:receipt.transactionHash,localBlockHash:receipt.blockHash,receiptHash:receipt.receiptHash
    });
}

export function verifyPhilRoutineFailedExecutionOutcomeV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly journal: PhilRoutineJournalRecordV1;
  readonly evidence: PhilRoutineFailedExecutionEvidenceV1;
}): VerifiedOutcomeV1 {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request),journal=withHash(input.journal),e=input.evidence;
  validateCommittedOperation(request,journal);
  if (uint(e.scanStartBlockNumber,64,"scanStartBlockNumber")!==journal.scanStartBlockNumber
    || b32(e.scanStartBlockHash,"scanStartBlockHash",false)!==journal.scanStartBlockHash) {
    fail("PHIL_ROUTINE_RECONCILIATION_ANCHOR_MISMATCH","scan anchor is not the durable commit anchor");
  }
  const head=BigInt(uint(e.capturedHeadBlockNumber,64,"capturedHeadBlockNumber"));
  const eventBlock=BigInt(uint(e.eventBlockNumber,64,"eventBlockNumber"));
  if (head<=BigInt(journal.scanStartBlockNumber) || eventBlock<=BigInt(journal.scanStartBlockNumber) || eventBlock>head
    || b32(e.capturedHeadBlockHash,"capturedHeadBlockHash",false)===PHIL_ZERO_BYTES32
    || uint(e.transactionStatus,64,"transactionStatus")!=="1") {
    fail("PHIL_ROUTINE_RECONCILIATION_RANGE_INVALID","failed event is outside the authenticated captured range");
  }
  const transactionHash=b32(e.transactionHash,"transactionHash",false),blockHash=b32(e.blockHash,"blockHash",false);
  if (journal.state===7 && journal.localTransactionHash!==transactionHash) {
    fail("PHIL_ROUTINE_RECONCILIATION_TRANSACTION_MISMATCH","failed event transaction differs from submitted transaction");
  }
  const topic=keccak256(toUtf8Bytes("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)")) as Hex;
  const matches=e.logs.map(normalizedLog).filter((log)=>log.topics[0]===topic);
  if (matches.length!==1) fail("PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID","exactly one EntryPoint event is required");
  const log=matches[0]!;
  if (log.removed || log.address!==journal.entryPoint || log.transactionHash!==transactionHash || log.blockHash!==blockHash
    || log.topics.length!==4 || log.topics[1]!==journal.officialUserOperationHash
    || log.topics[2]!==topicAddress(journal.sender)
    || log.topics[3]!==topicAddress(PHIL_ROUTINE_JOURNAL_ZERO_ADDRESS)) {
    fail("PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID","failed EntryPoint event identity is invalid");
  }
  let decoded: ReturnType<typeof abiCoder.decode>;
  const types=["uint256","bool","uint256","uint256"] as const;
  try { decoded=abiCoder.decode(types,log.data); }
  catch { return fail("PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID","failed EntryPoint event data is malformed"); }
  if (abiCoder.encode(types,[...decoded]).toLowerCase()!==log.data || BigInt(decoded[0])!==BigInt(journal.userOperationNonce)
    || decoded[1]!==false || BigInt(uint(e.entryPointNonceAfter,256,"entryPointNonceAfter"))!==BigInt(journal.userOperationNonce)+1n
    || b32(e.targetCodeHash,"targetCodeHash",false)!==request.accountConfiguration.approvedTargetRuntimeCodeHash
    || b32(e.targetRecordedValueAfter,"targetRecordedValueAfter")!==journal.targetRecordedValueBefore
    || uint(e.targetRecordedSequenceAfter,64,"targetRecordedSequenceAfter")!==journal.targetRecordedSequenceBefore) {
    fail("PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID","failed execution state does not match the durable pre-state");
  }
  const reasonHash=keccak256(abiCoder.encode(["bytes32","bytes32","bytes32","uint64","bytes32"],
    [journal.officialUserOperationHash,transactionHash,blockHash,eventBlock,b32(e.capturedHeadBlockHash,"capturedHeadBlockHash",false)])) as Hex;
  return verified(journal,PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_EXECUTION,
    {localTransactionHash:transactionHash,localBlockHash:blockHash,reasonHash});
}

export function verifyPhilRoutineUnknownReconciliationV1(input: {
  readonly request: PhilRoutineAuthorizationRequestV1; readonly journal: PhilRoutineJournalRecordV1;
  readonly evidence: PhilRoutineUnknownReconciliationEvidenceV1;
}): VerifiedOutcomeV1 {
  const request=validatePhilRoutineAuthorizationRequestV1(input.request),journal=withHash(input.journal),e=input.evidence;
  validateCommittedOperation(request,journal);
  if (uint(e.scanStartBlockNumber,64,"scanStartBlockNumber")!==journal.scanStartBlockNumber
    || b32(e.scanStartBlockHash,"scanStartBlockHash",false)!==journal.scanStartBlockHash
    || typeof e.chainAccessible!=="boolean") {
    fail("PHIL_ROUTINE_RECONCILIATION_ANCHOR_MISMATCH","unknown outcome does not authenticate the durable scan anchor");
  }
  const matching=e.matchingUserOperationLogs.map(normalizedLog);
  if (matching.length!==0) fail("PHIL_ROUTINE_RECONCILIATION_EVENT_INVALID","unknown outcome cannot discard matching events");
  const head=uint(e.capturedHeadBlockNumber,64,"capturedHeadBlockNumber");
  const headHash=b32(e.capturedHeadBlockHash,"capturedHeadBlockHash",!e.chainAccessible);
  if (e.chainAccessible && (BigInt(head)<BigInt(journal.scanStartBlockNumber) || headHash===PHIL_ZERO_BYTES32)) {
    fail("PHIL_ROUTINE_RECONCILIATION_RANGE_INVALID","captured head is not authenticated");
  }
  const reasonHash=keccak256(abiCoder.encode(
    ["bytes32","bool","uint64","bytes32","uint256","bytes32","bytes32","uint64"],
    [journal.recordHash,e.chainAccessible,BigInt(head),headHash,BigInt(uint(e.entryPointNonceAfter,256,"entryPointNonceAfter")),
      b32(e.targetCodeHash,"targetCodeHash"),b32(e.targetRecordedValueAfter,"targetRecordedValueAfter"),
      BigInt(uint(e.targetRecordedSequenceAfter,64,"targetRecordedSequenceAfter"))])) as Hex;
  return verified(journal,PHIL_ROUTINE_JOURNAL_STATE_V1.SUBMISSION_OUTCOME_UNKNOWN,{reasonHash});
}

/// @notice Synthetic durable-CAS seam: publication occurs only after the injected flush succeeds.
export class PhilRoutineJournalSyntheticCasHostV1 {
  #current: PhilRoutineJournalRecordV1;
  readonly #flush: (candidate: PhilRoutineJournalRecordV1) => Promise<void>;
  constructor(input: { readonly initial: PhilRoutineJournalRecordV1;
    readonly flush: (candidate: PhilRoutineJournalRecordV1) => Promise<void>; }) {
    this.#current=withHash(input.initial);this.#flush=input.flush;
  }
  read(): PhilRoutineJournalRecordV1 { return this.#current; }
  async compareAndSwap(input: Omit<Parameters<typeof transitionPhilRoutineJournalRecordV1>[0],"current">): Promise<PhilRoutineJournalRecordV1> {
    const candidate=transitionPhilRoutineJournalRecordV1({...input,current:this.#current});
    await this.#flush(candidate);this.#current=candidate;return candidate;
  }
  async publishVerifiedOutcome(outcome: VerifiedOutcomeV1, recordedAt: string | number | bigint): Promise<PhilRoutineJournalRecordV1> {
    if (outcome[VERIFIED_OUTCOME]!==true || outcome.currentRecordHash!==this.#current.recordHash) {
      fail("PHIL_ROUTINE_JOURNAL_VERIFIED_OUTCOME_INVALID","verified outcome does not bind the current record");
    }
    const candidate=transitionRecord({current:this.#current,expectedGeneration:this.#current.generation,
      expectedRecordHash:this.#current.recordHash,nextState:outcome.nextState,recordedAt,evidence:outcome.evidence},true);
    await this.#flush(candidate);this.#current=candidate;return candidate;
  }
}

interface CoordinatorEntryV1 {
  readonly request: PhilRoutineAuthorizationRequestV1;
  response?: PhilRoutineAuthorizationResponseV1;
  simulation?: PhilRoutineSyntheticSimulationV1;
  readonly journal: PhilRoutineJournalSyntheticCasHostV1;
}

/// @notice Dependency-injected Step 6C-1 lifecycle used only with synthetic local transport/effects.
/// @dev A product host must replace the in-memory map with the durable encrypted CAS primitive.
export class PhilRoutineAuthorizationSyntheticCoordinatorV1 {
  readonly #entries = new Map<Hex, CoordinatorEntryV1>();
  readonly #locks = new Map<Hex, Promise<void>>();
  readonly #now: () => bigint;
  readonly #flush: (candidate: PhilRoutineJournalRecordV1) => Promise<void>;
  readonly #readTrustedState: (requestId: Hex) => Promise<PhilRoutineSyntheticTrustedStateV1>;
  readonly #simulate: (request: PhilRoutineAuthorizationRequestV1) => Promise<PhilRoutineSyntheticSimulationV1>;
  readonly #execute: (
    request: PhilRoutineAuthorizationRequestV1,
    response: PhilRoutineAuthorizationResponseV1,
    simulation: PhilRoutineSyntheticSimulationV1,
    journal: PhilRoutineJournalRecordV1
  ) => Promise<PhilRoutineSyntheticExecutionOutcomeV1>;
  readonly #reconcile: (request: PhilRoutineAuthorizationRequestV1,
    journal: PhilRoutineJournalRecordV1) => Promise<PhilRoutineSyntheticReconciliationOutcomeV1>;

  constructor(input: {
    readonly now: () => bigint;
    readonly flush: (candidate: PhilRoutineJournalRecordV1) => Promise<void>;
    readonly readTrustedState: (requestId: Hex) => Promise<PhilRoutineSyntheticTrustedStateV1>;
    readonly simulate: (request: PhilRoutineAuthorizationRequestV1) => Promise<PhilRoutineSyntheticSimulationV1>;
    readonly execute: (
      request: PhilRoutineAuthorizationRequestV1,
      response: PhilRoutineAuthorizationResponseV1,
      simulation: PhilRoutineSyntheticSimulationV1,
      journal: PhilRoutineJournalRecordV1
    ) => Promise<PhilRoutineSyntheticExecutionOutcomeV1>;
    readonly reconcile: (request: PhilRoutineAuthorizationRequestV1,
      journal: PhilRoutineJournalRecordV1) => Promise<PhilRoutineSyntheticReconciliationOutcomeV1>;
  }) {
    this.#now=input.now;this.#flush=input.flush;this.#readTrustedState=input.readTrustedState;
    this.#simulate=input.simulate;this.#execute=input.execute;this.#reconcile=input.reconcile;
  }

  async beginRoutineAuthorization(requestInput: PhilRoutineAuthorizationRequestV1): Promise<PhilRoutineAuthorizationRequestV1> {
    const request=validatePhilRoutineAuthorizationRequestV1(requestInput);
    if (this.#entries.has(request.requestId)) fail("PHIL_ROUTINE_COORDINATOR_REPLAY","requestId already exists");
    const record=createPhilRoutineJournalRecordV1({requestId:request.requestId,sessionId:request.authorizationCore.sessionId,recordedAt:this.#now()});
    await this.#flush(record);
    const host=new PhilRoutineJournalSyntheticCasHostV1({initial:record,flush:this.#flush});
    await host.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
      nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.TRANSPORT_WAITING,recordedAt:this.#now()});
    this.#entries.set(request.requestId,{request,journal:host});
    return request;
  }

  restoreRoutineAuthorization(input: {
    readonly request: PhilRoutineAuthorizationRequestV1;
    readonly journalChain: readonly PhilRoutineJournalRecordV1[];
  }): void {
    const request=validatePhilRoutineAuthorizationRequestV1(input.request);
    const chain=validatePhilRoutineJournalChainV1({request,records:input.journalChain}),record=chain.at(-1)!;
    if (this.#entries.has(request.requestId)) fail("PHIL_ROUTINE_COORDINATOR_REPLAY","requestId already exists");
    if (!Object.values(PHIL_ROUTINE_JOURNAL_STATE_V1).includes(record.state) || record.requestId!==request.requestId
      || record.sessionId!==request.authorizationCore.sessionId) {
      fail("PHIL_ROUTINE_COORDINATOR_RESTORE_INVALID","restored journal does not match the request or a restart-safe state");
    }
    if ([6,7,8,25].includes(record.state)) validateCommittedOperation(request,record);
    this.#entries.set(request.requestId,{request,journal:new PhilRoutineJournalSyntheticCasHostV1({initial:record,flush:this.#flush})});
  }

  restoreEncryptedRoutineAuthorization(input: {
    readonly request: PhilRoutineAuthorizationRequestV1;
    readonly frameCipher: PhilRoutineJournalFrameCipherV1;
    readonly journalFrameJsonChain: readonly (string | Uint8Array)[];
  }): void {
    if (!Array.isArray(input.journalFrameJsonChain) || input.journalFrameJsonChain.length===0) {
      fail("PHIL_ROUTINE_JOURNAL_CHAIN_INVALID","encrypted journal chain must contain its genesis frame");
    }
    const journalChain=input.journalFrameJsonChain.map((frameJson,index)=>input.frameCipher.decryptRecord({
      frameJson,expectedGeneration:index+1
    }));
    this.restoreRoutineAuthorization({request:input.request,journalChain});
  }

  getRoutineAuthorizationStatus(requestId: BytesLike): Readonly<{
    requestId: Hex; state: PhilRoutineJournalStateV1; generation: string; recordHash: Hex; terminalReason: "rejected" | null;
  }> {
    const id=b32(requestId,"requestId",false),entry=this.#entries.get(id);
    if (!entry) fail("PHIL_ROUTINE_COORDINATOR_UNKNOWN_REQUEST","requestId is unknown");
    const record=entry.journal.read();
    return Object.freeze({requestId:id,state:record.state,generation:record.generation,recordHash:record.recordHash,
      terminalReason:record.state===20 && record.reasonHash===PHIL_ROUTINE_PHONE_REJECTED_V1_HASH ? "rejected" : null});
  }

  async cancelRoutineAuthorization(requestId: BytesLike): Promise<"cancelled"|"too_late_submission_committed"> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      const record=entry.journal.read();
      if (record.state>=6 && record.state<20) return "too_late_submission_committed";
      if (record.state>=20) return record.state===20 ? "cancelled" : "too_late_submission_committed";
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.CANCELLED,recordedAt:this.#now()});
      return "cancelled";
    });
  }

  async failRoutineTransport(requestId: BytesLike): Promise<boolean> {
    return this.#withLock(b32(requestId,"requestId",false),async entry=>{
      const record=entry.journal.read();
      if(record.state>=6) return false;
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,recordedAt:this.#now(),
        evidence:{reasonHash:keccak256(toUtf8Bytes("PHIL_ROUTINE_TRANSPORT_VALIDATION_FAILED_V1")) as Hex}});
      return true;
    });
  }

  async rejectRoutineAuthorization(requestId: BytesLike): Promise<"rejected"|"too_late_submission_committed"> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      const record=entry.journal.read();
      // Rejection is accepted only from the waiting transport, before approval.
      if (record.state!==PHIL_ROUTINE_JOURNAL_STATE_V1.TRANSPORT_WAITING) return "too_late_submission_committed";
      if (this.#now()>=BigInt(entry.request.authorizationCore.expiresAt)) return "too_late_submission_committed";
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.CANCELLED,recordedAt:this.#now(),
        evidence:{reasonHash:PHIL_ROUTINE_PHONE_REJECTED_V1_HASH}});
      return "rejected";
    });
  }

  async expireRoutineAuthorization(requestId: BytesLike): Promise<"expired"|"too_late_submission_committed"> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      const record=entry.journal.read();
      if (record.state>=6 && record.state<20) return "too_late_submission_committed";
      if (record.state>=20) return record.state===21 ? "expired" : "too_late_submission_committed";
      if (this.#now()<BigInt(entry.request.authorizationCore.expiresAt)) {
        fail("PHIL_ROUTINE_COORDINATOR_NOT_EXPIRED","request has not expired");
      }
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.EXPIRED,recordedAt:this.#now()});
      return "expired";
    });
  }

  async acceptRoutineDeviceResponse(input: {
    readonly requestId: BytesLike; readonly response: PhilRoutineAuthorizationResponseV1;
  }): Promise<PhilRoutineAuthorizationResponseV1> {
    return this.#withLock(b32(input.requestId,"requestId",false),async (entry) => {
      let record=entry.journal.read();
      if (record.state!==PHIL_ROUTINE_JOURNAL_STATE_V1.TRANSPORT_WAITING) {
        fail("PHIL_ROUTINE_COORDINATOR_STATE_INVALID","device response is out of order");
      }
      const response=verifyPhilRoutineAuthorizationResponseV1({request:entry.request,response:input.response});
      await this.#assertTrustedPreSubmission(entry);
      entry.response=response;
      record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.RESPONSE_VERIFIED,recordedAt:this.#now()});
      return response;
    });
  }

  async simulateApprovedRoutineAuthorization(requestId: BytesLike): Promise<PhilRoutineSyntheticSimulationV1> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      if (entry.journal.read().state!==PHIL_ROUTINE_JOURNAL_STATE_V1.RESPONSE_VERIFIED || !entry.response) {
        fail("PHIL_ROUTINE_COORDINATOR_STATE_INVALID","simulation requires one verified response");
      }
      await this.#assertTrustedPreSubmission(entry);
      const simulation=this.#normalizeSimulation(entry.request,await this.#simulate(entry.request));
      await this.#assertTrustedPreSubmission(entry);
      entry.simulation=simulation;
      const record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.SIMULATION_PASSED,recordedAt:this.#now()});
      return simulation;
    });
  }

  async commitAndExecuteSimulatedRoutineAuthorization(requestId: BytesLike): Promise<PhilRoutineSyntheticExecutionOutcomeV1> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      if (entry.journal.read().state!==PHIL_ROUTINE_JOURNAL_STATE_V1.SIMULATION_PASSED || !entry.response || !entry.simulation) {
        fail("PHIL_ROUTINE_COORDINATOR_STATE_INVALID","execution requires a verified response and exact simulation");
      }
      const s=entry.simulation;
      await this.#assertTrustedPreSubmission(entry);
      const fresh=this.#normalizeSimulation(entry.request,await this.#simulate(entry.request));
      if (JSON.stringify(fresh)!==JSON.stringify(s)) {
        const drifted=entry.journal.read();
        await entry.journal.compareAndSwap({expectedGeneration:drifted.generation,expectedRecordHash:drifted.recordHash,
          nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,recordedAt:this.#now(),
          evidence:{reasonHash:keccak256(toUtf8Bytes("simulation pre-state changed before commit")) as Hex}});
        fail("PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_DRIFT","pre-state changed before submission commit");
      }
      await this.#assertTrustedPreSubmission(entry);
      let record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.SUBMISSION_COMMITTED,
        recordedAt:this.#now(),evidence:{entryPoint:address(s.entryPoint,"entryPoint",false),sender:address(s.sender,"sender",false),
          userOperationNonce:uint(s.userOperationNonce,256,"userOperationNonce"),
          serializedUserOperationHash:b32(s.serializedUserOperationHash,"serializedUserOperationHash",false),
          officialUserOperationHash:b32(s.officialUserOperationHash,"officialUserOperationHash",false),
          packedUserOperationBytes:packed(s.packedUserOperationBytes),target:address(s.target,"target",false),
          targetRecordedValueBefore:b32(s.targetRecordedValueBefore,"targetRecordedValueBefore"),
          targetRecordedSequenceBefore:uint(s.targetRecordedSequenceBefore,64,"targetRecordedSequenceBefore"),
          targetPreStateHash:b32(s.targetPreStateHash,"targetPreStateHash",false),
          scanStartBlockNumber:uint(s.scanStartBlockNumber,64,"scanStartBlockNumber"),
          scanStartBlockHash:b32(s.scanStartBlockHash,"scanStartBlockHash",false)}});
      let result: PhilRoutineSyntheticExecutionOutcomeV1;
      try { result=await this.#execute(entry.request,entry.response,s,entry.journal.read()); }
      catch {
        record=entry.journal.read();
        await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
          nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.SUBMISSION_OUTCOME_UNKNOWN,recordedAt:this.#now(),
          evidence:{reasonHash:keccak256(abiCoder.encode(["bytes32","bytes32"],
            [record.recordHash,keccak256(toUtf8Bytes("submission returned no trustworthy outcome"))])) as Hex}});
        return fail("PHIL_ROUTINE_COORDINATOR_SUBMISSION_OUTCOME_UNKNOWN","submission outcome is unknown and cannot be retried");
      }
      await this.#applyOutcome(entry,result);
      return result;
    });
  }

  async reconcileRoutineAuthorization(requestId: BytesLike): Promise<PhilRoutineJournalRecordV1> {
    return this.#withLock(b32(requestId,"requestId",false),async (entry) => {
      let record=entry.journal.read();
      if (record.state>=1 && record.state<=5) {
        await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
          nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,
          recordedAt:this.#now(),evidence:{reasonHash:keccak256(toUtf8Bytes("restart before submission commit")) as Hex}});
      } else if ([6,7,8,25].includes(record.state)) {
        const outcome=await this.#reconcile(entry.request,record);
        if (outcome.kind==="unknown") {
          const checked=verifyPhilRoutineUnknownReconciliationV1({request:entry.request,journal:record,evidence:outcome.evidence});
          if (record.state!==25) await entry.journal.publishVerifiedOutcome(checked,this.#now());
        } else {
          await this.#applyOutcome(entry,outcome);
        }
      }
      return entry.journal.read();
    });
  }

  #normalizeSimulation(request: PhilRoutineAuthorizationRequestV1,
    supplied: PhilRoutineSyntheticSimulationV1): PhilRoutineSyntheticSimulationV1 {
    const simulation=Object.freeze({entryPoint:address(supplied.entryPoint,"entryPoint",false),
      sender:address(supplied.sender,"sender",false),userOperationNonce:uint(supplied.userOperationNonce,256,"userOperationNonce"),
      serializedUserOperationHash:b32(supplied.serializedUserOperationHash,"serializedUserOperationHash",false),
      officialUserOperationHash:b32(supplied.officialUserOperationHash,"officialUserOperationHash",false),
      packedUserOperationBytes:packed(supplied.packedUserOperationBytes),target:address(supplied.target,"target",false),
      targetRecordedValueBefore:b32(supplied.targetRecordedValueBefore,"targetRecordedValueBefore"),
      targetRecordedSequenceBefore:uint(supplied.targetRecordedSequenceBefore,64,"targetRecordedSequenceBefore"),
      targetPreStateHash:b32(supplied.targetPreStateHash,"targetPreStateHash",false),
      scanStartBlockNumber:uint(supplied.scanStartBlockNumber,64,"scanStartBlockNumber"),
      scanStartBlockHash:b32(supplied.scanStartBlockHash,"scanStartBlockHash",false)});
    const expectedOfficial=derivePhilOfficialUserOperationHashV07({packedUserOperationBytes:simulation.packedUserOperationBytes,
      entryPoint:simulation.entryPoint,chainId:request.executionEnvironment.chainId});
    const expectedPreState=derivePhilRoutineTargetPreStateHashV1({target:simulation.target,
      approvedTargetRuntimeCodeHash:request.accountConfiguration.approvedTargetRuntimeCodeHash,
      recordedValueBefore:simulation.targetRecordedValueBefore,recordedSequenceBefore:simulation.targetRecordedSequenceBefore,
      scanStartBlockNumber:simulation.scanStartBlockNumber,scanStartBlockHash:simulation.scanStartBlockHash});
    if (keccak256(simulation.packedUserOperationBytes)!==simulation.serializedUserOperationHash
      || expectedOfficial!==simulation.officialUserOperationHash || expectedPreState!==simulation.targetPreStateHash
      || simulation.entryPoint!==request.executionEnvironment.entryPoint || simulation.sender!==request.action.account
      || simulation.target!==request.action.target || BigInt(simulation.userOperationNonce)!==BigInt(request.action.userOpNonce)) {
      fail("PHIL_ROUTINE_COORDINATOR_SIMULATION_INVALID","simulation operation or pre-state does not match the request");
    }
    return simulation;
  }

  async #assertTrustedPreSubmission(entry: CoordinatorEntryV1): Promise<void> {
    const trusted=await this.#readTrustedState(entry.request.requestId);
    if (Object.keys(trusted).sort().join(",")!=="desktopUnlocked,iphoneSessionCurrent,request") {
      fail("PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_INVALID","trusted state schema is not exact");
    }
    let current: PhilRoutineAuthorizationRequestV1;
    try { current=validatePhilRoutineAuthorizationRequestV1(trusted.request); }
    catch {
      const record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,recordedAt:this.#now(),
        evidence:{reasonHash:keccak256(toUtf8Bytes("trusted request record is invalid")) as Hex}});
      return fail("PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_DRIFT","trusted request record is invalid");
    }
    if (current.requestId!==entry.request.requestId) {
      const record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,recordedAt:this.#now(),
        evidence:{reasonHash:keccak256(toUtf8Bytes("trusted request or policy drift")) as Hex}});
      fail("PHIL_ROUTINE_COORDINATOR_TRUSTED_STATE_DRIFT","trusted request or policy changed");
    }
    if (!trusted.desktopUnlocked || !trusted.iphoneSessionCurrent) {
      const record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.FAILED_PRE_SUBMISSION,recordedAt:this.#now(),
        evidence:{reasonHash:keccak256(toUtf8Bytes("desktop lock or iPhone session replacement")) as Hex}});
      fail("PHIL_ROUTINE_COORDINATOR_SESSION_INVALID","desktop lock or iPhone session replacement invalidated the request");
    }
    if (this.#now()>BigInt(entry.request.authorizationCore.expiresAt)) {
      const record=entry.journal.read();
      await entry.journal.compareAndSwap({expectedGeneration:record.generation,expectedRecordHash:record.recordHash,
        nextState:PHIL_ROUTINE_JOURNAL_STATE_V1.EXPIRED,recordedAt:this.#now()});
      fail("PHIL_ROUTINE_COORDINATOR_EXPIRED","request expired before submission commit");
    }
  }

  async #applyOutcome(entry: CoordinatorEntryV1, outcome: PhilRoutineSyntheticExecutionOutcomeV1): Promise<void> {
    const record=entry.journal.read();
    let checked: VerifiedOutcomeV1;
    try {
      checked=outcome.kind==="success"
        ? verifyPhilRoutineSuccessfulOutcomeV1({request:entry.request,journal:record,outcome})
        : verifyPhilRoutineFailedExecutionOutcomeV1({request:entry.request,journal:record,evidence:outcome.evidence});
    } catch (error) {
      if (outcome.kind!=="success" || record.state!==PHIL_ROUTINE_JOURNAL_STATE_V1.SUBMITTED) throw error;
      const errorCode=typeof error==="object" && error!==null && "code" in error && typeof error.code==="string"
        ? error.code : "PHIL_ROUTINE_RECEIPT_INVALID";
      checked=verified(record,PHIL_ROUTINE_JOURNAL_STATE_V1.RECEIPT_INVALID,{reasonHash:keccak256(abiCoder.encode(
        ["bytes32","bytes32"],[record.recordHash,keccak256(toUtf8Bytes(errorCode))])) as Hex});
    }
    await entry.journal.publishVerifiedOutcome(checked,this.#now());
  }

  async #withLock<T>(requestId: Hex, operation: (entry: CoordinatorEntryV1) => Promise<T>): Promise<T> {
    const predecessor=this.#locks.get(requestId)??Promise.resolve();
    let release!:()=>void;const current=new Promise<void>((resolve)=>{release=resolve;});
    const chain=predecessor.then(()=>current);
    this.#locks.set(requestId,chain);
    await predecessor;
    try {
      const entry=this.#entries.get(requestId);
      if (!entry) fail("PHIL_ROUTINE_COORDINATOR_UNKNOWN_REQUEST","requestId is unknown");
      return await operation(entry);
    } finally {
      release();
      if (this.#locks.get(requestId)===chain) this.#locks.delete(requestId);
    }
  }
}
