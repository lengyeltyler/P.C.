import {
  AbiCoder,
  Interface,
  concat,
  getAddress,
  getCreate2Address,
  getCreateAddress,
  isAddress,
  isHexString,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} from "ethers";

import type { Hex } from "../hashes.ts";
import {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} from "./ethereumSepoliaReadiness.ts";
import {
  LOCAL_PROOF_GATED_SECURITY_MODEL,
  encodeLocalProofGatedExecutionCall
} from "./localProofGatedAccount.ts";
import {
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees,
  type PhilCorePackedUserOperation
} from "./philcore4337UserOperationPreparation.ts";

const abiCoder = AbiCoder.defaultAbiCoder();
const factoryInterface = new Interface([
  "function createAccount(address owner,bytes32 ownerCommitment,bytes32 validatorKeyId,uint256 salt)"
]);
const entryPointInterface = new Interface([
  "function getNonce(address sender,uint192 key) view returns (uint256)"
]);

export const LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS =
  "Conditionally Approved for Disposable Sepolia Preparation" as const;
export const LOCAL_PROOF_GATED_PREPARATION_SCHEMA =
  "philcore-local-proof-gated-preparation-v1" as const;
export const LOCAL_PROOF_GATED_VALIDATOR_KEY_BINDING_DOMAIN =
  "PHILCORE_DEVICE_VAULT_VALIDATOR_KEY_ID_BINDING_V1" as const;
export const LOCAL_PROOF_GATED_PREPARATION_LIMITS = Object.freeze({
  maxVerificationGasLimit: 1_500_000n,
  maxCallGasLimit: 300_000n,
  maxPreVerificationGas: 200_000n,
  maxFeePerGasWei: 100_000_000_000n,
  maxPriorityFeePerGasWei: 5_000_000_000n,
  maxAuthorizationLifetimeSeconds: 600n
});

export type SepoliaReadOnlyRpcMethod =
  | "eth_chainId"
  | "eth_blockNumber"
  | "eth_getCode"
  | "eth_getBalance"
  | "eth_getTransactionCount"
  | "eth_gasPrice"
  | "eth_feeHistory"
  | "eth_call"
  | "eth_estimateGas";

export type SepoliaBundlerPreparationMethod =
  | "eth_chainId"
  | "eth_supportedEntryPoints"
  | "eth_estimateUserOperationGas"
  | "eth_getUserOperationByHash"
  | "eth_getUserOperationReceipt";

export interface JsonRpcRequestTransport {
  request(method: string, params: readonly unknown[]): Promise<unknown>;
}

export class RestrictedJsonRpcError extends Error {
  readonly service: "chain_rpc" | "bundler";
  readonly code?: number;
  readonly data?: unknown;
  readonly requestId?: string | number | null;

  constructor(input: {
    readonly service: "chain_rpc" | "bundler";
    readonly message: string;
    readonly code?: number;
    readonly data?: unknown;
    readonly requestId?: string | number | null;
  }) {
    super(input.message);
    this.name = "RestrictedJsonRpcError";
    this.service = input.service;
    this.code = input.code;
    this.data = input.data;
    this.requestId = input.requestId;
  }
}

export interface RestrictedSepoliaReadOnlyClient {
  readonly endpointClassification: string;
  readonly mutationMethodsExposed: false;
  request(method: SepoliaReadOnlyRpcMethod, params: readonly unknown[]): Promise<unknown>;
}

export interface RestrictedSepoliaBundlerClient {
  readonly endpointClassification: string;
  readonly mutationMethodsExposed: false;
  request(method: SepoliaBundlerPreparationMethod, params: readonly unknown[]): Promise<unknown>;
}

export interface LocalProofGatedProposedAddressInputs {
  readonly deployerAddress: string;
  readonly deployerNonce: string;
  readonly ownerAddress: string;
  readonly ownerCommitment: Hex;
  readonly validatorKeyId: Hex;
  readonly accountSalt: string;
  readonly accountCreationBytecode: Hex;
}

export interface LocalProofGatedProposedAddresses {
  readonly status: "calculated" | "inputs_missing" | "invalid";
  readonly targetAddress?: string;
  readonly factoryAddress?: string;
  readonly accountAddress?: string;
  readonly targetDeploymentNonce?: string;
  readonly factoryDeploymentNonce?: string;
  readonly inputs?: Readonly<{
    readonly deployerAddress: string;
    readonly ownerAddress: string;
    readonly ownerCommitment: Hex;
    readonly validatorKeyId: Hex;
    readonly accountSalt: string;
    readonly chainId: typeof ETHEREUM_SEPOLIA_CHAIN_ID;
    readonly entryPointAddress: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
  }>;
  readonly missing: readonly string[];
  readonly errors: readonly string[];
}

export interface LocalProofGatedAddressObservation {
  readonly address: string;
  readonly codeStatus: "empty" | "code_present" | "not_checked";
  readonly codeHash?: Hex;
  readonly balanceWei?: string;
}

export interface LocalProofGatedSepoliaPreparationPreflight {
  readonly schemaVersion: typeof LOCAL_PROOF_GATED_PREPARATION_SCHEMA;
  readonly status:
    | "READ_ONLY_RPC_NOT_CONFIGURED"
    | "READ_ONLY_PREFLIGHT_PASSED"
    | "READ_ONLY_PREFLIGHT_FAILED";
  readonly checkedAt: string;
  readonly rpcClassification: string;
  readonly chainId?: number;
  readonly blockNumber?: string;
  readonly entryPoint: Readonly<{
    readonly address: typeof ERC4337_V07_CANONICAL_ENTRYPOINT;
    readonly codePresent: boolean;
    readonly codeHash?: Hex;
    readonly balanceWei?: string;
    readonly getNonceCallSupported?: boolean;
  }>;
  readonly proposedAddresses: Readonly<Record<string, LocalProofGatedAddressObservation>>;
  readonly deployer?: Readonly<{
    readonly address: string;
    readonly configuredPendingNonce: string;
    readonly observedLatestNonce?: string;
    readonly observedPendingNonce?: string;
    readonly nonceMatched: boolean;
    readonly balanceWei?: string;
  }>;
  readonly validator?: Readonly<{
    readonly address: string;
    readonly codePresent: boolean;
    readonly balanceWei?: string;
  }>;
  readonly feeData: Readonly<{
    readonly gasPriceWei?: string;
    readonly source: "rpc" | "unresolved";
  }>;
  readonly mutationMethodsExposed: false;
  readonly mutationAttempted: false;
  readonly publicMutationOccurred: false;
  readonly errors: readonly string[];
}

export interface LocalProofGatedGasEstimates {
  readonly source: "live_read_only_rpc" | "local_fixture" | "unresolved";
  readonly targetDeploymentGas?: string;
  readonly factoryDeploymentGas?: string;
  readonly counterfactualAccountVerificationGas?: string;
  readonly firstUserOperationCallGas?: string;
  readonly firstUserOperationPreVerificationGas?: string;
  readonly gasPriceWei?: string;
  readonly maxFeePerGasWei?: string;
  readonly maxPriorityFeePerGasWei?: string;
  readonly bundlerEstimateStatus:
    | "configured_read_only"
    | "BUNDLER_ESTIMATE_NOT_CONFIGURED"
    | "failed";
}

export interface LocalProofGatedFundingPlan {
  readonly status: "calculated" | "estimates_unresolved" | "invalid";
  readonly deployerMinimumWei?: string;
  readonly accountPrefundMinimumWei?: string;
  readonly totalMinimumWei?: string;
  readonly conservativeRecommendedWei?: string;
  readonly hardMaximumExposureWei?: string;
  readonly bufferBasisPoints: number;
  readonly entryPointDepositRequired: false;
  readonly counterfactualAccountPreFundingRequired: true;
  readonly unusedSepoliaEthTreatment: "retain only in disposable test addresses";
  readonly errors: readonly string[];
}

export interface LocalProofGatedFirstUserOperationInput {
  readonly sender: string;
  readonly factoryAddress: string;
  readonly ownerAddress: string;
  readonly ownerCommitment: Hex;
  readonly validatorKeyId: Hex;
  readonly accountSalt: string;
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
  readonly expiry: string;
  readonly nonce: string;
  readonly verificationGasLimit: string;
  readonly callGasLimit: string;
  readonly preVerificationGas: string;
  readonly maxFeePerGas: string;
  readonly maxPriorityFeePerGas: string;
  readonly nowSeconds?: number;
}

export interface LocalProofGatedFirstUserOperationProposal {
  readonly status: "proposed_unsigned";
  readonly securityModel: typeof LOCAL_PROOF_GATED_SECURITY_MODEL;
  readonly userOperation: PhilCorePackedUserOperation;
  readonly userOperationHash: Hex;
  readonly actionId: Hex;
  readonly authorizationDigest: Hex;
  readonly expiry: string;
  readonly targetMethod: "confirmPhilCoreAction(bytes32,bytes32)";
  readonly valueWei: "0";
  readonly tokenMovement: false;
  readonly paymasterEnabled: false;
  readonly batchEnabled: false;
  readonly delegatecallEnabled: false;
  readonly signaturePresent: false;
  readonly publicMutationAuthorized: false;
  readonly publicMutationOccurred: false;
}

export type LocalProofGatedMutationStage =
  | "target_deployment"
  | "factory_deployment"
  | "account_funding"
  | "first_user_operation_submission";

export interface LocalProofGatedMutationGateResult {
  readonly stage: LocalProofGatedMutationStage;
  readonly allowed: boolean;
  readonly errors: readonly string[];
}

function freezeRecord<T>(value: T): T {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeRecord)) as T;
  if (value && typeof value === "object") {
    return Object.freeze(Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, freezeRecord(entry)])
    )) as T;
  }
  return value;
}

function parseNonNegative(value: string): bigint {
  const parsed = BigInt(value);
  if (parsed < 0n) throw new Error("negative integer");
  return parsed;
}

function toQuantity(value: bigint): string {
  return `0x${value.toString(16)}`;
}

export function redactRpcEndpoint(rawUrl: string | undefined): string {
  if (!rawUrl) return "not_configured";
  try {
    const parsed = new URL(rawUrl);
    const port = parsed.port ? `:${parsed.port}` : "";
    return `${parsed.protocol}//${parsed.hostname}${port}/<redacted>`;
  } catch {
    return "configured_invalid_url_redacted";
  }
}

export function deriveLocalProofGatedValidatorKeyIdBinding(
  validatorKeyReferenceId: string
): Hex {
  if (!/^validator_key_[0-9a-f]{16}$/.test(validatorKeyReferenceId)) {
    throw new Error("validator_key_reference_id_invalid");
  }
  return keccak256(toUtf8Bytes(
    `${LOCAL_PROOF_GATED_VALIDATOR_KEY_BINDING_DOMAIN}:${validatorKeyReferenceId}`
  )) as Hex;
}

export function createRestrictedSepoliaReadOnlyClient(input: {
  readonly url: string;
  readonly transport?: JsonRpcRequestTransport;
}): RestrictedSepoliaReadOnlyClient {
  const endpointClassification = redactRpcEndpoint(input.url);
  let chainVerified = false;
  const allowed = new Set<SepoliaReadOnlyRpcMethod>([
    "eth_chainId",
    "eth_blockNumber",
    "eth_getCode",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_gasPrice",
    "eth_feeHistory",
    "eth_call",
    "eth_estimateGas"
  ]);
  let requestId = 0;
  const transport = input.transport ?? {
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      const response = await fetch(input.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++requestId, method, params })
      });
      if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
      const payload = await response.json() as {
        id?: string | number | null;
        result?: unknown;
        error?: { code?: number; message?: string; data?: unknown };
      };
      if (payload.error) {
        throw new RestrictedJsonRpcError({
          service: "chain_rpc",
          message: payload.error.message ?? "RPC request failed",
          code: payload.error.code,
          data: payload.error.data,
          requestId: payload.id
        });
      }
      return payload.result;
    }
  };
  return Object.freeze({
    endpointClassification,
    mutationMethodsExposed: false as const,
    async request(method: SepoliaReadOnlyRpcMethod, params: readonly unknown[]): Promise<unknown> {
      if (!allowed.has(method)) throw new Error("RPC_METHOD_NOT_ALLOWED");
      if (!chainVerified && method !== "eth_chainId") throw new Error("CHAIN_ID_MUST_BE_VERIFIED_FIRST");
      const result = await transport.request(method, params);
      if (method === "eth_chainId") {
        if (Number(BigInt(String(result))) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
          throw new Error("WRONG_ETHEREUM_CHAIN");
        }
        chainVerified = true;
      }
      return result;
    }
  });
}

export function createRestrictedSepoliaBundlerClient(input: {
  readonly url: string;
  readonly transport?: JsonRpcRequestTransport;
}): RestrictedSepoliaBundlerClient {
  const allowed = new Set<SepoliaBundlerPreparationMethod>([
    "eth_chainId",
    "eth_supportedEntryPoints",
    "eth_estimateUserOperationGas",
    "eth_getUserOperationByHash",
    "eth_getUserOperationReceipt"
  ]);
  let requestId = 0;
  const transport = input.transport ?? {
    async request(method: string, params: readonly unknown[]): Promise<unknown> {
      const response = await fetch(input.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++requestId, method, params })
      });
      if (!response.ok) throw new Error(`Bundler HTTP ${response.status}`);
      const payload = await response.json() as {
        id?: string | number | null;
        result?: unknown;
        error?: { code?: number; message?: string; data?: unknown };
      };
      if (payload.error) {
        throw new RestrictedJsonRpcError({
          service: "bundler",
          message: payload.error.message ?? "Bundler request failed",
          code: payload.error.code,
          data: payload.error.data,
          requestId: payload.id
        });
      }
      return payload.result;
    }
  };
  return Object.freeze({
    endpointClassification: redactRpcEndpoint(input.url),
    mutationMethodsExposed: false as const,
    async request(method: SepoliaBundlerPreparationMethod, params: readonly unknown[]): Promise<unknown> {
      if (!allowed.has(method)) throw new Error("BUNDLER_METHOD_NOT_ALLOWED");
      return transport.request(method, params);
    }
  });
}

export function calculateLocalProofGatedProposedAddresses(
  input?: Partial<LocalProofGatedProposedAddressInputs>
): LocalProofGatedProposedAddresses {
  const required = [
    "deployerAddress",
    "deployerNonce",
    "ownerAddress",
    "ownerCommitment",
    "validatorKeyId",
    "accountSalt",
    "accountCreationBytecode"
  ] as const;
  const missing = required.filter((key) => input?.[key] === undefined || input[key] === "");
  if (missing.length > 0) {
    return freezeRecord({ status: "inputs_missing", missing, errors: [] });
  }
  try {
    const value = input as LocalProofGatedProposedAddressInputs;
    if (!isAddress(value.deployerAddress) || !isAddress(value.ownerAddress)) {
      throw new Error("address_invalid");
    }
    if (!isHexString(value.ownerCommitment, 32)) throw new Error("owner_commitment_invalid");
    if (!isHexString(value.validatorKeyId, 32)) throw new Error("validator_key_id_invalid");
    if (!isHexString(value.accountCreationBytecode)) throw new Error("account_bytecode_invalid");
    const deployerNonce = parseNonNegative(value.deployerNonce);
    const salt = parseNonNegative(value.accountSalt);
    const targetAddress = getCreateAddress({ from: getAddress(value.deployerAddress), nonce: deployerNonce });
    // The factory deploys accounts directly. No standalone implementation transaction exists.
    const factoryAddress = getCreateAddress({
      from: getAddress(value.deployerAddress),
      nonce: deployerNonce + 1n
    });
    const constructorData = abiCoder.encode(
      ["address", "address", "bytes32", "address", "bytes32", "uint256"],
      [
        ERC4337_V07_CANONICAL_ENTRYPOINT,
        getAddress(value.ownerAddress),
        value.ownerCommitment,
        targetAddress,
        value.validatorKeyId,
        ETHEREUM_SEPOLIA_CHAIN_ID
      ]
    );
    const accountInitCodeHash = keccak256(concat([value.accountCreationBytecode, constructorData]));
    const accountAddress = getCreate2Address(
      factoryAddress,
      zeroPadValue(toBeHex(salt), 32),
      accountInitCodeHash
    );
    return freezeRecord({
      status: "calculated",
      targetAddress,
      factoryAddress,
      accountAddress,
      targetDeploymentNonce: deployerNonce.toString(),
      factoryDeploymentNonce: (deployerNonce + 1n).toString(),
      inputs: {
        deployerAddress: getAddress(value.deployerAddress),
        ownerAddress: getAddress(value.ownerAddress),
        ownerCommitment: value.ownerCommitment,
        validatorKeyId: value.validatorKeyId,
        accountSalt: salt.toString(),
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
        entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT
      },
      missing: [],
      errors: []
    });
  } catch (error) {
    return freezeRecord({
      status: "invalid",
      missing: [],
      errors: [error instanceof Error ? error.message : "address_calculation_failed"]
    });
  }
}

export async function runLocalProofGatedPreparationPreflight(input: {
  readonly client?: RestrictedSepoliaReadOnlyClient;
  readonly proposedAddresses?: Readonly<Record<string, string | undefined>>;
  readonly deployer?: Readonly<{
    readonly address: string;
    readonly configuredPendingNonce: string;
  }>;
  readonly validatorAddress?: string;
  readonly checkedAt?: string;
}): Promise<LocalProofGatedSepoliaPreparationPreflight> {
  const observations: Record<string, LocalProofGatedAddressObservation> = {};
  for (const [name, address] of Object.entries(input.proposedAddresses ?? {})) {
    if (address && isAddress(address)) {
      observations[name] = { address: getAddress(address), codeStatus: "not_checked" };
    }
  }
  const checkedAt = input.checkedAt ?? new Date().toISOString();
  if (!input.client) {
    return freezeRecord({
      schemaVersion: LOCAL_PROOF_GATED_PREPARATION_SCHEMA,
      status: "READ_ONLY_RPC_NOT_CONFIGURED",
      checkedAt,
      rpcClassification: "not_configured",
      entryPoint: {
        address: ERC4337_V07_CANONICAL_ENTRYPOINT,
        codePresent: false
      },
      proposedAddresses: observations,
      deployer: input.deployer && isAddress(input.deployer.address)
        ? {
            address: getAddress(input.deployer.address),
            configuredPendingNonce: input.deployer.configuredPendingNonce,
            nonceMatched: false
          }
        : undefined,
      validator: input.validatorAddress && isAddress(input.validatorAddress)
        ? { address: getAddress(input.validatorAddress), codePresent: false }
        : undefined,
      feeData: { source: "unresolved" },
      mutationMethodsExposed: false,
      mutationAttempted: false,
      publicMutationOccurred: false,
      errors: ["PHILCORE_SEPOLIA_RPC_URL is not configured"]
    });
  }
  const errors: string[] = [];
  let chainId: number | undefined;
  try {
    chainId = Number(BigInt(String(await input.client.request("eth_chainId", []))));
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "chain_id_read_failed");
    return freezeRecord({
      schemaVersion: LOCAL_PROOF_GATED_PREPARATION_SCHEMA,
      status: "READ_ONLY_PREFLIGHT_FAILED",
      checkedAt,
      rpcClassification: input.client.endpointClassification,
      chainId,
      entryPoint: {
        address: ERC4337_V07_CANONICAL_ENTRYPOINT,
        codePresent: false
      },
      proposedAddresses: observations,
      deployer: input.deployer && isAddress(input.deployer.address)
        ? {
            address: getAddress(input.deployer.address),
            configuredPendingNonce: input.deployer.configuredPendingNonce,
            nonceMatched: false
          }
        : undefined,
      validator: input.validatorAddress && isAddress(input.validatorAddress)
        ? { address: getAddress(input.validatorAddress), codePresent: false }
        : undefined,
      feeData: { source: "unresolved" },
      mutationMethodsExposed: false,
      mutationAttempted: false,
      publicMutationOccurred: false,
      errors
    });
  }
  let blockNumber: string | undefined;
  let entryPointCode = "0x";
  let entryPointBalance: string | undefined;
  let getNonceCallSupported = false;
  let gasPriceWei: string | undefined;
  let deployer: LocalProofGatedSepoliaPreparationPreflight["deployer"];
  let validator: LocalProofGatedSepoliaPreparationPreflight["validator"];
  try {
    blockNumber = BigInt(String(await input.client.request("eth_blockNumber", []))).toString();
    entryPointCode = String(await input.client.request("eth_getCode", [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      "latest"
    ]));
    if (entryPointCode === "0x" || entryPointCode === "0x0") errors.push("entry_point_code_missing");
    entryPointBalance = BigInt(String(await input.client.request("eth_getBalance", [
      ERC4337_V07_CANONICAL_ENTRYPOINT,
      "latest"
    ]))).toString();
    const nonceCall = entryPointInterface.encodeFunctionData("getNonce", [
      "0x0000000000000000000000000000000000000001",
      0
    ]);
    await input.client.request("eth_call", [{
      to: ERC4337_V07_CANONICAL_ENTRYPOINT,
      data: nonceCall
    }, "latest"]);
    getNonceCallSupported = true;
    gasPriceWei = BigInt(String(await input.client.request("eth_gasPrice", []))).toString();
    if (input.deployer && isAddress(input.deployer.address)) {
      const address = getAddress(input.deployer.address);
      const observedLatestNonce = BigInt(String(await input.client.request(
        "eth_getTransactionCount",
        [address, "latest"]
      ))).toString();
      const observedPendingNonce = BigInt(String(await input.client.request(
        "eth_getTransactionCount",
        [address, "pending"]
      ))).toString();
      const balanceWei = BigInt(String(await input.client.request("eth_getBalance", [
        address,
        "latest"
      ]))).toString();
      const nonceMatched = observedPendingNonce === input.deployer.configuredPendingNonce;
      deployer = {
        address,
        configuredPendingNonce: input.deployer.configuredPendingNonce,
        observedLatestNonce,
        observedPendingNonce,
        nonceMatched,
        balanceWei
      };
      if (!nonceMatched) errors.push("deployer_pending_nonce_mismatch");
    }
    if (input.validatorAddress && isAddress(input.validatorAddress)) {
      const address = getAddress(input.validatorAddress);
      const code = String(await input.client.request("eth_getCode", [address, "latest"]));
      const balanceWei = BigInt(String(await input.client.request("eth_getBalance", [
        address,
        "latest"
      ]))).toString();
      validator = {
        address,
        codePresent: code !== "0x" && code !== "0x0",
        balanceWei
      };
    }
  } catch (error) {
    errors.push(error instanceof Error ? error.message : "entry_point_read_failed");
  }
  for (const [name, observation] of Object.entries(observations)) {
    try {
      const code = String(await input.client.request("eth_getCode", [observation.address, "latest"]));
      const balance = BigInt(String(await input.client.request("eth_getBalance", [
        observation.address,
        "latest"
      ]))).toString();
      observations[name] = {
        address: observation.address,
        codeStatus: code === "0x" || code === "0x0" ? "empty" : "code_present",
        ...(code === "0x" || code === "0x0" ? {} : { codeHash: keccak256(code) as Hex }),
        balanceWei: balance
      };
      if (observations[name]?.codeStatus === "code_present") errors.push(`${name}_address_collision`);
    } catch {
      errors.push(`${name}_address_read_failed`);
    }
  }
  return freezeRecord({
    schemaVersion: LOCAL_PROOF_GATED_PREPARATION_SCHEMA,
    status: errors.length === 0 ? "READ_ONLY_PREFLIGHT_PASSED" : "READ_ONLY_PREFLIGHT_FAILED",
    checkedAt,
    rpcClassification: input.client.endpointClassification,
    chainId,
    blockNumber,
    entryPoint: {
      address: ERC4337_V07_CANONICAL_ENTRYPOINT,
      codePresent: entryPointCode !== "0x" && entryPointCode !== "0x0",
      ...(entryPointCode === "0x" || entryPointCode === "0x0"
        ? {}
        : { codeHash: keccak256(entryPointCode) as Hex }),
      entryPointBalance,
      getNonceCallSupported
    },
    proposedAddresses: observations,
    deployer,
    validator,
    feeData: {
      gasPriceWei,
      source: gasPriceWei === undefined ? "unresolved" : "rpc"
    },
    mutationMethodsExposed: false,
    mutationAttempted: false,
    publicMutationOccurred: false,
    errors
  });
}

export function calculateLocalProofGatedFundingPlan(input: {
  readonly estimates: LocalProofGatedGasEstimates;
  readonly bufferBasisPoints?: number;
  readonly hardMaximumExposureWei?: string;
}): LocalProofGatedFundingPlan {
  const bufferBasisPoints = input.bufferBasisPoints ?? 2_500;
  try {
    const required = [
      input.estimates.targetDeploymentGas,
      input.estimates.factoryDeploymentGas,
      input.estimates.counterfactualAccountVerificationGas,
      input.estimates.firstUserOperationCallGas,
      input.estimates.firstUserOperationPreVerificationGas,
      input.estimates.maxFeePerGasWei
    ];
    if (required.some((value) => value === undefined)) {
      return freezeRecord({
        status: "estimates_unresolved",
        bufferBasisPoints,
        entryPointDepositRequired: false,
        counterfactualAccountPreFundingRequired: true,
        unusedSepoliaEthTreatment: "retain only in disposable test addresses",
        errors: ["live gas or fee estimates are unresolved"]
      });
    }
    const [
      targetGas,
      factoryGas,
      accountVerificationGas,
      callGas,
      preVerificationGas,
      maxFeePerGas
    ] = required.map((value) => parseNonNegative(value!));
    const deployerMinimum = (targetGas! + factoryGas!) * maxFeePerGas!;
    const accountMinimum = (
      accountVerificationGas! + callGas! + preVerificationGas!
    ) * maxFeePerGas!;
    const total = deployerMinimum + accountMinimum;
    const recommended = total * BigInt(10_000 + bufferBasisPoints) / 10_000n;
    const hardMaximum = input.hardMaximumExposureWei
      ? parseNonNegative(input.hardMaximumExposureWei)
      : recommended;
    if (recommended > hardMaximum) throw new Error("recommended funding exceeds hard maximum");
    return freezeRecord({
      status: "calculated",
      deployerMinimumWei: deployerMinimum.toString(),
      accountPrefundMinimumWei: accountMinimum.toString(),
      totalMinimumWei: total.toString(),
      conservativeRecommendedWei: recommended.toString(),
      hardMaximumExposureWei: hardMaximum.toString(),
      bufferBasisPoints,
      entryPointDepositRequired: false,
      counterfactualAccountPreFundingRequired: true,
      unusedSepoliaEthTreatment: "retain only in disposable test addresses",
      errors: []
    });
  } catch (error) {
    return freezeRecord({
      status: "invalid",
      bufferBasisPoints,
      entryPointDepositRequired: false,
      counterfactualAccountPreFundingRequired: true,
      unusedSepoliaEthTreatment: "retain only in disposable test addresses",
      errors: [error instanceof Error ? error.message : "funding_calculation_failed"]
    });
  }
}

export function createLocalProofGatedFirstUserOperationProposal(
  input: LocalProofGatedFirstUserOperationInput
): LocalProofGatedFirstUserOperationProposal {
  const verificationGasLimit = parseNonNegative(input.verificationGasLimit);
  const callGasLimit = parseNonNegative(input.callGasLimit);
  const preVerificationGas = parseNonNegative(input.preVerificationGas);
  const maxFeePerGas = parseNonNegative(input.maxFeePerGas);
  const maxPriorityFeePerGas = parseNonNegative(input.maxPriorityFeePerGas);
  const expiry = parseNonNegative(input.expiry);
  const nowSeconds = BigInt(input.nowSeconds ?? Math.floor(Date.now() / 1000));
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  if (verificationGasLimit > limits.maxVerificationGasLimit) {
    throw new Error("verification_gas_cap_exceeded");
  }
  if (callGasLimit > limits.maxCallGasLimit) throw new Error("call_gas_cap_exceeded");
  if (preVerificationGas > limits.maxPreVerificationGas) {
    throw new Error("pre_verification_gas_cap_exceeded");
  }
  if (maxFeePerGas > limits.maxFeePerGasWei) throw new Error("max_fee_cap_exceeded");
  if (maxPriorityFeePerGas > limits.maxPriorityFeePerGasWei) {
    throw new Error("priority_fee_cap_exceeded");
  }
  if (expiry <= nowSeconds) throw new Error("authorization_expired");
  if (expiry > nowSeconds + limits.maxAuthorizationLifetimeSeconds) {
    throw new Error("authorization_lifetime_exceeded");
  }
  const factoryData = factoryInterface.encodeFunctionData("createAccount", [
    getAddress(input.ownerAddress),
    input.ownerCommitment,
    input.validatorKeyId,
    parseNonNegative(input.accountSalt)
  ]) as Hex;
  const callData = encodeLocalProofGatedExecutionCall({
    actionId: input.actionId,
    authorizationDigest: input.authorizationDigest,
    expiry: expiry.toString()
  });
  const userOperation: PhilCorePackedUserOperation = {
    sender: getAddress(input.sender),
    nonce: parseNonNegative(input.nonce).toString(),
    initCode: concat([getAddress(input.factoryAddress), factoryData]) as Hex,
    callData,
    accountGasLimits: packPhilCore4337AccountGasLimits({
      verificationGasLimit: verificationGasLimit.toString(),
      callGasLimit: callGasLimit.toString()
    }),
    preVerificationGas: preVerificationGas.toString(),
    gasFees: packPhilCore4337GasFees({
      maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
      maxFeePerGas: maxFeePerGas.toString()
    }),
    paymasterAndData: PHILCORE_4337_EMPTY_BYTES,
    signature: PHILCORE_4337_EMPTY_BYTES
  };
  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID
  });
  return freezeRecord({
    status: "proposed_unsigned",
    securityModel: LOCAL_PROOF_GATED_SECURITY_MODEL,
    userOperation,
    userOperationHash,
    actionId: input.actionId,
    authorizationDigest: input.authorizationDigest,
    expiry: expiry.toString(),
    targetMethod: "confirmPhilCoreAction(bytes32,bytes32)",
    valueWei: "0",
    tokenMovement: false,
    paymasterEnabled: false,
    batchEnabled: false,
    delegatecallEnabled: false,
    signaturePresent: false,
    publicMutationAuthorized: false,
    publicMutationOccurred: false
  });
}

export function evaluateLocalProofGatedMutationGate(input: {
  readonly stage: LocalProofGatedMutationStage;
  readonly environment: Readonly<Record<string, string | undefined>>;
  readonly manifestStatus: string;
  readonly architectureApprovalStatus: string;
  readonly repositoryClean: boolean;
}): LocalProofGatedMutationGateResult {
  const errors: string[] = [];
  const common = [
    "PHILCORE_PUBLIC_NETWORK_APPROVED",
    "PHILCORE_ETHEREUM_SEPOLIA_APPROVED",
    "PHILCORE_LOCAL_PROOF_ACCOUNT_MODEL_APPROVED"
  ];
  const stageGate: Record<LocalProofGatedMutationStage, string> = {
    target_deployment: "PHILCORE_SEPOLIA_TARGET_DEPLOYMENT_APPROVED",
    factory_deployment: "PHILCORE_SEPOLIA_ACCOUNT_DEPLOYMENT_APPROVED",
    account_funding: "PHILCORE_SEPOLIA_FUNDING_APPROVED",
    first_user_operation_submission: "PHILCORE_SEPOLIA_USEROP_SUBMISSION_APPROVED"
  };
  for (const name of [...common, stageGate[input.stage]]) {
    if (input.environment[name] !== "1") errors.push(`${name}_missing`);
  }
  if (input.manifestStatus !== "accepted") errors.push("accepted_manifest_required");
  if (
    input.architectureApprovalStatus
      !== LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS
  ) {
    errors.push("scoped_architecture_approval_missing");
  }
  if (!input.repositoryClean) errors.push("repository_not_clean");
  return freezeRecord({ stage: input.stage, allowed: errors.length === 0, errors });
}

export function hashLocalProofGatedConstructorData(input: {
  readonly types: readonly string[];
  readonly values: readonly unknown[];
}): Hex {
  return keccak256(abiCoder.encode([...input.types], [...input.values])) as Hex;
}

export function toRpcQuantity(value: string): string {
  return toQuantity(parseNonNegative(value));
}
