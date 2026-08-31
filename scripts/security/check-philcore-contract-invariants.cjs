#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..");
const reportPath = path.join(repoRoot, "config/security/philcore-contract-invariants-report.json");

function read(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
}

function bodyOf(source, signature) {
  const start = source.indexOf(signature);
  if (start === -1) return "";
  const open = source.indexOf("{", start);
  if (open === -1) return "";
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    if (source[i] === "}") depth -= 1;
    if (depth === 0) return source.slice(open, i + 1);
  }
  return "";
}

const files = {
  account: "contracts/base/erc4337/PhilCore4337Account.sol",
  factory: "contracts/base/erc4337/PhilCore4337AccountFactory.sol",
  localProofAccount: "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol",
  localProofFactory: "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
  localProofTarget: "contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol",
  sepoliaMintAccount: "contracts/base/erc4337/PhilSepoliaMintAccountV1.sol",
  sepoliaMintFactory: "contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol",
  sepoliaMintGate: "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol",
  sepoliaMintConsumer: "contracts/base/PhilSepoliaMintPassConsumerV1.sol",
  actionGate: "contracts/base/PhilBaseActionGate.sol",
  mirror: "contracts/base/PhilBaseProofInputHashMirror.sol",
  verifier: "contracts/base/PhilBaseMirroredFactUnlockProofVerifier.sol",
  mintConsumer: "contracts/base/PhilMintPassConsumer.sol",
  l1Anchor: "contracts/l1/PhilL1ProofInputHashAnchor.sol",
  l1Relay: "contracts/l1/PhilL1ToBaseProofInputHashMessenger.sol"
};

const source = Object.fromEntries(Object.entries(files).map(([key, file]) => [key, read(file)]));
const accountValidateUserOp = bodyOf(source.account, "function validateUserOp(");
const accountExecute = bodyOf(source.account, "function execute(address target, uint256 value, bytes calldata data) external");
const accountReleaseTestFunds = bodyOf(source.account, "function releaseTestFunds(uint256 nativeAmountWei, uint256 entryPointDepositAmountWei)");
const accountValidate = bodyOf(source.account, "function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)");
const requestRecovery = bodyOf(source.account, "function requestRecovery(address pendingOwner) external");
const completeRecovery = bodyOf(source.account, "function completeRecovery(bytes32 requestId, address expectedPendingOwner) external");
const requestRecoveryAuthorityRotation = bodyOf(source.account, "function requestRecoveryAuthorityRotation(address pendingRecoveryAuthority, address expectedProposer)");
const cancelRecoveryAuthorityRotation = bodyOf(source.account, "function cancelRecoveryAuthorityRotation(bytes32 requestId, address expectedCanceller) external");
const completeRecoveryAuthorityRotation = bodyOf(source.account, "function completeRecoveryAuthorityRotation(bytes32 requestId, address expectedPendingRecoveryAuthority) external");
const factoryGetAddress = bodyOf(source.factory, "function getAddress(address owner, bytes32 ownerCommitment, uint256 salt)");
const localProofExecute = bodyOf(source.localProofAccount, "function executeLocalProofAuthorization(");
const localProofValidate = bodyOf(source.localProofAccount, "function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)");
const localProofFactoryGetAddress = bodyOf(source.localProofFactory, "function getAddress(");
const localProofConfirm = bodyOf(source.localProofTarget, "function confirmPhilCoreAction(bytes32 actionId, bytes32 authorizationDigest) external");
const sepoliaMintExecute = bodyOf(source.sepoliaMintAccount, "function execute(address target, uint256 value, bytes calldata data) external");
const sepoliaMintValidate = bodyOf(source.sepoliaMintAccount, "function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)");
const sepoliaMintFactoryAddress = bodyOf(source.sepoliaMintFactory, "function getAddress(address executionOwner, bytes32 ownerCommitment, uint256 salt)");
const sepoliaMintGateConsume = bodyOf(source.sepoliaMintGate, "function verifyAndConsume(");
const sepoliaMintConsumerConsume = bodyOf(source.sepoliaMintConsumer, "function consumeComposedMint(");
const actionVerify = bodyOf(source.actionGate, "function verifyAndConsume(");
const mirrorBody = bodyOf(source.mirror, "function mirrorProofInputHashFact(uint256 factHigh, uint256 factLow) external");
const mintConsume = bodyOf(source.mintConsumer, "function consumePhilAuthorization(BaseActionAuthorization calldata authorization, bytes calldata consumerData)");

const productionSources = Object.entries(files)
  .filter(([, file]) => !file.includes("/mocks/"))
  .map(([key, file]) => ({ key, file, text: source[key] }));

const checks = [
  {
    id: "N6-INV-001",
    description: "PhilCore4337Account.execute remains EntryPoint-only.",
    passed: accountExecute.includes("_requireFromEntryPoint();")
  },
  {
    id: "N6-INV-002",
    description: "PhilCore4337Account.execute restricts target to immutable approvedActionGate.",
    passed: accountExecute.includes("target != approvedActionGate")
  },
  {
    id: "N6-INV-003",
    description: "PhilCore4337Account.execute restricts calldata to the two reviewed ActionGate selectors.",
    passed: accountExecute.includes("COMPOSED_VERIFY_AND_CONSUME_SELECTOR")
      && accountExecute.includes("VERIFY_AND_CONSUME_SELECTOR")
      && accountExecute.includes("bytes4(data[:4])")
  },
  {
    id: "N6-INV-004",
    description: "Account-self cannot bypass execution restrictions.",
    passed: !accountExecute.includes("target == address(this)") && source.account.includes("UnauthorizedExecutionTarget")
  },
  {
    id: "N6-INV-005",
    description: "No delegatecall exists in the account/factory path.",
    passed: !/delegatecall\s*\(/.test(source.account) && !/delegatecall\s*\(/.test(source.factory)
  },
  {
    id: "N6-INV-006",
    description: "No generic batch execution exists in the account/factory path.",
    passed: !/executeBatch|batchExecute|multicall|batch\s*\(/.test(source.account) && !/executeBatch|batchExecute|multicall|batch\s*\(/.test(source.factory)
  },
  {
    id: "N6-INV-007",
    description: "No upgrade/proxy entry point exists in the account/factory path.",
    passed: !/upgradeTo|upgradeToAndCall|implementation|delegatecall|proxy/i.test(`${source.account}\n${source.factory}`)
  },
  {
    id: "N6-INV-008",
    description: "Recovery authority cannot invoke ordinary execution.",
    passed: accountValidate.includes("expectedSigner = _owner")
      && accountValidate.includes("this.requestRecovery.selector")
      && accountValidate.includes("this.completeRecovery.selector")
      && !accountExecute.includes("recoveryAuthority")
  },
  {
    id: "N6-INV-009",
    description: "Recovery functions do not change EntryPoint, ActionGate, or ownerCommitment.",
    passed: !/_entryPoint\s*=|approvedActionGate\s*=|ownerCommitment\s*=/.test(`${requestRecovery}\n${completeRecovery}`)
  },
  {
    id: "N6-INV-010",
    description: "Factory and account share exact ActionGate binding.",
    passed: source.factory.includes("address public immutable approvedActionGate")
      && source.factory.includes("approvedActionGate,")
      && factoryGetAddress.includes("approvedActionGate")
  },
  {
    id: "N6-INV-011",
    description: "CREATE2 derivation includes initialization-critical fields.",
    passed: [
      "entryPoint",
      "owner",
      "ownerCommitment",
      "approvedActionGate",
      "recoveryAuthority",
      "recoveryDelaySeconds",
      "recoveryExpirySeconds"
    ].every((token) => factoryGetAddress.includes(token))
  },
  {
    id: "N6-INV-012",
    description: "Paymasters are explicitly rejected and no session-key or aggregator behavior exists.",
    passed: accountValidateUserOp.includes("userOp.paymasterAndData.length != 0")
      && accountValidateUserOp.includes("PaymasterForbidden")
      && !/sessionKey|session key|aggregator/i.test(`${source.account}\n${source.factory}`)
  },
  {
    id: "N6-INV-013",
    description: "Base mirror remains messenger-only.",
    passed: mirrorBody.includes("msg.sender != crossDomainMessenger") && mirrorBody.includes("OnlyCrossDomainMessenger")
  },
  {
    id: "N6-INV-014",
    description: "Base mirror validates authorized L1 remote sender.",
    passed: mirrorBody.includes("xDomainMessageSender()")
      && mirrorBody.includes("remoteSender != authorizedL1Messenger")
  },
  {
    id: "N6-INV-015",
    description: "ActionGate nullifier handling remains atomic with consumer execution.",
    passed: actionVerify.indexOf("consumedNullifier[authorization.nullifier] = true;") > -1
      && actionVerify.indexOf("IPhilAuthorizationConsumer(authorization.consumer).consumePhilAuthorization") > -1
      && actionVerify.indexOf("consumedNullifier[authorization.nullifier] = true;")
        < actionVerify.indexOf("IPhilAuthorizationConsumer(authorization.consumer).consumePhilAuthorization")
  },
  {
    id: "N6-INV-016",
    description: "No raw private-key-shaped constants or test secrets appear in production Solidity source.",
    passed: productionSources.every(({ text }) => !/(privateKey|PRIVATE_KEY|mnemonic|seedPhrase|phil_secret|nullifierSeed)\s*=/.test(text))
  },
  {
    id: "N6-INV-017",
    description: "Recovery and execution selectors remain separated.",
    passed: source.account.includes("VERIFY_AND_CONSUME_SELECTOR")
      && source.account.includes("this.requestRecovery.selector")
      && source.account.includes("this.completeRecovery.selector")
      && !requestRecovery.includes("VERIFY_AND_CONSUME_SELECTOR")
      && !completeRecovery.includes("VERIFY_AND_CONSUME_SELECTOR")
  },
  {
    id: "N7-INV-018",
    description: "PhilMintPassConsumer cannot retain unauthorized ETH because nonzero msg.value is rejected before mint state changes.",
    passed: source.mintConsumer.includes("error UnexpectedMintPassValue()")
      && mintConsume.includes("if (msg.value != 0) revert UnexpectedMintPassValue();")
      && mintConsume.indexOf("if (msg.value != 0) revert UnexpectedMintPassValue();") > -1
      && mintConsume.indexOf("if (msg.value != 0) revert UnexpectedMintPassValue();") < mintConsume.indexOf("mintedNullifier[authorization.nullifier] = true;")
  },
  {
    id: "N8-INV-019",
    description: "Recovery authority rotation stores exactly one pending authority and only activates it on completion.",
    passed: source.account.includes("address private _recoveryAuthority")
      && source.account.includes("RecoveryAuthorityRotationRequest private _recoveryAuthorityRotationRequest")
      && requestRecoveryAuthorityRotation.includes("pendingRecoveryAuthority")
      && completeRecoveryAuthorityRotation.includes("_recoveryAuthority = pending.pendingRecoveryAuthority")
      && cancelRecoveryAuthorityRotation.includes("delete _recoveryAuthorityRotationRequest")
  },
  {
    id: "N8-INV-020",
    description: "Recovery authority rotation cannot change execution owner, EntryPoint, ActionGate, or ownerCommitment.",
    passed: !/_owner\s*=|_entryPoint\s*=|approvedActionGate\s*=|ownerCommitment\s*=/.test(`${requestRecoveryAuthorityRotation}\n${cancelRecoveryAuthorityRotation}\n${completeRecoveryAuthorityRotation}`)
      && completeRecoveryAuthorityRotation.includes("_recoveryAuthority = pending.pendingRecoveryAuthority")
  },
  {
    id: "N8-INV-021",
    description: "Recovery authority rotation performs no external calls or value transfers.",
    passed: !/\.call\s*\{|\.call\s*\(|transfer\s*\(|send\s*\(|delegatecall\s*\(/.test(`${requestRecoveryAuthorityRotation}\n${cancelRecoveryAuthorityRotation}\n${completeRecoveryAuthorityRotation}`)
      && !/value:/.test(`${requestRecoveryAuthorityRotation}\n${cancelRecoveryAuthorityRotation}\n${completeRecoveryAuthorityRotation}`)
  },
  {
    id: "N8-INV-022",
    description: "Initial recovery authority remains part of factory CREATE2 derivation while post-deployment account rotation preserves address stability.",
    passed: factoryGetAddress.includes("recoveryAuthority")
      && source.account.includes("function recoveryAuthority() public view returns (address)")
      && source.account.includes("RecoveryAuthorityRotationCompleted")
  },
  {
    id: "BETA-INV-035",
    description: "Beta ordinary ActionGate execution is explicitly zero-value.",
    passed: accountExecute.includes("value != 0")
      && accountExecute.includes("NonZeroActionValueForbidden")
      && !accountExecute.includes("call{value:")
  },
  {
    id: "BETA-INV-036",
    description: "Beta account validation rejects every paymaster payload on chain.",
    passed: accountValidateUserOp.includes("userOp.paymasterAndData.length != 0")
      && accountValidateUserOp.includes("PaymasterForbidden")
  },
  {
    id: "BETA-INV-037",
    description: "Disposable fund release is EntryPoint-only, freeze-aware, and fixed to the current owner.",
    passed: accountReleaseTestFunds.includes("_requireFromEntryPoint();")
      && accountReleaseTestFunds.includes("if (frozen) revert AccountFrozen();")
      && accountReleaseTestFunds.includes("address payable recipient = payable(_owner);")
      && accountReleaseTestFunds.includes("entryPoint().withdrawTo(recipient")
      && !/address\s+(?:payable\s+)?recipient/.test(
        source.account.slice(
          source.account.indexOf("function releaseTestFunds"),
          source.account.indexOf("function rotateExecutionOwner")
        ).split("external")[0]
      )
  },
  {
    id: "BETA-INV-038",
    description: "The account rejects a zero owner commitment during construction.",
    passed: source.account.includes("ownerCommitment_ == bytes32(0)")
  },
  {
    id: "BETA-INV-039",
    description: "The reusable factory registers deployed accounts for the composed Sepolia ActionGate.",
    passed: source.factory.includes("mapping(address => bool) public isPhilSepoliaMintAccount")
      && source.factory.includes("isPhilSepoliaMintAccount[address(account)] = true;")
      && source.factory.includes("isPhilSepoliaMintAccount[accountAddress] = true;")
  },
  {
    id: "O18-INV-023",
    description: "The local-proof account has one fixed execution function and no generic, batch, delegatecall, or upgrade path.",
    passed: source.localProofAccount.includes("executeLocalProofAuthorization")
      && !/function execute\s*\(|executeBatch|multicall|delegatecall|upgradeTo|selfdestruct/.test(source.localProofAccount)
  },
  {
    id: "O18-INV-024",
    description: "The local-proof account validates exact calldata, rejects paymasters, and binds version, model, expiry, and validator key.",
    passed: localProofValidate.includes("userOp.paymasterAndData.length != 0")
      && localProofValidate.includes("userOp.callData.length != 100")
      && localProofValidate.includes("executeLocalProofAuthorization.selector")
      && localProofValidate.includes("SIGNATURE_ENVELOPE_LENGTH")
      && localProofValidate.includes("SIGNATURE_SCHEME_VERSION")
      && localProofValidate.includes("SECURITY_MODEL_ID")
      && localProofValidate.includes("validatorKeyId")
  },
  {
    id: "O18-INV-025",
    description: "The local-proof account calls only the immutable confirmation target with no value.",
    passed: localProofExecute.includes("_requireFromEntryPoint();")
      && localProofExecute.includes("approvedConfirmationTarget")
      && localProofExecute.includes(".confirmPhilCoreAction(actionId, authorizationDigest)")
      && !/value\s*:|\.call\s*\(|delegatecall/.test(localProofExecute)
  },
  {
    id: "O18-INV-026",
    description: "Local-proof CREATE2 derivation binds all public initialization fields without secret material.",
    passed: [
      "entryPoint",
      "owner",
      "ownerCommitment",
      "approvedConfirmationTarget",
      "validatorKeyId",
      "expectedChainId"
    ].every((token) => localProofFactoryGetAddress.includes(token))
      && !/phil_secret|passphrase|privateKey|World ID|artwork|displayName/i.test(localProofFactoryGetAddress)
  },
  {
    id: "O18-INV-027",
    description: "The local-proof confirmation target validates account model, target, chain, and exact evidence.",
    passed: localProofConfirm.includes("msg.sender.code.length")
      && localProofConfirm.includes("securityModelId()")
      && localProofConfirm.includes("approvedConfirmationTarget()")
      && localProofConfirm.includes("expectedChainId()")
      && localProofConfirm.includes("confirmedAction[msg.sender][actionId]")
      && !/delegatecall|selfdestruct|transfer\s*\(|send\s*\(/.test(source.localProofTarget)
  },
  {
    id: "SEPOLIA-MINT-INV-028",
    description: "The Sepolia mint account is EntryPoint-only, zero-value, gate-only, and selector-restricted.",
    passed: sepoliaMintExecute.includes("_requireFromEntryPoint();")
      && sepoliaMintExecute.includes("target != actionGate")
      && sepoliaMintExecute.includes("value != 0")
      && sepoliaMintExecute.includes("verifyAndConsume.selector")
  },
  {
    id: "SEPOLIA-MINT-INV-029",
    description: "Malformed execution signatures fail validation without a reverting recover path.",
    passed: sepoliaMintValidate.includes("ECDSA.tryRecover")
      && sepoliaMintValidate.includes("ECDSA.RecoverError.NoError")
      && sepoliaMintValidate.includes("this.execute.selector")
      && !sepoliaMintValidate.includes("ECDSA.recover(")
  },
  {
    id: "SEPOLIA-MINT-INV-030",
    description: "The Sepolia mint account and factory contain no generic batch, delegatecall, proxy, or upgrade path.",
    passed: !/executeBatch|batchExecute|multicall|delegatecall|upgradeTo|upgradeToAndCall|selfdestruct|proxy/i
      .test(`${source.sepoliaMintAccount}\n${source.sepoliaMintFactory}`)
  },
  {
    id: "SEPOLIA-MINT-INV-031",
    description: "Sepolia mint CREATE2 derivation binds EntryPoint, execution owner, owner commitment, gate, salt, and factory.",
    passed: ["entryPoint", "executionOwner", "ownerCommitment", "actionGate", "salt"]
      .every((token) => sepoliaMintFactoryAddress.includes(token))
      && sepoliaMintFactoryAddress.includes("address(this)")
  },
  {
    id: "SEPOLIA-MINT-INV-032",
    description: "The ActionGate enforces chain, registered account, expiry, and atomic three-dimensional replay consumption before mint.",
    passed: sepoliaMintGateConsume.includes("block.chainid != expectedChainId")
      && sepoliaMintGateConsume.includes("accountFactory.isPhilSepoliaMintAccount(msg.sender)")
      && sepoliaMintGateConsume.includes("block.timestamp > validUntil")
      && [
        "consumedEnvelopeDigest[authorizationEnvelopeDigest] = true;",
        "consumedRootNullifier[rootProofNullifier] = true;",
        "consumedDeviceApprovalNonce[deviceApprovalNonce] = true;"
      ].every((statement) => sepoliaMintGateConsume.includes(statement))
      && sepoliaMintGateConsume.indexOf("consumedDeviceApprovalNonce[deviceApprovalNonce] = true;")
        < sepoliaMintGateConsume.indexOf("mintConsumer.consumeComposedMint")
  },
  {
    id: "SEPOLIA-MINT-INV-033",
    description: "The harmless pass is gate-only, non-transferable, non-payable, and independently replay protected.",
    passed: sepoliaMintConsumerConsume.includes("msg.sender != actionGate")
      && sepoliaMintConsumerConsume.includes("tokenIdByEnvelopeDigest")
      && sepoliaMintConsumerConsume.includes("tokenIdByRootNullifier")
      && !/function transfer|function approve|safeTransferFrom|transferFrom|payable/u
        .test(source.sepoliaMintConsumer)
  },
  {
    id: "SEPOLIA-MINT-INV-034",
    description: "The on-chain boundary explicitly disclaims Noir and P-256 verification and contains no alternate verifier or attestation path.",
    passed: source.sepoliaMintAccount.includes("not Noir/P-256")
      && source.sepoliaMintGate.includes("Noir and P-256 are NOT verified here")
      && !/Garaga|Cairo|attestation|verifyProof|P256\.verify/u.test(
        `${source.sepoliaMintAccount}\n${source.sepoliaMintFactory}\n${source.sepoliaMintGate}\n${source.sepoliaMintConsumer}`
      )
  },
  {
    id: "BETA-INV-040",
    description: "The composed ActionGate admits only its one immutable counterfactual Beta account.",
    passed: source.sepoliaMintGate.includes("address public immutable authorizedAccount")
      && source.sepoliaMintGate.includes("authorizedAccount = authorizedAccount_")
      && sepoliaMintGateConsume.includes("msg.sender != authorizedAccount")
      && sepoliaMintGateConsume.includes("UnauthorizedAccountBinding")
  },
  {
    id: "BETA-INV-041",
    description: "The composed ActionGate mints only to the authorized account's current execution owner.",
    passed: sepoliaMintGateConsume.includes("mintRecipient != _currentExecutionOwner(msg.sender)")
      && source.sepoliaMintGate.includes("MintRecipientNotCurrentOwner")
      && source.sepoliaMintGate.includes("IPhilSepoliaMintAccountOwnerV1.owner.selector")
  }
];

const failed = checks.filter((check) => !check.passed);
const report = {
  phase: "O.19",
  status: failed.length === 0 ? "passed" : "failed",
  generatedAt: new Date().toISOString(),
  scope: Object.values(files),
  checks,
  failed,
  betaGateImpact: failed.length === 0 ? "custom_invariants_passing" : "blocked_by_custom_invariant_failure"
};

fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failed.length > 0) process.exit(1);
