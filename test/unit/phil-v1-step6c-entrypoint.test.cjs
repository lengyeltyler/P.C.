const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const {
  auth,
  deployStep6CFixture,
  buildRequestForNonce,
  setNextTimestamp,
  serializePackedUserOperation,
  eventCommitment,
  rawSignature
} = require("../helpers/phil-v1-step6c-fixture.cjs");

describe("Phil V1 Step 6C official local EntryPoint composition", function () {
  it("normally deploys official v0.7 constructor state and the bound local profile", async function () {
    const f = await deployStep6CFixture();
    assert.equal(await ethers.provider.getNetwork().then((network) => network.chainId), 31337n);
    assert.notEqual(f.entryPointAddress, "0x0000000071727de22e5e9d8baf0edac6f37da032");
    assert.equal(f.reentrancySlot, ethers.zeroPadValue("0x01", 32));
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 0n);
    assert.equal(f.depositBefore, 0n);
    assert.equal(await f.entryPoint.balanceOf(f.accountAddress), ethers.parseEther("1"));
    assert.equal((await f.account.entryPoint()).toLowerCase(), f.entryPointAddress);
    assert.equal(await f.account.chainId(), 31337n);
    assert.equal(await f.account.catalogHash(), f.catalog.catalogHash);
    assert.equal(await f.account.capabilityPolicyHash(), f.policy.capabilityPolicyHash);
    assert.equal(await f.account.parameterSchemaId(), f.parameterSchemaId);
    assert.equal(await f.account.accountRuntimeCodeHash(), f.accountRuntimeCodeHash);
    assert.equal(await f.account.executionEnvironmentHash(), f.environment.executionEnvironmentHash);
    assert.equal(await f.account.adapterManifestHash(), f.manifest.manifestHash);
    assert.equal(await f.account.signatureRegistryHash(), f.signatureRegistry.registryHash);
    assert.equal(await f.account.deviceEnrollmentHash(), f.enrollment.deviceEnrollmentHash);
    assert.equal(await f.account.accountConfigurationHash(), f.configuration.accountConfigurationHash);
    assert.equal(await f.account.applicationId(), f.configuration.applicationId);
    assert.equal(await f.account.principalIdHash(), f.configuration.principalIdHash);
    assert.equal(await f.account.scopedOwnerCommitment(), f.configuration.scopedOwnerCommitment);
    assert.equal(await f.account.scopeId(), f.configuration.scopeId);
    assert.equal(await f.account.scopeInstance(), f.configuration.scopeInstance);
    assert.equal(await f.account.scopeEpoch(), BigInt(f.configuration.scopeEpoch));
    assert.equal(await f.account.capabilityId(), f.policy.capabilityId);
    assert.equal(await f.account.capabilityEpoch(), BigInt(f.policy.capabilityEpoch));
    assert.equal(await f.account.policyEpoch(), BigInt(f.policy.policyEpoch));
    assert.equal(await f.account.deviceId(), f.enrollment.deviceId);
    assert.equal(await f.account.deviceKeyId(), f.enrollment.deviceKeyId);
    assert.equal(await f.account.deviceEpoch(), BigInt(f.enrollment.deviceEpoch));
    assert.equal(await f.account.signatureSuiteId(), f.enrollment.signatureSuiteId);
    assert.equal(await f.account.providerProfileId(), f.enrollment.providerProfileId);
    assert.equal(await f.account.wireEncodingId(), f.enrollment.wireEncodingId);
    assert.equal(await f.account.devicePublicKeyX(), f.enrollment.publicKeyX);
    assert.equal(await f.account.devicePublicKeyY(), f.enrollment.publicKeyY);
    assert.equal(await f.account.recoveryEpoch(), BigInt(f.configuration.recoveryEpoch));
    assert.equal(await f.account.validatorEpoch(), BigInt(f.configuration.validatorEpoch));
    assert.equal(await f.account.approvedTargetRuntimeCodeHash(), f.targetCodeHash);
    assert.equal(await f.account.actionTypeHash(), f.configuration.actionTypeHash);
    assert.equal(await f.account.nonceKey(), BigInt(f.configuration.nonceKey));
    assert.equal(await f.account.maximumValueWei(), BigInt(f.configuration.maximumValueWei));
    assert.equal(await f.account.maximumTotalFeeWei(), BigInt(f.configuration.maximumTotalFeeWei));
    assert.equal(f.account.interface.getFunction("executeAuthorized").selector, "0x5a99466a");
    for (let index = 0; index < 6; index += 1) {
      assert.equal(await f.account.catalogDisplayTextHashes(index), auth.PHIL_STEP6C_CATALOG_TEXT_HASHES[index]);
    }
    const Account = await ethers.getContractFactory("PhilV1Step6CAccount");
    await assert.rejects(Account.deploy({
      ...f.constructorConfig,
      catalogDisplayTextHashes: [ethers.id("caller-selected-label"), ...f.constructorConfig.catalogDisplayTextHashes.slice(1)]
    }), /PhilStep6CInvalidConstructor/);
  });

  it("consumes failed nonce n and accepts a fresh signed success at n+1 without a second nonce", async function () {
    const f = await deployStep6CFixture();
    const firstIssuedAt = BigInt(f.policy.validAfter) + 20n;
    await setNextTimestamp(firstIssuedAt + 1n);
    const failed = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: true,
      issuedAt: firstIssuedAt,
      sessionLabel: "failed-n"
    });

    await f.entryPoint.handleOps.staticCall([failed.userOp], f.beneficiary.address);
    const failedTx = await f.entryPoint.handleOps([failed.userOp], f.beneficiary.address);
    const failedReceipt = await failedTx.wait();
    const parsedFailed = failedReceipt.logs
      .map((log) => { try { return f.entryPoint.interface.parseLog(log); } catch { return null; } })
      .find((log) => log?.name === "UserOperationEvent");
    assert.equal(parsedFailed.args.userOpHash, failed.userOpHash);
    assert.equal(parsedFailed.args.success, false);
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 1n);
    assert.equal(await f.target.recordedSequence(), 0n);
    assert.equal(await f.account.validatedUserOperationHash(failed.request.requestId), failed.userOpHash);

    const secondIssuedAt = firstIssuedAt + 10n;
    await setNextTimestamp(secondIssuedAt + 1n);
    const success = await buildRequestForNonce(f, {
      nonceSequence: 1,
      shouldRevert: false,
      issuedAt: secondIssuedAt,
      sessionLabel: "success-n-plus-one"
    });
    assert.equal(success.request.capabilityPolicyHash, failed.request.capabilityPolicyHash);
    assert.equal(success.request.catalogHash, failed.request.catalogHash);
    assert.equal(f.parameterSchemaId, f.parameterSchemaId);
    assert.notEqual(success.request.actionHash, failed.request.actionHash);
    assert.notEqual(success.request.requestId, failed.request.requestId);
    assert.notEqual(success.signature, failed.signature);

    const scanStart = await ethers.provider.getBlock("latest");
    const targetPreStateHash = require("../../apps/phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts")
      .derivePhilRoutineTargetPreStateHashV1({
        target: f.targetAddress,
        approvedTargetRuntimeCodeHash: f.targetCodeHash,
        recordedValueBefore: await f.target.recordedValue(),
        recordedSequenceBefore: await f.target.recordedSequence(),
        scanStartBlockNumber: scanStart.number,
        scanStartBlockHash: scanStart.hash
      });
    const packedUserOperationBytes = serializePackedUserOperation(success.userOp);

    await f.entryPoint.handleOps.staticCall([success.userOp], f.beneficiary.address);
    const successTx = await f.entryPoint.handleOps([success.userOp], f.beneficiary.address);
    const successReceipt = await successTx.wait();
    const parsedSuccess = successReceipt.logs
      .map((log) => { try { return f.entryPoint.interface.parseLog(log); } catch { return null; } })
      .find((log) => log?.name === "UserOperationEvent");
    assert.equal(parsedSuccess.args.userOpHash, success.userOpHash);
    assert.equal(parsedSuccess.args.success, true);
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 2n);
    assert.equal(await f.target.recordedSequence(), 1n);
    assert.equal(await f.target.recordedValue(), auth.PHIL_STEP6C_RECORDED_VALUE);
    assert.equal(await f.account.validatedUserOperationHash(success.request.requestId), ethers.ZeroHash);
    assert.equal(await f.account.validatedUserOperationHash(failed.request.requestId), failed.userOpHash);

    const entryPointTopic = ethers.id("UserOperationEvent(bytes32,address,address,uint256,bool,uint256,uint256)");
    const accountTopic = ethers.id("PhilV1Step6CAuthorizationConsumed(bytes32,bytes32,bytes32,bytes32,bytes32,address)");
    const targetTopic = ethers.id("ValueRecorded(bytes32,uint64)");
    const entryPointLog = successReceipt.logs.find((log) => log.topics[0] === entryPointTopic);
    const accountLog = successReceipt.logs.find((log) => log.topics[0] === accountTopic);
    const targetLog = successReceipt.logs.find((log) => log.topics[0] === targetTopic);
    assert.ok(entryPointLog && accountLog && targetLog);
    assert.ok(accountLog.index < targetLog.index && targetLog.index < entryPointLog.index);
    const receiptBlock = await ethers.provider.getBlock(successReceipt.blockNumber);
    const finalTargetStateHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes32", "uint64", "bytes32", "bytes32"],
      [f.targetAddress, auth.PHIL_STEP6C_RECORDED_VALUE, 1, successReceipt.hash, receiptBlock.hash]
    ));
    const routineReceipt = auth.createPhilRoutineAuthorizationReceiptV1({
      requestId: success.request.requestId,
      authorizationCoreDigest: success.request.authorizationCoreDigest,
      authorizationEnvelopeDigest: success.request.authorizationEnvelopeDigest,
      deviceApprovalDigest: success.request.deviceApprovalDigest,
      platformSigningDigest: success.request.platformSigningDigest,
      serializedUserOperationHash: ethers.keccak256(packedUserOperationBytes),
      userOperationHash: success.userOpHash,
      executionEnvironmentHash: f.environment.executionEnvironmentHash,
      entryPointEventCommitment: eventCommitment(entryPointLog),
      accountEventCommitment: eventCommitment(accountLog),
      targetEventCommitment: eventCommitment(targetLog),
      targetPreStateHash,
      finalTargetStateHash,
      entryPointCodeHash: f.entryPointCodeHash,
      senderCreatorCodeHash: f.senderCreatorCodeHash,
      accountCodeHash: f.accountRuntimeCodeHash,
      targetCodeHash: f.targetCodeHash,
      transactionHash: successReceipt.hash,
      blockHash: receiptBlock.hash,
      entryPointNonceBefore: 1,
      entryPointNonceAfter: 2,
      executedAt: receiptBlock.timestamp,
      simulationPassed: true,
      executionSucceeded: true,
      externalNetwork: false,
      productionAuthority: false
    });
    const observedLogs = successReceipt.logs.map((log) => ({
      address: log.address,
      topics: [...log.topics],
      data: log.data,
      index: log.index,
      transactionHash: log.transactionHash,
      blockHash: log.blockHash,
      removed: false
    }));
    const receiptEvidence = {
      packedUserOperationBytes,
      userOperationHash: success.userOpHash,
      logs: observedLogs,
      transactionStatus: successReceipt.status,
      targetRecordedValueBefore: ethers.ZeroHash,
      targetRecordedSequenceBefore: 0,
      scanStartBlockNumber: scanStart.number,
      scanStartBlockHash: scanStart.hash,
      targetRecordedValueAfter: auth.PHIL_STEP6C_RECORDED_VALUE,
      targetRecordedSequenceAfter: 1,
      blockTimestamp: receiptBlock.timestamp,
      entryPointNonceBefore: 1,
      entryPointNonceAfter: 2,
      entryPointCodeHash: f.entryPointCodeHash,
      senderCreatorCodeHash: f.senderCreatorCodeHash,
      accountCodeHash: f.accountRuntimeCodeHash,
      targetCodeHash: f.targetCodeHash,
      transactionHash: successReceipt.hash,
      blockHash: receiptBlock.hash
    };
    const submissionCommit = {
      requestId: success.request.requestId,
      sessionId: success.request.authorizationCore.sessionId,
      state: 6,
      entryPoint: f.entryPointAddress,
      sender: f.accountAddress,
      userOperationNonce: success.request.action.userOpNonce,
      serializedUserOperationHash: ethers.keccak256(packedUserOperationBytes),
      officialUserOperationHash: success.userOpHash,
      packedUserOperationBytes,
      target: f.targetAddress,
      targetRecordedValueBefore: ethers.ZeroHash,
      targetRecordedSequenceBefore: 0,
      targetPreStateHash,
      scanStartBlockNumber: scanStart.number,
      scanStartBlockHash: scanStart.hash
    };
    assert.equal(auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: routineReceipt,
      submissionCommit,
      evidence: receiptEvidence
    }).receiptHash, routineReceipt.receiptHash);
    const wrongAccountLogs = observedLogs.map((log) => log.topics[0] === accountTopic
      ? { ...log, data: ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "address"],
        [success.request.platformSigningDigest, ethers.id("wrong-operation"), f.targetAddress]
      ) }
      : log);
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: routineReceipt,
      submissionCommit,
      evidence: { ...receiptEvidence, logs: wrongAccountLogs }
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_MISMATCH");

    const substitutedPacked = serializePackedUserOperation({
      ...success.userOp,
      preVerificationGas: success.userOp.preVerificationGas + 1
    });
    const selfConsistentWrongReceipt = auth.createPhilRoutineAuthorizationReceiptV1({
      ...routineReceipt,
      serializedUserOperationHash: ethers.keccak256(substitutedPacked)
    });
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: selfConsistentWrongReceipt,
      submissionCommit,
      evidence: { ...receiptEvidence, packedUserOperationBytes: substitutedPacked }
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH");
    const expectEvidenceFailure = (evidence) => assert.throws(
      () => auth.verifyPhilRoutineAuthorizationReceiptV1({ request: success.request, receipt: routineReceipt, submissionCommit, evidence }),
      (error) => /PHIL_ROUTINE_RECEIPT/.test(error.code)
    );
    expectEvidenceFailure({ ...receiptEvidence, transactionStatus: 0 });
    expectEvidenceFailure({ ...receiptEvidence, logs: [...observedLogs, observedLogs.find((log) => log.topics[0] === accountTopic)] });
    expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === targetTopic
      ? { ...log, removed: true }
      : log) });
    expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === accountTopic
      ? { ...log, index: targetLog.index + 1 }
      : log) });
    expectEvidenceFailure({ ...receiptEvidence, targetRecordedValueAfter: ethers.id("wrong-final-value") });
    expectEvidenceFailure({ ...receiptEvidence, targetRecordedSequenceAfter: 2 });
    expectEvidenceFailure({ ...receiptEvidence, targetRecordedValueBefore: ethers.id("wrong-pre-value") });
    expectEvidenceFailure({ ...receiptEvidence, scanStartBlockHash: ethers.id("wrong-scan-block") });
    expectEvidenceFailure({ ...receiptEvidence, blockTimestamp: receiptBlock.timestamp + 1 });
    expectEvidenceFailure({ ...receiptEvidence, entryPointNonceBefore: 0 });
    expectEvidenceFailure({ ...receiptEvidence, entryPointCodeHash: ethers.id("wrong-entrypoint-code") });
    expectEvidenceFailure({ ...receiptEvidence, senderCreatorCodeHash: ethers.id("wrong-sender-code") });
    expectEvidenceFailure({ ...receiptEvidence, accountCodeHash: ethers.id("wrong-account-code") });
    expectEvidenceFailure({ ...receiptEvidence, targetCodeHash: ethers.id("wrong-target-code") });
    expectEvidenceFailure({ ...receiptEvidence, transactionHash: ethers.id("wrong-transaction") });
    expectEvidenceFailure({ ...receiptEvidence, blockHash: ethers.id("wrong-block") });
    expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === accountTopic
      ? { ...log, address: f.targetAddress }
      : log) });
    expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === targetTopic
      ? { ...log, topics: [ethers.id("WrongTargetEvent(bytes32,uint64)"), ...log.topics.slice(1)] }
      : log) });
    expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === entryPointTopic
      ? { ...log, transactionHash: ethers.id("wrong-log-transaction") }
      : log) });
    for (const topic of [entryPointTopic, accountTopic, targetTopic]) {
      expectEvidenceFailure({ ...receiptEvidence, logs: observedLogs.map((log) => log.topics[0] === topic
        ? { ...log, data: `${log.data}${"00".repeat(32)}` }
        : log) });
    }
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: routineReceipt,
      submissionCommit: { ...submissionCommit, targetPreStateHash: ethers.id("different-durable-prestate") },
      evidence: receiptEvidence
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH");
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: routineReceipt,
      submissionCommit: { ...submissionCommit, officialUserOperationHash: ethers.id("different-durable-operation") },
      evidence: receiptEvidence
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH");
    const selfConsistentWrongNonceReceipt = auth.createPhilRoutineAuthorizationReceiptV1({
      ...routineReceipt,
      entryPointNonceBefore: 500,
      entryPointNonceAfter: 501
    });
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: selfConsistentWrongNonceReceipt,
      submissionCommit,
      evidence: { ...receiptEvidence, entryPointNonceBefore: 500, entryPointNonceAfter: 501 }
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_JOURNAL_MISMATCH");
    assert.throws(() => auth.verifyPhilRoutineAuthorizationReceiptV1({
      request: success.request,
      receipt: { ...routineReceipt, receiptHash: ethers.id("wrong-receipt-hash") },
      submissionCommit,
      evidence: receiptEvidence
    }), (error) => error.code === "PHIL_ROUTINE_RECEIPT_MISMATCH");
  });

  it("fails closed before execution for wrong signature and packed-operation substitution", async function () {
    const f = await deployStep6CFixture();
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    await setNextTimestamp(issuedAt + 1n);
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "entrypoint-negative"
    });
    const wrongKey = ethers.getBytes(ethers.toBeHex(9n, 32));
    const wrongSignature = rawSignature(built.request.platformSigningDigest, wrongKey);
    await assert.rejects(
      f.entryPoint.handleOps.staticCall([{ ...built.userOp, signature: wrongSignature }], f.beneficiary.address),
      /AA24|signature/i
    );
    await assert.rejects(
      f.entryPoint.handleOps.staticCall([{ ...built.userOp, preVerificationGas: 100001 }], f.beneficiary.address),
      /PhilStep6CUserOperationMismatch|AA23|reverted/i
    );
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 0n);
    assert.equal(await f.account.validatedUserOperationHash(built.request.requestId), ethers.ZeroHash);
    assert.equal(await f.target.recordedSequence(), 0n);
  });

  it("rejects an executing target reentry attempt while preserving the admitted outer action", async function () {
    const f = await deployStep6CFixture({ targetContractName: "PhilV1Step6CReentrantTarget" });
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    await setNextTimestamp(issuedAt + 1n);
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0, shouldRevert: false, issuedAt, sessionLabel: "entrypoint-reentry"
    });
    const tx = await f.entryPoint.handleOps([built.userOp], f.beneficiary.address);
    const receipt = await tx.wait();
    const event = receipt.logs.map((log) => { try { return f.entryPoint.interface.parseLog(log); } catch { return null; } })
      .find((log) => log?.name === "UserOperationEvent");
    assert.equal(event.args.success, true);
    assert.equal(await f.target.reentryAttempted(), true);
    assert.equal(await f.target.reentrySucceeded(), false);
    assert.equal(await f.target.recordedSequence(), 1n);
    assert.equal(await f.target.recordedValue(), auth.PHIL_STEP6C_RECORDED_VALUE);
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 1n);
    assert.equal(await f.account.validatedUserOperationHash(built.request.requestId), ethers.ZeroHash);
  });

  it("rejects the exact valid operation when the account deposit cannot supply prefund", async function () {
    const f = await deployStep6CFixture({ fundDeposit: false });
    assert.equal(await f.entryPoint.balanceOf(f.accountAddress), 0n);
    const issuedAt = BigInt(f.policy.validAfter) + 20n;
    await setNextTimestamp(issuedAt + 1n);
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt,
      sessionLabel: "entrypoint-no-prefund"
    });
    await assert.rejects(
      f.entryPoint.handleOps.staticCall([built.userOp], f.beneficiary.address),
      /AA21|AA23|prefund|PhilStep6CUserOperationMismatch/i
    );
    assert.equal(await f.entryPoint.getNonce(f.accountAddress, 0), 0n);
    assert.equal(await f.target.recordedSequence(), 0n);
  });
});
