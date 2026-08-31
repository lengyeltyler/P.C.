const HYPOTHETICAL_STACK_CLASSIFICATION =
  "HYPOTHETICAL_WITNESS_HIDING_TEST_STACK_NOT_AN_IMPLEMENTATION";
const PROOF_TYPE = "stwo-unlock-keccak-v1";
const PROOF_DIGEST =
  "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

function approved(value) {
  return { status: "approved", value };
}

function factShapePreview(proofInputHash) {
  const raw = String(proofInputHash).slice(2).padStart(64, "0");
  return {
    factShapeReference: "[fact_high, fact_low]",
    factHigh: `0x${raw.slice(0, 32)}`,
    factLow: `0x${raw.slice(32)}`,
    sourceProofInputHash: proofInputHash,
    ordering: "fact_high_then_fact_low",
    factPublished: false,
    onChainRegistered: false
  };
}

function createHypotheticalWitnessHidingProofStack() {
  return Object.freeze({
    classification: HYPOTHETICAL_STACK_CLASSIFICATION,
    async generateActionUnlockProof(input) {
      const draft = input.authorizationPackageDraft;
      const publicInputs = draft.actionUnlockPublicInputDraft.publicInputs;
      return approved({
        proofGenerationArtifactId: `${input.requestId}:hypothetical-generation`,
        status: "proof_generated",
        outcome: "proof_generated",
        binding: {
          authorizationPackageDraftId: draft.authorizationPackageDraftId,
          proofInputHash: draft.hashSummary.proofInputHash,
          auditCorrelationId: input.auditCorrelationId
        },
        publicInputs,
        proofInputHash: draft.hashSummary.proofInputHash,
        proofArtifact: {
          proofArtifactId: `${input.requestId}:hypothetical-proof`,
          proofType: PROOF_TYPE,
          proofDigest: PROOF_DIGEST,
          proofByteLength: 0,
          proofInputHash: draft.hashSummary.proofInputHash,
          proofBlobIncluded: false,
          proofBytesLogged: false,
          nonSecretProofArtifact: true,
          containsWitnessOpenings: false,
          safeForExternalVerifierTransmission: true,
          executableByAdapters: false,
          classification: HYPOTHETICAL_STACK_CLASSIFICATION
        },
        summary: {
          durationMs: 0,
          publicInputsMatched: true
        },
        classification: HYPOTHETICAL_STACK_CLASSIFICATION
      });
    },
    async verifyGeneratedActionUnlockProof(input) {
      const draft = input.authorizationPackageDraft;
      const generation = input.proofGenerationArtifact;
      return approved({
        proofVerificationResultId: `${input.requestId}:hypothetical-verification`,
        status: "proof_verified",
        outcome: "proof_verified",
        binding: {
          authorizationPackageDraftId: draft.authorizationPackageDraftId,
          proofGenerationArtifactId: generation.proofGenerationArtifactId,
          proofArtifactId: generation.proofArtifact.proofArtifactId,
          proofInputHash: draft.hashSummary.proofInputHash,
          auditCorrelationId: input.auditCorrelationId
        },
        publicInputs: draft.actionUnlockPublicInputDraft.publicInputs,
        proofInputHash: draft.hashSummary.proofInputHash,
        proofVerifiedLocally: true,
        factShapePreview: factShapePreview(draft.hashSummary.proofInputHash),
        summary: { durationMs: 0 },
        classification: HYPOTHETICAL_STACK_CLASSIFICATION
      });
    },
    finalizeAuthorizationPackage(input) {
      const draft = input.authorizationPackageDraft;
      const generation = input.proofGenerationArtifact;
      const verification = input.proofVerificationResult;
      const publicInputs = draft.actionUnlockPublicInputDraft.publicInputs;
      const preview = factShapePreview(draft.hashSummary.proofInputHash);
      return approved({
        finalizedAuthorizationPackageId: `${input.requestId}:hypothetical-finalized-package`,
        status: "authorization_package_finalized",
        outcome: "authorization_package_finalized",
        binding: {
          authorizationPackageDraftId: draft.authorizationPackageDraftId,
          proofGenerationArtifactId: generation.proofGenerationArtifactId,
          proofVerificationResultId: verification.proofVerificationResultId,
          sessionId: draft.binding.sessionId,
          applicationId: draft.binding.applicationId,
          intentId: draft.binding.intentId,
          capabilityName: draft.binding.capabilityName,
          ownerCommitment: draft.binding.ownerCommitment,
          proofInputHash: draft.hashSummary.proofInputHash,
          auditCorrelationId: input.auditCorrelationId
        },
        actionUnlockAuthorization: {
          version: "v1",
          proofType: PROOF_TYPE,
          ...publicInputs,
          expiry: BigInt(publicInputs.expiry).toString(),
          proofInputHash: draft.hashSummary.proofInputHash,
          factShapeReference: "[fact_high, fact_low]"
        },
        proofArtifact: {
          proofArtifactId: generation.proofArtifact.proofArtifactId,
          proofGenerationArtifactId: generation.proofGenerationArtifactId,
          proofVerificationResultId: verification.proofVerificationResultId,
          proofType: PROOF_TYPE,
          proofDigest: generation.proofArtifact.proofDigest,
          proofByteLength: generation.proofArtifact.proofByteLength,
          proofInputHash: draft.hashSummary.proofInputHash,
          proofBlobIncluded: false,
          proofBytesLogged: false,
          nonSecretProofArtifact: true,
          containsWitnessOpenings: false,
          safeForExternalVerifierTransmission: true,
          executableByAdapters: false,
          classification: HYPOTHETICAL_STACK_CLASSIFICATION
        },
        evidence: {
          proofGenerated: true,
          proofVerifiedLocally: true,
          proofTypeMatched: true,
          publicInputsMatched: true,
          proofInputHashMatched: true,
          factShapeValidated: true,
          localVerificationResultId: verification.proofVerificationResultId,
          verifiedProofReferenceId: generation.proofArtifact.proofArtifactId
        },
        factShapePreview: preview,
        validity: { issuedAt: input.issuedAt, expiresAt: input.expiresAt, expired: false },
        limitations: [
          "local_finalization_only",
          "non_executing_authorization_package",
          "no_verified_fact_publication",
          "no_on_chain_verification",
          "no_nullifier_consumption",
          "no_adapter_execution",
          "no_contract_execution",
          "no_transaction_submission",
          "process_local_package_store_only"
        ],
        authorizationPackageFinalized: true,
        proofGenerated: true,
        proofVerifiedLocally: true,
        verifiedFactPublished: false,
        onChainVerificationPerformed: false,
        nullifierConsumed: false,
        adapterExecutionAllowed: false,
        contractExecutionAllowed: false,
        transactionSubmitted: false,
        executableByApplications: false,
        witnessMaterialExposed: false,
        persisted: false,
        classification: HYPOTHETICAL_STACK_CLASSIFICATION
      });
    }
  });
}

module.exports = {
  HYPOTHETICAL_STACK_CLASSIFICATION,
  createHypotheticalWitnessHidingProofStack
};
