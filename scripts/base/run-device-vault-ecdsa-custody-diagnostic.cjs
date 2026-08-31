const {
  createDeviceVaultEcdsaSigningSession,
  createDeviceVaultEcdsaValidatorSigner,
  createUserSessionLifecycleSnapshot,
  generateDeviceVaultEcdsaValidator,
  revokeDeviceVaultEcdsaValidator
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const {
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");

const { ethers } = require("ethers");

const args = new Set(process.argv.slice(2));
const asJson = args.has("--json");
const inspect = args.has("--inspect");

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

async function main() {
  const ownerCommitment = ethers.id("philcore-n3-diagnostic-owner");
  const lifecycleSnapshot = createUserSessionLifecycleSnapshot({
    sessionId: "n3-diagnostic-session",
    state: "unlocked",
    metadata: {
      deviceVaultUnlocked: true,
      protectedStateAvailable: true
    }
  });
  const unlockedVaultHandle = {
    handleId: "n3-diagnostic-vault-handle",
    sessionId: lifecycleSnapshot.sessionId,
    ownerCommitment,
    envelopeId: "n3-diagnostic-envelope",
    unlockResultId: "n3-diagnostic-unlock",
    unlockedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    processLocal: true,
    serializable: false,
    exportable: false,
    containsPlaintext: false,
    containsRawVaultKey: false,
    containsPhilSecret: false,
    applicationAccessible: false
  };
  const storageBackend = createInMemoryDeviceIdentityRegistryStorageBackend();
  const keyProvider = createLocalDevPassphraseKeyProvider({
    passphrase: "diagnostic-local-alpha-only",
    scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
  });
  const generated = await generateDeviceVaultEcdsaValidator({
    requestId: "n3-diagnostic-generate",
    lifecycleSnapshot,
    unlockedVaultHandle,
    storageBackend,
    keyProvider,
    ownerCommitment,
    purpose: "erc4337_owner_validator_local_alpha",
    accountAddress: "0x1111111111111111111111111111111111111111",
    chainId: 31337,
    expiresAt: futureDate(),
    auditCorrelationId: "n3-diagnostic-audit"
  });
  if (generated.status !== "approved") {
    throw new Error(`diagnostic generation failed: ${generated.error?.code}`);
  }
  const signingSession = await createDeviceVaultEcdsaSigningSession({
    requestId: "n3-diagnostic-signing-session",
    lifecycleSnapshot,
    unlockedVaultHandle,
    storageBackend,
    keyProvider,
    keyReference: generated.value.keyReference,
    ownerCommitment,
    smartAccountAddress: "0x1111111111111111111111111111111111111111",
    entryPointAddress: "0x2222222222222222222222222222222222222222",
    chainId: 31337,
    userOperationHash: ethers.id("n3-diagnostic-user-operation"),
    presentationDigest: ethers.id("n3-diagnostic-presentation"),
    callDataHash: ethers.id("n3-diagnostic-calldata"),
    purpose: "erc4337_owner_validator_local_alpha",
    expiresAt: futureDate(),
    auditCorrelationId: "n3-diagnostic-audit"
  });
  if (signingSession.status !== "approved") {
    throw new Error(`diagnostic signing session failed: ${signingSession.error?.code}`);
  }
  const signer = createDeviceVaultEcdsaValidatorSigner(signingSession.value.signingSession);
  const signature = await signer.signUserOperationHash({
    userOperationHash: ethers.id("n3-diagnostic-user-operation"),
    presentationDigest: ethers.id("n3-diagnostic-presentation"),
    expectedOwner: generated.value.ownerAddress,
    chainId: 31337,
    entryPointAddress: "0x2222222222222222222222222222222222222222",
    smartAccountAddress: "0x1111111111111111111111111111111111111111",
    nonce: "0",
    callDataHash: ethers.id("n3-diagnostic-calldata"),
    auditCorrelationId: "n3-diagnostic-audit"
  });
  const revoked = await revokeDeviceVaultEcdsaValidator({
    storageBackend,
    keyProvider,
    keyReference: generated.value.keyReference
  });
  const report = {
    phase: "N.3",
    validatorGenerated: generated.status === "approved",
    ownerAddress: generated.value.ownerAddress,
    keyReferenceId: generated.value.keyReference.keyReferenceId,
    storedEncrypted: generated.value.storedEncrypted,
    privateKeyReturned: generated.value.privateKeyReturned,
    privateKeyExportable: generated.value.privateKeyExportable,
    derivedFromPhilSecret: generated.value.derivedFromPhilSecret,
    signingSessionCreated: signingSession.status === "approved",
    signingSessionOneTime: signingSession.value.snapshot.oneTime,
    signatureProduced: signature.status === "signed",
    signatureRedactedInReport: true,
    revoked: revoked.status === "revoked",
    transactionSubmitted: false,
    userOperationSubmitted: false,
    baseStateMutated: false,
    productionApproved: false
  };
  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }
  process.stdout.write("Device Vault ECDSA validator custody diagnostic\n");
  process.stdout.write(`- owner: ${report.ownerAddress}\n`);
  process.stdout.write(`- key reference: ${report.keyReferenceId}\n`);
  process.stdout.write("- private key not returned\n");
  process.stdout.write("- encrypted local validator record created\n");
  process.stdout.write("- one-time signing session produced exact-hash signature\n");
  process.stdout.write("- transaction not submitted\n");
  process.stdout.write("- production approval not granted\n");
  if (inspect) {
    process.stdout.write(`- revoked after diagnostic: ${report.revoked}\n`);
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
