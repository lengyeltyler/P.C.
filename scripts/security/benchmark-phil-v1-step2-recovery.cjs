const { performance } = require("node:perf_hooks");

const { keccak256, toUtf8Bytes } = require("ethers");
const {
  createPhilIdentityContinuityPackageV1,
  createPhilIdentityDataRecoveryBundleV1,
  restorePhilIdentityDataRecoveryBundleV1
} = require("../../apps/phil-device-sdk/src/identityDataRecoveryV1.ts");

function hash(value) {
  return keccak256(toUtf8Bytes(value));
}

const continuityPackage = createPhilIdentityContinuityPackageV1({
  philSecret: `0x${"00".repeat(27)}1234567890`,
  dataRootKey: hash("synthetic-step2-benchmark-data-key")
});

const iterations = 200;
const pairs = [[0, 1], [0, 2], [1, 2]];
const rssBefore = process.memoryUsage().rss;
let peakRss = rssBefore;
const createStarted = performance.now();
const fixtures = [];
for (let index = 0; index < iterations; index += 1) {
  fixtures.push(createPhilIdentityDataRecoveryBundleV1({
    continuityPackage,
    packageCounter: index + 1,
    createdAt: 1_800_000_000 + index
  }));
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
}
const createFinished = performance.now();

const restoreStarted = performance.now();
let restores = 0;
for (const fixture of fixtures) {
  for (const [left, right] of pairs) {
    const restored = restorePhilIdentityDataRecoveryBundleV1({
      bundle: fixture.bundle,
      shares: [fixture.shares[left], fixture.shares[right]]
    });
    if (restored.rootOwnerCommitment !== continuityPackage.rootOwnerCommitment) {
      throw new Error("synthetic benchmark restore mismatch");
    }
    restores += 1;
  }
  peakRss = Math.max(peakRss, process.memoryUsage().rss);
}
const restoreFinished = performance.now();

process.stdout.write(`${JSON.stringify({
  classification: "synthetic_local_benchmark_only",
  runtime: process.version,
  architecture: process.arch,
  platform: process.platform,
  iterations,
  restores,
  createTotalMs: Number((createFinished - createStarted).toFixed(3)),
  createMeanMs: Number(((createFinished - createStarted) / iterations).toFixed(3)),
  restoreTotalMs: Number((restoreFinished - restoreStarted).toFixed(3)),
  restoreMeanMs: Number(((restoreFinished - restoreStarted) / restores).toFixed(3)),
  rssBeforeMiB: Number((rssBefore / 1024 / 1024).toFixed(3)),
  observedPeakRssMiB: Number((peakRss / 1024 / 1024).toFixed(3)),
  deviceEvidence: false,
  networkActivity: false
}, null, 2)}\n`);
