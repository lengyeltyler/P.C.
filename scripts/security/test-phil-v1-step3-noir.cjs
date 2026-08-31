const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "../..");
const SOURCE_DIR = path.join(REPO_ROOT, "proofs/phil-v1-step3-noir");
const CACHE_DIR = process.env.PHIL_STEP3_CACHE_DIR
  || path.join(os.homedir(), ".cache/phil-v1-step3");
const NARGO = path.join(
  CACHE_DIR,
  "toolchains/nargo-1.0.0-beta.16/nargo"
);
const BB = path.join(
  CACHE_DIR,
  "toolchains/bb-3.0.0-nightly.20251104/bb"
);

function run(command, args, cwd, expectedSuccess = true) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024
  });
  if (expectedSuccess && result.status !== 0) {
    throw new Error(`${command} failed:\n${result.stdout}\n${result.stderr}`);
  }
  if (!expectedSuccess && result.status === 0) {
    throw new Error(`${command} unexpectedly accepted an adversarial case`);
  }
  return result;
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

function replaceRequired(source, before, after) {
  assert(source.includes(before), `missing fixture token: ${before}`);
  return source.replace(before, after);
}

function containsBytes(haystack, needle) {
  return haystack.indexOf(needle) !== -1;
}

for (const executable of [NARGO, BB]) {
  assert(fs.existsSync(executable), `missing pinned executable: ${executable}`);
}

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "phil-v1-step3-noir-"));
try {
  fs.cpSync(path.join(SOURCE_DIR, "Nargo.toml"), path.join(temporaryRoot, "Nargo.toml"));
  fs.cpSync(path.join(SOURCE_DIR, "src"), path.join(temporaryRoot, "src"), {
    recursive: true
  });
  fs.cpSync(path.join(SOURCE_DIR, "Prover.toml"), path.join(temporaryRoot, "Prover.toml"));

  assert.match(run(NARGO, ["--version"], temporaryRoot).stdout, /1\.0\.0-beta\.16/);
  assert.match(run(BB, ["--version"], temporaryRoot).stdout, /3\.0\.0-nightly\.20251104/);
  run(NARGO, ["compile"], temporaryRoot);
  run(NARGO, ["execute", "valid_witness"], temporaryRoot);

  const committedVk = path.join(SOURCE_DIR, "artifacts/vk");
  const committedProof = path.join(SOURCE_DIR, "artifacts/synthetic_proof");
  const committedPublicInputs = path.join(
    SOURCE_DIR,
    "artifacts/synthetic_public_inputs"
  );
  run(BB, [
    "verify", "-s", "ultra_honk", "--oracle_hash", "keccak",
    "-i", committedPublicInputs, "-p", committedProof, "-k", committedVk
  ], temporaryRoot);

  const validProver = fs.readFileSync(path.join(temporaryRoot, "Prover.toml"), "utf8");
  const adversarialCases = [
    ["wrong secret", ", 18, 52, 86, 120, 144]", ", 18, 52, 86, 120, 145]"],
    ["noncanonical secret", "phil_secret = [0,", "phil_secret = [8,"],
    ["wrong nullifier seed", ", 65, 141, 12, 243, 252, 231]", ", 65, 141, 12, 243, 252, 230]"],
    ["wrong scoped commitment", "114829005082543429532154036199259576055", "114829005082543429532154036199259576056"],
    ["wrong scope id", "305815341793405972068381771784905924498", "305815341793405972068381771784905924499"],
    ["wrong scope instance", "221185144350792829726803508867899731948", "221185144350792829726803508867899731949"],
    ["wrong scope epoch", "scope_epoch = \"7\"", "scope_epoch = \"8\""],
    ["wrong envelope digest", "108377501239390983149796241448049967275", "108377501239390983149796241448049967276"],
    ["wrong nullifier", "207937584796931974411581383312354337076", "207937584796931974411581383312354337077"],
    ["zero descriptor", "proof_descriptor_hash_high = \"272189026722687169272981680005061644033\"", "proof_descriptor_hash_high = \"0\""],
    ["zero descriptor low", "proof_descriptor_hash_low = \"170920577092785971460241183570792673589\"", "proof_descriptor_hash_low = \"0\""]
  ];
  for (const [name, before, after] of adversarialCases.slice(0, -1)) {
    let candidate = replaceRequired(validProver, before, after);
    if (name === "zero descriptor") {
      candidate = replaceRequired(
        candidate,
        adversarialCases.at(-1)[1],
        adversarialCases.at(-1)[2]
      );
    }
    fs.writeFileSync(path.join(temporaryRoot, "Prover.toml"), candidate);
    run(NARGO, ["execute", name.replaceAll(" ", "_")], temporaryRoot, false);
  }
  fs.writeFileSync(path.join(temporaryRoot, "Prover.toml"), validProver);
  run(NARGO, ["execute", "proof_witness"], temporaryRoot);

  const bytecode = path.join(
    temporaryRoot,
    "target/phil_v1_step3_root_proof.json"
  );
  const witness = path.join(temporaryRoot, "target/proof_witness.gz");
  const vk = committedVk;
  const proofHashes = [];
  const philSecret = Buffer.from(
    "0000000000000000000000000000000000000000000000000000001234567890",
    "hex"
  );
  const nullifierSeed = Buffer.from(
    "ac8e8626249620e3f00f636415520c8b1997fd073ded4005e968418d0cf3fce7",
    "hex"
  );
  for (const index of [1, 2]) {
    const output = path.join(temporaryRoot, `proof-${index}`);
    run(BB, [
      "prove", "-s", "ultra_honk", "--oracle_hash", "keccak",
      "-b", bytecode, "-w", witness, "-k", vk, "--vk_policy", "check",
      "-o", output
    ], temporaryRoot);
    run(BB, [
      "verify", "-s", "ultra_honk", "--oracle_hash", "keccak",
      "-i", path.join(output, "public_inputs"),
      "-p", path.join(output, "proof"), "-k", vk
    ], temporaryRoot);
    const serialized = Buffer.concat([
      fs.readFileSync(path.join(output, "proof")),
      fs.readFileSync(path.join(output, "public_inputs"))
    ]);
    assert.equal(containsBytes(serialized, philSecret), false);
    assert.equal(containsBytes(serialized, nullifierSeed), false);
    proofHashes.push(sha256(path.join(output, "proof")));
  }
  assert.notEqual(proofHashes[0], proofHashes[1], "repeated ZK proofs were identical");

  const malformed = path.join(temporaryRoot, "malformed-proof");
  const canonicalProof = fs.readFileSync(path.join(temporaryRoot, "proof-1/proof"));
  canonicalProof[Math.floor(canonicalProof.length / 2)] ^= 1;
  fs.writeFileSync(malformed, canonicalProof);
  run(BB, [
    "verify", "-s", "ultra_honk", "--oracle_hash", "keccak",
    "-i", path.join(temporaryRoot, "proof-1/public_inputs"),
    "-p", malformed, "-k", vk
  ], temporaryRoot, false);

  process.stdout.write(`${JSON.stringify({
    status: "passed",
    productionAuthority: false,
    networkActivity: false,
    adversarialCases: adversarialCases.length - 1,
    committedSyntheticProofVerified: true,
    repeatedProofsRandomized: true,
    serializedPrivateLiteralsAbsent: true,
    malformedProofRejected: true,
    proofHashes
  }, null, 2)}\n`);
} finally {
  fs.rmSync(temporaryRoot, { recursive: true, force: true });
}
