const assert = require("node:assert/strict");
const { p256 } = require("@noble/curves/p256");
const { ethers } = require("hardhat");

const {
  PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH,
  PHIL_P256_HALF_ORDER,
  PHIL_P256_ORDER,
  PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID,
  PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID,
  PHIL_ROUTINE_WIRE_ENCODING_V2_ID,
  decodePhilP256RawSignatureV2,
  derivePhilDeviceApprovalSigningDigestV2,
  encodePhilP256RawSignatureV2,
  parsePhilP256DerSignatureV2,
  validatePhilP256PublicKeyX963V2,
  verifyPhilP256RawSignatureV2
} = require("../../apps/phil-device-sdk/src/p256SignatureWireV2.ts");

function derInteger(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = Buffer.from(hex, "hex");
  if (bytes[0] & 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
  return Buffer.concat([Buffer.from([0x02, bytes.length]), bytes]);
}

function derSignature(r, s) {
  const body = Buffer.concat([derInteger(r), derInteger(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

describe("Phil V1 Step 6C P-256 signature wire V2", function () {
  const privateKey = ethers.getBytes(ethers.toBeHex(7n, 32));
  const publicKey = p256.getPublicKey(privateKey, false);
  const requestId = ethers.id("PHIL_STEP6C_WIRE_REQUEST_V1");

  it("freezes the distinct suite, provider, wire, and terminal SHA-256 prehash identities", function () {
    assert.equal(PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH, ethers.id("PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2"));
    assert.equal(PHIL_ROUTINE_SIGNATURE_SUITE_V2_ID, ethers.id("phil-signature-p256-sha256-prehash-raw-rs-low-s-v2"));
    assert.equal(PHIL_ROUTINE_PROVIDER_PROFILE_V2_ID, ethers.id("apple-secure-enclave-p256-x962-sha256-digest-der-v1"));
    assert.equal(PHIL_ROUTINE_WIRE_ENCODING_V2_ID, ethers.id("phil-p256-signature-rs-64-low-s-v1"));
    assert.equal(
      derivePhilDeviceApprovalSigningDigestV2(requestId),
      ethers.sha256(ethers.concat([PHIL_DEVICE_APPROVAL_SIGNING_PREHASH_V2_HASH, requestId]))
    );
  });

  it("validates X9.63 keys and verifies exactly one raw low-S signature without a second prehash", function () {
    const key = validatePhilP256PublicKeyX963V2(publicKey);
    assert.equal(key.publicKeyX963, ethers.hexlify(publicKey));
    assert.equal(key.publicKeyFingerprint, ethers.sha256(publicKey));
    const digest = derivePhilDeviceApprovalSigningDigestV2(requestId);
    const signature = p256.sign(ethers.getBytes(digest), privateKey, { lowS: true, prehash: false });
    const raw = encodePhilP256RawSignatureV2({
      r: ethers.toBeHex(signature.r, 32),
      s: ethers.toBeHex(signature.s, 32)
    });
    assert.equal(ethers.getBytes(raw).length, 64);
    assert.equal(verifyPhilP256RawSignatureV2({ digest, signature: raw, publicKeyX963: publicKey }), true);
    assert.equal(verifyPhilP256RawSignatureV2({ digest: ethers.id("wrong"), signature: raw, publicKeyX963: publicKey }), false);
  });

  it("strictly parses DER and normalizes high-S while raw input rejects high-S", function () {
    const digest = derivePhilDeviceApprovalSigningDigestV2(requestId);
    const low = p256.sign(ethers.getBytes(digest), privateKey, { lowS: true, prehash: false });
    const highS = PHIL_P256_ORDER - low.s;
    assert.ok(highS > PHIL_P256_HALF_ORDER);
    const normalized = parsePhilP256DerSignatureV2(derSignature(low.r, highS));
    assert.equal(BigInt(normalized.r), low.r);
    assert.equal(BigInt(normalized.s), low.s);
    assert.throws(
      () => decodePhilP256RawSignatureV2(ethers.concat([ethers.toBeHex(low.r, 32), ethers.toBeHex(highS, 32)])),
      (error) => error.code === "PHIL_ROUTINE_P256_HIGH_S_FORBIDDEN"
    );
  });

  it("rejects nonminimal, negative, zero, trailing, wrong-length, and invalid-key encodings", function () {
    const valid = derSignature(1n, 2n);
    assert.throws(() => parsePhilP256DerSignatureV2(Buffer.concat([valid, Buffer.from([0])])));
    assert.throws(() => parsePhilP256DerSignatureV2("0x3006020180020101"));
    assert.throws(() => parsePhilP256DerSignatureV2("0x3006020100020101"));
    assert.throws(() => parsePhilP256DerSignatureV2("0x300702020001020101"));
    assert.throws(() => decodePhilP256RawSignatureV2("0x1234"));
    assert.throws(() => validatePhilP256PublicKeyX963V2(new Uint8Array(65)));
  });
});
