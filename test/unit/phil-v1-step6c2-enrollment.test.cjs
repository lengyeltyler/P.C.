const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { p256 } = require("@noble/curves/p256");

const enrollment = require("../../apps/phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");

function fixture() {
  const privateKey=Buffer.from("03".repeat(32),"hex"),publicKey=Buffer.from(p256.getPublicKey(privateKey,false));
  const ackPrivateKey=Buffer.from("05".repeat(32),"hex"),ackPublicKey=Buffer.from(p256.getPublicKey(ackPrivateKey,false));
  const bootstrap={sessionId:`0x${"11".repeat(32)}`,ipv4:"192.168.7.9",port:43124,challenge:`0x${"22".repeat(32)}`,expiresAt:"1787414700",expectedGeneration:"1",
    desktopAckPublicKeyX963:`0x${ackPublicKey.toString("hex")}`};
  const record={schemaVersion:2,generation:"1",deviceId:`0x${"33".repeat(32)}`,deviceKeyId:`0x${"44".repeat(32)}`,
    signatureSuiteId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
    providerProfileId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
    wireEncodingId:enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
    publicKeyX963:`0x${publicKey.toString("hex")}`,publicKeyFingerprint:`0x${createHash("sha256").update(publicKey).digest("hex")}`,
    secureEnclaveBacked:false,userPresenceRequired:false};
  const digest=enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({bootstrap,record});
  const proofSignatureDER=p256.sign(digest.slice(2),privateKey,{lowS:true,prehash:false}).toDERRawBytes();
  return {privateKey,ackPrivateKey,bootstrap,record,digest,proofSignatureDER};
}

describe("Phil V1 Step 6C-2 V2 routine-device enrollment", function () {
  it("round-trips the exact expiring RFC1918 bootstrap and fingerprint", function () {
    const {bootstrap}=fixture(),encoded=enrollment.encodePhilRoutineDeviceEnrollmentBootstrapV2(bootstrap);
    assert.equal(encoded.startsWith(enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.qrPrefix),true);
    assert.deepEqual(enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(encoded),bootstrap);
    assert.match(enrollment.formatPhilRoutineDeviceEnrollmentFingerprintV2(bootstrap),/^[0-9A-F]{4}(?:-[0-9A-F]{4}){5}$/u);
    assert.throws(()=>enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(`${encoded}A`));
    assert.throws(()=>enrollment.encodePhilRoutineDeviceEnrollmentBootstrapV2({...bootstrap,ipv4:"8.8.8.8"}),
      (error)=>error.code==="PHIL_ROUTINE_ENROLLMENT_PRIVATE_IPV4_REQUIRED");
    assert.throws(()=>enrollment.encodePhilRoutineDeviceEnrollmentBootstrapV2({...bootstrap,expectedGeneration:"65"}),
      (error)=>error.code==="PHIL_ROUTINE_ENROLLMENT_GENERATION_INVALID");
    assert.throws(()=>enrollment.validatePhilRoutineDevicePublicRecordV2({...fixture().record,generation:"65"},true),
      (error)=>error.code==="PHIL_ROUTINE_ENROLLMENT_GENERATION_INVALID");
  });

  it("verifies strict proof of possession and classifies synthetic enrollment explicitly", function () {
    const {bootstrap,record,proofSignatureDER,ackPrivateKey}=fixture();
    const json=enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap,record,proofSignatureDER});
    assert.deepEqual(enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json,bootstrap,allowSynthetic:true}),record);
    assert.throws(()=>enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json,bootstrap}));
    const acceptanceDigest=enrollment.derivePhilRoutineDeviceEnrollmentAcceptanceDigestV2({bootstrap,record});
    const acceptanceSignatureDER=p256.sign(acceptanceDigest.slice(2),ackPrivateKey,{lowS:true,prehash:false}).toDERRawBytes();
    const acceptance=enrollment.serializePhilRoutineDeviceEnrollmentAcceptanceV2({bootstrap,record,acceptanceSignatureDER});
    assert.equal(enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:acceptance,bootstrap,record}),acceptanceDigest);
    const changed=JSON.stringify({...JSON.parse(acceptance),challenge:`0x${"55".repeat(32)}`});
    assert.throws(()=>enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:changed,bootstrap,record}));
    const low=p256.sign(acceptanceDigest.slice(2),ackPrivateKey,{lowS:true,prehash:false});
    const highDer=new p256.Signature(low.r,BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")-low.s).toDERRawBytes();
    const highAcceptance=enrollment.serializePhilRoutineDeviceEnrollmentAcceptanceV2({bootstrap,record,acceptanceSignatureDER:highDer});
    assert.throws(()=>enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({json:highAcceptance,bootstrap,record}),
      (error)=>error.code==="PHIL_ROUTINE_ENROLLMENT_ACCEPTANCE_INVALID");
  });

  it("rejects transcript, identity, public-key, signature, schema, and duplicate-field substitution", function () {
    const {bootstrap,record,proofSignatureDER}=fixture();
    const json=enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({bootstrap,record,proofSignatureDER});
    const parsed=JSON.parse(json);
    for (const mutation of [
      {...parsed,challenge:`0x${"55".repeat(32)}`},
      {...parsed,record:{...record,deviceId:`0x${"66".repeat(32)}`}},
      {...parsed,proofSignatureDER:`0x${Buffer.from(proofSignatureDER).subarray(0,-1).toString("hex")}`},
      {...parsed,unexpected:true}
    ]) assert.throws(()=>enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json:JSON.stringify(mutation),bootstrap,allowSynthetic:true}));
    const duplicate=json.replace('"protocolVersion":2','"protocolVersion":2,"protocolVersion":2');
    assert.throws(()=>enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentResponseV2({json:duplicate,bootstrap,allowSynthetic:true}));
  });
});
