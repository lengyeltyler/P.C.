const assert = require("node:assert/strict");
const { createECDH } = require("node:crypto");
const { describe, it } = require("mocha");
const { hexlify } = require("ethers");

const transport = require("../../apps/phil-device-sdk/src/routineAuthorizationTransportV1.ts");

const sessionId = `0x${"11".repeat(32)}`;
const requestId = `0x${"22".repeat(32)}`;
const desktopPrivate = Buffer.from("01".repeat(32), "hex");
const phonePrivate = Buffer.from("02".repeat(32), "hex");
function publicKey(privateKey) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privateKey);
  return ecdh.getPublicKey(undefined, "uncompressed");
}
const desktopPublic = publicKey(desktopPrivate);
const phonePublic = publicKey(phonePrivate);

function bootstrap() {
  return {
    sessionId,
    ipv4: "192.168.7.9",
    port: 43123,
    desktopPublicKeyX963: hexlify(desktopPublic),
    requestId,
    expiresAt: "1800000120"
  };
}

describe("Phil V1 Step 6C-2 authenticated routine transport", function () {
  it("round-trips the exact 216-byte canonical QR bootstrap", function () {
    const encoded = transport.encodePhilRoutineTransportBootstrapV1(bootstrap());
    assert.ok(encoded.startsWith("phil-step6c-routine-v1:"));
    assert.equal(Buffer.from(encoded.split(":")[1], "base64url").length, 216);
    assert.deepEqual(transport.decodePhilRoutineTransportBootstrapV1(encoded), bootstrap());
  });

  it("rejects non-private endpoints, path mutation, padding, and trailing bytes", function () {
    assert.throws(() => transport.encodePhilRoutineTransportBootstrapV1({ ...bootstrap(), ipv4: "8.8.8.8" }),
      /RFC1918/);
    const encoded = transport.encodePhilRoutineTransportBootstrapV1(bootstrap());
    assert.throws(() => transport.decodePhilRoutineTransportBootstrapV1(`${encoded}=`), /base64url/);
    const bytes = Buffer.from(encoded.split(":")[1], "base64url");
    bytes[47] ^= 1;
    assert.throws(() => transport.decodePhilRoutineTransportBootstrapV1(
      `phil-step6c-routine-v1:${bytes.toString("base64url")}`
    ), /path hashes/);
  });

  it("derives one transcript and comparison fingerprint from both device keys", function () {
    const transcript = transport.derivePhilRoutineTransportTranscriptHashV1({
      bootstrap: bootstrap(), iphonePublicKeyX963: phonePublic
    });
    assert.match(transcript, /^0x[0-9a-f]{64}$/);
    assert.match(transport.formatPhilRoutineTransportFingerprintV1(transcript),
      /^[0-9A-F]{4}(?:-[0-9A-F]{4}){5}$/);
  });

  it("derives the same ECDH/HKDF traffic key on Desktop and iPhone", function () {
    const transcript = transport.derivePhilRoutineTransportTranscriptHashV1({
      bootstrap: bootstrap(), iphonePublicKeyX963: phonePublic
    });
    const desktopKey = transport.derivePhilRoutineTransportKeyV1({
      privateKey: desktopPrivate, peerPublicKeyX963: phonePublic, transcriptHash: transcript
    });
    const phoneKey = transport.derivePhilRoutineTransportKeyV1({
      privateKey: phonePrivate, peerPublicKeyX963: desktopPublic, transcriptHash: transcript
    });
    assert.deepEqual(desktopKey, phoneKey);
  });

  it("authenticates exact direction/session/request AAD and rejects nonce reuse", function () {
    const key = Buffer.from("33".repeat(32), "hex");
    const nonce = Buffer.from("44".repeat(12), "hex");
    const aad = transport.derivePhilRoutineTransportAadV1({ direction: "request", sessionId, requestId });
    const writer = new transport.PhilRoutineTransportCipherV1({ key, nonceSource: () => nonce });
    const frame = writer.encrypt({ plaintext: "{\"ok\":true}", aad });
    assert.equal(frame.length, 44);
    assert.throws(() => writer.encrypt({ plaintext: "x", aad }), /nonce was reused/);
    const reader = new transport.PhilRoutineTransportCipherV1({ key });
    assert.equal(reader.decrypt({ frame, aad }).toString(), "{\"ok\":true}");
    assert.throws(() => reader.decrypt({ frame, aad }), /nonce was reused/);
    const wrong = new transport.PhilRoutineTransportCipherV1({ key });
    const wrongAad = transport.derivePhilRoutineTransportAadV1({ direction: "response", sessionId, requestId });
    assert.throws(() => wrong.decrypt({ frame, aad: wrongAad }), /authentication failed/);
  });

  it("strictly parses the one begin message and rejects duplicate or unknown fields", function () {
    const begin = {
      protocolVersion: 1,
      sessionId,
      requestId,
      iphonePublicKey: hexlify(phonePublic)
    };
    const serialized = transport.serializePhilRoutineTransportBeginJsonV1(begin);
    assert.deepEqual(transport.parsePhilRoutineTransportBeginJsonV1(serialized), begin);
    assert.throws(() => transport.parsePhilRoutineTransportBeginJsonV1(
      serialized.replace('"requestId"', '"extra":true,"requestId"')
    ), /schema/);
    assert.throws(() => transport.parsePhilRoutineTransportBeginJsonV1(
      serialized.replace('"requestId":', `"requestId":"${requestId}","requestId":`)
    ), /duplicate JSON key/);
  });
});


describe("routine terminal protocol", function () {
  it("binds an exact versioned negative result and isolates every traffic direction", function () {
    const value={protocolVersion:1,purpose:"PHIL_ROUTINE_TERMINAL_RESULT_V1",sessionId,requestId,outcome:"rejected"};
    assert.equal(transport.parsePhilRoutineTerminalV1(JSON.stringify(value)).outcome,"rejected");
    for(const delta of [{protocolVersion:2},{purpose:"approval"},{outcome:"approved"},{signatureR:"forbidden"},{requestId:"0x00"}]) {
      assert.throws(()=>transport.parsePhilRoutineTerminalV1(JSON.stringify({...value,...delta})));
    }
    assert.throws(()=>transport.parsePhilRoutineTerminalV1(JSON.stringify(value).replace('"protocolVersion":1','"protocolVersion":1,"protocolVersion":1')));
    const aads=["request","response","terminal","terminalAck"].map(direction=>transport.derivePhilRoutineTransportAadV1({direction,sessionId,requestId}));
    assert.equal(new Set(aads.map(value=>value.toString("hex"))).size,4);
    const key=Buffer.alloc(32,7),sender=new transport.PhilRoutineTransportCipherV1({key});
    const frame=sender.encrypt({plaintext:JSON.stringify(value),aad:aads[2]});
    for(const index of [0,1,3]) {
      const receiver=new transport.PhilRoutineTransportCipherV1({key});assert.throws(()=>receiver.decrypt({frame,aad:aads[index]}));receiver.destroy();
    }
    assert.throws(()=>transport.parsePhilRoutineTerminalV1(JSON.stringify(value),true));sender.destroy();
  });
});
