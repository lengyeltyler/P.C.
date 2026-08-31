"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { p256 } = require("@noble/curves/p256");

require("tsx/cjs");
const enrollment = require("../../phil-device-sdk/src/routineDeviceEnrollmentTransportV2.ts");
const { createRoutineDeviceEnrollmentHost } = require("../src/main/routine-device-enrollment-host.cjs");

function privateAddress() {
  return Object.values(os.networkInterfaces()).flat().find((value) => value?.family === "IPv4" && !value.internal
    && (/^10\./u.test(value.address) || /^192\.168\./u.test(value.address) || /^172\.(?:1[6-9]|2[0-9]|3[01])\./u.test(value.address)))?.address;
}

function runSwift(arguments_) {
  return new Promise((resolve, reject) => {
    const child = spawn("/usr/bin/swift", arguments_, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [], stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));child.stderr.on("data", (chunk) => stderr.push(chunk));
    child.once("error", reject);child.once("close", (code) => {
      if (code !== 0) return reject(new Error(`swift transport failed (${code}): ${Buffer.concat(stderr).toString("utf8")}`));
      resolve(Buffer.concat(stdout).toString("utf8"));
    });
  });
}

test("production-shaped URLSession HEAD and POST satisfy the exact enrollment listener", {
  skip: process.platform !== "darwin" || !fs.existsSync("/usr/bin/swift") ? "requires macOS Foundation URLSession" : false
}, async (t) => {
  const ipv4 = privateAddress();assert.ok(ipv4, "private test interface required");let stored = null;
  const store = {
    async save(_id, json, evidenceClass) { stored = { canonicalEnrollmentJson: json, evidenceClass }; },
    async load() { if (!stored) throw Object.assign(new Error("missing"), { code: "ROUTINE_ENROLLMENT_NOT_FOUND" });return stored; },
    async delete() { stored = null; }
  };
  const host = createRoutineDeviceEnrollmentHost({ disposableProfileId: `0x${"79".repeat(32)}`, ipv4, enrollmentStore: store,
    now: () => 1_800_000_000n, allowSynthetic: true });
  await host.start();t.after(() => host.stop());
  const begun = await host.beginEnrollment(), bootstrap = enrollment.decodePhilRoutineDeviceEnrollmentBootstrapV2(begun.qrPayload);
  const privateKey = Buffer.from("08".repeat(32), "hex"), publicKey = Buffer.from(p256.getPublicKey(privateKey, false));
  const record = { schemaVersion: 2, generation: "1", deviceId: `0x${"71".repeat(32)}`, deviceKeyId: `0x${"72".repeat(32)}`,
    signatureSuiteId: enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.signatureSuiteId,
    providerProfileId: enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.providerProfileId,
    wireEncodingId: enrollment.PHIL_ROUTINE_DEVICE_ENROLLMENT_TRANSPORT_V2.wireEncodingId,
    publicKeyX963: `0x${publicKey.toString("hex")}`, publicKeyFingerprint: `0x${crypto.createHash("sha256").update(publicKey).digest("hex")}`,
    secureEnclaveBacked: false, userPresenceRequired: false };
  const digest = enrollment.derivePhilRoutineDeviceEnrollmentProofDigestV2({ bootstrap, record });
  const signature = p256.sign(digest.slice(2), privateKey, { lowS: true, prehash: false }).toDERRawBytes();
  const body = Buffer.from(enrollment.serializePhilRoutineDeviceEnrollmentResponseV2({ bootstrap, record, proofSignatureDER: signature }));
  const origin = `http://${bootstrap.ipv4}:${bootstrap.port}`;
  const swift = `import Foundation
func configuration() -> URLSessionConfiguration { let c=URLSessionConfiguration.ephemeral;c.waitsForConnectivity=true;c.httpShouldSetCookies=false;c.httpCookieAcceptPolicy = .never;c.httpCookieStorage=nil;c.urlCache=nil;c.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData;c.connectionProxyDictionary=[:];c.allowsCellularAccess=false;c.allowsExpensiveNetworkAccess=false;c.allowsConstrainedNetworkAccess=false;c.httpMaximumConnectionsPerHost=1;c.timeoutIntervalForRequest=10;c.timeoutIntervalForResource=15;return c }
func exchange(_ request:URLRequest)throws->(Data,HTTPURLResponse){let sem=DispatchSemaphore(value:0);var result:Result<(Data,HTTPURLResponse),Error>!;URLSession(configuration:configuration()).dataTask(with:request){data,response,error in if let error{result = .failure(error)} else if let response=response as? HTTPURLResponse{result = .success((data ?? Data(),response))} else {result = .failure(NSError(domain:"response",code:1))};sem.signal()}.resume();sem.wait();return try result.get()}
let origin=CommandLine.arguments[1],session=CommandLine.arguments[2],body=Data(base64Encoded:CommandLine.arguments[3])!
var head=URLRequest(url:URL(string:origin+"/philcore/routine-enrollment/v2/preflight")!);head.httpMethod="HEAD";head.setValue("no-store",forHTTPHeaderField:"Cache-Control");head.setValue("close",forHTTPHeaderField:"Connection");head.setValue(session,forHTTPHeaderField:"X-PhilCore-Enrollment-Session");let (_,headResponse)=try exchange(head);print(headResponse.statusCode)
var post=URLRequest(url:URL(string:origin+"/philcore/routine-enrollment/v2/complete")!);post.httpMethod="POST";post.httpBody=body;post.setValue("application/json",forHTTPHeaderField:"Content-Type");post.setValue(String(body.count),forHTTPHeaderField:"Content-Length");post.setValue("no-store",forHTTPHeaderField:"Cache-Control");post.setValue("close",forHTTPHeaderField:"Connection");let (responseBody,postResponse)=try exchange(post);print(postResponse.statusCode);print(responseBody.base64EncodedString())`;
  const output = await runSwift(["-e", swift, origin, bootstrap.sessionId, body.toString("base64")]);
  const [preflightStatus, completionStatus, acceptanceBase64] = output.trim().split(/\r?\n/u);
  assert.equal(preflightStatus, "204");assert.equal(completionStatus, "200");
  enrollment.parseAndVerifyPhilRoutineDeviceEnrollmentAcceptanceV2({ json: Buffer.from(acceptanceBase64, "base64"), bootstrap, record });
  const status = host.status(begun.requestId);assert.equal(status.state, "completed");assert.equal(status.preflightCount, 1);
  assert.equal(status.completionAttemptCount, 1);assert.equal(status.lastAttempt.stage, "completion_accepted");
  assert.deepEqual(JSON.parse(stored.canonicalEnrollmentJson), record);
});
