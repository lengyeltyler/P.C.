"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const guidance = require("../src/renderer/routine-authorization-ui.cjs");

const root = path.resolve(__dirname, "../../..");
const renderer = fs.readFileSync(path.join(root, "apps/philcore-desktop/src/renderer/app.js"), "utf8");
const styles = fs.readFileSync(path.join(root, "apps/philcore-desktop/src/renderer/styles.css"), "utf8");
const ios = fs.readFileSync(path.join(root, "apps/philcore-ios-companion/PhilCoreCompanion/RootView.swift"), "utf8");
const activeViews = renderer.slice(renderer.indexOf("Object.assign(views, {"));
const approvalSummary = renderer.slice(renderer.indexOf("function approvalSummaryRows"), renderer.indexOf("function approvalTechnicalRows"));

test("onboarding introduces Phil and the Controlled Sepolia Beta accurately and concisely", () => {
  assert.match(renderer, /title: "I'm your security sidekick"/u);
  assert.match(renderer, /help protect your digital identity/u);
  assert.match(renderer, /what you are approving before protected signing/u);
  assert.match(renderer, /Ethereum's Sepolia test network and test-only assets/u);
  assert.match(renderer, /not mainnet or production custody/u);
  assert.doesNotMatch(renderer.slice(renderer.indexOf("const introSteps"), renderer.indexOf("function introProgress")), /Meet Phil|A safer way back in/u);
  assert.equal((renderer.slice(renderer.indexOf("const introSteps"), renderer.indexOf("function introProgress")).match(/eyebrow:/gu) || []).length, 3);
});

test("authorization primary copy uses the bounded plain-language summary", () => {
  for (const label of ["Who", "What", "Where", "Value", "Maximum cost", "Expires", "Why Phil allows it"]) {
    assert.match(approvalSummary, new RegExp(`\\["${label}"`, "u"));
  }
  for (const technical of ["UserOperation", "EntryPoint", "calldata", "digest", "nullifier", "witness", "ActionGate", "validator", "raw gas"]) {
    assert.doesNotMatch(approvalSummary, new RegExp(technical, "iu"));
  }
  assert.match(renderer, /detailsMarkup\("Details", kv\(technicalRows\)\)/u);
  assert.match(renderer, /<dl class="approval-grid" aria-label="Authorization summary">/u);
  assert.match(styles, /\.approval-row dt/u);
  assert.match(styles, /\.approval-row dd/u);
});

test("stage guidance and failure language cover the required fail-closed states", () => {
  for (const stage of ["ready", "locked", "waiting_for_phone", "review_on_phone", "local_proof", "protected_signing", "submitting", "success", "rejected", "expired", "failure"]) {
    assert.ok(guidance.guidanceForStage(stage).title);
    assert.ok(guidance.guidanceForStage(stage).message);
  }
  for (const reason of ["user_denied", "request_expired", "iphone_unavailable", "device_response_mismatch", "local_proof_failed", "identity_locked", "provider_unavailable", "provider_disagreement", "network_timeout", "ambiguous_public_status", "feature_deferred"]) {
    assert.notEqual(guidance.failureMessage(reason), guidance.failureMessage("unknown"), reason);
  }
  assert.match(guidance.failureMessage("provider_disagreement"), /cannot confirm the public status; do not retry/u);
  assert.match(guidance.failureMessage("ambiguous_public_status"), /Do not retry or assume/u);
  assert.doesNotMatch(JSON.stringify(Object.values({
    denied: guidance.failureMessage("user_denied"),
    expired: guidance.failureMessage("request_expired"),
    timeout: guidance.failureMessage("network_timeout")
  })), /failed safely/iu);
});

test("Desktop keeps local demonstrations separate from completed read-only Beta evidence", () => {
  assert.match(renderer, /Reusable local demonstration/u);
  assert.match(renderer, /not public Sepolia/u);
  assert.match(renderer, /Completed Beta activity is read-only history/u);
  assert.match(renderer, /does not recreate or submit the completed P2, P3, or P5 Beta actions/u);
  assert.doesNotMatch(renderer.slice(renderer.indexOf("function controlledBetaStatusPanel"), renderer.indexOf("function controlledBetaActivityPanel")), /data-action=/u);
});

test("recovery, Ask Phil, and ordinary UI copy preserve Beta boundaries", () => {
  assert.match(renderer, /Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared/u);
  for (const question of ["What is Phil?", "Why do I need my phone?", "What am I approving?", "What happens if I reject this?", "What does locked mean?", "What is the Sepolia Beta?", "Is this using real money?", "Is Phil post-quantum secure?", "Why isn't recovery available yet?"]) {
    assert.match(renderer, new RegExp(question.replace(/[?]/gu, "\\?"), "u"));
  }
  assert.doesNotMatch(activeViews, /paste this into Codex|run a terminal command|inspect Role 0|inspect Role 1|provide raw RPC output/iu);
});

test("iPhone review preserves important facts and moves technical identifiers behind Details", () => {
  for (const label of ["Who", "What", "Where", "Value", "Maximum cost", "Expires", "Why Phil allows it"]) {
    assert.match(ios, new RegExp(`routineSummaryLabel\\(\"${label}\"`, "u"));
  }
  assert.match(ios, /DisclosureGroup\("Details"\)/u);
  assert.match(ios, /routineDetailLabel\("Comparison fingerprint"/u);
  assert.match(ios, /Waiting for Face ID or passcode to approve this exact action/u);
  assert.match(ios, /PhilBetaGuidance\.recoveryDeferred/u);
  assert.doesNotMatch(ios.slice(ios.indexOf("Text(\"Authorization summary\")"), ios.indexOf(".accessibilityIdentifier(\"routine.review.card\")")), /UserOperation|EntryPoint|calldata|digest|nullifier|witness|ActionGate|validator|raw gas/iu);
});
