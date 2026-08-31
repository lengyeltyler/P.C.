import XCTest

final class PhilCoreCompanionUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testSafetyCriticalScreensAreReachable() {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(app.navigationBars["Device status"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Controlled Sepolia Beta completed"].exists)
        XCTAssertTrue(app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "Recovery is intentionally unavailable")
        ).firstMatch.exists)
        capture("status")

        app.tabBars.buttons["Pair"].firstMatch.tap()
        XCTAssertTrue(app.navigationBars["Pair with desktop"].exists)
        XCTAssertTrue(app.buttons["Scan desktop QR code"].exists)
        capture("pair")

        app.tabBars.buttons["Approve"].firstMatch.tap()
        XCTAssertTrue(app.navigationBars["Routine approval"].waitForExistence(timeout: 5))
        capture("approve")

        app.tabBars.buttons["Recovery"].tap()
        XCTAssertTrue(app.navigationBars["Recovery"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Recovery deferred"].exists)
        XCTAssertFalse(app.buttons["Scan recovery QR code"].exists)
        capture("recovery")

        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.navigationBars["Settings"].exists)
        XCTAssertTrue(app.staticTexts["Device controls"].exists)
        XCTAssertFalse(app.buttons["Delete or invalidate credential"].exists)
        capture("settings")
    }

    func testPassBAuthorizationGuidanceStates() {
        verifyFixture("pair-review", navigationTitle: "Pair with desktop", text: "A1B2-C3D4-E5F6-G7H8", screenshot: "pass-b-pair-fingerprint")
        verifyFixture("routine-review", navigationTitle: "Routine approval", text: "Authorization summary", screenshot: "pass-b-approve-review")
        verifyFixture("routine-waiting", navigationTitle: "Routine approval", text: "Waiting for your Mac", screenshot: "pass-b-waiting")
        verifyFixture("routine-signing", navigationTitle: "Routine approval", text: "Protected signing", screenshot: "pass-b-signing")
        verifyFixture("routine-success", navigationTitle: "Routine approval", text: "Local action verified", screenshot: "pass-b-success")
        verifyFixture("routine-rejected", navigationTitle: "Routine approval", text: "Request not approved", screenshot: "pass-b-rejected")
        verifyFixture("routine-failure", navigationTitle: "Routine approval", text: "Request stopped", screenshot: "pass-b-failure")
    }

    func testActiveRoutineCancellationStillDisplaysCancelled() {
        let app = launchFixture("routine-waiting")
        XCTAssertTrue(app.staticTexts["Waiting for your Mac"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Request cancelled"].exists)
        let cancel = app.buttons["routine.cancel.button"]
        scrollUntilHittable(cancel, in: app)
        cancel.tap()
        XCTAssertTrue(app.staticTexts["Request cancelled"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Waiting for your Mac"].exists)
        capture("scan-state-active-cancellation")
    }

    func testPassCLargeDynamicTypeKeepsCriticalAuthorizationReachable() {
        let app = XCUIApplication()
        app.launchArguments += [
            "-ApplePersistenceIgnoreState", "YES",
            "--philcore-ui-test-large-type",
            "--philcore-ui-test-state", "routine-review"
        ]
        app.launch()

        XCTAssertTrue(app.navigationBars["Routine approval"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Authorization summary"].exists)
        let approval = app.buttons["Approve harmless local action"]
        scrollUntilHittable(approval, in: app)
        XCTAssertTrue(approval.isHittable)
        XCTAssertTrue(app.buttons["Details"].exists)
        capture("pass-c-approve-review-accessibility-type")

        app.tabBars.buttons["Recovery"].tap()
        XCTAssertTrue(app.staticTexts["Recovery deferred"].waitForExistence(timeout: 5))
        let recoveryBoundary = app.staticTexts["Future recovery requires a separate reviewed release"]
        scrollUntilHittable(recoveryBoundary, in: app)
        XCTAssertTrue(recoveryBoundary.isHittable)
        capture("pass-c-recovery-accessibility-type")

        app.tabBars.buttons["Settings"].tap()
        XCTAssertTrue(app.staticTexts["Device controls"].waitForExistence(timeout: 5))
        let aboutBeta = app.staticTexts["ABOUT THIS BETA"]
        scrollUntilHittable(aboutBeta, in: app)
        XCTAssertTrue(aboutBeta.isHittable)
        capture("pass-c-settings-accessibility-type")
    }

    func testPassCSafeAreaAndDeferredRecoveryAtCompactHeight() {
        let app = XCUIApplication()
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
        app.launch()
        app.tabBars.buttons["Recovery"].tap()

        XCTAssertTrue(app.navigationBars["Recovery"].waitForExistence(timeout: 5))
        let finalBoundary = app.staticTexts["Future recovery requires a separate reviewed release"]
        scrollUntilHittable(finalBoundary, in: app)
        XCTAssertTrue(finalBoundary.isHittable)
        XCTAssertTrue(app.tabBars.buttons["Recovery"].isHittable)
        XCTAssertFalse(app.buttons["Scan recovery QR code"].exists)
        capture("pass-c-recovery-safe-area")
    }

    func testPassCAccessibilityOrderKeepsEssentialContentBeforeDetails() {
        let pair = launchFixture("pair-review")
        pair.tabBars.buttons["Pair"].tap()
        let pairSummary = pair.navigationBars["Pair with desktop"]
        let pairFingerprint = pair.staticTexts["A1B2-C3D4-E5F6-G7H8"]
        XCTAssertTrue(pairSummary.waitForExistence(timeout: 5))
        XCTAssertTrue(pairFingerprint.exists)
        XCTAssertLessThan(pairSummary.frame.minY, pairFingerprint.frame.minY)
        pair.terminate()

        let approval = launchFixture("routine-review")
        approval.tabBars.buttons["Approve"].tap()
        let approvalSummary = approval.staticTexts["Authorization summary"]
        let technicalDetails = approval.buttons["Details"]
        XCTAssertTrue(approvalSummary.waitForExistence(timeout: 5))
        XCTAssertTrue(technicalDetails.exists)
        XCTAssertLessThan(approvalSummary.frame.minY, technicalDetails.frame.minY)
        approval.terminate()

        let failure = launchFixture("routine-failure")
        failure.tabBars.buttons["Approve"].tap()
        let failureState = failure.staticTexts["FAILED"]
        let freshRequest = failure.buttons["Scan a fresh routine QR code"]
        XCTAssertTrue(failureState.waitForExistence(timeout: 5))
        XCTAssertTrue(freshRequest.exists)
        XCTAssertLessThan(failureState.frame.minY, freshRequest.frame.minY)
        failure.terminate()

        let recovery = XCUIApplication()
        recovery.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
        recovery.launch()
        recovery.tabBars.buttons["Recovery"].tap()
        let recoveryState = recovery.staticTexts["Recovery deferred"]
        let recoveryDetails = recovery.staticTexts["Future recovery requires a separate reviewed release"]
        XCTAssertTrue(recoveryState.waitForExistence(timeout: 5))
        XCTAssertTrue(recoveryDetails.exists)
        XCTAssertLessThan(recoveryState.frame.minY, recoveryDetails.frame.minY)
    }

    func testPassDAboutAndAdvancedEvidenceRemainSeparated() {
        let canonicalSmartAccount = "0xb72053013089F089502B075009c0BD807349eCC6"
        let app = XCUIApplication()
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
        app.launch()
        app.tabBars.buttons["Settings"].tap()

        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Phil — Controlled Sepolia Beta"].exists)
        XCTAssertTrue(app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "Not mainnet")
        ).firstMatch.exists)
        XCTAssertTrue(app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "not currently post-quantum secure")
        ).firstMatch.exists)
        XCTAssertFalse(app.staticTexts[canonicalSmartAccount].exists)
        capture("pass-d-settings-about")

        let disclosure = app.buttons["Advanced Beta evidence"]
        scrollUntilHittable(disclosure, in: app)
        XCTAssertTrue(disclosure.isHittable)
        disclosure.tap()
        let smartAccount = app.staticTexts[canonicalSmartAccount]
        scrollUntilHittable(smartAccount, in: app)
        XCTAssertTrue(smartAccount.exists)
        XCTAssertFalse(app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS[c] %@", "private key")
        ).firstMatch.exists)
        capture("pass-d-settings-advanced")
    }

    private func verifyFixture(_ fixture: String, navigationTitle: String, text: String, screenshot: String) {
        let app = launchFixture(fixture)
        let targetTab = navigationTitle == "Pair with desktop" ? "Pair" : "Approve"
        if app.tabBars.buttons["Status"].exists, app.tabBars.buttons[targetTab].exists {
            app.tabBars.buttons["Status"].tap()
            app.tabBars.buttons[targetTab].tap()
        }
        XCTAssertTrue(app.navigationBars[navigationTitle].waitForExistence(timeout: 5))
        let matchingText = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS[c] %@", text)
        ).firstMatch
        XCTAssertTrue(matchingText.waitForExistence(timeout: 5))
        capture(screenshot)
        app.terminate()
    }

    private func launchFixture(_ fixture: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments += ["-ApplePersistenceIgnoreState", "YES", "--philcore-ui-test-state", fixture]
        app.launch()
        return app
    }

    private func capture(_ name: String) {
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func scrollUntilHittable(_ element: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<6 where !element.isHittable {
            app.swipeUp()
        }
    }
}
