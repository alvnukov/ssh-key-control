import XCTest
@testable import SSHKeyControlUI

@MainActor
private final class FakeMonitorNotifications: MonitorNotifications {
    var status: MonitorNotificationPermission = .notDetermined
    var grant = false
    var requests = 0
    var attempts = 0
    var delivered: [(UInt64, UInt64)] = []
    var failSubmission = false
    var failPermission = false
    var testAttempts = 0
    var testIDs: [String] = []
    var holdPermission = false
    var permissionReply: CheckedContinuation<Void, Never>?
    private var permissionStarted: CheckedContinuation<Void, Never>?
    func waitUntilPermissionRequested() async {
        if requests > 0 { return }
        await withCheckedContinuation { permissionStarted = $0 }
    }
    func permission() async -> MonitorNotificationPermission { status }
    func requestPermission() async throws -> Bool {
        requests += 1
        permissionStarted?.resume(); permissionStarted = nil
        if holdPermission { await withCheckedContinuation { permissionReply = $0 } }
        if failPermission { throw CocoaError(.fileReadUnknown) }
        status = grant ? .allowed : .denied; return grant
    }
    func send(id: String, removed: UInt64, failed: UInt64) async throws {
        attempts += 1
        if failSubmission { throw CocoaError(.fileWriteUnknown) }
        delivered.append((removed, failed))
    }
    func sendTest(id: String) async throws {
        testAttempts += 1
        if failSubmission { throw CocoaError(.fileWriteUnknown) }
        testIDs.append(id)
    }
}

@MainActor
final class NativeAgentMonitorTests: XCTestCase {
    private func defaults() -> UserDefaults {
        let name = "NativeAgentMonitorTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        addTeardownBlock { defaults.removePersistentDomain(forName: name) }
        return defaults
    }
    func testMissingSettingDefaultsOnAndExplicitOptOutPersists() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("policy")
        XCTAssertTrue(try NativeMonitorFiles.policy(at: url).enabled)
        try NativeMonitorFiles.save(NativeMonitorPolicy(enabled: false), at: url)
        XCTAssertFalse(try NativeMonitorFiles.policy(at: url).enabled)
    }
    func testDeniedPermissionIsRequestedOnlyOnceAndNoFalseDelivery() async {
        let center = FakeMonitorNotifications()
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults(),
            readPolicy: { NativeMonitorPolicy() }, readState: { throw CocoaError(.fileNoSuchFile) })
        await model.refresh(); await model.permissionRequest?.value; await model.refresh()
        XCTAssertEqual(center.requests, 1)
        XCTAssertEqual(model.notificationPermission, .denied)
        XCTAssertEqual(center.attempts, 0)
    }
    func testUnansweredPermissionDoesNotFreezeHealthOrOptOut() async {
        let center = FakeMonitorNotifications(); center.holdPermission = true
        var policy = NativeMonitorPolicy()
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults(), readPolicy: { policy }, readState: {
            NativeMonitorState(enabled: policy.enabled, session: "session", checkedAt: Date(), status: policy.enabled ? "clear" : "disabled", removed: 0, failed: 0)
        })
        await model.refresh()
        await center.waitUntilPermissionRequested()
        policy.enabled = false
        await model.refresh()
        XCTAssertFalse(model.enabled)
        XCTAssertEqual(model.title, L10n.string("Monitoring is off"))
        XCTAssertEqual(center.requests, 1)
        center.permissionReply?.resume(); center.permissionReply = nil
        await model.permissionRequest?.value
    }
    func testOptOutDoesNotRequestPermissionOrNotify() async {
        let center = FakeMonitorNotifications()
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults(),
            readPolicy: { NativeMonitorPolicy(enabled: false) }, readState: {
                NativeMonitorState(enabled: true, session: "session", checkedAt: Date(), status: "clear", removed: 1, failed: 0)
            })
        await model.refresh()
        XCTAssertEqual(center.requests, 0); XCTAssertEqual(center.attempts, 0)
        XCTAssertEqual(model.title, L10n.string("Monitoring is off"))
    }
    func testAuthorizedNotificationsAggregateAndCursorSurvivesRestart() async {
        let center = FakeMonitorNotifications(); center.status = .allowed
        let stored = defaults()
        var removed: UInt64 = 1
        let read = { NativeMonitorState(enabled: true, session: "session", checkedAt: Date(), status: "clear", removed: removed, failed: 0) }
        let model = NativeAgentMonitorModel(notifications: center, defaults: stored, readPolicy: { NativeMonitorPolicy() }, readState: read)
        let now = Date()
        await model.refresh(now: now)
        XCTAssertEqual(center.delivered.count, 1)
        removed = 4
        await model.refresh(now: now.addingTimeInterval(2))
        XCTAssertEqual(center.delivered.count, 1)
        await model.refresh(now: now.addingTimeInterval(31))
        XCTAssertEqual(center.delivered.count, 2)
        XCTAssertEqual(center.delivered[1].0, 3)
        let restarted = NativeAgentMonitorModel(notifications: center, defaults: stored, readPolicy: { NativeMonitorPolicy() }, readState: read)
        await restarted.refresh(now: now.addingTimeInterval(40))
        XCTAssertEqual(center.delivered.count, 2)
        XCTAssertEqual(center.requests, 0)
    }
    func testNotificationSubmissionFailureStaysVisibleAndRetriesWithoutFlood() async {
        let center = FakeMonitorNotifications(); center.status = .allowed; center.failSubmission = true
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults(), readPolicy: { NativeMonitorPolicy() }, readState: {
            NativeMonitorState(enabled: true, session: "session", checkedAt: Date(), status: "removal_failed", removed: 0, failed: 1)
        })
        let now = Date()
        await model.refresh(now: now); await model.refresh(now: now.addingTimeInterval(2))
        XCTAssertNotNil(model.notificationError); XCTAssertEqual(center.attempts, 1); XCTAssertEqual(center.delivered.count, 0)
        center.failSubmission = false
        await model.refresh(now: now.addingTimeInterval(31))
        XCTAssertNil(model.notificationError); XCTAssertEqual(center.delivered.count, 1)
        XCTAssertEqual(center.delivered[0].1, 1)
    }
    func testStaleHeartbeatDoesNotClaimMonitoring() async {
        let center = FakeMonitorNotifications(); center.status = .denied
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults(), readPolicy: { NativeMonitorPolicy() }, readState: {
            NativeMonitorState(enabled: true, session: "session", checkedAt: Date().addingTimeInterval(-30), status: "clear", removed: 0, failed: 0)
        })
        await model.refresh()
        XCTAssertEqual(model.title, L10n.string("Monitoring is not running or has not applied the setting yet"))
    }
    func testNotificationTestWorksWhenMonitoringIsOffWithoutTouchingItsState() async {
        let center = FakeMonitorNotifications(); center.status = .allowed
        let stored = defaults()
        let cursor = Data("saved-real-event-cursor".utf8)
        stored.set(cursor, forKey: "nativeAgentMonitor.notificationCursor")
        var reads = 0
        let model = NativeAgentMonitorModel(notifications: center, defaults: stored,
            readPolicy: { NativeMonitorPolicy(enabled: false) },
            writePolicy: { _ in XCTFail("notification test wrote monitoring policy") },
            readState: { reads += 1; throw CocoaError(.fileNoSuchFile) })
        await model.refresh()
        XCTAssertFalse(model.enabled)
        let readsBefore = reads
        await model.sendTestNotification()
        XCTAssertEqual(center.testIDs.count, 1)
        XCTAssertEqual(center.attempts, 0)
        XCTAssertEqual(center.requests, 0)
        XCTAssertEqual(reads, readsBefore)
        XCTAssertEqual(stored.data(forKey: "nativeAgentMonitor.notificationCursor"), cursor)
        XCTAssertNotNil(model.testNotificationFeedback)
        XCTAssertFalse(model.testNotificationFailed)
        XCTAssertFalse(model.sendingTestNotification)
    }

    func testDeniedNotificationTestExplainsSettingsWithoutRequestingAgain() async {
        let center = FakeMonitorNotifications(); center.status = .denied
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults())
        await model.sendTestNotification()
        XCTAssertEqual(center.requests, 0)
        XCTAssertEqual(center.testAttempts, 0)
        XCTAssertTrue(model.testNotificationFailed)
        XCTAssertEqual(model.testNotificationFeedback,
                       L10n.string("Notifications are off in macOS. Open Notification Settings to allow them."))
    }

    func testFirstNotificationTestRequestsPermissionAndSendsOnlyWhenGranted() async {
        for grant in [false, true] {
            let center = FakeMonitorNotifications(); center.grant = grant
            let model = NativeAgentMonitorModel(notifications: center, defaults: defaults())
            await model.sendTestNotification()
            XCTAssertEqual(center.requests, 1)
            XCTAssertEqual(center.testIDs.count, grant ? 1 : 0)
            XCTAssertEqual(model.testNotificationFailed, !grant)
            XCTAssertEqual(center.attempts, 0)
        }
    }

    func testNotificationTestDoesNotDuplicateInFlightRequestsOrDoubleClicks() async {
        let center = FakeMonitorNotifications(); center.holdPermission = true; center.grant = true
        let model = NativeAgentMonitorModel(notifications: center, defaults: defaults())
        let now = Date()
        let first = Task { await model.sendTestNotification(now: now) }
        await center.waitUntilPermissionRequested()
        XCTAssertTrue(model.sendingTestNotification)
        await model.sendTestNotification(now: now)
        XCTAssertEqual(center.requests, 1)
        center.permissionReply?.resume(); center.permissionReply = nil
        await first.value
        await model.sendTestNotification(now: now.addingTimeInterval(0.5))
        XCTAssertEqual(center.testIDs.count, 1)
        await model.sendTestNotification(now: now.addingTimeInterval(3))
        XCTAssertEqual(center.testIDs.count, 2)
        XCTAssertNotEqual(center.testIDs.first, center.testIDs.last)
    }

    func testNotificationTestReportsPermissionAndSubmissionErrors() async {
        for permissionFailure in [false, true] {
            let center = FakeMonitorNotifications()
            center.status = permissionFailure ? .notDetermined : .allowed
            center.failPermission = permissionFailure
            center.failSubmission = !permissionFailure
            let model = NativeAgentMonitorModel(notifications: center, defaults: defaults())
            await model.sendTestNotification()
            XCTAssertTrue(model.testNotificationFailed)
            XCTAssertNotNil(model.testNotificationFeedback)
            XCTAssertTrue(center.testIDs.isEmpty)
            XCTAssertFalse(model.sendingTestNotification)
        }
    }

}
