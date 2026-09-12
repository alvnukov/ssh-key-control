import XCTest
@testable import SSHKeyControlUI

@MainActor
final class MonitorSettingsRoutingTests: XCTestCase {
    func testNotificationSettingsUsesFallbackWithoutChangingPermission() {
        var opened: [URL] = []
        XCTAssertTrue(MonitorNotificationSettings.open { url in
            opened.append(url)
            return opened.count == 2
        })
        XCTAssertEqual(opened.map(\.absoluteString), [
            "x-apple.systempreferences:com.apple.Notifications-Settings.extension",
            "x-apple.systempreferences:com.apple.preference.notifications"
        ])
    }
    func testNotificationSettingsReportsFailureAfterAppFallback() {
        var opened: [URL] = []
        XCTAssertFalse(MonitorNotificationSettings.open { opened.append($0); return false })
        XCTAssertEqual(opened.count, 3)
        XCTAssertEqual(opened.last?.path, "/System/Applications/System Settings.app")
    }
}
