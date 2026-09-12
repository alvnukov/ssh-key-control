import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
private final class SettingsTestNotifications: MonitorNotifications {
    func permission() async -> MonitorNotificationPermission { .allowed }
    func requestPermission() async throws -> Bool { throw Failure.denied }
    func send(id: String, removed: UInt64, failed: UInt64) async throws { throw Failure.denied }
    func sendTest(id: String) async throws { throw Failure.denied }
}

@MainActor
final class SettingsWindowTests: XCTestCase {
    func testSettingsUsesNativeToolbarAndFixedWindow() throws {
        let suite = "SettingsWindowTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let monitor = NativeAgentMonitorModel(notifications: SettingsTestNotifications(), defaults: defaults,
            readPolicy: { NativeMonitorPolicy() }, writePolicy: { _ in XCTFail("layout test changed policy") },
            readState: { throw CocoaError(.fileNoSuchFile) })
        let controller = SettingsWindowController(monitor: monitor)
        let window = try XCTUnwrap(controller.window)
        XCTAssertTrue(window.styleMask.contains(.closable))
        XCTAssertFalse(window.styleMask.contains(.resizable))
        XCTAssertFalse(window.styleMask.contains(.miniaturizable))
        let tabs = try XCTUnwrap(window.contentViewController as? NSTabViewController)
        XCTAssertEqual(tabs.tabStyle, .toolbar)
        XCTAssertEqual(tabs.tabViewItems.map(\.label), ["General", "Advanced"].map { L10n.string($0) })
        XCTAssertEqual(window.toolbar?.allowsUserCustomization, false)
        XCTAssertEqual(window.toolbar?.displayMode, .iconAndLabel)
        for (index, title, width) in [(0, "General", 520.0), (1, "Advanced", 560.0)] {
            tabs.selectedTabViewItemIndex = index
            (tabs as? SettingsTabController)?.fitSelectedPane()
            XCTAssertEqual(window.title, L10n.string(title))
            XCTAssertGreaterThanOrEqual(window.contentLayoutRect.width, width)
        }
    }
}
