import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class SettingsWindowTests: XCTestCase {
    func testSettingsUsesNativeToolbarAndFixedWindow() throws {
        let controller = SettingsWindowController()
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
