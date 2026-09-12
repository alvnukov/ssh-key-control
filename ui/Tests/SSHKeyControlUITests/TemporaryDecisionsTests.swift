import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class TemporaryDecisionsTests: XCTestCase {
    private func entry(_ id: String, allowed: Bool = true, expires: TimeInterval = 900) -> TemporaryDecision {
        TemporaryDecision(id: id, keyFingerprint: "SHA256:key-" + id, hostFingerprint: "SHA256:server-" + id,
                          host: "router-" + id, user: "alice", allowed: allowed,
                          expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(expires)))
    }
    private func descendants(_ view: NSView) -> [NSView] {
        [view] + view.subviews.flatMap { descendants($0) }
    }
    private func button(_ title: String, in view: NSView) -> NSButton? {
        descendants(view).compactMap { $0 as? NSButton }.first { $0.title == L10n.string(title) }
    }
    private func later(_ body: @escaping @MainActor () -> Void) -> Timer {
        let timer = Timer(timeInterval: 0.08, repeats: false) { _ in MainActor.assumeIsolated { body() } }
        RunLoop.main.add(timer, forMode: RunLoop.Mode("NSModalPanelRunLoopMode"))
        return timer
    }
    func testRevokeTargetsSelectedIDAndRefreshPreservesSelection() throws {
        _ = NSApplication.shared
        let panel = TemporaryDecisionsPanel()
        let first = entry("one"), second = entry("two", allowed: false)
        let timer = later {
            panel.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
            self.button("Refresh", in: panel.window.contentView!)?.performClick(nil)
        }
        XCTAssertEqual(panel.present([first, second], message: "", activate: false).action, "refresh")
        timer.invalidate()
        let next = later {
            XCTAssertEqual(panel.table.selectedRow, 0)
            self.button("Revoke Decision", in: panel.window.contentView!)?.performClick(nil)
        }
        XCTAssertEqual(panel.present([second, first], message: "", activate: false),
                       DecisionChange(action: "revoke", id: second.id))
        next.invalidate()
        panel.window.orderOut(nil)
    }
    func testExpiredSelectionCannotRevokeOrEdit() {
        _ = NSApplication.shared
        let panel = TemporaryDecisionsPanel()
        let timer = later {
            XCTAssertEqual(panel.table.numberOfRows, 0)
            XCTAssertEqual(self.button("Revoke Decision", in: panel.window.contentView!)?.isEnabled, false)
            XCTAssertEqual(self.button("Change Duration…", in: panel.window.contentView!)?.isEnabled, false)
            self.button("Done", in: panel.window.contentView!)?.performClick(nil)
        }
        XCTAssertEqual(panel.present([entry("expired", expires: -1)], message: "", activate: false).action, "close")
        timer.invalidate()
    }
    func testDurationEditorChangesMinutesAndKeepsDecisionIdentity() {
        _ = NSApplication.shared
        let panel = TemporaryDecisionsPanel()
        let value = entry("denied", allowed: false)
        var editorTimer: Timer?
        let timer = later {
            editorTimer = self.later {
                guard let content = NSApp.modalWindow?.contentView else { XCTFail("no editor"); NSApp.abortModal(); return }
                let field = self.descendants(content).compactMap { $0 as? NSTextField }.first { $0.isEditable }
                XCTAssertNotNil(field)
                field?.stringValue = "37"
                self.button("Apply", in: content)?.performClick(nil)
            }
            self.button("Change Duration…", in: panel.window.contentView!)?.performClick(nil)
        }
        XCTAssertEqual(panel.present([value], message: "", activate: false),
                       DecisionChange(action: "update", id: value.id, minutes: 37))
        timer.invalidate(); editorTimer?.invalidate()
        panel.window.orderOut(nil)
    }
    func testManagementProtocolRoundTrip() throws {
        let change = DecisionChange(action: "update", id: "opaque", endOfDay: true)
        XCTAssertEqual(try JSONDecoder().decode(DecisionChange.self, from: JSONEncoder().encode(change)), change)
        let decision = entry("one")
        XCTAssertEqual(try JSONDecoder().decode(TemporaryDecision.self, from: JSONEncoder().encode(decision)), decision)
    }
}
