import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class TemporaryDecisionsTests: XCTestCase {
    private func entry(_ id: String, allowed: Bool = true, expires: TimeInterval = 900,
                       process: String? = nil, pid: Int32? = nil, live: Bool? = nil) -> TemporaryDecision {
        TemporaryDecision(id: id, keyFingerprint: "SHA256:key-" + id, hostFingerprint: "SHA256:server-" + id,
                          host: "router-" + id, user: "alice", allowed: allowed,
                          expiresAt: ISO8601DateFormatter().string(from: Date().addingTimeInterval(expires)),
                          process: process, processPid: pid, processLive: live)
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
        for decision in [entry("one"), entry("two", process: "zsh", pid: 102, live: true)] {
            XCTAssertEqual(try JSONDecoder().decode(TemporaryDecision.self, from: JSONEncoder().encode(decision)), decision)
        }
        // An agent that predates process anchors sends no program at all.
        let old = #"{"id":"old","keyFingerprint":"k","hostFingerprint":"h","host":"router","user":"alice","allowed":true,"expiresAt":"2030-01-01T00:00:00Z"}"#
        XCTAssertNil(try JSONDecoder().decode(TemporaryDecision.self, from: Data(old.utf8)).process)
    }

    func testEachRowSaysWhichProgramHoldsItAndWhetherItIsStillRunning() {
        XCTAssertEqual(entry("a", process: "zsh", pid: 102, live: true).programLabel, "zsh [102]")
        XCTAssertEqual(entry("b", process: "zsh", pid: 102, live: false).programLabel,
                       "zsh [102] " + L10n.string("(ended)"))
        // A decision nobody in particular holds says so rather than nothing.
        XCTAssertEqual(entry("c").programLabel, L10n.string("Every program"))
        XCTAssertFalse(entry("c").isAnchored)
    }

    func testRevokingEveryDecisionOfAProgramNamesOneRowAndOnlyWhenOneIsHeld() {
        _ = NSApplication.shared
        let panel = TemporaryDecisionsPanel()
        let held = entry("held", process: "zsh", pid: 102, live: true)
        let everyone = entry("everyone")
        let timer = later {
            let content = panel.window.contentView!
            // The button is meaningless for a decision that was never kept for
            // one program: revoking that row is what the plain button does.
            panel.table.selectRowIndexes(IndexSet(integer: 1), byExtendingSelection: false)
            XCTAssertEqual(self.button("Revoke All for Program", in: content)?.isEnabled, false)
            panel.table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
            XCTAssertEqual(self.button("Revoke All for Program", in: content)?.isEnabled, true)
            self.button("Revoke All for Program", in: content)?.performClick(nil)
        }
        XCTAssertEqual(panel.present([held, everyone], message: "", activate: false),
                       DecisionChange(action: "revoke-process", id: held.id))
        timer.invalidate()
        panel.window.orderOut(nil)
    }
}
