import AppKit
import XCTest
@testable import SSHKeyControlUI

/// ssh, the shell that ran it, and the terminal that owns the session: the
/// shape every one of these tests is written against.
private let callers = [
    ProcessLink(name: "ssh", pid: 101),
    ProcessLink(name: "zsh", pid: 102),
    ProcessLink(name: "Terminal", pid: 103, team: "APPLE", verified: true)
]

@MainActor
private final class ChainFakeDialogs: Dialogs {
    var choice = Confirmation(allowed: true)
    var chain: [ProcessLink] = []
    var boundary = -1

    func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool) { ("", false) }
    func text(title: String, message: String, placeholder: String) throws -> String { "" }
    func notify(title: String, message: String) throws {}
    func confirm(title: String, message: String, allow: String, deny: String, chain: [ProcessLink]) throws -> Bool {
        self.chain = chain
        return true
    }
    func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String,
                       chain: [ProcessLink], boundary: Int) throws -> Confirmation {
        self.chain = chain
        self.boundary = boundary
        return choice
    }
}

@MainActor
final class ProcessChainTests: XCTestCase {
    private func panel(chain: [ProcessLink] = callers, boundary: Int = 1,
                       destination: String = "root @ server", unanchored: Bool = true) -> ConfirmationPanel {
        ConfirmationPanel(title: "Allow SSH key use?", message: "", allow: "Allow", deny: "Deny",
                          destination: destination, chain: chain, boundary: boundary,
                          unanchoredDurations: unanchored)
    }

    func testChainAndBoundaryTravelFromTheWireToTheDialog() throws {
        let line = #"{"op":"confirm","destination":"alice@production","chain":[{"name":"ssh","pid":101},{"name":"Terminal","pid":103,"team":"APPLE","verified":true}],"boundary":1}"#
        let request = try Wire.decode(Data(line.utf8))
        XCTAssertEqual(request.chain?.count, 2)
        XCTAssertEqual(request.chain?.last, ProcessLink(name: "Terminal", pid: 103, team: "APPLE", verified: true))
        let dialogs = ChainFakeDialogs()
        _ = Dispatcher(dialogs: dialogs, store: FakeStore()).handle(request)
        XCTAssertEqual(dialogs.chain, request.chain)
        XCTAssertEqual(dialogs.boundary, 1)
    }

    func testABoundaryOutsideItsOwnChainIsDroppedNotShown() {
        for offered in [-1, 0, 3, 99] {
            let dialogs = ChainFakeDialogs()
            _ = Dispatcher(dialogs: dialogs, store: FakeStore()).handle(
                Request(op: .confirm, destination: "alice@production", chain: callers, boundary: offered))
            XCTAssertEqual(dialogs.boundary, 0, "boundary \(offered) should not name a link")
        }
    }

    func testEveryLinkSaysWhichProgramAndWhetherMacOSVouchedForIt() {
        let view = ProcessChainView(links: callers, boundary: 1)
        XCTAssertEqual(view.linkButtons[0]?.title.hasPrefix("ssh [101]"), true)
        // Unsigned is ordinary, not a failure, but it is never left unsaid.
        XCTAssertTrue(view.linkButtons[0]?.title.contains("⚠") == true)
        XCTAssertFalse(view.linkButtons[2]?.title.contains("⚠") == true)
        XCTAssertTrue(view.linkButtons[2]?.title.contains("APPLE") == true)
        XCTAssertEqual(view.anchor?.label, "zsh [102]")
    }

    func testTheLineMovesUpTheChainAndNeverBelowWhatTheAgentProposed() {
        let view = ProcessChainView(links: callers, boundary: 1)
        var changes = 0
        view.onChange = { changes += 1 }
        view.linkButtons[0]?.performClick(nil)
        XCTAssertEqual(view.boundary, 1, "ssh itself outlives nothing; the line cannot go there")
        XCTAssertEqual(changes, 0)
        view.linkButtons[2]?.performClick(nil)
        XCTAssertEqual(view.boundary, 2)
        XCTAssertEqual(view.anchor?.label, "Terminal [103]")
        XCTAssertEqual(changes, 1)
        // Back to the agent's own proposal is a move up from nothing lower.
        view.linkButtons[1]?.performClick(nil)
        XCTAssertEqual(view.boundary, 1)
    }

    func testNothingIsSelectableWhenNoProcessCouldBeNamed() {
        let view = ProcessChainView(links: callers, boundary: 0)
        XCTAssertNil(view.anchor)
        for index in callers.indices { XCTAssertNil(view.linkButtons[index]?.action) }
        view.linkButtons[2]?.performClick(nil)
        XCTAssertEqual(view.boundary, 0)
    }

    func testALongChainFoldsItsMiddleAndKeepsWhatTheDecisionRestsOn() {
        let long = (0..<20).map { ProcessLink(name: "p\($0)", pid: Int32(200 + $0)) }
        let view = ProcessChainView(links: long, boundary: 5)
        let shown = Set(view.visibleIndices)
        XCTAssertLessThan(shown.count, long.count)
        for kept in [0, 5, 19] { XCTAssertTrue(shown.contains(kept), "index \(kept) must stay visible") }
        XCTAssertFalse(view.expandButtons.isEmpty)
        view.expandButtons[0].performClick(nil)
        XCTAssertEqual(view.visibleIndices.count, long.count)
        // Widening past the fold keeps the chosen link on screen.
        view.linkButtons[12]?.performClick(nil)
        XCTAssertEqual(view.boundary, 12)
    }

    func testADecisionMeasuredAgainstAProgramNeedsAProgramToMeasureItAgainst() {
        XCTAssertTrue(panel().durationPicker.itemArray.compactMap { $0.representedObject as? String }.contains("process"))
        for unnamed in [panel(chain: [], boundary: 0), panel(boundary: 0)] {
            XCTAssertFalse(unnamed.durationPicker.itemArray.compactMap { $0.representedObject as? String }.contains("process"))
        }
    }

    func testAMacMayRefuseToTimeADecisionItCannotAttachToAProgram() {
        let offered = panel(boundary: 0, unanchored: true)
        XCTAssertTrue(offered.durationPicker.isEnabled)
        XCTAssertEqual(offered.durationPicker.itemArray.count, 5)
        let withheld = panel(boundary: 0, unanchored: false)
        XCTAssertFalse(withheld.durationPicker.isEnabled)
        XCTAssertEqual(withheld.durationPicker.itemArray.compactMap { $0.representedObject as? String }, ["once"])
        // The setting cannot reach a request that did name its program.
        XCTAssertTrue(panel(unanchored: false).durationPicker.isEnabled)
    }

    func testBothDecisionButtonsNameTheProgramTheyApplyTo() {
        let panel = self.panel()
        panel.durationPicker.selectItem(at: 2)
        panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
        // A refusal stops what the user turned away, not their own next
        // connection, so the deny button names the same program the allow
        // button does — and follows the line when it is moved.
        for button in [panel.allowButton, panel.denyButton] {
            XCTAssertTrue(button.title.contains("zsh [102]"), button.title)
        }
        panel.chainView?.linkButtons[2]?.performClick(nil)
        for button in [panel.allowButton, panel.denyButton] {
            XCTAssertTrue(button.title.contains("Terminal [103]"), button.title)
        }
        // With nobody to name, a refusal keeps nothing, and says so.
        XCTAssertEqual(self.panel(boundary: 0).denyButton.title, L10n.string("Deny once"))
    }

    func testBothAnswersSayWhichProgramTheyAttachTo() throws {
        for allowed in [true, false] {
            let panel = self.panel()
            let result = runConfirmation(panel) {
                panel.durationPicker.selectItem(at: 4) // While this program runs.
                panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
                panel.chainView?.linkButtons[2]?.performClick(nil)
                (allowed ? panel.allowButton : panel.denyButton).performClick(nil)
            }
            XCTAssertEqual(result, allowed ? .OK : .cancel)
            // The refusal is measured against the same program's life: it is
            // the answer to something that asks in a loop from that window.
            XCTAssertEqual(panel.scope, allowed ? .process : .denyProcess)
            XCTAssertEqual(panel.boundary, 2)
            let response = Response.confirmation(Confirmation(allowed: allowed, scope: panel.scope,
                                                              durationMinutes: panel.durationMinutes,
                                                              boundary: panel.boundary))
            XCTAssertEqual(response.boundary, 2)
            XCTAssertEqual(response.scope, allowed ? .process : .denyProcess)
        }
    }

    func testARefusalWithNoProgramToAttachToAnswersOnceAndIsGone() {
        // The duration menu is still offered here for approvals, so the panel
        // has a chosen interval to throw away.
        let panel = self.panel(boundary: 0)
        let result = runConfirmation(panel) {
            panel.durationPicker.selectItem(at: 2)
            panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
            panel.denyButton.performClick(nil)
        }
        XCTAssertEqual(result, .cancel)
        XCTAssertEqual(panel.scope, .once)
        XCTAssertNil(panel.boundary)
        XCTAssertNil(Response.confirmation(Confirmation(allowed: false, scope: panel.scope)).scope)
    }

    func testAnUnnamedProgramIsGrantedWithoutClaimingWhereTheDecisionSits() {
        let panel = self.panel(boundary: 0)
        let result = runConfirmation(panel) {
            panel.durationPicker.selectItem(at: 1)
            panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
            panel.allowButton.performClick(nil)
        }
        XCTAssertEqual(result, .OK)
        XCTAssertEqual(panel.scope, .fiveMinutes)
        XCTAssertNil(panel.boundary)
    }

    func testTheDecisionButtonsAreNeverClippedAndThePanelNeverJumps() {
        let panel = self.panel()
        let content = try! XCTUnwrap(panel.contentView)
        var widths: Set<CGFloat> = []
        for index in 0..<panel.durationPicker.itemArray.count {
            panel.durationPicker.selectItem(at: index)
            panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
            for link in [2, 1] {
                panel.chainView?.linkButtons[link]?.performClick(nil)
                content.layoutSubtreeIfNeeded()
                widths.insert(content.frame.width)
                for button in [panel.allowButton, panel.denyButton] {
                    XCTAssertEqual(button.frame.width, button.fittingSize.width, button.title)
                }
                // The row of buttons stays inside the panel's own margin.
                let row = try! XCTUnwrap(panel.allowButton.superview)
                XCTAssertGreaterThanOrEqual(row.frame.minX, 24)
                XCTAssertLessThanOrEqual(row.frame.maxX, content.frame.width - 24)
            }
        }
        // Naming a program widens the panel once, not on every choice made in it.
        XCTAssertEqual(widths.count, 1)
        XCTAssertGreaterThan(widths.first ?? 0, 560)
        XCTAssertEqual(self.panel(chain: [], boundary: 0).contentView?.frame.width, 560)
    }

    func testEscapeStillDeniesOnceWithoutAttachingToAnything() {
        let panel = self.panel()
        let result = runConfirmation(panel) {
            panel.durationPicker.selectItem(at: 4)
            panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
            panel.cancelOperation(nil)
        }
        XCTAssertEqual(result, .cancel)
        XCTAssertEqual(panel.scope, .once)
        XCTAssertNil(panel.boundary)
    }
}
