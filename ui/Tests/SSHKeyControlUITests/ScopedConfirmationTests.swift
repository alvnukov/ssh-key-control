import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class ScopedConfirmationTests: XCTestCase {
    func testDestinationAndLegacyDialogFallback() throws {
        let request = try Wire.decode(Data(#"{"op":"confirm","destination":"alice@production"}"#.utf8))
        XCTAssertEqual(request.destination, "alice@production")
        let dialogs = FakeDialogs()
        let dispatcher = Dispatcher(dialogs: dialogs, store: FakeStore())
        XCTAssertEqual(String(decoding: Wire.encode(dispatcher.handle(request)), as: UTF8.self),
                       #"{"answer":"yes","ok":true,"scope":"once"}"# + "\n")
        dialogs.confirmAnswer = false
        XCTAssertNil(dispatcher.handle(request).scope)
    }

    func testScopedChoicesAndDenialOnWire() throws {
        let dialogs = ScopedFakeDialogs()
        let dispatcher = Dispatcher(dialogs: dialogs, store: FakeStore())
        for (scope, wire) in [(GrantScope.once, "once"), (.fiveMinutes, "5m"), (.fifteenMinutes, "15m"), (.day, "day")] {
            dialogs.choice = Confirmation(allowed: true, scope: scope)
            let response = dispatcher.handle(Request(op: .confirm, destination: "alice@production"))
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Wire.encode(response)) as? [String: Any])
            XCTAssertEqual(json["scope"] as? String, wire)
            XCTAssertEqual(json["answer"] as? String, "yes")
            XCTAssertEqual(dialogs.destination, "alice@production")
        }
        dialogs.choice = Confirmation(allowed: false, scope: .day)
        XCTAssertNil(dispatcher.handle(Request(op: .confirm, destination: "alice@production")).scope)
        dialogs.choice = Confirmation(allowed: false, scope: .denyFiveMinutes)
        XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: "alice@production")).scope, .denyFiveMinutes)
        dialogs.choice = Confirmation(allowed: false, scope: .denyOneHour)
        XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: "alice@production")).scope, .denyOneHour)
        dialogs.choice = Confirmation(allowed: false, scope: .denyProcess, boundary: 1)
        let refusal = dispatcher.handle(Request(op: .confirm, destination: "alice@production"))
        XCTAssertEqual(refusal.scope, .denyProcess)
        XCTAssertEqual(refusal.boundary, 1)
        for destination in [nil, ""] as [String?] {
            XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: destination)), .success(answer: "yes"))
        }
        XCTAssertEqual(dialogs.legacyCalls, 2)
        XCTAssertEqual(dialogs.scopedCalls, 8) // No UI-side grant caching.
        XCTAssertNil(dispatcher.handle(Request(op: .text, destination: "alice@production")).scope)
        dialogs.error = .cancelled
        XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: "alice@production")), .failure(.cancelled))
    }

    func testOneDurationSelectorOffersBothDecisionsAndStartsOnce() {
        let panel = ConfirmationPanel(title: "Allow SSH key use?", message: "", allow: "Allow", deny: "Deny", destination: "root @ server")
        XCTAssertEqual(panel.durationPicker.itemArray.compactMap { $0.representedObject as? String },
                       ["once", "5m", "15m", "day", "custom"])
        XCTAssertEqual(panel.durationPicker.indexOfSelectedItem, 0)
        XCTAssertTrue(panel.initialFirstResponder === panel.denyButton)
        XCTAssertTrue(panel.allowButton.nextKeyView === panel.durationPicker)
        XCTAssertTrue(panel.durationPicker.nextKeyView === panel.denyButton)
        XCTAssertTrue(panel.defaultButtonCell === panel.denyButton.cell)
    }

    func testUnverifiedDestinationCannotOfferTimedChoices() {
        let panel = ConfirmationPanel(title: "Allow SSH key use?", message: "work\nKey: SHA256:test", allow: "Allow", deny: "Deny", destination: "")
        XCTAssertEqual(panel.durationPicker.itemArray.compactMap { $0.representedObject as? String }, ["once"])
        XCTAssertFalse(panel.durationPicker.isEnabled)
        XCTAssertTrue(panel.allowButton.nextKeyView === panel.denyButton)
    }

    func testDurationOnlyAnswersOnButtonAndBothDecisionsUseIt() throws {
        // A program is named, because both answers are kept for one: a refusal
        // with nobody to attach to lasts for this request only.
        let chain = [ProcessLink(name: "ssh", pid: 101), ProcessLink(name: "zsh", pid: 102)]
        let choices: [(Int, GrantScope, GrantScope)] = [
            (0, .once, .once), (1, .fiveMinutes, .denyFiveMinutes),
            (2, .fifteenMinutes, .denyFifteenMinutes), (3, .day, .denyDay),
            (4, .process, .denyProcess), (5, .custom, .denyCustom)
        ]
        for (index, allowScope, denyScope) in choices {
            for allowed in [false, true] {
                let panel = ConfirmationPanel(title: "Allow SSH key use?", message: "", allow: "Allow", deny: "Deny",
                                              destination: "root @ server", chain: chain, boundary: 1)
                let result = runConfirmation(panel) {
                    panel.durationPicker.selectItem(at: index)
                    panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
                    XCTAssertEqual(panel.scope, .once)
                    XCTAssertNil(panel.durationMinutes)
                    panel.customValue.stringValue = "2"
                    panel.customUnit.selectItem(at: 1)
                    (allowed ? panel.allowButton : panel.denyButton).performClick(nil)
                }
                XCTAssertEqual(result, allowed ? .OK : .cancel)
                XCTAssertEqual(panel.scope, allowed ? allowScope : denyScope)
                XCTAssertEqual(panel.durationMinutes, index == 5 ? 120 : nil)
                let response = Response.confirmation(Confirmation(allowed: allowed, scope: panel.scope,
                                                                  durationMinutes: panel.durationMinutes,
                                                                  boundary: panel.boundary))
                XCTAssertEqual(response.answer, allowed ? "yes" : "no")
                XCTAssertEqual(response.scope, !allowed && index == 0 ? nil : panel.scope)
                XCTAssertEqual(response.durationMinutes, panel.durationMinutes)
                // Whatever is kept is kept for the program that asked.
                XCTAssertEqual(response.boundary, index == 0 && !allowed ? nil : 1)
            }
        }
    }

    func testInvalidCustomIntervalDoesNotAnswerAndEscapeStillWorks() {
        for value in ["0", "-1", "1.5", "NaN", "inf", "1441", "99999999999999999999", ""] {
            let panel = ConfirmationPanel(title: "Allow?", message: "", allow: "Allow", deny: "Deny", destination: "root @ server")
            let result = runConfirmation(panel) {
                panel.durationPicker.selectItem(at: 4)
                panel.durationPicker.sendAction(panel.durationPicker.action, to: panel.durationPicker.target)
                panel.customValue.stringValue = value
                panel.allowButton.performClick(nil)
                XCTAssertEqual(panel.scope, .once)
                XCTAssertNil(panel.durationMinutes)
                panel.cancelOperation(nil)
            }
            XCTAssertEqual(result, .cancel)
            XCTAssertEqual(panel.scope, .once)
            XCTAssertNil(panel.durationMinutes)
        }
    }

}

@MainActor
private final class ScopedFakeDialogs: Dialogs {
    var choice = Confirmation(allowed: true)
    var destination: String?
    var chain: [ProcessLink] = []
    var boundary = 0
    var legacyCalls = 0
    var scopedCalls = 0
    var error: Failure?

    func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool) { ("", false) }
    func text(title: String, message: String, placeholder: String) throws -> String { "yes" }
    func notify(title: String, message: String) throws {}
    func confirm(title: String, message: String, allow: String, deny: String, chain: [ProcessLink]) throws -> Bool {
        legacyCalls += 1
        self.chain = chain
        return true
    }
    func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String,
                       chain: [ProcessLink], boundary: Int) throws -> Confirmation {
        scopedCalls += 1
        self.destination = destination
        self.chain = chain
        self.boundary = boundary
        if let error { throw error }
        return choice
    }
}

@MainActor
func runConfirmation(_ panel: ConfirmationPanel, action: @escaping @MainActor () -> Void) -> NSApplication.ModalResponse {
    let app = NSApplication.shared
    DispatchQueue.main.async {
        action()
        if let wake = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [],
            timestamp: 0, windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0) {
            app.postEvent(wake, atStart: true)
        }
    }
    let result = app.runModal(for: panel)
    panel.orderOut(nil)
    return result
}
