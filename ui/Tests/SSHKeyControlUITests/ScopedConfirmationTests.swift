import Foundation
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
        for destination in [nil, ""] as [String?] {
            XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: destination)), .success(answer: "yes"))
        }
        XCTAssertEqual(dialogs.legacyCalls, 2)
        XCTAssertEqual(dialogs.scopedCalls, 7) // No UI-side grant caching.
        XCTAssertNil(dispatcher.handle(Request(op: .text, destination: "alice@production")).scope)
        dialogs.error = .cancelled
        XCTAssertEqual(dispatcher.handle(Request(op: .confirm, destination: "alice@production")), .failure(.cancelled))
    }

    func testPanelKeyboardLoop() {
        let panel = ConfirmationPanel(title: "Allow?", message: "m", allow: "Allow", deny: "Deny", destination: "root@server")
        XCTAssertTrue(panel.initialFirstResponder === panel.denyButton)
        XCTAssertTrue(panel.allowButton.nextKeyView === panel.denyButton)
        XCTAssertTrue(panel.denyButton.nextKeyView === panel.enterActionPicker)
        XCTAssertTrue(panel.enterActionPicker.nextKeyView === panel.allowButton)
    }

    func testPanelWithoutDestinationKeepsTwoButtonLoop() {
        let panel = ConfirmationPanel(title: "Allow?", message: "m", allow: "Allow", deny: "Deny", destination: "")
        XCTAssertNil(panel.allowButton.menu)
        XCTAssertNil(panel.denyButton.menu)
        XCTAssertFalse(panel.allowButton is NSComboButton)
        XCTAssertTrue(panel.defaultButtonCell === panel.denyButton.cell)
        XCTAssertEqual((panel.denyButton as? NSButton)?.keyEquivalent, "\r")
        XCTAssertTrue(panel.allowButton.nextKeyView === panel.denyButton)
        XCTAssertTrue(panel.denyButton.nextKeyView === panel.enterActionPicker)
        XCTAssertTrue(panel.enterActionPicker.nextKeyView === panel.allowButton)
    }

    func testDurationMenusStayEnabledAndOfferDenyDurations() {
        let panel = ConfirmationPanel(title: "Allow?", message: "m", allow: "Allow", deny: "Deny", destination: "root@server")
        for menu in [panel.allowMenu, panel.denyMenu] {
            XCTAssertFalse(menu.autoenablesItems)
            XCTAssertTrue(menu.items.allSatisfy(\.isEnabled))
        }
        XCTAssertEqual(panel.allowMenu.items.compactMap { $0.representedObject as? String }, ["5m", "15m", "day"])
        XCTAssertEqual(panel.denyMenu.items.compactMap { $0.representedObject as? String }, ["deny5m", "deny1h"])
    }

    func testSplitButtonsCarryTheirMenusAndOpenOnArrowKey() throws {
        let panel = ConfirmationPanel(title: "Allow?", message: "m", allow: "Allow", deny: "Deny", destination: "root@server")
        let allow = try XCTUnwrap(panel.allowButton as? SplitButton)
        let deny = try XCTUnwrap(panel.denyButton as? SplitButton)
        // AppKit owns the split: the leading segment sends the action, the
        // trailing segment shows the menu.
        XCTAssertEqual(allow.style, .split)
        XCTAssertEqual(deny.style, .split)
        XCTAssertTrue(allow.menu === panel.allowMenu)
        XCTAssertTrue(deny.menu === panel.denyMenu)
        XCTAssertEqual(allow.title, L10n.string("Allow"))
        XCTAssertEqual(deny.title, L10n.string("Deny"))

        var opened: [NSMenu] = []
        allow.menuOpener = { menu, _ in opened.append(menu) }
        let down = NSEvent.keyEvent(
            with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil,
            characters: "\u{F701}", charactersIgnoringModifiers: "\u{F701}",
            isARepeat: false, keyCode: 125)!
        XCTAssertTrue(allow.performKeyEquivalent(with: down))
        XCTAssertTrue(opened.first === panel.allowMenu)
        XCTAssertEqual(opened.count, 1)
    }
}

@MainActor
private final class ScopedFakeDialogs: Dialogs {
    var choice = Confirmation(allowed: true)
    var destination: String?
    var legacyCalls = 0
    var scopedCalls = 0
    var error: Failure?

    func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool) { ("", false) }
    func text(title: String, message: String, placeholder: String) throws -> String { "yes" }
    func notify(title: String, message: String) throws {}
    func confirm(title: String, message: String, allow: String, deny: String) throws -> Bool {
        legacyCalls += 1
        return true
    }
    func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String) throws -> Confirmation {
        scopedCalls += 1
        self.destination = destination
        if let error { throw error }
        return choice
    }
}
