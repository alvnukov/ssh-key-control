import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class ConfirmationKeyboardTests: XCTestCase {
    func testNativeDefaultCellMatchesGlobalActionRegardlessOfFocus() {
        for destination in ["", "alice @ server"] {
            for action in [ConfirmationEnterAction.deny, .allow] {
                let panel = ConfirmationPanel(title: "Allow?", message: "Test", allow: "Allow", deny: "Deny",
                                              destination: destination, enterAction: action)
                let selected = action == .allow ? panel.allowButton : panel.denyButton
                let opposite = action == .allow ? panel.denyButton : panel.allowButton
                XCTAssertTrue(panel.makeFirstResponder(opposite))
                XCTAssertTrue(panel.defaultButtonCell === selected.cell)
                XCTAssertEqual(selected.keyEquivalent, "\r")
                XCTAssertEqual(opposite.keyEquivalent, "")
                XCTAssertEqual(panel.enterAction, action)
            }
        }
    }

    func testReturnAndKeypadEnterUseSelectedDurationButEscapeDeniesOnce() throws {
        // Both answers are kept for the program that asked, so one is named.
        let chain = [ProcessLink(name: "ssh", pid: 101), ProcessLink(name: "zsh", pid: 102)]
        for destination in ["", "alice @ server"] {
            for action in [ConfirmationEnterAction.deny, .allow] {
                for key in ["\r", "\u{3}", "\u{1b}"] {
                    let panel = ConfirmationPanel(title: "Allow SSH key use?", message: "", allow: "Allow", deny: "Deny",
                                                  destination: destination, chain: chain, boundary: 1,
                                                  enterAction: action)
                    if !destination.isEmpty { panel.durationPicker.selectItem(at: 2) }
                    let event = try XCTUnwrap(NSEvent.keyEvent(
                        with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
                        windowNumber: panel.windowNumber, context: nil, characters: key,
                        charactersIgnoringModifiers: key, isARepeat: false, keyCode: key == "\u{3}" ? 76 : 36))
                    panel.initialFirstResponder = action == .allow ? panel.denyButton : panel.allowButton
                    let result = runConfirmation(panel) { XCTAssertTrue(panel.performKeyEquivalent(with: event)) }
                    let allowed = action == .allow && key != "\u{1b}"
                    XCTAssertEqual(result, allowed ? .OK : .cancel)
                    let expected: GrantScope = destination.isEmpty || key == "\u{1b}" ? .once
                        : allowed ? .fifteenMinutes : .denyFifteenMinutes
                    XCTAssertEqual(panel.scope, expected)
                }
            }
        }
    }
}
