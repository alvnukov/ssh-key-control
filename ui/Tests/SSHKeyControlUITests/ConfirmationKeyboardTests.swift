import AppKit
import XCTest
@testable import SSHKeyControlUI

@MainActor
final class ConfirmationKeyboardTests: XCTestCase {
    func testDefaultActionIsVisibleAndPreferenceChangesIt() throws {
        for destination in ["", "alice @ server"] {
            var saved: ConfirmationEnterAction?
            let panel = ConfirmationPanel(title: "Allow?", message: "Test", allow: "Allow", deny: "Deny",
                                          destination: destination) { saved = $0 }
            XCTAssertEqual(panel.enterAction, .deny)
            XCTAssertEqual(panel.enterActionPicker.indexOfSelectedItem, 0)
            if destination.isEmpty {
                XCTAssertTrue(panel.defaultButtonCell === panel.denyButton.cell)
            } else {
                let deny = try XCTUnwrap(panel.denyButton as? SplitButton)
                XCTAssertTrue(deny.isDefaultAction)
                XCTAssertNotNil(deny.image)
                XCTAssertFalse((panel.allowButton as? SplitButton)?.isDefaultAction ?? true)
            }
            panel.enterActionPicker.selectItem(at: 1)
            XCTAssertTrue(panel.enterActionPicker.sendAction(panel.enterActionPicker.action, to: panel.enterActionPicker.target))
            XCTAssertEqual(saved, .allow)
            XCTAssertEqual(panel.enterAction, .allow)
            if destination.isEmpty {
                XCTAssertTrue(panel.defaultButtonCell === panel.allowButton.cell)
                XCTAssertEqual((panel.denyButton as? NSButton)?.keyEquivalent, "")
            } else {
                XCTAssertTrue((panel.allowButton as? SplitButton)?.isDefaultAction ?? false)
                XCTAssertFalse((panel.denyButton as? SplitButton)?.isDefaultAction ?? true)
            }
        }
    }

    func testReturnKeypadEnterAndEscapeUseDisplayedAction() throws {
        let app = NSApplication.shared
        for action in [ConfirmationEnterAction.deny, .allow] {
            for key in ["\r", "\u{3}", "\u{1b}"] {
                let panel = ConfirmationPanel(title: "Keyboard test", message: "", allow: "Allow", deny: "Deny",
                                              destination: "alice @ server", enterAction: action)
                // Focus the opposite action: Return must still match the highlight.
                panel.initialFirstResponder = action == .allow ? panel.denyButton : panel.allowButton
                let event = try XCTUnwrap(NSEvent.keyEvent(
                    with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
                    windowNumber: panel.windowNumber, context: nil, characters: key,
                    charactersIgnoringModifiers: key, isARepeat: false, keyCode: key == "\u{3}" ? 76 : 36))
                DispatchQueue.main.async {
                    XCTAssertTrue(panel.performKeyEquivalent(with: event))
                    if let wake = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [],
                        timestamp: 0, windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0) {
                        app.postEvent(wake, atStart: true)
                    }
                }
                let result = app.runModal(for: panel)
                panel.orderOut(nil)
                XCTAssertEqual(result, action == .allow && key != "\u{1b}" ? .OK : .cancel)
                XCTAssertEqual(panel.scope, .once)
            }
        }
    }

    func testDefaultSplitButtonHasVisibleAccentIndependentOfFocus() throws {
        for action in [ConfirmationEnterAction.deny, .allow] {
            let panel = ConfirmationPanel(title: "Allow?", message: "Test", allow: "Allow", deny: "Deny",
                                          destination: "alice @ server", enterAction: action)
            let selected = try XCTUnwrap((action == .allow ? panel.allowButton : panel.denyButton) as? SplitButton)
            let opposite = action == .allow ? panel.denyButton : panel.allowButton
            XCTAssertTrue(panel.makeFirstResponder(opposite))
            let highlighted = try renderedBackgroundColor(of: selected)

            panel.enterActionPicker.selectItem(at: action == .allow ? 0 : 1)
            XCTAssertTrue(panel.enterActionPicker.sendAction(panel.enterActionPicker.action,
                                                              to: panel.enterActionPicker.target))
            let ordinary = try renderedBackgroundColor(of: selected)

            XCTAssertGreaterThan(colorDistance(highlighted, ordinary), 0.08)
        }
    }

    private func renderedBackgroundColor(of view: NSView) throws -> NSColor {
        view.layoutSubtreeIfNeeded()
        view.displayIfNeeded()
        let bitmap = try XCTUnwrap(view.bitmapImageRepForCachingDisplay(in: view.bounds))
        view.cacheDisplay(in: view.bounds, to: bitmap)
        let x = Int(CGFloat(bitmap.pixelsWide) * 0.12)
        let y = bitmap.pixelsHigh / 2
        return try XCTUnwrap(bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB))
    }

    private func colorDistance(_ lhs: NSColor, _ rhs: NSColor) -> CGFloat {
        abs(lhs.redComponent - rhs.redComponent)
            + abs(lhs.greenComponent - rhs.greenComponent)
            + abs(lhs.blueComponent - rhs.blueComponent)
    }
}
