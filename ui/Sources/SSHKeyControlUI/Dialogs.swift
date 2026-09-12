import AppKit
import SSHKeyControlUIObjC

/// The dialogs, as standard alerts.
@MainActor
public final class AppKitDialogs: Dialogs {
    /// Where the last state of the "remember" checkbox is kept.
    public static let defaultsSuite = "io.github.alvnukov.ssh-key-control"
    public static let rememberKey = "rememberInKeychain"
    public static let enterActionKey = "confirmationEnterAction"

    private let defaults: UserDefaults
    private var panels: [NSPanel] = []

    public init(defaults: UserDefaults? = nil) {
        self.defaults = defaults ?? UserDefaults(suiteName: Self.defaultsSuite) ?? .standard
    }

    public func secret(title: String, message: String, remember: String?) throws -> (secret: String, remember: Bool) {
        let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        var checkbox: NSButton?
        if let label = remember {
            let box = NSButton(checkboxWithTitle: L10n.string(label), target: nil, action: nil)
            box.state = rememberDefault ? .on : .off
            checkbox = box
        }
        let alert = makeAlert(title: title, message: message, accessory: stack(field, checkbox))
        alert.addButton(withTitle: L10n.string("OK"))
        addCancel(to: alert)
        guard run(alert, focus: field) == .alertFirstButtonReturn else { throw Failure.cancelled }
        let ticked = checkbox?.state == .on
        if checkbox != nil {
            rememberDefault = ticked
        }
        return (field.stringValue, ticked)
    }

    public func text(title: String, message: String, placeholder: String) throws -> String {
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        field.placeholderString = L10n.string(placeholder)
        let alert = makeAlert(title: title, message: message, accessory: stack(field, nil))
        alert.addButton(withTitle: L10n.string("OK"))
        addCancel(to: alert)
        guard run(alert, focus: field) == .alertFirstButtonReturn else { throw Failure.cancelled }
        return field.stringValue
    }

    public func confirm(title: String, message: String, allow: String, deny: String) throws -> Bool {
        try confirmScoped(title: title, message: message, allow: allow, deny: deny, destination: "").allowed
    }

    public func confirmScoped(title: String, message: String, allow: String, deny: String, destination: String) throws -> Confirmation {
        // A fresh panel for every request: grants are never remembered by the UI.
        let enterAction = ConfirmationEnterAction(rawValue: defaults.string(forKey: Self.enterActionKey) ?? "") ?? .deny
        let panel = ConfirmationPanel(title: title, message: message, allow: allow, deny: deny,
                                      destination: destination, enterAction: enterAction) { [defaults] action in
            defaults.set(action.rawValue, forKey: Self.enterActionKey)
        }
        panel.center()
        SSHKeyControlActivateApp()
        panel.makeKeyAndOrderFront(nil)
        let result = NSApp.runModal(for: panel)
        panel.orderOut(nil)
        return Confirmation(allowed: result == .OK, scope: panel.scope)
    }

    public func notify(title: String, message: String) throws {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 360, height: 100),
            styleMask: [.titled, .nonactivatingPanel, .hudWindow, .utilityWindow],
            backing: .buffered, defer: false)
        panel.title = "SSH Key Control"
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        let heading = NSTextField(labelWithString: L10n.string(title))
        heading.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        let body = NSTextField(wrappingLabelWithString: L10n.message(message))
        let column = NSStackView(views: message.isEmpty ? [heading] : [heading, body])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.edgeInsets = NSEdgeInsets(top: 16, left: 20, bottom: 16, right: 20)
        column.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView = column
        column.widthAnchor.constraint(equalToConstant: 360).isActive = true
        panel.setContentSize(column.fittingSize)
        panel.center()
        panel.orderFrontRegardless()
        panels.append(panel)
    }

    // MARK: - Pieces

    private var rememberDefault: Bool {
        get { defaults.object(forKey: Self.rememberKey) as? Bool ?? true }
        set { defaults.set(newValue, forKey: Self.rememberKey) }
    }

    private func makeAlert(title: String, message: String, accessory: NSView?) -> NSAlert {
        let alert = NSAlert()
        alert.messageText = L10n.string(title)
        alert.informativeText = L10n.message(message)
        alert.accessoryView = accessory
        return alert
    }

    /// Cancel gets Escape; NSAlert only does that for a button literally titled L10n.string("Cancel").
    private func addCancel(to alert: NSAlert) {
        alert.addButton(withTitle: L10n.string("Cancel")).keyEquivalent = "\u{1b}"
    }

    /// A field with an optional checkbox under it, laid out by hand: NSAlert
    /// sizes accessory views by their frame, not by constraints.
    private func stack(_ field: NSTextField, _ checkbox: NSButton?) -> NSView {
        let width: CGFloat = 320
        let fieldHeight: CGFloat = 24
        let gap: CGFloat = 8
        var height = fieldHeight
        let view = NSView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        if let checkbox {
            checkbox.sizeToFit()
            let boxHeight = checkbox.frame.height
            height += gap + boxHeight
            view.frame.size.height = height
            checkbox.frame.origin = NSPoint(x: 0, y: 0)
            view.addSubview(checkbox)
        }
        field.frame = NSRect(x: 0, y: height - fieldHeight, width: width, height: fieldHeight)
        view.addSubview(field)
        return view
    }

    private func run(_ alert: NSAlert, focus: NSView?) -> NSApplication.ModalResponse {
        alert.window.level = .floating
        if let focus {
            alert.window.initialFirstResponder = focus
        }
        SSHKeyControlActivateApp()
        return alert.runModal()
    }
}
enum ConfirmationEnterAction: String {
    case deny, allow
}

/// A split Allow/Deny panel. Each button answers one request; the menu
/// segment of a button opens that button's duration menu, never a remembered
/// choice.
@MainActor
final class ConfirmationPanel: NSPanel {
    private(set) var scope: GrantScope = .once
    private(set) var allowMenu = NSMenu()
    private(set) var denyMenu = NSMenu()
    private(set) var allowButton: NSControl = NSButton()
    private(set) var denyButton: NSControl = NSButton()

    private(set) var enterAction: ConfirmationEnterAction
    let enterActionPicker = NSPopUpButton(frame: .zero, pullsDown: false)
    private let onEnterActionChange: ((ConfirmationEnterAction) -> Void)?

    init(title: String, message: String, allow: String, deny: String, destination: String,
         enterAction: ConfirmationEnterAction = .deny,
         onEnterActionChange: ((ConfirmationEnterAction) -> Void)? = nil) {
        self.enterAction = enterAction
        self.onEnterActionChange = onEnterActionChange
        super.init(contentRect: NSRect(x: 0, y: 0, width: 420, height: 180),
                   styleMask: [.titled], backing: .buffered, defer: false)
        self.title = "SSH Key Control"
        level = .floating
        isReleasedWhenClosed = false

        let heading = NSTextField(wrappingLabelWithString: L10n.string(title))
        heading.font = .boldSystemFont(ofSize: 16)
        let body = NSTextField(wrappingLabelWithString: L10n.message(message, preservingFirstLine: title == "Allow SSH key use?"))
        var views: [NSView] = [heading]
        if !destination.isEmpty {
            let target = NSTextField(wrappingLabelWithString: destination)
            target.font = .boldSystemFont(ofSize: 20)
            target.isSelectable = true
            target.setAccessibilityLabel(L10n.format("Destination: %@", destination))
            views.append(target)
        }
        if !message.isEmpty { views.append(body) }

        if destination.isEmpty {
            let denyOnce = NSButton(title: L10n.string(deny), target: self, action: #selector(denyRequest))
            denyOnce.bezelStyle = .rounded
            denyOnce.keyEquivalent = ""
            denyOnce.toolTip = L10n.string("Deny this request")
            let allowOnce = NSButton(title: L10n.string(allow), target: self, action: #selector(allowOnce))
            allowOnce.bezelStyle = .rounded
            allowOnce.keyEquivalent = ""
            allowOnce.setAccessibilityLabel(L10n.format("%@ once", L10n.string(allow)))
            allowOnce.toolTip = L10n.string("Allow this request once")
            denyButton = denyOnce
            allowButton = allowOnce
        } else {
            // Menu validation is disabled inside a modal session: AppKit would
            // grey every item out. Items here have no enabling condition.
            allowMenu = durationMenu([
                (L10n.string("5 minutes"), GrantScope.fiveMinutes),
                (L10n.string("15 minutes"), .fifteenMinutes),
                (L10n.string("Until end of local day"), .day),
            ], action: #selector(pickScope(_:)))
            denyMenu = durationMenu([
                (L10n.string("5 minutes"), .denyFiveMinutes),
                (L10n.string("1 hour"), .denyOneHour),
            ], action: #selector(pickScope(_:)))
            let allowSplit = SplitButton(title: L10n.string(allow), menu: allowMenu, target: self, action: #selector(allowOnce))
            allowSplit.setAccessibilityLabel(L10n.format("%@ once; the menu segment picks a duration", L10n.string(allow)))
            allowSplit.toolTip = L10n.string("Allow once, or choose a duration from the menu")
            let denySplit = SplitButton(title: L10n.string(deny), menu: denyMenu, target: self, action: #selector(denyRequest))
            denySplit.setAccessibilityLabel(L10n.format("%@; the menu segment picks a duration", L10n.string(deny)))
            denySplit.toolTip = L10n.string("Deny, or deny for a duration from the menu")
            allowButton = allowSplit
            denyButton = denySplit
        }
        let buttons: [NSView] = [denyButton, allowButton]
        let controls = NSStackView(views: buttons)
        controls.orientation = .horizontal
        controls.spacing = 8
        views.append(controls)

        enterActionPicker.addItems(withTitles: [L10n.string("Deny"), L10n.string("Allow once")])
        enterActionPicker.selectItem(at: enterAction == .allow ? 1 : 0)
        enterActionPicker.target = self
        enterActionPicker.action = #selector(changeEnterAction(_:))
        enterActionPicker.setAccessibilityLabel(L10n.string("Action for Return and Enter"))
        enterActionPicker.toolTip = L10n.string("Saved for future confirmations. Escape always denies.")
        let preference = NSStackView(views: [NSTextField(labelWithString: L10n.string("Return / Enter:")), enterActionPicker])
        preference.orientation = .horizontal
        preference.spacing = 8
        views.append(preference)

        let column = NSStackView(views: views)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 14
        column.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 20, right: 24)
        column.translatesAutoresizingMaskIntoConstraints = false
        contentView = column
        column.widthAnchor.constraint(equalToConstant: 420).isActive = true
        controls.trailingAnchor.constraint(equalTo: column.trailingAnchor, constant: -24).isActive = true
        setContentSize(column.fittingSize)
        // macOS skips push buttons during Tab traversal unless an explicit key
        // view loop is wired; Return and Escape are handled in
        // performKeyEquivalent regardless of focus.
        updateDefaultAction()
        initialFirstResponder = enterAction == .allow ? allowButton : denyButton
        allowButton.nextKeyView = denyButton
        denyButton.nextKeyView = enterActionPicker
        enterActionPicker.nextKeyView = allowButton
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    override func cancelOperation(_ sender: Any?) { denyRequest() }

    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        // Both Enter keys use the displayed preference, independent of focus.
        guard let key = event.charactersIgnoringModifiers else {
            return super.performKeyEquivalent(with: event)
        }
        switch key {
        case "\r", "\u{3}":
            if enterAction == .allow { allowOnce() } else { denyRequest() }
            return true
        case "\u{1b}": denyRequest(); return true
        default: return super.performKeyEquivalent(with: event)
        }
    }

    @objc private func changeEnterAction(_ sender: NSPopUpButton) {
        enterAction = sender.indexOfSelectedItem == 1 ? .allow : .deny
        updateDefaultAction()
        onEnterActionChange?(enterAction)
    }

    private func updateDefaultAction() {
        let selected = enterAction == .allow ? allowButton : denyButton
        for control in [allowButton, denyButton] {
            (control as? NSButton)?.keyEquivalent = control === selected ? "\r" : ""
            (control as? SplitButton)?.isDefaultAction = control === selected
        }
        defaultButtonCell = selected.cell as? NSButtonCell
    }

    private func durationMenu(_ choices: [(String, GrantScope)], action: Selector) -> NSMenu {
        let menu = NSMenu()
        menu.autoenablesItems = false
        for (label, scope) in choices {
            let item = NSMenuItem(title: label, action: action, keyEquivalent: "")
            item.target = self
            item.isEnabled = true
            item.representedObject = scope.rawValue
            menu.addItem(item)
        }
        return menu
    }

    @objc private func denyRequest() { NSApp.stopModal(withCode: .cancel) }

    @objc private func allowOnce() {
        scope = .once
        NSApp.stopModal(withCode: .OK)
    }

    /// A menu pick ends the dialog: allowed scopes stop with .OK, deny scopes
    /// with .cancel; the chosen scope travels with the answer either way.
    @objc private func pickScope(_ sender: NSMenuItem) {
        guard let wire = sender.representedObject as? String,
              let selected = GrantScope(rawValue: wire) else {
            denyRequest()
            return
        }
        scope = selected
        NSApp.stopModal(withCode: selected.isDenyDuration ? .cancel : .OK)
        // stopModal only takes effect when the modal loop next checks, after
        // an event. A pick arrives from the menu's own tracking loop, which
        // has already consumed the click, so hand the modal loop an event to
        // check on. abortModal wakes the loop the same way.
        if let wake = NSEvent.otherEvent(
            with: .applicationDefined, location: .zero, modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: 0, context: nil,
            subtype: 0, data1: 0, data2: 0) {
            NSApp.postEvent(wake, atStart: true)
        }
    }
}

/// AppKit's own split button: the leading segment performs the action, the
/// trailing segment with the menu indicator opens `menu`. The down arrow
/// while the button has focus opens the menu as well.
@MainActor
final class SplitButton: NSComboButton {
    // NSComboButton has no public keyEquivalent/default-button API. Mark the
    // selected action with an accent fill, outline and the standard Return symbol.
    var isDefaultAction = false {
        didSet { updateDefaultAppearance() }
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        updateDefaultAppearance()
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard isDefaultAction else { return }

        let indicator = NSBezierPath(
            roundedRect: bounds.insetBy(dx: 1.5, dy: 1.5),
            xRadius: 6,
            yRadius: 6)
        NSColor.controlAccentColor.withAlphaComponent(0.22).setFill()
        indicator.fill()
        NSColor.controlAccentColor.setStroke()
        indicator.lineWidth = 3
        indicator.stroke()
    }

    private func updateDefaultAppearance() {
        image = isDefaultAction ? NSImage(systemSymbolName: "return", accessibilityDescription: L10n.string("Return or Enter")) : nil
        needsDisplay = true
    }

    /// Test seam: defaults to popping the menu under the button.
    var menuOpener: ((NSMenu, NSComboButton) -> Void)?

    func openDurationMenu() {
        let menu = self.menu
        guard !menu.items.isEmpty else { return }
        (menuOpener ?? { $0.popUp(positioning: nil, at: NSPoint(x: 0, y: $1.bounds.maxY), in: $1) })(menu, self)
    }

    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        if event.charactersIgnoringModifiers == Self.downArrow {
            openDurationMenu()
            return true
        }
        return super.performKeyEquivalent(with: event)
    }
}

private extension SplitButton {
    /// NSDownArrowFunctionKey arrives as Int in AppKit, not as a String.
    static let downArrow = String(UnicodeScalar(NSDownArrowFunctionKey)!)
}
