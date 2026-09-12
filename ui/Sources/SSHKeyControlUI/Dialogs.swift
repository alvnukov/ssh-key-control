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
    private var temporaryDecisions: TemporaryDecisionsPanel?

    public func manageDecisions(_ decisions: [TemporaryDecision], message: String, activate: Bool) throws -> DecisionChange {
        if temporaryDecisions == nil { temporaryDecisions = TemporaryDecisionsPanel() }
        guard let temporaryDecisions else { throw Failure.other("Temporary decision management is unavailable.") }
        return temporaryDecisions.present(decisions, message: message, activate: activate)
    }

    public init(defaults: UserDefaults? = nil) {
        self.defaults = defaults ?? UserDefaults(suiteName: Self.defaultsSuite) ?? .standard
        // The standalone helper needs AppKit's responder-chain editing commands.
        // Preserve the full application menu when hosted by the menu bar app.
        let app = NSApplication.shared
        if app.mainMenu == nil {
            let main = NSMenu()
            let application = NSMenuItem()
            application.submenu = NSMenu(title: "SSH Key Control")
            main.addItem(application)
            let edit = NSMenu(title: L10n.string("Edit"))
            for (label, action, key) in [
                ("Cut", #selector(NSText.cut(_:)), "x"),
                ("Copy", #selector(NSText.copy(_:)), "c"),
                ("Paste", #selector(NSText.paste(_:)), "v"),
                ("Select All", #selector(NSText.selectAll(_:)), "a")
            ] {
                edit.addItem(withTitle: L10n.string(label), action: action, keyEquivalent: key)
            }
            let item = NSMenuItem()
            item.submenu = edit
            main.addItem(item)
            app.mainMenu = main
        }
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
        if title == "Enter the passphrase for your SSH key" {
            alert.informativeText += "\n\n" + L10n.string("Enter this SSH key's passphrase only in SSH Key Control. Entering it in another app may allow the key to be used without our confirmations.")
        }
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
                                      destination: destination, enterAction: enterAction)
        panel.center()
        SSHKeyControlActivateApp()
        panel.makeKeyAndOrderFront(nil)
        let result = NSApp.runModal(for: panel)
        panel.orderOut(nil)
        return Confirmation(allowed: result == .OK, scope: panel.scope, durationMinutes: panel.durationMinutes)
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

/// Duration selection never answers a request. Only a decision button (or its
/// keyboard equivalent) sends the selected lifetime; Escape always denies once.
@MainActor
final class ConfirmationPanel: NSPanel {
    private(set) var scope: GrantScope = .once
    private(set) var durationMinutes: Int?
    let allowButton = NSButton()
    let denyButton = NSButton()
    let durationPicker = NSPopUpButton(frame: .zero, pullsDown: false)
    let customValue = NSTextField(string: "15")
    let customUnit = NSPopUpButton(frame: .zero, pullsDown: false)
    let enterAction: ConfirmationEnterAction
    private let timedChoicesAllowed: Bool
    private let customControls = NSStackView()
    private let validationMessage = NSTextField(wrappingLabelWithString: "")
    private var column: NSStackView!

    init(title: String, message: String, allow: String, deny: String, destination: String,
         enterAction: ConfirmationEnterAction = .deny) {
        self.enterAction = enterAction
        timedChoicesAllowed = !destination.isEmpty
        super.init(contentRect: NSRect(x: 0, y: 0, width: 560, height: 180),
                   styleMask: [.titled], backing: .buffered, defer: false)
        self.title = "SSH Key Control"
        level = .floating
        isReleasedWhenClosed = false

        let heading = Self.label(L10n.string(title))
        heading.font = .boldSystemFont(ofSize: 16)
        var views: [NSView] = [heading]
        let isSSH = title == "Allow SSH key use?"
        if isSSH || !destination.isEmpty {
            let server = Self.label(destination.isEmpty ? L10n.string("Server not verified") : destination)
            server.font = .boldSystemFont(ofSize: 18)
            server.isSelectable = true
            server.setAccessibilityLabel(L10n.format("Destination: %@", server.stringValue))
            views.append(server)
        }
        if isSSH {
            let lines = message.components(separatedBy: "\n")
            if let comment = lines.first, !comment.isEmpty {
                views.append(Self.detail("Key comment", value: comment))
            }
            for line in lines.dropFirst() {
                if line.hasPrefix("Key: ") {
                    views.append(Self.detail("Key fingerprint", value: String(line.dropFirst(5)), monospace: true))
                } else if line.hasPrefix("Server identity: ") {
                    views.append(Self.detail("Server fingerprint", value: String(line.dropFirst(17)), monospace: true))
                } else if !line.isEmpty && line != "Destination not verified. This approval applies to one signature only." {
                    views.append(Self.label(L10n.message(line)))
                }
            }
            if destination.isEmpty {
                views.append(Self.label(L10n.string("The server is not verified. Allow or deny this request once; timed decisions are unavailable.")))
            }
        } else if !message.isEmpty {
            views.append(Self.label(L10n.message(message)))
        }

        for (button, label, selector) in [
            (denyButton, deny, #selector(denyRequest)),
            (allowButton, allow, #selector(allowRequest))
        ] {
            button.title = L10n.string(label)
            button.bezelStyle = .rounded
            button.target = self
            button.action = selector
            button.setContentHuggingPriority(.required, for: .horizontal)
        }
        let selected = enterAction == .allow ? allowButton : denyButton
        selected.keyEquivalent = "\r"
        defaultButtonCell = selected.cell as? NSButtonCell
        let controls = NSStackView(views: [denyButton, allowButton])
        controls.orientation = .horizontal
        controls.spacing = 8
        views.append(controls)

        if isSSH || timedChoicesAllowed {
            durationPicker.menu?.autoenablesItems = false
            let choices: [(String, GrantScope)] = [
                ("Once", .once), ("5 minutes", .fiveMinutes), ("15 minutes", .fifteenMinutes),
                ("Until end of local day", .day), ("Custom interval…", .custom)
            ]
            for (label, scope) in choices where timedChoicesAllowed || scope == .once {
                durationPicker.addItem(withTitle: L10n.string(label))
                durationPicker.lastItem?.representedObject = scope.rawValue
            }
            durationPicker.isEnabled = timedChoicesAllowed
            durationPicker.target = self
            durationPicker.action = #selector(durationChanged)
            durationPicker.setAccessibilityLabel(L10n.string("Duration for allow or deny"))
            customValue.alignment = .right
            customValue.setAccessibilityLabel(L10n.string("Custom interval value"))
            customValue.widthAnchor.constraint(equalToConstant: 55).isActive = true
            customUnit.addItems(withTitles: [L10n.string("minutes"), L10n.string("hours")])
            customUnit.setAccessibilityLabel(L10n.string("Interval unit"))
            customControls.addArrangedSubview(customValue)
            customControls.addArrangedSubview(customUnit)
            customControls.spacing = 6
            customControls.isHidden = true
            let footer = NSStackView(views: [Self.label(L10n.string("Duration:")), durationPicker, customControls])
            footer.orientation = .horizontal
            footer.spacing = 8
            footer.alignment = .centerY
            views.append(footer)
            validationMessage.textColor = .systemRed
            validationMessage.isHidden = true
            views.append(validationMessage)
        }

        column = NSStackView(views: views)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 14
        column.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 20, right: 24)
        column.translatesAutoresizingMaskIntoConstraints = false
        contentView = column
        column.widthAnchor.constraint(equalToConstant: 560).isActive = true
        controls.trailingAnchor.constraint(equalTo: column.trailingAnchor, constant: -24).isActive = true
        for view in views where view !== controls {
            view.widthAnchor.constraint(lessThanOrEqualTo: column.widthAnchor, constant: -48).isActive = true
        }
        setContentSize(column.fittingSize)
        initialFirstResponder = selected
        denyButton.nextKeyView = allowButton
        allowButton.nextKeyView = timedChoicesAllowed ? durationPicker : denyButton
        durationPicker.nextKeyView = denyButton
        customValue.nextKeyView = customUnit
        customUnit.nextKeyView = denyButton
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    private static func label(_ value: String) -> NSTextField {
        let field = NSTextField(wrappingLabelWithString: value)
        field.lineBreakMode = .byWordWrapping
        return field
    }

    private static func detail(_ name: String, value: String, monospace: Bool = false) -> NSView {
        let caption = label(L10n.string(name))
        caption.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        caption.textColor = .secondaryLabelColor
        let text = label(value)
        text.isSelectable = true
        if monospace {
            text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            text.lineBreakMode = .byCharWrapping
        }
        let stack = NSStackView(views: [caption, text])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 3
        return stack
    }

    @objc private func durationChanged() {
        let custom = durationPicker.selectedItem?.representedObject as? String == GrantScope.custom.rawValue
        customControls.isHidden = !custom
        durationPicker.nextKeyView = custom ? customValue : denyButton
        validationMessage.isHidden = true
        customValue.toolTip = L10n.string("Choose 1–1440 minutes or 1–24 hours.")
        setContentSize(column.fittingSize)
    }

    override func cancelOperation(_ sender: Any?) { finish(allowed: false, once: true) }

    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        guard let key = event.charactersIgnoringModifiers else { return super.performKeyEquivalent(with: event) }
        switch key {
        case "\r", "\u{3}": finish(allowed: enterAction == .allow); return true
        case "\u{1b}": finish(allowed: false, once: true); return true
        default: return super.performKeyEquivalent(with: event)
        }
    }

    @objc private func denyRequest() { finish(allowed: false) }
    @objc private func allowRequest() { finish(allowed: true) }

    private func finish(allowed: Bool, once: Bool = false) {
        let selected = timedChoicesAllowed && !once
            ? (durationPicker.selectedItem?.representedObject as? String).flatMap(GrantScope.init(rawValue:)) ?? .once
            : .once
        var minutes: Int?
        if selected == .custom {
            let value = customValue.stringValue
            guard !value.isEmpty, value.count <= 4, value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  let amount = Int(value), amount > 0,
                  amount <= (customUnit.indexOfSelectedItem == 1 ? 24 : 1440) else {
                validationMessage.stringValue = L10n.string("Choose 1–1440 minutes or 1–24 hours.")
                validationMessage.isHidden = false
                setContentSize(column.fittingSize)
                makeFirstResponder(customValue)
                return
            }
            minutes = amount * (customUnit.indexOfSelectedItem == 1 ? 60 : 1)
        }
        guard let decisionScope = selected.scope(forAllowed: allowed) else { return }
        scope = decisionScope
        durationMinutes = minutes
        NSApp.stopModal(withCode: allowed ? .OK : .cancel)
    }
}
