import AppKit
import SSHKeyControlUIObjC

public struct TemporaryDecision: Codable, Equatable, Sendable {
    public let id: String
    public let keyFingerprint: String
    public let hostFingerprint: String
    public let host: String
    public let user: String
    public let allowed: Bool
    public let expiresAt: String
    /// The program this decision is kept for, and whether that program is
    /// still running. An empty name means every program on this Mac, which is
    /// where refusals live and where an approval goes when nobody could be named.
    public var process: String? = nil
    public var processPid: Int32? = nil
    public var processLive: Bool? = nil

    var expiry: Date? { ISO8601DateFormatter().date(from: expiresAt) }
    var isActive: Bool { expiry.map { $0 > Date() } ?? false }
    var isAnchored: Bool { !(process ?? "").isEmpty }

    /// What the program column reads. A decision whose program has ended is
    /// still shown: it stops matching, and saying so is clearer than hiding it.
    var programLabel: String {
        guard let name = process, !name.isEmpty else { return L10n.string("Every program") }
        let label = processPid.map { "\(name) [\($0)]" } ?? name
        return processLive == true ? label : label + " " + L10n.string("(ended)")
    }
}

public struct DecisionChange: Codable, Equatable, Sendable {
    public var action: String
    public var id: String? = nil
    public var minutes: Int? = nil
    public var endOfDay: Bool? = nil
}

@MainActor
private final class DurationFieldToggle: NSObject {
    let field: NSTextField
    init(_ field: NSTextField) { self.field = field }
    @objc func toggle(_ button: NSButton) { field.isEnabled = button.state != .on }
}

/// The daemon starts this helper and exchanges snapshots/actions only over
/// its private stdin/stdout pipe. No file or public socket authorizes edits.
@MainActor
final class TemporaryDecisionsPanel: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSWindowDelegate {
    let window = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 800, height: 460),
                         styleMask: [.titled, .closable], backing: .buffered, defer: false)
    let table = NSTableView()
    private let detail = NSTextField(wrappingLabelWithString: "")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let edit = NSButton(title: L10n.string("Change Duration…"), target: nil, action: nil)
    private let revoke = NSButton(title: L10n.string("Revoke Decision"), target: nil, action: nil)
    private let revokeProgram = NSButton(title: L10n.string("Revoke All for Program"), target: nil, action: nil)
    private var items: [TemporaryDecision] = []
    private var response = DecisionChange(action: "close")
    private var inModal = false
    private var presented = false

    override init() {
        super.init()
        window.title = L10n.string("Temporary Decisions")
        window.delegate = self
        window.isReleasedWhenClosed = false
        table.dataSource = self
        table.delegate = self
        table.allowsMultipleSelection = false
        table.style = .inset
        table.rowHeight = 28
        for (id, title, width) in [("decision", "Decision", 100.0), ("program", "Program", 170.0),
                                   ("destination", "Server / SSH user", 280.0), ("expiry", "Expires", 150.0)] {
            let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id))
            column.title = L10n.string(title)
            column.width = width
            if id == "expiry" { column.minWidth = 170 }
            table.addTableColumn(column)
        }
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.heightAnchor.constraint(equalToConstant: 185).isActive = true
        scroll.widthAnchor.constraint(equalToConstant: 752).isActive = true
        let explanation = NSTextField(wrappingLabelWithString: L10n.string("Active approvals and refusals stored by the agent. Revoking a decision makes the next matching request ask again."))
        explanation.textColor = .secondaryLabelColor
        detail.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        detail.isSelectable = true
        detail.setContentCompressionResistancePriority(.required, for: .vertical)
        detail.heightAnchor.constraint(greaterThanOrEqualToConstant: 80).isActive = true
        status.textColor = .secondaryLabelColor
        edit.target = self; edit.action = #selector(editDuration)
        revoke.target = self; revoke.action = #selector(revokeSelected)
        revokeProgram.target = self; revokeProgram.action = #selector(revokeProgramOfSelected)
        let refresh = NSButton(title: L10n.string("Refresh"), target: self, action: #selector(refreshList))
        let close = NSButton(title: L10n.string("Done"), target: self, action: #selector(closePanel))
        close.keyEquivalent = "\r"
        for button in [edit, revoke, revokeProgram, refresh, close] { button.bezelStyle = .rounded }
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = NSStackView(views: [edit, revoke, revokeProgram, spacer, refresh, close])
        buttons.orientation = .horizontal
        buttons.spacing = 8
        let column = NSStackView(views: [explanation, scroll, detail, status, buttons])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 14
        column.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 20, right: 24)
        for view in [explanation, detail, status, buttons] { view.widthAnchor.constraint(equalToConstant: 752).isActive = true }
        window.contentView = column
        window.setContentSize(column.fittingSize)
        window.center()
    }

    func present(_ decisions: [TemporaryDecision], message: String, activate: Bool) -> DecisionChange {
        let selectedID = selected?.id
        let active = decisions.filter(\.isActive)
        if items != active {
            items = active
            table.reloadData()
        }
        if let selectedID, let index = items.firstIndex(where: { $0.id == selectedID }) {
            table.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
        } else if !presented && !items.isEmpty {
            table.selectRowIndexes(IndexSet(integer: 0), byExtendingSelection: false)
        } else { table.deselectAll(nil) }
        updateSelection()
        status.stringValue = message.isEmpty
            ? (items.isEmpty ? L10n.string("No active temporary decisions.") : L10n.format("Active decisions: %d", items.count))
            : L10n.string(message)
        status.textColor = message.isEmpty ? .secondaryLabelColor : .systemRed
        if activate || !presented {
            SSHKeyControlActivateApp()
            window.makeKeyAndOrderFront(nil)
        }
        presented = true
        response = DecisionChange(action: "close")
        inModal = true
        // A refresh keeps this same window and selected ID. Editing uses a
        // nested modal alert; never interrupt it with a background snapshot.
        let timer = Timer(timeInterval: 1.5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, self.inModal, NSApp.modalWindow === self.window else { return }
                self.finish(DecisionChange(action: "refresh"))
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: RunLoop.Mode("NSModalPanelRunLoopMode"))
        NSApp.runModal(for: window)
        timer.invalidate()
        inModal = false
        if response.action == "close" { window.orderOut(nil) }
        return response
    }

    private var selected: TemporaryDecision? {
        let row = table.selectedRow
        return items.indices.contains(row) ? items[row] : nil
    }

    private func updateSelection() {
        guard let item = selected else {
            detail.stringValue = L10n.string("Select a decision to view its exact key and server fingerprints.")
            edit.isEnabled = false; revoke.isEnabled = false; revokeProgram.isEnabled = false
            return
        }
        detail.stringValue = L10n.string("Key fingerprint") + ": " + item.keyFingerprint + "\n"
            + L10n.string("Server fingerprint") + ": " + item.hostFingerprint + "\n"
            + L10n.string("SSH user") + ": " + item.user + "\n"
            + L10n.string("Program") + ": " + item.programLabel
        edit.isEnabled = item.isActive
        revoke.isEnabled = item.isActive
        // There is nothing to gather up for a decision that was never kept for
        // one program: revoking it is what the plain button already does.
        revokeProgram.isEnabled = item.isActive && item.isAnchored
    }

    func numberOfRows(in tableView: NSTableView) -> Int { items.count }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard items.indices.contains(row) else { return nil }
        let item = items[row]
        let text: String
        switch tableColumn?.identifier.rawValue {
        case "decision": text = L10n.string(item.allowed ? "Allowed" : "Denied")
        case "program": text = item.programLabel
        case "destination":
            text = item.user + " @ " + (item.host.isEmpty ? L10n.string("server name unavailable") : item.host)
        default:
            if let expiry = item.expiry {
                text = DateFormatter.localizedString(from: expiry, dateStyle: .short, timeStyle: .short)
            } else { text = "—" }
        }
        let label = NSTextField(labelWithString: text)
        label.lineBreakMode = .byTruncatingMiddle
        label.toolTip = text
        return label
    }

    func tableViewSelectionDidChange(_ notification: Notification) { updateSelection() }
    func windowShouldClose(_ sender: NSWindow) -> Bool { closePanel(); return false }

    private func finish(_ change: DecisionChange) {
        guard inModal else { return }
        response = change
        inModal = false
        NSApp.stopModal()
    }

    @objc private func closePanel() { finish(DecisionChange(action: "close")) }
    @objc private func refreshList() { finish(DecisionChange(action: "refresh")) }
    @objc private func revokeSelected() {
        guard let item = selected, item.isActive else { return }
        finish(DecisionChange(action: "revoke", id: item.id))
    }

    /// Names one row and asks the agent for the rest. Which decisions belong
    /// to the same program is the agent's answer, from the anchor it stored.
    @objc private func revokeProgramOfSelected() {
        guard let item = selected, item.isActive, item.isAnchored else { return }
        finish(DecisionChange(action: "revoke-process", id: item.id))
    }

    @objc private func editDuration() {
        guard let item = selected, item.isActive else { return }
        let alert = NSAlert()
        alert.messageText = L10n.string("Change Temporary Decision Duration")
        alert.informativeText = L10n.string("The new interval starts now. The decision, key, server and SSH user stay the same.")
        alert.addButton(withTitle: L10n.string("Apply"))
        alert.addButton(withTitle: L10n.string("Cancel"))
        let day = NSButton(checkboxWithTitle: L10n.string("Until end of local day"), target: nil, action: nil)
        day.frame = NSRect(x: 0, y: 40, width: 330, height: 28)
        let value = NSTextField(string: "15")
        value.frame = NSRect(x: 0, y: 0, width: 75, height: 24)
        value.setAccessibilityLabel(L10n.string("Custom interval in minutes"))
        let label = NSTextField(labelWithString: L10n.string("minutes (1–1440)"))
        label.frame = NSRect(x: 86, y: 0, width: 244, height: 24)
        let accessory = NSView(frame: NSRect(x: 0, y: 0, width: 330, height: 76))
        let toggle = DurationFieldToggle(value)
        day.target = toggle; day.action = #selector(DurationFieldToggle.toggle(_:))
        accessory.addSubview(day); accessory.addSubview(value); accessory.addSubview(label)
        alert.accessoryView = accessory
        defer { withExtendedLifetime(toggle) {} }
        while alert.runModal() == .alertFirstButtonReturn {
            var change = DecisionChange(action: "update", id: item.id)
            if day.state == .on {
                change.endOfDay = true
            } else {
                guard let minutes = Int(value.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)), (1...1440).contains(minutes) else {
                    alert.informativeText = L10n.string("Choose an interval from 1 to 1440 minutes.")
                    continue
                }
                change.minutes = minutes
            }
            finish(change)
            return
        }
    }
}
