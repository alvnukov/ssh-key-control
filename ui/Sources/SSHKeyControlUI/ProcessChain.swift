import AppKit

/// The ancestry behind a signing request, drawn as a column with the durable
/// end of the session at the top and the process that actually asked at the
/// bottom, and a line through it showing how far a timed decision reaches.
///
/// Clicking a link moves that line up the chain. It never moves down: below
/// the link the agent proposed there is nothing that outlives the request
/// being answered, so a decision stored there would be dead when it was made.
@MainActor
final class ProcessChainView: NSStackView {
    let links: [ProcessLink]
    /// The narrowest link a decision may attach to. Zero means no process
    /// could be named at all, and then nothing here is selectable.
    let proposed: Int
    private(set) var boundary: Int
    private(set) var expanded = false
    private(set) var linkButtons: [Int: NSButton] = [:]
    private(set) var expandButtons: [NSButton] = []
    /// Called whenever the drawing changed, so the panel can resize and
    /// rewrite the button that names the chosen program.
    var onChange: (() -> Void)?

    /// Beyond this many processes the middle is folded away. A dialog that
    /// fills the screen stops being a dialog.
    static let collapseLimit = 12

    init(links: [ProcessLink], boundary: Int) {
        self.links = links
        self.proposed = (boundary > 0 && boundary < links.count) ? boundary : 0
        self.boundary = self.proposed
        super.init(frame: .zero)
        orientation = .vertical
        alignment = .leading
        spacing = 3
        setContentHuggingPriority(.required, for: .vertical)
        rebuild()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// The link a decision would attach to, or nil when none was on offer.
    var anchor: ProcessLink? { proposed > 0 ? links[boundary] : nil }

    /// Which links are drawn, topmost ancestor first. The process that asked,
    /// the one the agent proposed, the one the user moved to, and the topmost
    /// application are never folded away: they are the whole of the decision.
    var visibleIndices: [Int] {
        if expanded || links.count <= Self.collapseLimit {
            return links.indices.reversed()
        }
        var keep: Set<Int> = [0, proposed, boundary, links.count - 1]
        for index in 0..<min(4, links.count) { keep.insert(index) }
        for index in max(0, links.count - 3)..<links.count { keep.insert(index) }
        return keep.sorted(by: >)
    }

    private func rebuild() {
        for view in arrangedSubviews { view.removeFromSuperview() }
        linkButtons = [:]
        expandButtons = []
        var previous: Int?
        for index in visibleIndices {
            if let previous, previous - index > 1 {
                addArrangedSubview(expander(hiding: previous - index - 1))
            }
            addArrangedSubview(row(index))
            if index == boundary && proposed > 0 {
                addArrangedSubview(Self.divider())
            }
            previous = index
        }
        onChange?()
    }

    private func row(_ index: Int) -> NSButton {
        let link = links[index]
        var title = link.label
        var description = link.label
        if link.isVerified, let team = link.team, !team.isEmpty {
            title += "  " + L10n.format("signed by %@", team)
            description = L10n.format("%@, signed by %@", link.label, team)
        } else if !link.isVerified {
            title += "  ⚠"
            description = L10n.format("%@, signature not verified", link.label)
        }
        let selectable = proposed > 0 && index >= proposed
        let button = NSButton(title: title, target: selectable ? self : nil,
                              action: selectable ? #selector(pick(_:)) : nil)
        button.tag = index
        button.isBordered = false
        button.alignment = .left
        button.refusesFirstResponder = !selectable
        button.font = index == boundary && proposed > 0
            ? .boldSystemFont(ofSize: NSFont.systemFontSize)
            : .systemFont(ofSize: NSFont.systemFontSize)
        button.setAccessibilityLabel(description)
        button.toolTip = selectable ? L10n.string("Keep the decision for this program and everything it starts.") : description
        linkButtons[index] = button
        return button
    }

    private func expander(hiding count: Int) -> NSButton {
        let button = NSButton(title: L10n.format("Show %lld more processes", count),
                              target: self, action: #selector(expandAll))
        button.isBordered = false
        button.alignment = .left
        button.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        expandButtons.append(button)
        return button
    }

    private static func divider() -> NSView {
        let line = NSBox()
        line.boxType = .separator
        line.widthAnchor.constraint(equalToConstant: 320).isActive = true
        let caption = NSTextField(labelWithString: L10n.string("A timed decision covers everything above this line."))
        caption.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
        caption.textColor = .secondaryLabelColor
        let stack = NSStackView(views: [line, caption])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 2
        return stack
    }

    @objc private func pick(_ sender: NSButton) {
        guard proposed > 0, sender.tag >= proposed, sender.tag < links.count, sender.tag != boundary else { return }
        boundary = sender.tag
        rebuild()
    }

    @objc private func expandAll() {
        expanded = true
        rebuild()
    }
}
