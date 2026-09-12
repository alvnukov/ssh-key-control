import AppKit
import SwiftUI

struct SecurityHistoryView: View {
    @ObservedObject var model: SecurityHistoryModel
    @State private var query = ""
    @State private var filter = "all"
    @State private var selection: UInt64?

    private var visible: [SecurityEvent] {
        model.events.filter { event in
            let matchesFilter = filter == "all"
                || (filter == "denied" && event.outcome == "denied")
                || (filter == "unverified" && event.kind == "decision" && !event.isVerified)
                || (filter == "cached" && event.source == "cached")
            let text = [event.keyFingerprint, event.hostFingerprint, event.user, event.title].compactMap { $0 }.joined(separator: " ")
            return matchesFilter && (query.isEmpty || text.localizedCaseInsensitiveContains(query))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if let status = model.status {
                    Image(systemName: status.running ? "circle.fill" : "circle")
                        .foregroundStyle(status.running ? .green : .secondary).font(.caption)
                    Text(status.running ? L10n.string("Agent running") : L10n.string("Agent not running"))
                } else {
                    Image(systemName: "questionmark.circle").foregroundStyle(.secondary)
                    Text(L10n.string("Agent status unavailable"))
                }
                Spacer()
                Text(L10n.format("Events: %lld", visible.count)).foregroundStyle(.secondary)
                Button { model.refresh() } label: { Image(systemName: "arrow.clockwise") }
                    .help(L10n.string("Refresh")).keyboardShortcut("r").disabled(model.refreshing)
            }
            .padding(16)
            HStack {
                TextField(L10n.string("Search fingerprints or username"), text: $query).textFieldStyle(.roundedBorder)
                Picker(L10n.string("Filter"), selection: $filter) {
                    Text(L10n.string("All events")).tag("all")
                    Text(L10n.string("Denied")).tag("denied")
                    Text(L10n.string("Unverified")).tag("unverified")
                    Text(L10n.string("Remembered decisions")).tag("cached")
                }.labelsHidden().frame(width: 180)
            }.padding([.horizontal, .bottom], 16)
            Divider()
            if let error = model.error {
                VStack(spacing: 12) {
                    Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                    Text(error)
                    Button(L10n.string("Try Again")) { model.refresh() }
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if model.events.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "clock").font(.system(size: 32)).foregroundStyle(.secondary)
                    Text(L10n.string("No recorded decisions yet")).font(.title3).bold()
                    Text(L10n.string("New requests appear after the updated SSH agent starts.\nApprovals made before history was added are not available."))
                        .multilineTextAlignment(.center).foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HSplitView {
                    Table(visible, selection: $selection) {
                        TableColumn(L10n.string("Time")) { event in
                            Text(event.time, format: .dateTime.month(.abbreviated).day().hour().minute().second())
                                .monospacedDigit()
                        }.width(min: 130, ideal: 150)
                        TableColumn(L10n.string("Decision")) { event in
                            HStack(spacing: 5) {
                                Image(systemName: event.outcome == "approved" ? "checkmark.circle" : event.outcome == "denied" ? "xmark.circle" : "clock")
                                Text(event.title)
                            }.foregroundStyle(event.outcome == "denied" ? Color.red : Color.primary)
                        }.width(min: 95, ideal: 110)
                        TableColumn(L10n.string("Destination")) { event in Text(event.destination).lineLimit(1) }
                    }.frame(minWidth: 440)
                    ScrollView {
                        if let event = model.events.first(where: { $0.id == selection }) {
                            EventDetails(event: event).padding(20)
                        } else {
                            Text(L10n.string("Select an event to inspect its fingerprints and decision."))
                                .foregroundStyle(.secondary).padding(24)
                        }
                    }.frame(minWidth: 290, idealWidth: 320, maxWidth: 440)
                }
            }
            Divider()
            Text(L10n.string("Records describe approval decisions, not completed logins or shell commands. Local history can be modified by processes running as your user."))
                .font(.caption).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(12)
        }
        .frame(minWidth: 820, minHeight: 460)
        .onAppear { model.refresh() }
    }
}

private struct EventDetails: View {
    let event: SecurityEvent
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(event.title).font(.title2).bold()
            Text(event.time.formatted(date: .complete, time: .standard)).foregroundStyle(.secondary)
            if event.kind == "native_agent" {
                if let fingerprint = event.keyFingerprint { field(L10n.string("Signing key"), fingerprint, fingerprint: true) }
                if event.outcome == "native_removed" {
                    Text(L10n.string("Another application may add the key again. Monitoring continues."))
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            if event.kind == "decision" {
                field(L10n.string("Signing key"), event.keyFingerprint ?? L10n.string("Unknown"), fingerprint: true)
                field(L10n.string("Destination"), event.isVerified ? L10n.string("Verified server identity") : L10n.string("Not verified — one signature only"))
                if event.isVerified {
                    field(L10n.string("Server key"), event.hostFingerprint ?? "", fingerprint: true)
                    field(L10n.string("SSH user"), event.user ?? "")
                }
                field(L10n.string("Decision source"), event.source == "management" ? L10n.string("Management") : (event.source == "cached" ? L10n.string("Previously remembered decision") : L10n.string("Confirmation dialog")))
                field(L10n.string("Scope"), scopeName(event.scope))
                if let expiry = event.expiresAt {
                    field(L10n.string("Expiry recorded at this decision"), expiry.formatted(date: .abbreviated, time: .standard))
                }
                Text(L10n.string("Fingerprints identify individual keys. A server name never authorizes all keys of that server."))
                    .font(.callout).foregroundStyle(.secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
    }
    private func field(_ title: String, _ value: String, fingerprint: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.system(.body, design: fingerprint ? .monospaced : .default))
                .fixedSize(horizontal: false, vertical: true)
        }
    }
    private func scopeName(_ value: String?) -> String {
        switch value {
        case "5m": L10n.string("Allow for 5 minutes")
        case "15m": L10n.string("Allow for 15 minutes")
        case "day": L10n.string("Allow until end of local day")
        case "deny5m": L10n.string("Deny for 5 minutes")
        case "deny1h": L10n.string("Deny for 1 hour")
        case "deny15m": L10n.string("Deny for 15 minutes")
        case "denyday": L10n.string("Deny until end of local day")
        case "custom": L10n.string("Allow for a custom interval")
        case "denycustom": L10n.string("Deny for a custom interval")
        case "timed-approval": L10n.string("Remembered approval")
        case "timed-denial": L10n.string("Remembered denial")
        default: L10n.string("One request")
        }
    }
}

@MainActor
final class HistoryWindowController: NSWindowController {
    init(model: SecurityHistoryModel) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 620),
                              styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = L10n.string("Security History")
        window.isReleasedWhenClosed = false
        window.contentViewController = NSHostingController(rootView: SecurityHistoryView(model: model))
        window.setFrameAutosaveName("SSHKeyControlHistory")
        window.center()
        super.init(window: window)
    }
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func open() {
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}
