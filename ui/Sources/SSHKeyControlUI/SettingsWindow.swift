import AppKit
import ServiceManagement
import SwiftUI

@MainActor
final class LoginItemModel: ObservableObject {
    @Published private(set) var enabled = false
    @Published private(set) var needsApproval = false
    @Published var error: String?

    init() { refresh() }

    struct Approval: Equatable {
        let enabled: Bool
        let needsApproval: Bool
    }

    static func currentApproval(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> Approval {
        let directory = home.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        let names = ["io.github.alvnukov.ssh-key-control.plist", "io.github.alvnukov.ssh-key-control.menubar.plist"]
        let statuses = names.map { SMAppService.statusForLegacyPlist(at: directory.appendingPathComponent($0)) }
        return approval(for: statuses)
    }

    static func approval(for statuses: [SMAppService.Status]) -> Approval {
        Approval(
            enabled: statuses.allSatisfy { $0 == .enabled },
            needsApproval: statuses.contains(.requiresApproval)
        )
    }

    func refresh() {
        let approval = Self.currentApproval()
        enabled = approval.enabled
        needsApproval = approval.needsApproval
    }

    func openSettings() {
        SMAppService.openSystemSettingsLoginItems()
        error = L10n.string("macOS controls this permission in Login Items. Return here after changing it to refresh the status.")
        refresh()
    }
}

@MainActor
final class HistorySettingsModel: ObservableObject {
    @Published var policy = HistoryFiles.readPolicy()
    @Published var error: String?
    func save() {
        do { try HistoryFiles.savePolicy(policy); error = nil }
        catch { self.error = L10n.string("History settings could not be saved."); policy = HistoryFiles.readPolicy() }
    }
}

struct GeneralSettingsView: View {
    @AppStorage(AppKitDialogs.enterActionKey, store: UserDefaults(suiteName: AppKitDialogs.defaultsSuite))
    private var enterAction = "deny"
    @AppStorage(AppKitDialogs.rememberKey, store: UserDefaults(suiteName: AppKitDialogs.defaultsSuite))
    private var remember = true
    @ObservedObject var login: LoginItemModel
    @ObservedObject var lifecycle: LifecycleModel

    var body: some View {
        Form {
            Section {
                Picker(L10n.string("Return and Enter"), selection: $enterAction) {
                    Text(L10n.string("Deny")).tag("deny")
                    Text(L10n.string("Allow")).tag("allow")
                }
                Text(L10n.string("The highlighted button uses the selected duration. Escape always denies once."))
                    .font(.callout).foregroundStyle(.secondary)
            } header: { Text(L10n.string("Confirmations")) }
            Section {
                Toggle(L10n.string("Remember new passwords in Keychain by default"), isOn: $remember)
                Text(L10n.string("Sets the checkbox in password dialogs. Existing Keychain items are unchanged."))
                    .font(.callout).foregroundStyle(.secondary)
            } header: { Text(L10n.string("Passwords")) }
            Section {
                Toggle(L10n.string("Open SSH Key Control at login"), isOn: Binding(get: { login.enabled }, set: { _ in login.openSettings() }))
                Text(L10n.string("Starts the protected SSH agent and menu bar icon after you sign in."))
                    .font(.callout).foregroundStyle(.secondary)
                lifecycleStatus
                if login.needsApproval {
                    Text(L10n.string("Allow SSH Key Control in Login Items to finish enabling automatic launch."))
                    Button(L10n.string("Open Login Items…")) { login.openSettings() }
                }
                if let error = login.error { Text(error).foregroundStyle(.red).font(.callout) }
            } header: { Text(L10n.string("Menu bar")) }
        }
        .formStyle(.grouped)
        .frame(width: 520, height: 410)
        .onAppear { login.refresh() }
    }

    @ViewBuilder private var lifecycleStatus: some View {
        switch lifecycle.state {
        case .checking, .repairing:
            Label(L10n.string("Checking SSH Key Control…"), systemImage: "hourglass")
                .foregroundStyle(.secondary)
        case .healthy:
            Label(L10n.string("Protected SSH agent is ready"), systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .needsRepair, .failed:
            Label(lifecycle.detail ?? L10n.string("SSH Key Control needs recovery"), systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        }
    }
}

struct AdvancedSettingsView: View {
    @ObservedObject var model: HistorySettingsModel
    @ObservedObject var monitor: NativeAgentMonitorModel
    var body: some View {
        Form {
            SystemAgentSettingsSection(model: monitor)
            Section {
                Picker(L10n.string("Keep history for"), selection: $model.policy.retentionDays) {
                    Text(L10n.string("1 day")).tag(1); Text(L10n.string("7 days")).tag(7); Text(L10n.string("30 days")).tag(30)
                }.onChange(of: model.policy.retentionDays) { _ in model.save() }
                Picker(L10n.string("Maximum events"), selection: $model.policy.maxEvents) {
                    Text(250, format: .number).tag(250); Text(1000, format: .number).tag(1000); Text(5000, format: .number).tag(5000)
                }.onChange(of: model.policy.maxEvents) { _ in model.save() }
                Text(L10n.string("Older records are hidden immediately and removed from storage when the agent records its next event."))
                    .font(.callout).foregroundStyle(.secondary)
                Text(L10n.string("Stored locally: time, key and server fingerprints, SSH username, and the approval decision. No passwords or signed payloads."))
                    .font(.callout).foregroundStyle(.secondary)
                if let error = model.error { Text(error).foregroundStyle(.red).font(.callout) }
            } header: { Text(L10n.string("Security history")) }
            Section {
                LabeledContent(L10n.string("Reusable approvals"), value: L10n.string("Exact key + server key + user"))
                LabeledContent(L10n.string("Destination proof"), value: L10n.string("Verified session and SSH client"))
                LabeledContent(L10n.string("Connections / packet size"), value: L10n.string("64 / 256 KiB"))
                LabeledContent(L10n.string("Partial request timeout"), value: L10n.string("5 seconds"))
                Text(L10n.string("These limits describe this build. History is informational and is never used to authorize requests."))
                    .font(.callout).foregroundStyle(.secondary)
            } header: { Text(L10n.string("Security policy")) }
        }
        .formStyle(.grouped)
        .frame(width: 560, height: 690)
    }
}

@MainActor
final class SettingsWindowController: NSWindowController, NSWindowDelegate {
    private let login = LoginItemModel()
    private let lifecycle: LifecycleModel
    private let historySettings = HistorySettingsModel()
    private let tabs = SettingsTabController()

    init(lifecycle: LifecycleModel = LifecycleModel(), monitor: NativeAgentMonitorModel = .shared) {
        self.lifecycle = lifecycle
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 500),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        super.init(window: window)
        window.delegate = self
        tabs.tabStyle = .toolbar
        let general = NSTabViewItem(viewController: NSHostingController(rootView: GeneralSettingsView(login: login, lifecycle: lifecycle)))
        general.viewController?.preferredContentSize = NSSize(width: 520, height: 410)
        general.label = L10n.string("General")
        general.image = NSImage(systemSymbolName: "gearshape", accessibilityDescription: nil)
        let advanced = NSTabViewItem(viewController: NSHostingController(rootView: AdvancedSettingsView(model: historySettings, monitor: monitor)))
        advanced.viewController?.preferredContentSize = NSSize(width: 560, height: 690)
        advanced.label = L10n.string("Advanced")
        advanced.image = NSImage(systemSymbolName: "slider.horizontal.3", accessibilityDescription: nil)
        tabs.addTabViewItem(general)
        tabs.addTabViewItem(advanced)
        window.contentViewController = tabs
        tabs.selectedTabViewItemIndex = UserDefaults.standard.integer(forKey: "settingsPane") == 1 ? 1 : 0
        window.toolbar?.allowsUserCustomization = false
        window.toolbar?.displayMode = .iconAndLabel
        tabs.fitSelectedPane()
        window.setFrameAutosaveName("SSHKeyControlSettings")
        window.center()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func open() {
        login.refresh()
        historySettings.policy = HistoryFiles.readPolicy()
        tabs.fitSelectedPane()
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
    func windowWillClose(_ notification: Notification) {
        UserDefaults.standard.set(tabs.selectedTabViewItemIndex, forKey: "settingsPane")
    }
}

@MainActor
final class SettingsTabController: NSTabViewController {
    override func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        super.tabView(tabView, didSelect: tabViewItem)
        fitSelectedPane()
    }

    func fitSelectedPane() {
        guard tabViewItems.indices.contains(selectedTabViewItemIndex),
              let window = view.window else { return }
        let item = tabViewItems[selectedTabViewItemIndex]
        guard let size = item.viewController?.preferredContentSize, size.width > 0 else { return }
        let topLeft = NSPoint(x: window.frame.minX, y: window.frame.maxY)
        window.title = item.label
        window.setContentSize(size)
        window.setFrameTopLeftPoint(topLeft)
    }
}
