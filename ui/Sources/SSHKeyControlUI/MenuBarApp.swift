import AppKit
import ServiceManagement

@MainActor
public final class MenuBarApp: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var item: NSStatusItem?
    private var settings: SettingsWindowController?
    private var history: HistoryWindowController?
    private var setup: AgentSetupWindowController?
    private let historyModel = SecurityHistoryModel()
    private let lifecycle = LifecycleModel()
    private let managed: Bool

    public init(managed: Bool = false) {
        self.managed = managed
        super.init()
    }

    public func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = AppIdentity.menuImage()
        item.button?.toolTip = "SSH Key Control"
        item.button?.setAccessibilityLabel(L10n.string("SSH Key Control — SSH key approvals"))
        let menu = NSMenu()
        menu.autoenablesItems = false
        menu.delegate = self
        menu.addItem(withTitle: "SSH Key Control", action: nil, keyEquivalent: "").isEnabled = false
        menu.addItem(.separator())
        menu.addItem(actionItem(L10n.string("Security History…"), #selector(openHistory), key: "y"))
        menu.addItem(actionItem(L10n.string("Settings…"), #selector(openSettings), key: ","))
        menu.addItem(actionItem(L10n.string("Set Up SSH Agent…"), #selector(openSetup)))
        menu.addItem(.separator())
        menu.addItem(actionItem(L10n.string("About SSH Key Control"), #selector(about)))
        menu.addItem(.separator())
        menu.addItem(actionItem(L10n.string("Quit SSH Key Control"), #selector(quit), key: "q"))
        item.menu = menu
        self.item = item
        installMainMenu()
        let defaults = UserDefaults.standard
        let needsInitialSetup = !defaults.bool(forKey: "hasSeenAgentSetup") || CommandLine.arguments.contains("--setup")
        if CommandLine.arguments.contains("--settings") {
            openSettings()
        } else if needsInitialSetup {
            defaults.set(true, forKey: "hasSeenAgentSetup")
            openSetup()
        }
        if !needsInitialSetup {
            Task { await checkLifecycle() }
        }
    }

    public func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openSettings()
        return true
    }
    public func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    public func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard setup?.isRunning != true else { setup?.open(); return .terminateCancel }
        return .terminateNow
    }
    public func menuWillOpen(_ menu: NSMenu) { historyModel.refresh() }

    private func actionItem(_ title: String, _ action: Selector, key: String = "") -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: key)
        item.target = self
        return item
    }
    private func installMainMenu() {
        let main = NSMenu()
        let app = NSMenu()
        app.addItem(actionItem(L10n.string("About SSH Key Control"), #selector(about)))
        app.addItem(.separator())
        app.addItem(actionItem(L10n.string("Settings…"), #selector(openSettings), key: ","))
        app.addItem(actionItem(L10n.string("Set Up SSH Agent…"), #selector(openSetup)))
        app.addItem(.separator())
        app.addItem(withTitle: L10n.string("Hide SSH Key Control"), action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthers = app.addItem(withTitle: L10n.string("Hide Others"), action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        app.addItem(withTitle: L10n.string("Show All"), action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        app.addItem(.separator())
        app.addItem(actionItem(L10n.string("Quit SSH Key Control"), #selector(quit), key: "q"))
        let appItem = NSMenuItem(); appItem.submenu = app; main.addItem(appItem)
        let edit = NSMenu(title: L10n.string("Edit"))
        edit.addItem(withTitle: L10n.string("Undo"), action: Selector(("undo:")), keyEquivalent: "z")
        let redo = edit.addItem(withTitle: L10n.string("Redo"), action: Selector(("redo:")), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        edit.addItem(.separator())
        for (title, selector, key) in [(L10n.string("Cut"), #selector(NSText.cut(_:)), "x"),
                                      (L10n.string("Paste"), #selector(NSText.paste(_:)), "v"),
                                      (L10n.string("Copy"), #selector(NSText.copy(_:)), "c"),
                                      (L10n.string("Select All"), #selector(NSText.selectAll(_:)), "a")] {
            edit.addItem(withTitle: title, action: selector, keyEquivalent: key)
        }
        let editItem = NSMenuItem(title: L10n.string("Edit"), action: nil, keyEquivalent: ""); editItem.submenu = edit; main.addItem(editItem)
        let window = NSMenu(title: L10n.string("Window"))
        window.addItem(actionItem(L10n.string("Security History"), #selector(openHistory), key: "y"))
        window.addItem(withTitle: L10n.string("Close"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        let windowItem = NSMenuItem(title: L10n.string("Window"), action: nil, keyEquivalent: ""); windowItem.submenu = window; main.addItem(windowItem)
        NSApp.mainMenu = main
        NSApp.windowsMenu = window
    }
    @objc private func openSetup() {
        if setup == nil { setup = AgentSetupWindowController() }
        setup?.open()
    }
    @objc private func openSettings() {
        if settings == nil { settings = SettingsWindowController(lifecycle: lifecycle) }
        settings?.open()
    }
    @objc private func openHistory() {
        if history == nil { history = HistoryWindowController(model: historyModel) }
        historyModel.refresh()
        history?.open()
    }
    @objc private func about() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.orderFrontStandardAboutPanel(options: [
            .applicationName: "SSH Key Control",
            .applicationIcon: AppIdentity.applicationImage(),
            .credits: NSAttributedString(string: L10n.string("Explicit approval for SSH keys.\nQuitting this app leaves the SSH agent running."))
        ])
    }
    @objc private func quit() {
        guard !managed else { NSApp.terminate(nil); return }
        Task {
            let result = await AgentSetupCommand.run(.stopMenu, bundle: Bundle.main.bundleURL)
            if result.succeeded {
                NSApp.terminate(nil)
            } else {
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = L10n.string("SSH Key Control could not stop menu bar supervision")
                alert.informativeText = result.details
                alert.addButton(withTitle: L10n.string("OK"))
                alert.runModal()
            }
        }
    }

    private func checkLifecycle(retry: Int = 0) async {
        let approval = LoginItemModel.currentApproval()
        if approval.needsApproval {
            lifecycle.issue(L10n.string("macOS is blocking SSH Key Control in Login Items."))
            showApprovalRequired()
            return
        }
        let loginEligible = approval.enabled
        if await lifecycle.check(loginEligible: loginEligible) { return }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = L10n.string("Restore SSH Key Control?")
        alert.informativeText = L10n.string("The protected SSH agent, its managed socket or automatic launch is not ready. Restore rewrites only SSH Key Control's owned launchd files and SSH config block, starts the protected agent and menu supervision, and registers the app in Login Items. Other SSH settings, saved passwords, history and Apple's SSH agent setting are unchanged.")
        alert.addButton(withTitle: L10n.string("Restore"))
        alert.addButton(withTitle: L10n.string("Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else {
            lifecycle.cancelled()
            return
        }

        guard await lifecycle.repair() else {
            showLifecycleFailure(retry: retry)
            return
        }
        let repairedApproval = LoginItemModel.currentApproval()
        if repairedApproval.needsApproval {
            showApprovalRequired()
            return
        }
        if !(await lifecycle.check(loginEligible: repairedApproval.enabled)) {
            showLifecycleFailure(retry: retry)
        }
    }

    private func showApprovalRequired() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = L10n.string("Allow SSH Key Control in Login Items")
        alert.informativeText = L10n.string("macOS is blocking the protected SSH agent and menu bar service. SSH Key Control will not change this decision. Open Login Items, allow SSH Key Control, then return and retry.")
        alert.addButton(withTitle: L10n.string("Open Login Items…"))
        alert.addButton(withTitle: L10n.string("Cancel"))
        if alert.runModal() == .alertFirstButtonReturn {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    private func showLifecycleFailure(_ message: String? = nil, retry: Int) {
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = L10n.string("SSH Key Control recovery did not complete")
        alert.informativeText = message ?? lifecycle.detail ?? L10n.string("The protected SSH agent is still unavailable.")
        if retry < 1 {
            alert.addButton(withTitle: L10n.string("Retry"))
            alert.addButton(withTitle: L10n.string("Cancel"))
            if alert.runModal() == .alertFirstButtonReturn {
                Task { await checkLifecycle(retry: retry + 1) }
            }
            return
        }
        alert.addButton(withTitle: L10n.string("Cancel"))
        alert.runModal()
    }
}
