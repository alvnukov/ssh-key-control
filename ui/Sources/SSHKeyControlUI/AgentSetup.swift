import AppKit
import ServiceManagement
import SwiftUI

enum AgentSetupOperation: Sendable, Equatable {
    case enable, remove, lifecycle, repair, stopMenu, configMigration, migrateConfig, permissions
    /// The key files to put into the agent; none means every key this Mac has.
    case loadKeys([String])
    /// The keys to take back out, by fingerprint; none means all of them.
    case unloadKeys([String])
    /// Key files to list beside the ones found in ~/.ssh and the SSH config.
    case listKeys([String])
    var arguments: [String] {
        switch self {
        case .enable: ["install"]
        case .remove: ["uninstall"]
        case .lifecycle: ["lifecycle", "--json"]
        case .repair: ["repair"]
        case .stopMenu: ["stop-menu"]
        case .configMigration: ["config-migration", "--json"]
        case .migrateConfig: ["migrate-config"]
        case .permissions: ["permissions"]
        case .loadKeys(let paths): ["keys", "load"] + paths
        case .unloadKeys(let fingerprints): ["keys", "unload"] + fingerprints
        case .listKeys(let paths): ["keys", "list", "--json"] + paths
        }
    }

    /// How long the command may take before it is stopped. Everything here is
    /// a launchd or filesystem operation that either finishes in a moment or
    /// is stuck — except loading a key, which waits for a passphrase to be
    /// typed into a dialog, and a person is allowed to take their time.
    var timeout: TimeInterval {
        switch self {
        case .loadKeys: 600
        default: 30
        }
    }
}

enum AgentSetupLocation {
    // A launch agent persists an absolute path. Never register an executable on
    // a disk image, in App Translocation, or through a symlink to either.
    static func isInstalled(_ bundle: URL, home: URL = FileManager.default.homeDirectoryForCurrentUser) -> Bool {
        let resolved = bundle.resolvingSymlinksInPath().standardizedFileURL
        let parent = resolved.deletingLastPathComponent()
        let destinations = [
            URL(fileURLWithPath: "/Applications", isDirectory: true),
            home.appendingPathComponent("Applications", isDirectory: true)
        ].map { $0.resolvingSymlinksInPath().standardizedFileURL.path }
        // URL equality also compares directory hints; canonical filesystem
        // paths identify the same folder consistently across Foundation versions.
        return resolved.pathExtension == "app" && destinations.contains(parent.path)
    }

    static func executable(in bundle: URL, home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> URL {
        guard isInstalled(bundle, home: home),
              try bundle.resourceValues(forKeys: [.volumeIsReadOnlyKey]).volumeIsReadOnly == false else {
            throw CocoaError(.fileWriteVolumeReadOnly)
        }
        let directory = bundle.appendingPathComponent("Contents/MacOS", isDirectory: true)
        for name in ["ssh-key-control", "ssh-key-control-ui", "ssh-key-control-menubar"] {
            let file = directory.appendingPathComponent(name)
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  file.resolvingSymlinksInPath().deletingLastPathComponent() == directory.resolvingSymlinksInPath(),
                  FileManager.default.isExecutableFile(atPath: file.path) else {
                throw CocoaError(.fileReadCorruptFile)
            }
        }
        return directory.appendingPathComponent("ssh-key-control")
    }
}

struct AgentSetupResult: Sendable {
    let succeeded: Bool
    let details: String
    let mayHaveAppliedChanges: Bool

    init(succeeded: Bool, details: String, mayHaveAppliedChanges: Bool = true) {
        self.succeeded = succeeded
        self.details = details
        self.mayHaveAppliedChanges = mayHaveAppliedChanges
    }
}

struct ConfigMigrationStatus: Decodable, Equatable, Sendable {
    enum State: String, Decodable, Sendable { case none, current, legacy, unknown }
    let state: State
    let path: String
    let backupPath: String?
    let detail: String?

    enum CodingKeys: String, CodingKey {
        case state, path, detail
        case backupPath = "backup_path"
    }
}

enum AgentSetupCommand {
    static func run(_ operation: AgentSetupOperation, bundle: URL) async -> AgentSetupResult {
        await Task.detached {
            do {
                let executable = try AgentSetupLocation.executable(in: bundle)
                let process = Process()
                process.executableURL = executable
                process.arguments = operation.arguments
                // No shell and no inherited helper override or loader injection.
                process.environment = [
                    "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
                    "USER": NSUserName(), "LOGNAME": NSUserName(),
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "TMPDIR": NSTemporaryDirectory()
                ]
                let output = Pipe()
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = output
                process.standardError = output
                try process.run()
                try output.fileHandleForWriting.close()
                defer { try? output.fileHandleForReading.close() }
                let timer = DispatchSource.makeTimerSource()
                timer.schedule(deadline: .now() + operation.timeout)
                timer.setEventHandler { if process.isRunning { process.terminate() } }
                timer.resume()
                defer { timer.cancel() }
                // Drain while running; keep a bounded diagnostic tail.
                var tail = Data()
                while let chunk = try output.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                    tail.append(chunk)
                    if tail.count > 16384 { tail.removeFirst(tail.count - 16384) }
                }
                process.waitUntilExit()
                return AgentSetupResult(succeeded: process.terminationStatus == 0,
                                        details: String(decoding: tail, as: UTF8.self))
            } catch {
                return AgentSetupResult(succeeded: false,
                    details: L10n.format("Setup could not run. Keep a complete copy of SSH Key Control in Applications. %@", error.localizedDescription))
            }
        }.value
    }
}

@MainActor
final class AgentSetupModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var result: AgentSetupResult?
    @Published private(set) var migrationPrompt: ConfigMigrationStatus?
    @Published private(set) var unknownConfigPath: String?
    let bundle: URL
    private let run: (AgentSetupOperation, URL) async -> AgentSetupResult
    private let approval: () -> LoginItemModel.Approval
    private let terminate: () -> Void

    init(bundle: URL = Bundle.main.bundleURL,
         run: @escaping (AgentSetupOperation, URL) async -> AgentSetupResult = { await AgentSetupCommand.run($0, bundle: $1) },
         approval: @escaping () -> LoginItemModel.Approval = { LoginItemModel.currentApproval() },
         terminate: @escaping () -> Void = { NSApp.terminate(nil) }) {
        self.bundle = bundle
        self.run = run
        self.approval = approval
        self.terminate = terminate
    }

    static func blockedByLoginItems(_ operation: AgentSetupOperation, approval: LoginItemModel.Approval) -> Bool {
        operation == .enable && approval.needsApproval
    }

    func perform(_ operation: AgentSetupOperation) {
        guard !busy else { return }
        if operation == .enable {
            Task { await prepareEnable() }
            return
        }
        if Self.blockedByLoginItems(operation, approval: approval()) {
            result = AgentSetupResult(
                succeeded: false,
                details: L10n.string("macOS is blocking SSH Key Control in Login Items.")
            )
            return
        }
        busy = true
        result = nil
        Task {
            result = await run(operation, bundle)
            busy = false
        }
    }

    func prepareEnable() async {
        guard !busy else { return }
        if Self.blockedByLoginItems(.enable, approval: approval()) {
            result = AgentSetupResult(succeeded: false,
                                      details: L10n.string("macOS is blocking SSH Key Control in Login Items."),
                                      mayHaveAppliedChanges: false)
            return
        }
        busy = true
        result = nil
        migrationPrompt = nil
        unknownConfigPath = nil
        let preflight = await run(.configMigration, bundle)
        guard preflight.succeeded,
              let data = preflight.details.data(using: .utf8),
              let status = try? JSONDecoder().decode(ConfigMigrationStatus.self, from: data) else {
            busy = false
            result = AgentSetupResult(succeeded: false,
                                      details: preflight.details,
                                      mayHaveAppliedChanges: false)
            return
        }
        switch status.state {
        case .legacy:
            migrationPrompt = status
            busy = false
        case .unknown:
            busy = false
            unknownConfigPath = status.path
            let detail = status.detail.map { "\n\n" + L10n.string("Technical details:") + " " + $0 } ?? ""
            result = AgentSetupResult(
                succeeded: false,
                details: L10n.format("SSH Key Control cannot update %@ automatically because its managed section does not match a known format. Open the file to review the managed section and restore a trusted backup if needed, then retry.", status.path) + detail,
                mayHaveAppliedChanges: false
            )
        case .none, .current:
            await runEnable(.enable)
        }
    }

    func confirmMigration() {
        guard migrationPrompt != nil, !busy else { return }
        migrationPrompt = nil
        busy = true
        result = nil
        Task { await runEnable(.migrateConfig) }
    }

    func cancelMigration() {
        migrationPrompt = nil
        result = AgentSetupResult(succeeded: false,
                                  details: L10n.string("No settings were changed. You can update the previous SSH settings later."),
                                  mayHaveAppliedChanges: false)
    }

    func revealConfig() {
        guard let path = unknownConfigPath else { return }
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    private func runEnable(_ operation: AgentSetupOperation) async {
        let commandResult = await run(operation, bundle)
        result = commandResult
        busy = false
        guard commandResult.succeeded else { return }
        let currentApproval = approval()
        if currentApproval.needsApproval {
            result = AgentSetupResult(
                succeeded: false,
                details: L10n.string("The agent is ready, but macOS requires approval in Login Items before automatic launch works."),
                mayHaveAppliedChanges: true
            )
        } else {
            terminate()
        }
    }
}

struct AgentSetupView: View {
    @ObservedObject var model: AgentSetupModel
    @State private var confirmRemoval = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(L10n.string("Connect SSH to approval dialogs")).font(.title2).fontWeight(.semibold)
            Text(L10n.string("Enable the bundled SSH agent and supervised menu bar icon for your account. Setup backs up your SSH settings, adds confirmation rules and starts both through launchd. Administrator access is not required."))
            Text(L10n.string("Updating restarts the agent and clears loaded keys and temporary approvals. SSH can load keys again; keys added only with ssh-add must be added again."))
                .font(.callout).foregroundStyle(.secondary)
            if !AgentSetupLocation.isInstalled(model.bundle) {
                Label(L10n.string("Move SSH Key Control to Applications, eject the disk image, then open the installed app to continue."),
                      systemImage: "folder").foregroundStyle(.secondary)
            }
            HStack {
                Button(L10n.string("Enable / Update Agent")) { model.perform(.enable) }
                Button(L10n.string("Remove Agent Setup…")) { confirmRemoval = true }
                if model.busy { ProgressView().controlSize(.small) }
            }
            .disabled(model.busy || !AgentSetupLocation.isInstalled(model.bundle))
            .alert(L10n.string("Remove SSH agent setup?"), isPresented: $confirmRemoval) {
                Button(L10n.string("Cancel"), role: .cancel) {}
                Button(L10n.string("Remove Setup"), role: .destructive) { model.perform(.remove) }
            } message: {
                Text(L10n.string("Removing setup stops SSH Key Control and removes its managed SSH settings. Apple's agent and macOS protection are not changed. Saved passwords and history are kept."))
            }
            .alert(L10n.string("Update previous SSH settings?"),
                   isPresented: Binding(get: { model.migrationPrompt != nil }, set: { _ in })) {
                Button(L10n.string("Cancel"), role: .cancel) { model.cancelMigration() }
                Button(L10n.string("Update Settings")) { model.confirmMigration() }
            } message: {
                Text(L10n.string("Settings from a previous installation were found. To continue, SSH Key Control needs to update its SSH settings. The app will save a backup and preserve your other SSH settings. Updating restarts the agent and clears keys held only in memory."))
            }
            if let result = model.result {
                Label(result.succeeded ? L10n.string("Completed") : L10n.string("Setup needs attention"),
                      systemImage: result.succeeded ? "checkmark.circle" : "exclamationmark.triangle")
                ScrollView {
                    Text(result.details).font(.callout).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if LoginItemModel.currentApproval().needsApproval {
                    Button(L10n.string("Open Login Items…")) { SMAppService.openSystemSettingsLoginItems() }
                }
                if model.unknownConfigPath != nil {
                    Button(L10n.string("Show SSH Config…")) { model.revealConfig() }
                }
                if !result.succeeded {
                    if result.mayHaveAppliedChanges {
                        Text(L10n.string("Setup may have applied some changes. Keep the app installed and review the details before retrying."))
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
            } else {
                Text(L10n.string("After enabling, this window closes while launchd takes ownership of the menu bar icon. Reopen terminals to refresh their environment. Keep the app here while the agent is enabled."))
                    .font(.callout).foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
        }
        .padding(24)
        .frame(width: 560, height: 460)
    }
}

@MainActor
final class AgentSetupWindowController: NSWindowController {
    private let model = AgentSetupModel()
    var isRunning: Bool { model.busy }

    init() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 460),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = L10n.string("Set Up SSH Agent")
        window.isReleasedWhenClosed = false
        super.init(window: window)
        window.contentView = NSHostingView(rootView: AgentSetupView(model: model))
        window.center()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    func open() {
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
}
