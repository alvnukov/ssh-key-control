import AppKit
import ServiceManagement
import SwiftUI

enum AgentSetupOperation: Sendable, Equatable {
    case enable, remove, lifecycle, repair, stopMenu
    var arguments: [String] {
        switch self {
        case .enable: ["install"]
        case .remove: ["uninstall"]
        case .lifecycle: ["lifecycle", "--json"]
        case .repair: ["repair"]
        case .stopMenu: ["stop-menu"]
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
                timer.schedule(deadline: .now() + 30)
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
    let bundle: URL

    init(bundle: URL = Bundle.main.bundleURL) { self.bundle = bundle }

    static func blockedByLoginItems(_ operation: AgentSetupOperation, approval: LoginItemModel.Approval) -> Bool {
        operation == .enable && approval.needsApproval
    }

    func perform(_ operation: AgentSetupOperation) {
        guard !busy else { return }
        if Self.blockedByLoginItems(operation, approval: LoginItemModel.currentApproval()) {
            result = AgentSetupResult(
                succeeded: false,
                details: L10n.string("macOS is blocking SSH Key Control in Login Items.")
            )
            return
        }
        busy = true
        result = nil
        Task {
            result = await AgentSetupCommand.run(operation, bundle: bundle)
            busy = false
            if operation == .enable, result?.succeeded == true {
                let approval = LoginItemModel.currentApproval()
                if approval.needsApproval {
                    result = AgentSetupResult(
                        succeeded: false,
                        details: L10n.string("The agent is ready, but macOS requires approval in Login Items before automatic launch works.")
                    )
                } else {
                    NSApp.terminate(nil)
                }
            }
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
                Text(L10n.string("First turn off Disable Apple's SSH agent in Advanced settings and complete any requested sign-out. Removing setup stops the protected agent and removes managed SSH settings. Saved passwords and history are kept."))
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
                if !result.succeeded {
                    Text(L10n.string("Setup may have applied some changes. Keep the app installed and review the details before retrying."))
                        .font(.callout).foregroundStyle(.secondary)
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
