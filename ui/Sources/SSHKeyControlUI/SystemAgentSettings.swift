import Foundation
import SwiftUI

struct SystemAgentState: Decodable, Sendable {
    let disabled: Bool
    let loaded: Bool
    let running: Bool
    let requiresLogout: Bool

    var title: String {
        if disabled {
            return loaded ? L10n.string("Startup disabled — sign out to finish") : L10n.string("Apple's SSH agent is disabled")
        }
        return loaded ? L10n.string("Apple's SSH agent is enabled") : L10n.string("Startup enabled — sign out to finish")
    }

    var instructions: String {
        if requiresLogout {
            return L10n.string("Save your work, then choose Apple menu > Log Out and sign in again. Closing a terminal or this app is not enough. Open these settings after signing in to verify the result. To restore Apple's agent, turn this setting off before uninstalling SSH Key Control.")
        }
        if disabled {
            return L10n.string("To restore Apple's agent, turn this setting off before removing SSH Key Control. If macOS cannot load it immediately, sign out and sign in again.")
        }
        return L10n.string("Turn this setting on to stop Apple's agent and prevent its service from loading for your account.")
    }
}

private enum SystemAgentAction: String, Sendable {
    case status, disable, enable
}

@MainActor
final class SystemAgentSettingsModel: ObservableObject {
    @Published private(set) var state: SystemAgentState?
    @Published private(set) var busy = false
    @Published private(set) var error: String?

    func refresh() { request(.status) }
    func setDisabled(_ value: Bool) { request(value ? .disable : .enable) }

    private func request(_ action: SystemAgentAction) {
        guard !busy else { return }
        busy = true
        Task {
            let response = await Self.run(action)
            switch response {
            case .success(let state): self.state = state; error = nil
            case .failure(let failure):
                error = failure.localizedDescription
                // A failed operation may have changed startup policy already.
                // Read it back; never leave the switch claiming an old state.
                if case .success(let fresh) = await Self.run(.status) { state = fresh }
                else { state = nil }
            }
            busy = false
        }
    }

    private nonisolated static func run(_ action: SystemAgentAction) async -> Result<SystemAgentState, NSError> {
        await Task.detached {
            do {
                guard let executable = Bundle.main.url(forAuxiliaryExecutable: "ssh-key-control") else {
                    throw CocoaError(.fileNoSuchFile)
                }
                let process = Process()
                process.executableURL = executable
                process.arguments = ["system-agent", action.rawValue]
                let pipe = Pipe()
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = pipe
                process.standardError = pipe
                try process.run()
                try pipe.fileHandleForWriting.close()
                defer { try? pipe.fileHandleForReading.close() }
                let timer = DispatchSource.makeTimerSource()
                timer.schedule(deadline: .now() + 15)
                timer.setEventHandler { if process.isRunning { process.terminate() } }
                timer.resume()
                defer { timer.cancel() }
                var data = Data()
                while let chunk = try pipe.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                    data.append(chunk)
                    if data.count > 16384 { data.removeFirst(data.count - 16384) }
                }
                process.waitUntilExit()
                guard process.terminationStatus == 0 else {
                    throw NSError(domain: "SSHKeyControl.SystemAgent", code: Int(process.terminationStatus),
                                  userInfo: [NSLocalizedDescriptionKey: String(decoding: data, as: UTF8.self)])
                }
                return .success(try JSONDecoder().decode(SystemAgentState.self, from: data))
            } catch { return .failure(error as NSError) }
        }.value
    }
}

struct SystemAgentSettingsSection: View {
    @StateObject private var model = SystemAgentSettingsModel()

    var body: some View {
        Section {
            Toggle(L10n.string("Disable Apple's SSH agent"), isOn: Binding(
                get: { model.state?.disabled ?? false },
                set: { model.setDisabled($0) }
            )).disabled(model.busy || model.state == nil)
            Text(L10n.string("Stops the system service and prevents its automatic launch for your account. Stopping it clears its loaded keys. Other agents and direct use of private keys remain possible."))
                .font(.callout).foregroundStyle(.secondary)
            if let state = model.state {
                Label(state.title, systemImage: state.requiresLogout ? "exclamationmark.triangle" : "info.circle")
                Text(state.instructions).font(.callout).foregroundStyle(.secondary)
                if state.disabled && state.loaded {
                    Text(state.running ? L10n.string("The system agent is still running. Its keys remain available until it stops.")
                                       : L10n.string("The system service is still loaded and can be activated. Disabling is not complete."))
                        .font(.callout).foregroundStyle(.orange)
                }
            }
            if let error = model.error { Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled) }
            HStack {
                Button(L10n.string("Check Status")) { model.refresh() }.disabled(model.busy)
                if model.busy { ProgressView().controlSize(.small) }
            }
        } header: { Text(L10n.string("System SSH agent")) }
        .onAppear { model.refresh() }
    }
}
